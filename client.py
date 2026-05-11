"""
Interactive terminal client for the multi-user X25519 secure chat demo.

Run the relay server first:
    python server.py --host 127.0.0.1 --port 5000

Then open multiple terminals:
    python client.py --name Alice --server 127.0.0.1 --port 5000
    python client.py --name Bob   --server 127.0.0.1 --port 5000
    python client.py --name X     --server 127.0.0.1 --port 5000

Useful commands inside the client:
    /users
    /connect Bob
    /accept Alice
    /reject Alice
    /use Bob
    /sessions
    /fingerprint Bob
    /disconnect Bob
    /quit
"""

from __future__ import annotations

import argparse
import socket
import threading
from typing import Any

from src import protocol
from src.network import NetworkError, make_reader, read_json, send_json
from src.secure_message import decrypt_message, encrypt_message
from src.session import SecureSession
from src.x25519 import KEY_SIZE

HELP_TEXT = """
Commands:
  /help                 Show this help menu
  /users                Show online users
  /connect <name>       Request a secure chat with another user
  /accept <name>        Accept a pending secure chat request
  /reject <name>        Reject a pending secure chat request
  /use <name>           Switch the active secure chat session
  /sessions             Show active/pending secure sessions
  /fingerprint <name>   Show the session fingerprint for manual comparison
  /disconnect <name>    Close a secure session with one user
  /quit                 Exit the client

After choosing an active established session with /use, type normal text to
send encrypted messages to that user.
""".strip()


class ChatClient:
    def __init__(self, name: str, host: str, port: int):
        protocol.require_valid_username(name)
        self.name = name
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reader = None
        self.send_lock = threading.Lock()
        self.state_lock = threading.Lock()
        self.running = threading.Event()
        self.sessions: dict[str, SecureSession] = {}
        self.pending_requests: set[str] = set()
        self.active_peer: str | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        self.sock.connect((self.host, self.port))
        self.reader = make_reader(self.sock)
        self.send(protocol.register(self.name))

        response = read_json(self.reader)
        if response is None:
            raise ConnectionError("server closed the connection during registration")

        if response.get("type") == "error":
            raise ConnectionError(response.get("message", "registration failed"))

        if response.get("type") != "registered":
            raise ConnectionError("server returned an unexpected registration response")

        self.running.set()
        receiver = threading.Thread(target=self.receive_loop, daemon=True)
        receiver.start()

        print(f"Connected as {self.name}.")
        print(HELP_TEXT)

    def close(self) -> None:
        self.running.clear()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    def receive_loop(self) -> None:
        assert self.reader is not None

        while self.running.is_set():
            try:
                message = read_json(self.reader)
            except (NetworkError, OSError) as exc:
                print(f"\n[network error] {exc}")
                self.running.clear()
                break

            if message is None:
                print("\n[server disconnected]")
                self.running.clear()
                break

            self.handle_server_message(message)

    def send(self, message: dict[str, Any]) -> None:
        with self.send_lock:
            send_json(self.sock, message)

    # ------------------------------------------------------------------
    # Incoming server messages
    # ------------------------------------------------------------------

    def handle_server_message(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")

        if message_type == "users":
            self.print_users(message)
        elif message_type == "error":
            print(f"\n[server error] {message.get('message', 'unknown error')}")
        elif message_type == "info":
            print(f"\n[server] {message.get('message', '')}")
        elif message_type == "chat_request":
            self.handle_chat_request(message)
        elif message_type == "chat_accept":
            self.handle_chat_accept(message)
        elif message_type == "chat_reject":
            self.handle_chat_reject(message)
        elif message_type == "public_key":
            self.handle_public_key(message)
        elif message_type == "encrypted_message":
            self.handle_encrypted_message(message)
        elif message_type == "session_disconnect":
            self.handle_session_disconnect(message)
        elif message_type == "user_disconnected":
            self.handle_user_disconnected(message)
        else:
            print(f"\n[unknown message] {message}")

    def print_users(self, message: dict[str, Any]) -> None:
        users = message.get("users", [])
        if not users:
            print("\nNo other users are online.")
            return

        print("\nOnline users:")
        for username in users:
            print(f"  - {username}")

    def handle_chat_request(self, message: dict[str, Any]) -> None:
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        with self.state_lock:
            self.pending_requests.add(peer)

        print(f"\nIncoming secure chat request from {peer}.")
        print(f"Type /accept {peer} or /reject {peer}")

    def handle_chat_accept(self, message: dict[str, Any]) -> None:
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None:
            print(f"\n{peer} accepted, but no local pending session was found.")
            return

        print(f"\n{peer} accepted your secure chat request.")
        self.send(protocol.public_key(self.name, peer, session.local_public_key))
        print(f"Sent fresh X25519 public key to {peer}.")

    def handle_chat_reject(self, message: dict[str, Any]) -> None:
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        with self.state_lock:
            self.sessions.pop(peer, None)
            if self.active_peer == peer:
                self.active_peer = None

        print(f"\n{peer} rejected your secure chat request.")

    def handle_public_key(self, message: dict[str, Any]) -> None:
        peer = message.get("from")
        public_key_hex = message.get("public_key")

        if not isinstance(peer, str):
            return

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None:
            print(f"\nReceived a public key from {peer}, but no session exists.")
            return

        try:
            peer_public_key = protocol.require_hex_bytes(public_key_hex, KEY_SIZE, "public_key")
            session.set_peer_public_key(peer_public_key)
        except (TypeError, ValueError) as exc:
            print(f"\nFailed to process public key from {peer}: {exc}")
            return

        with self.state_lock:
            if self.active_peer is None:
                self.active_peer = peer

        print(f"\nSecure session established with {peer}.")
        print(f"Session fingerprint: {session.fingerprint}")
        print("Compare this fingerprint with the other side to detect key replacement.")

    def handle_encrypted_message(self, message: dict[str, Any]) -> None:
        peer = message.get("from")
        nonce_hex = message.get("nonce")
        ciphertext_hex = message.get("ciphertext")

        if not isinstance(peer, str):
            return

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None or not session.established:
            print(f"\nReceived encrypted message from {peer}, but no established session exists.")
            return

        try:
            nonce = protocol.require_hex_bytes(nonce_hex, 12, "nonce")
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = decrypt_message(session.require_session_key(), nonce, ciphertext)
        except (TypeError, ValueError) as exc:
            print(f"\nFailed to decrypt message from {peer}: {exc}")
            return

        print(f"\n{peer}: {plaintext}")

    def handle_session_disconnect(self, message: dict[str, Any]) -> None:
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        self.remove_session(peer)
        print(f"\n{peer} closed the secure session.")

    def handle_user_disconnected(self, message: dict[str, Any]) -> None:
        peer = message.get("name")
        if not isinstance(peer, str):
            return

        removed = self.remove_session(peer)
        with self.state_lock:
            self.pending_requests.discard(peer)

        if removed:
            print(f"\n{peer} disconnected from the server. Secure session closed.")

    # ------------------------------------------------------------------
    # Command handling
    # ------------------------------------------------------------------

    def interactive_loop(self) -> None:
        while self.running.is_set():
            try:
                line = input("\n> ").strip()
            except (EOFError, KeyboardInterrupt):
                line = "/quit"

            if not line:
                continue

            if line.startswith("/"):
                self.handle_command(line)
            else:
                self.send_chat_text(line)

    def handle_command(self, line: str) -> None:
        parts = line.split(maxsplit=1)
        command = parts[0].lower()
        argument = parts[1].strip() if len(parts) == 2 else ""

        try:
            if command == "/help":
                print(HELP_TEXT)
            elif command == "/users":
                self.send(protocol.list_users())
            elif command == "/connect":
                self.command_connect(argument)
            elif command == "/accept":
                self.command_accept(argument)
            elif command == "/reject":
                self.command_reject(argument)
            elif command == "/use":
                self.command_use(argument)
            elif command == "/sessions":
                self.command_sessions()
            elif command == "/fingerprint":
                self.command_fingerprint(argument)
            elif command == "/disconnect":
                self.command_disconnect(argument)
            elif command == "/quit":
                print("Disconnecting...")
                self.close()
            else:
                print("Unknown command. Type /help for available commands.")
        except ValueError as exc:
            print(f"Command error: {exc}")
        except OSError as exc:
            print(f"Network error: {exc}")
            self.close()

    def command_connect(self, peer: str) -> None:
        self.require_peer_argument(peer)

        if peer == self.name:
            raise ValueError("you cannot connect to yourself")

        with self.state_lock:
            if peer in self.sessions:
                raise ValueError(f"a session with {peer} already exists or is pending")
            self.sessions[peer] = SecureSession(
                local_name=self.name,
                peer_name=peer,
                initiator_name=self.name,
                responder_name=peer,
            )

        self.send(protocol.chat_request(self.name, peer))
        print(f"Secure chat request sent to {peer}.")

    def command_accept(self, peer: str) -> None:
        self.require_peer_argument(peer)

        with self.state_lock:
            if peer not in self.pending_requests:
                raise ValueError(f"no pending request from {peer}")
            self.pending_requests.remove(peer)
            self.sessions[peer] = SecureSession(
                local_name=self.name,
                peer_name=peer,
                initiator_name=peer,
                responder_name=self.name,
            )
            session = self.sessions[peer]

        self.send(protocol.chat_accept(self.name, peer))
        self.send(protocol.public_key(self.name, peer, session.local_public_key))
        print(f"Accepted secure chat request from {peer}.")
        print(f"Sent fresh X25519 public key to {peer}.")

    def command_reject(self, peer: str) -> None:
        self.require_peer_argument(peer)

        with self.state_lock:
            self.pending_requests.discard(peer)

        self.send(protocol.chat_reject(self.name, peer))
        print(f"Rejected secure chat request from {peer}.")

    def command_use(self, peer: str) -> None:
        self.require_peer_argument(peer)

        with self.state_lock:
            session = self.sessions.get(peer)
            if session is None:
                raise ValueError(f"no session with {peer}")
            if not session.established:
                raise ValueError(f"session with {peer} is not established yet")
            self.active_peer = peer

        print(f"Active secure chat set to {peer}.")

    def command_sessions(self) -> None:
        with self.state_lock:
            sessions = list(self.sessions.items())
            pending = sorted(self.pending_requests)
            active_peer = self.active_peer

        if not sessions and not pending:
            print("No sessions or pending requests.")
            return

        if sessions:
            print("Sessions:")
            for peer, session in sessions:
                status = "established" if session.established else "pending handshake"
                marker = " (active)" if peer == active_peer else ""
                print(f"  - {peer}: {status}{marker}")

        if pending:
            print("Pending incoming requests:")
            for peer in pending:
                print(f"  - {peer}")

    def command_fingerprint(self, peer: str) -> None:
        self.require_peer_argument(peer)

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None:
            raise ValueError(f"no session with {peer}")
        if not session.established:
            raise ValueError(f"session with {peer} is not established yet")

        print(f"Fingerprint with {peer}: {session.fingerprint}")

    def command_disconnect(self, peer: str) -> None:
        self.require_peer_argument(peer)

        removed = self.remove_session(peer)
        if not removed:
            raise ValueError(f"no session with {peer}")

        self.send(protocol.session_disconnect(self.name, peer))
        print(f"Secure session with {peer} closed.")

    def send_chat_text(self, plaintext: str) -> None:
        with self.state_lock:
            peer = self.active_peer
            session = self.sessions.get(peer) if peer is not None else None

        if peer is None or session is None:
            print("No active secure session. Use /connect, /accept, and then /use <name>.")
            return

        if not session.established:
            print(f"Session with {peer} is not established yet.")
            return

        nonce, ciphertext = encrypt_message(session.require_session_key(), plaintext)
        self.send(protocol.encrypted_message(self.name, peer, nonce, ciphertext))
        print(f"[encrypted -> {peer}] {plaintext}")

    # ------------------------------------------------------------------
    # State helpers
    # ------------------------------------------------------------------

    def remove_session(self, peer: str) -> bool:
        with self.state_lock:
            existed = self.sessions.pop(peer, None) is not None
            if self.active_peer == peer:
                self.active_peer = None
        return existed

    @staticmethod
    def require_peer_argument(peer: str) -> None:
        if not peer:
            raise ValueError("missing username")
        protocol.require_valid_username(peer)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="X25519 secure terminal chat client")
    parser.add_argument("--name", required=True, help="Local username, such as Alice")
    parser.add_argument("--server", default="127.0.0.1", help="Relay server host/IP")
    parser.add_argument("--port", type=int, default=5000, help="Relay server TCP port")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    client = ChatClient(args.name, args.server, args.port)

    try:
        client.connect()
        client.interactive_loop()
    except Exception as exc:
        print(f"Failed to start client: {exc}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
