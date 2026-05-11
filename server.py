"""
Relay server for the multi-user X25519 secure terminal chat demo.

Run:
    python server.py --host 127.0.0.1 --port 5000

The server is deliberately not a cryptographic participant. It only:
    - registers connected users
    - lists online users
    - forwards chat requests
    - forwards X25519 public keys
    - forwards encrypted messages

It never sees private keys, shared secrets, session keys, or plaintext chat
messages.
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import threading
from dataclasses import dataclass
from typing import Any

from src import protocol
from src.network import NetworkError, make_reader, read_json, send_json


@dataclass
class ClientConnection:
    name: str
    sock: socket.socket


class ChatServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int]):
        super().__init__(server_address, ChatRequestHandler)
        self.clients: dict[str, ClientConnection] = {}
        self.lock = threading.Lock()

    def register_client(self, name: str, sock: socket.socket) -> None:
        with self.lock:
            if name in self.clients:
                raise ValueError(f"username '{name}' is already connected")
            self.clients[name] = ClientConnection(name, sock)

    def unregister_client(self, name: str) -> None:
        with self.lock:
            existed = self.clients.pop(name, None) is not None

        if existed:
            print(f"[server] {name} disconnected")
            self.broadcast(protocol.user_disconnected(name), exclude=name)

    def online_users(self, exclude: str | None = None) -> list[str]:
        with self.lock:
            names = sorted(self.clients.keys())

        if exclude is not None:
            names = [name for name in names if name != exclude]

        return names

    def send_to_client(self, name: str, message: dict[str, Any]) -> bool:
        with self.lock:
            client = self.clients.get(name)

        if client is None:
            return False

        try:
            send_json(client.sock, message)
            return True
        except OSError:
            return False

    def broadcast(self, message: dict[str, Any], exclude: str | None = None) -> None:
        for name in self.online_users():
            if name != exclude:
                self.send_to_client(name, message)


class ChatRequestHandler(socketserver.BaseRequestHandler):
    server: ChatServer

    def setup(self) -> None:
        self.name: str | None = None
        self.reader = make_reader(self.request)

    def handle(self) -> None:
        try:
            while True:
                message = read_json(self.reader)
                if message is None:
                    break
                self.handle_message(message)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        except NetworkError as exc:
            self.safe_send(protocol.error(str(exc)))
        finally:
            if self.name is not None:
                self.server.unregister_client(self.name)

    def handle_message(self, message: dict[str, Any]) -> None:
        message_type = message.get("type")

        if message_type == "register":
            self.handle_register(message)
            return

        if self.name is None:
            self.safe_send(protocol.error("first message must be register"))
            return

        if message_type == "list_users":
            self.safe_send(protocol.users(self.server.online_users(exclude=self.name)))
            return

        if message_type in {
            "chat_request",
            "chat_accept",
            "chat_reject",
            "public_key",
            "encrypted_message",
            "session_disconnect",
        }:
            self.forward_to_peer(message)
            return

        self.safe_send(protocol.error(f"unknown message type: {message_type}"))

    def handle_register(self, message: dict[str, Any]) -> None:
        if self.name is not None:
            self.safe_send(protocol.error("client is already registered"))
            return

        name = message.get("name")

        if not isinstance(name, str) or not protocol.is_valid_username(name):
            self.safe_send(protocol.error("invalid username; use 1-32 letters, numbers, '_' or '-'"))
            return

        try:
            self.server.register_client(name, self.request)
        except ValueError as exc:
            self.safe_send(protocol.error(str(exc)))
            return

        self.name = name
        print(f"[server] {name} connected")
        self.safe_send(protocol.registered(name))

    def forward_to_peer(self, message: dict[str, Any]) -> None:
        assert self.name is not None

        receiver = message.get("to")

        if not isinstance(receiver, str) or not protocol.is_valid_username(receiver):
            self.safe_send(protocol.error("message has invalid receiver"))
            return

        if receiver == self.name:
            self.safe_send(protocol.error("cannot send a message to yourself"))
            return

        # Never trust the client-supplied "from" field. The server writes it
        # based on the registered connection identity.
        message["from"] = self.name

        delivered = self.server.send_to_client(receiver, message)

        if not delivered:
            self.safe_send(protocol.error(f"user '{receiver}' is not online"))

    def safe_send(self, message: dict[str, Any]) -> None:
        try:
            send_json(self.request, message)
        except OSError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="X25519 secure chat relay server")
    parser.add_argument("--host", default="127.0.0.1", help="Host/IP to bind")
    parser.add_argument("--port", type=int, default=5000, help="TCP port to bind")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    address = (args.host, args.port)

    with ChatServer(address) as server:
        print(f"X25519 relay server listening on {args.host}:{args.port}")
        print("Press Ctrl+C to stop.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[server] shutting down")


if __name__ == "__main__":
    main()
