"""
gui_client.py — GUI-compatible client core for the X25519 secure chat demo.

This module contains exactly the same networking and cryptographic logic as
client.py, but replaces all print() calls with callbacks.  The GUI (gui_app.py)
registers those callbacks and uses them to update the Tkinter interface.

Why separate this from the GUI?
    Separating the network/crypto layer from the display layer is a classic
    design principle. Here it means:
      - The terminal client (client.py) keeps working exactly as before.
      - The GUI wraps this core without touching any crypto or protocol code.
      - This core could also be unit-tested without a display.

Callbacks registered by the GUI:
    on_log(message)             → write a timestamped line to the event log
    on_users_updated(users)     → refresh the connected-clients list
    on_session_updated(peer)    → refresh key-exchange status for a peer
    on_message_received(peer, plaintext) → display a received chat message
    on_connected()              → enable the GUI after successful registration
    on_disconnected()           → disable the GUI after disconnect
    on_incoming_request(peer)   → notify the GUI of an incoming key-exchange request
"""

from __future__ import annotations

import socket
import threading
from typing import Any, Callable

from src import protocol
from src.network import NetworkError, make_reader, read_json, send_json
from src.secure_message import decrypt_message, encrypt_message
from src.session import SecureSession
from src.x25519 import KEY_SIZE


# ---------------------------------------------------------------------------
# GUI-compatible client core
# ---------------------------------------------------------------------------

class GUIClient:
    """
    Network and cryptographic core for the GUI client.

    This class handles:
      - TCP connection to the relay server
      - User registration
      - Incoming message loop (on a background thread)
      - Key-exchange session management
      - Sending/receiving encrypted messages

    It does NOT do any GUI work.  Instead it fires callbacks that the GUI
    registers to update its widgets.

    Usage:
        client = GUIClient(name="Alice", host="127.0.0.1", port=5000)
        client.on_log = lambda msg: my_log_widget.append(msg)
        client.connect()
    """

    def __init__(self, name: str, host: str, port: int):
        """
        Initialise the client but do not connect yet.

        Args:
            name: Username to register with the server (1–32 alphanumeric chars).
            host: Relay server hostname or IP address.
            port: Relay server TCP port.
        """
        # Validate the username using the same rules as the terminal client.
        protocol.require_valid_username(name)

        self.name = name
        self.host = host
        self.port = port

        # Underlying TCP socket and line reader.
        self.sock: socket.socket | None = None
        self.reader = None

        # Thread-safety locks:
        #   send_lock  — prevents interleaved socket writes from two threads
        #   state_lock — protects session and pending-request state
        self.send_lock = threading.Lock()
        self.state_lock = threading.Lock()

        # Event used by the receive loop to know when to stop.
        self.running = threading.Event()

        # Pairwise secure sessions keyed by peer username.
        # A session is created when we /connect or /accept.
        self.sessions: dict[str, SecureSession] = {}

        # Usernames from which we have received a chat_request but not yet
        # accepted or rejected.
        self.pending_requests: set[str] = set()

        # The peer we are currently chatting with (used for sending messages).
        self.active_peer: str | None = None

        # -----------------------------------------------------------------------
        # Callback hooks — set these before calling connect().
        # -----------------------------------------------------------------------

        # Called with a human-readable status string.
        self.on_log: Callable[[str], None] = lambda msg: None

        # Called with the refreshed list of online users (excluding ourselves).
        self.on_users_updated: Callable[[list[str]], None] = lambda users: None

        # Called after a session's state changes (new key received, established, …).
        self.on_session_updated: Callable[[str], None] = lambda peer: None

        # Called when a plaintext message is ready to display.
        self.on_message_received: Callable[[str, str], None] = lambda peer, text: None

        # Called once after successful registration with the server.
        self.on_connected: Callable[[], None] = lambda: None

        # Called when the connection closes (cleanly or by error).
        self.on_disconnected: Callable[[], None] = lambda: None

        # Called when a peer sends us a chat_request that we have not yet acted on.
        self.on_incoming_request: Callable[[str], None] = lambda peer: None

    # -----------------------------------------------------------------------
    # Connection lifecycle
    # -----------------------------------------------------------------------

    def connect(self) -> None:
        """
        Open the TCP connection, register our username, and start the receive loop.

        This must be called from the GUI's background thread (or a worker
        thread) to avoid blocking the Tkinter event loop.

        Raises:
            ConnectionError: if registration fails.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.reader = make_reader(self.sock)

        # Send the first message the server expects: our chosen username.
        self.send(protocol.register(self.name))

        # Read the synchronous registration reply before entering the async loop.
        response = read_json(self.reader)
        if response is None:
            raise ConnectionError("Server closed the connection during registration.")

        if response.get("type") == "error":
            raise ConnectionError(response.get("message", "Registration failed."))

        if response.get("type") != "registered":
            raise ConnectionError("Server returned an unexpected registration response.")

        self.running.set()

        # Start the background receive loop.
        threading.Thread(target=self._receive_loop, daemon=True).start()

        self.on_log(f"Connected to server as '{self.name}'.")
        self.on_connected()

        # Ask the server for the current user list right away.
        self.request_users()

    def disconnect(self) -> None:
        """
        Close the TCP connection and stop the receive loop.
        """
        self.running.clear()
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
        self.on_log("Disconnected from server.")
        self.on_disconnected()

    # -----------------------------------------------------------------------
    # Sending helpers
    # -----------------------------------------------------------------------

    def send(self, message: dict[str, Any]) -> None:
        """
        Serialise and send one JSON message to the server.

        Thread-safe: multiple threads can call this concurrently.
        """
        if self.sock is None:
            return
        with self.send_lock:
            send_json(self.sock, message)

    def request_users(self) -> None:
        """
        Ask the server for the current list of connected users.

        The server replies with a 'users' message; _receive_loop handles it.
        """
        self.send(protocol.list_users())

    # -----------------------------------------------------------------------
    # Background receive loop
    # -----------------------------------------------------------------------

    def _receive_loop(self) -> None:
        """
        Read JSON messages from the server in a background thread.

        This loop runs until the connection closes or self.running is cleared.
        All incoming messages are dispatched to handler methods.
        """
        assert self.reader is not None

        while self.running.is_set():
            try:
                message = read_json(self.reader)
            except (NetworkError, OSError) as exc:
                self.on_log(f"[network error] {exc}")
                self.running.clear()
                self.on_disconnected()
                break

            if message is None:
                self.on_log("Server closed the connection.")
                self.running.clear()
                self.on_disconnected()
                break

            self._dispatch(message)

    def _dispatch(self, message: dict[str, Any]) -> None:
        """
        Route one incoming server message to the correct handler method.
        """
        message_type = message.get("type")

        if message_type == "users":
            self._handle_users(message)
        elif message_type == "error":
            self.on_log(f"[server error] {message.get('message', 'unknown error')}")
        elif message_type == "info":
            self.on_log(f"[server] {message.get('message', '')}")
        elif message_type == "chat_request":
            self._handle_chat_request(message)
        elif message_type == "chat_accept":
            self._handle_chat_accept(message)
        elif message_type == "chat_reject":
            self._handle_chat_reject(message)
        elif message_type == "public_key":
            self._handle_public_key(message)
        elif message_type == "encrypted_message":
            self._handle_encrypted_message(message)
        elif message_type == "session_disconnect":
            self._handle_session_disconnect(message)
        elif message_type == "user_disconnected":
            self._handle_user_disconnected(message)

    # -----------------------------------------------------------------------
    # Incoming message handlers
    # -----------------------------------------------------------------------

    def _handle_users(self, message: dict[str, Any]) -> None:
        """Update the GUI's connected-clients list."""
        users = message.get("users", [])
        self.on_users_updated(users)

    def _handle_chat_request(self, message: dict[str, Any]) -> None:
        """
        A peer wants to start a key exchange with us.

        We store the request and notify the GUI, which will show an
        Accept / Reject prompt.
        """
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        with self.state_lock:
            self.pending_requests.add(peer)

        self.on_log(f"Incoming key-exchange request from '{peer}'.")
        self.on_incoming_request(peer)

    def _handle_chat_accept(self, message: dict[str, Any]) -> None:
        """
        The peer accepted our key-exchange request.

        Now we send our fresh public key to complete the handshake.
        """
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None:
            self.on_log(f"'{peer}' accepted, but no local pending session found.")
            return

        self.on_log(f"'{peer}' accepted the key-exchange request.")
        # Send our freshly generated X25519 public key.
        self.send(protocol.public_key(self.name, peer, session.local_public_key))
        self.on_log(f"Sent X25519 public key to '{peer}'.")
        self.on_session_updated(peer)

    def _handle_chat_reject(self, message: dict[str, Any]) -> None:
        """The peer rejected our key-exchange request; clean up the session."""
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        with self.state_lock:
            self.sessions.pop(peer, None)
            if self.active_peer == peer:
                self.active_peer = None

        self.on_log(f"'{peer}' rejected the key-exchange request.")
        self.on_session_updated(peer)

    def _handle_public_key(self, message: dict[str, Any]) -> None:
        """
        We received the peer's X25519 public key.

        This triggers the final step of the key exchange:
          shared_secret = x25519(our_private_key, peer_public_key)

        After this the session is 'established' and chat is enabled.
        """
        peer = message.get("from")
        public_key_hex = message.get("public_key")

        if not isinstance(peer, str):
            return

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None:
            self.on_log(f"Received public key from '{peer}', but no session exists.")
            return

        try:
            peer_pk = protocol.require_hex_bytes(public_key_hex, KEY_SIZE, "public_key")
            # This call runs x25519(our_private, peer_public) inside SecureSession,
            # then runs HKDF to derive a symmetric session key and fingerprint.
            session.set_peer_public_key(peer_pk)
        except (TypeError, ValueError) as exc:
            self.on_log(f"Failed to process public key from '{peer}': {exc}")
            return

        # Automatically set this peer as active if we have no active chat.
        with self.state_lock:
            if self.active_peer is None:
                self.active_peer = peer

        self.on_log(f"X25519 public key received from '{peer}'.")
        self.on_log(f"Shared secret derived successfully.")
        self.on_log(f"Session fingerprint: {session.fingerprint}")
        self.on_session_updated(peer)

    def _handle_encrypted_message(self, message: dict[str, Any]) -> None:
        """
        Decrypt an incoming AES-GCM ciphertext and deliver the plaintext to the GUI.

        The session key was derived from the X25519 shared secret via HKDF-SHA256.
        AES-GCM provides both confidentiality and authenticity.
        """
        peer = message.get("from")
        nonce_hex = message.get("nonce")
        ciphertext_hex = message.get("ciphertext")

        if not isinstance(peer, str):
            return

        with self.state_lock:
            session = self.sessions.get(peer)

        if session is None or not session.established:
            self.on_log(f"Received encrypted message from '{peer}', but no established session exists.")
            return

        try:
            nonce = protocol.require_hex_bytes(nonce_hex, 12, "nonce")
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = decrypt_message(session.require_session_key(), nonce, ciphertext)
        except (TypeError, ValueError) as exc:
            self.on_log(f"Decryption failed (message from '{peer}'): {exc}")
            return

        self.on_message_received(peer, plaintext)

    def _handle_session_disconnect(self, message: dict[str, Any]) -> None:
        """Peer closed their session with us."""
        peer = message.get("from")
        if not isinstance(peer, str):
            return

        self._remove_session(peer)
        self.on_log(f"'{peer}' closed the secure session.")
        self.on_session_updated(peer)

    def _handle_user_disconnected(self, message: dict[str, Any]) -> None:
        """A user disconnected from the server entirely."""
        peer = message.get("name")
        if not isinstance(peer, str):
            return

        self._remove_session(peer)
        with self.state_lock:
            self.pending_requests.discard(peer)

        self.on_log(f"'{peer}' disconnected from the server.")
        self.on_session_updated(peer)
        # Refresh the users list immediately.
        self.request_users()

    # -----------------------------------------------------------------------
    # Actions triggered by the GUI
    # -----------------------------------------------------------------------

    def action_request_exchange(self, peer: str) -> None:
        """
        Initiate a key exchange with another connected client.

        This creates a fresh X25519 key pair for this session and sends a
        chat_request to the relay server, which forwards it to the peer.

        Args:
            peer: Username of the target client.
        """
        if peer == self.name:
            self.on_log("Cannot start a key exchange with yourself.")
            return

        with self.state_lock:
            if peer in self.sessions:
                self.on_log(f"A session with '{peer}' already exists or is pending.")
                return

            # Create a SecureSession, which internally creates a fresh X25519Party
            # (new private key + public key) for this specific session.
            self.sessions[peer] = SecureSession(
                local_name=self.name,
                peer_name=peer,
                initiator_name=self.name,   # we are the initiator
                responder_name=peer,
            )

        self.send(protocol.chat_request(self.name, peer))
        self.on_log(f"Key-exchange request sent to '{peer}'.")
        self.on_session_updated(peer)

    def action_accept_exchange(self, peer: str) -> None:
        """
        Accept a pending key-exchange request from a peer.

        As the responder, we immediately send our public key after accepting.
        The initiator will send their public key when they receive our 'accept'.

        Args:
            peer: Username of the peer whose request we are accepting.
        """
        with self.state_lock:
            if peer not in self.pending_requests:
                self.on_log(f"No pending request from '{peer}'.")
                return

            self.pending_requests.discard(peer)

            # Create our SecureSession as the responder side.
            self.sessions[peer] = SecureSession(
                local_name=self.name,
                peer_name=peer,
                initiator_name=peer,        # peer is the initiator
                responder_name=self.name,   # we are the responder
            )
            session = self.sessions[peer]

        self.send(protocol.chat_accept(self.name, peer))
        # Send our fresh public key immediately on accept.
        self.send(protocol.public_key(self.name, peer, session.local_public_key))
        self.on_log(f"Accepted key-exchange request from '{peer}'.")
        self.on_log(f"Sent X25519 public key to '{peer}'.")
        self.on_session_updated(peer)

    def action_reject_exchange(self, peer: str) -> None:
        """
        Reject a pending key-exchange request.

        Args:
            peer: Username of the peer whose request we are rejecting.
        """
        with self.state_lock:
            self.pending_requests.discard(peer)

        self.send(protocol.chat_reject(self.name, peer))
        self.on_log(f"Rejected key-exchange request from '{peer}'.")

    def action_send_message(self, plaintext: str) -> None:
        """
        Encrypt and send a chat message to the active peer.

        The message is encrypted with AES-GCM using the session key derived
        from the X25519 shared secret via HKDF.  The server only sees the
        ciphertext — it never has access to the session key or plaintext.

        Args:
            plaintext: The message text to encrypt and send.
        """
        with self.state_lock:
            peer = self.active_peer
            session = self.sessions.get(peer) if peer else None

        if peer is None or session is None:
            self.on_log("No active session. Complete a key exchange first.")
            return

        if not session.established:
            self.on_log(f"Session with '{peer}' is not established yet.")
            return

        nonce, ciphertext = encrypt_message(session.require_session_key(), plaintext)
        self.send(protocol.encrypted_message(self.name, peer, nonce, ciphertext))

    def action_disconnect_session(self, peer: str) -> None:
        """
        Close the secure session with a specific peer.

        Args:
            peer: Username of the peer to disconnect from.
        """
        removed = self._remove_session(peer)
        if removed:
            self.send(protocol.session_disconnect(self.name, peer))
            self.on_log(f"Closed secure session with '{peer}'.")
            self.on_session_updated(peer)

    def action_set_active_peer(self, peer: str) -> None:
        """
        Switch the active chat session to a different established peer.

        Args:
            peer: Username of the peer to chat with.
        """
        with self.state_lock:
            session = self.sessions.get(peer)
            if session and session.established:
                self.active_peer = peer
                self.on_log(f"Active chat switched to '{peer}'.")
            else:
                self.on_log(f"No established session with '{peer}'.")

    # -----------------------------------------------------------------------
    # Read-only state accessors (called by the GUI from the main thread)
    # -----------------------------------------------------------------------

    def get_session(self, peer: str) -> SecureSession | None:
        """Return the SecureSession for a peer, or None."""
        with self.state_lock:
            return self.sessions.get(peer)

    def get_my_public_key_hex(self, peer: str) -> str | None:
        """
        Return our local public key for a given session as a hex string.

        Each session has a fresh independent key pair, so the public key
        is per-session, not global.
        """
        session = self.get_session(peer)
        if session:
            return session.local_public_key.hex()
        return None

    def get_pending_requests(self) -> list[str]:
        """Return the list of peers from whom we have received requests."""
        with self.state_lock:
            return sorted(self.pending_requests)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _remove_session(self, peer: str) -> bool:
        """Remove a session and clear active_peer if it matches. Returns True if a session was removed."""
        with self.state_lock:
            existed = self.sessions.pop(peer, None) is not None
            if self.active_peer == peer:
                self.active_peer = None
        return existed
