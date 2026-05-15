"""
gui_server.py — Tkinter GUI for the X25519 relay server.

Run instead of (or alongside) the terminal server:
    python gui_server.py

The GUI server is fully compatible with both:
    python client.py --name Alice --server 127.0.0.1 --port 5000
    python gui_app.py    (then connect as Alice or Bob)

Architecture
------------
This file contains two layers:

1. ObservableChatServer / ObservableRequestHandler
   Subclasses of the original ChatServer and ChatRequestHandler (imported
   from server.py).  They override the key lifecycle methods to fire
   callback functions before/after the original logic, so the GUI stays
   informed without any changes to the original server code.

2. ServerApp (Tkinter GUI)
   Builds all the widgets, wires the callbacks, and runs serve_forever()
   on a background thread so the Tk event loop is never blocked.

What the GUI shows
------------------
  ┌─ Server Control ──────────────────────────────────────────────────────┐
  │  Host / Port / Start / Stop / status badge                           │
  ├─ Live Statistics ─────────────────────────────────────────────────────┤
  │  Total connections · Active clients · Key exchanges · Messages fwd'd │
  ├─ Connected Clients ───────────────────────────────────────────────────┤
  │  Live list of registered usernames + active key-exchange pairs        │
  ├─ Message Traffic ─────────────────────────────────────────────────────┤
  │  Every message the server forwards, color-coded by type               │
  │  (The server never sees private keys or plaintext — shown here)       │
  └─ Server Event Log ────────────────────────────────────────────────────┘
    Timestamped stream: connect, register, disconnect, errors

Important educational note displayed in the GUI:
    The server is a BLIND relay.
    It forwards public keys and encrypted payloads, but never has access to:
      - private keys
      - shared secrets
      - session keys
      - plaintext messages
"""

from __future__ import annotations

import datetime
import socket
import threading
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

# Import the original server classes — we subclass them, not modify them.
from server import ChatRequestHandler, ChatServer
from src import protocol
from src.network import NetworkError, make_reader, read_json, send_json

# ---------------------------------------------------------------------------
# Color palette — same dark academic theme as gui_app.py
# ---------------------------------------------------------------------------

COLORS = {
    "bg_dark":      "#0d1117",
    "bg_panel":     "#161b22",
    "bg_input":     "#1c2128",
    "bg_log":       "#0a0f14",

    "text_primary": "#e6edf3",
    "text_dim":     "#8b949e",
    "text_key":     "#79c0ff",
    "text_secret":  "#56d364",
    "text_pending": "#d29922",
    "text_error":   "#f85149",

    "accent":       "#238636",
    "accent_hover": "#2ea043",
    "accent_stop":  "#b62324",
    "accent_blue":  "#1f6feb",

    "border":       "#30363d",

    # Traffic log colors — one per message type
    "traffic_request":   "#d29922",   # chat_request  → amber
    "traffic_accept":    "#56d364",   # chat_accept   → green
    "traffic_reject":    "#f85149",   # chat_reject   → red
    "traffic_pubkey":    "#79c0ff",   # public_key    → blue
    "traffic_encrypted": "#bc8cff",   # encrypted_msg → purple
    "traffic_disconnect":"#8b949e",   # session_disconnect → dim
    "traffic_other":     "#e6edf3",   # anything else
}

MONO = "Courier New"
SANS = "Segoe UI"


# ---------------------------------------------------------------------------
# Observable server — subclasses the original ChatServer / ChatRequestHandler
# ---------------------------------------------------------------------------

class ObservableChatServer(ChatServer):
    """
    ChatServer subclass that fires callback functions at key lifecycle points.

    All callbacks are optional (defaulting to no-ops) so the server works
    exactly as before if no callbacks are registered.

    The original ChatServer logic is unchanged; we only add hooks around
    the existing calls.
    """

    def __init__(self, server_address: tuple[str, int]):
        # Pass our observable request handler instead of the original one.
        # We bypass ChatServer.__init__ which hard-codes ChatRequestHandler,
        # by calling ThreadingTCPServer.__init__ directly.
        import socketserver
        socketserver.ThreadingTCPServer.__init__(
            self, server_address, ObservableRequestHandler
        )
        # Re-initialise the state that ChatServer.__init__ would have set.
        self.clients: dict[str, Any] = {}
        self.lock = threading.Lock()

        # --- Callback hooks ------------------------------------------------
        # Called when a client successfully registers.
        self.on_client_connected: Callable[[str], None] = lambda name: None

        # Called when a client disconnects.
        self.on_client_disconnected: Callable[[str], None] = lambda name: None

        # Called every time a message is forwarded between two clients.
        # Args: (message_type, sender, receiver, extra_info)
        self.on_message_forwarded: Callable[[str, str, str, str], None] = (
            lambda mtype, sender, receiver, info: None
        )

        # Called for server-level log events (errors, info strings).
        self.on_server_log: Callable[[str], None] = lambda msg: None

        # Counters tracked at the server level (GUI reads these).
        self.total_connections: int = 0     # ever connected
        self.total_messages_fwd: int = 0    # messages forwarded
        self.total_key_exchanges: int = 0   # completed (public_key messages seen)

    def register_client(self, name: str, sock: socket.socket) -> None:
        """Register a client and fire the on_client_connected callback."""
        super().register_client(name, sock)
        self.total_connections += 1
        self.on_client_connected(name)
        self.on_server_log(f"'{name}' registered and connected.")

    def unregister_client(self, name: str) -> None:
        """
        Unregister a client and fire the on_client_disconnected callback.

        We override to suppress the print() from the base class and route
        the message through our logging callback instead.
        """
        with self.lock:
            existed = self.clients.pop(name, None) is not None

        if existed:
            # Fire our GUI callback instead of print().
            self.on_client_disconnected(name)
            self.on_server_log(f"'{name}' disconnected.")
            # Still broadcast the user_disconnected message to other clients.
            self.broadcast(protocol.user_disconnected(name), exclude=name)

    def record_forwarded(self, message: dict[str, Any], sender: str, receiver: str) -> None:
        """
        Called by ObservableRequestHandler every time a message is forwarded.

        This is where we update counters and fire the traffic callback.
        """
        mtype = message.get("type", "unknown")
        self.total_messages_fwd += 1

        # Track completed key exchanges (each public_key message means one
        # side sent their X25519 public key to the other).
        if mtype == "public_key":
            self.total_key_exchanges += 1

        # Build a human-readable description for the traffic log.
        info = _describe_message(message)
        self.on_message_forwarded(mtype, sender, receiver, info)


def _describe_message(message: dict[str, Any]) -> str:
    """
    Return a short human-readable description of a forwarded message.

    This is purely for the server GUI display — the server itself never
    decodes private keys or plaintext.
    """
    mtype = message.get("type", "")

    if mtype == "chat_request":
        return "Key-exchange request"
    if mtype == "chat_accept":
        return "Key-exchange accepted"
    if mtype == "chat_reject":
        return "Key-exchange rejected"
    if mtype == "public_key":
        pk_hex = message.get("public_key", "")
        # Show only the first 16 hex chars for display — not a secret.
        preview = pk_hex[:16] + "…" if len(pk_hex) > 16 else pk_hex
        return f"X25519 public key  [{preview}]  (32 bytes)"
    if mtype == "encrypted_message":
        # The server only sees the ciphertext hex — never the plaintext.
        ct_hex = message.get("ciphertext", "")
        ct_bytes = len(ct_hex) // 2
        nonce_hex = message.get("nonce", "")
        nonce_preview = nonce_hex[:12] + "…" if len(nonce_hex) > 12 else nonce_hex
        return f"AES-GCM ciphertext  [{ct_bytes} bytes]  nonce [{nonce_preview}]"
    if mtype == "session_disconnect":
        return "Session closed"
    return mtype


class ObservableRequestHandler(ChatRequestHandler):
    """
    ChatRequestHandler subclass that hooks into forward_to_peer.

    We override only forward_to_peer so that every forwarded message is
    recorded by ObservableChatServer.record_forwarded().

    Everything else (handle_register, handle_message, safe_send, etc.)
    inherits unchanged from ChatRequestHandler.
    """

    server: ObservableChatServer   # type narrowing for the IDE / reader

    def forward_to_peer(self, message: dict[str, Any]) -> None:
        """
        Forward a message and notify the GUI server about it.

        The base class logic is called first so the message is delivered;
        then we record it.  We also suppress the print() from handle_register
        by overriding it below.
        """
        assert self.name is not None

        receiver = message.get("to")
        if not isinstance(receiver, str) or not protocol.is_valid_username(receiver):
            self.safe_send(protocol.error("message has invalid receiver"))
            return

        if receiver == self.name:
            self.safe_send(protocol.error("cannot send a message to yourself"))
            return

        # The server always overwrites the 'from' field for security.
        message["from"] = self.name

        delivered = self.server.send_to_client(receiver, message)

        if not delivered:
            self.safe_send(protocol.error(f"user '{receiver}' is not online"))
            return

        # Notify the GUI about the forwarded message.
        self.server.record_forwarded(message, self.name, receiver)

    def handle_register(self, message: dict[str, Any]) -> None:
        """
        Override handle_register to suppress print() from the base class.

        The base class calls:
            print(f"[server] {name} connected")
        We route that through our callback instead.
        """
        if self.name is not None:
            self.safe_send(protocol.error("client is already registered"))
            return

        name = message.get("name")

        if not isinstance(name, str) or not protocol.is_valid_username(name):
            self.safe_send(protocol.error(
                "invalid username; use 1-32 letters, numbers, '_' or '-'"
            ))
            return

        try:
            # This calls ObservableChatServer.register_client which fires
            # on_client_connected and on_server_log.
            self.server.register_client(name, self.request)
        except ValueError as exc:
            self.safe_send(protocol.error(str(exc)))
            return

        self.name = name
        self.safe_send(protocol.registered(name))


# ---------------------------------------------------------------------------
# Tkinter GUI
# ---------------------------------------------------------------------------

class ServerApp:
    """
    Tkinter GUI application for the X25519 relay server.

    The server runs on a background daemon thread.  All GUI updates happen
    on the Tk main thread via root.after(0, callback).
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("X25519 Relay Server — Educational Demo")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.minsize(880, 680)

        # The running server instance (None when stopped).
        self.server: ObservableChatServer | None = None
        self.server_thread: threading.Thread | None = None

        self._build_ui()
        self._set_stopped_state()

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self) -> None:
        self._build_topbar()

        body = tk.Frame(self.root, bg=COLORS["bg_dark"])
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        body.columnconfigure(0, weight=1, minsize=240)
        body.columnconfigure(1, weight=3)
        body.rowconfigure(0, weight=1)

        left = tk.Frame(body, bg=COLORS["bg_dark"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        right = tk.Frame(body, bg=COLORS["bg_dark"])
        right.grid(row=0, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.columnconfigure(0, weight=1)

        self._build_control_panel(left)
        self._build_stats_panel(left)
        self._build_clients_panel(left)
        self._build_blind_relay_notice(left)

        self._build_traffic_panel(right)
        self._build_log_panel(right)

    def _build_topbar(self) -> None:
        bar = tk.Frame(self.root, bg=COLORS["bg_panel"], height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(
            bar,
            text="⬡  X25519 Relay Server — Educational Demo",
            bg=COLORS["bg_panel"],
            fg=COLORS["text_primary"],
            font=(SANS, 13, "bold"),
            anchor="w",
            padx=16,
        ).pack(side="left", fill="y")

        tk.Label(
            bar,
            text="Blind relay — never sees keys or plaintext",
            bg=COLORS["bg_panel"],
            fg=COLORS["text_dim"],
            font=(SANS, 9),
            anchor="e",
            padx=16,
        ).pack(side="right", fill="y")

        tk.Frame(self.root, bg=COLORS["border"], height=1).pack(fill="x")

    def _build_control_panel(self, parent: tk.Widget) -> None:
        panel = self._panel(parent)
        panel.pack(fill="x", pady=(0, 6))

        self._section_label(panel, "SERVER CONTROL").pack(anchor="w", pady=(0, 8))

        # Host
        tk.Label(panel, text="Bind address", bg=COLORS["bg_panel"],
                 fg=COLORS["text_dim"], font=(SANS, 9)).pack(anchor="w")
        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(
            panel, textvariable=self.host_var,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief="flat", font=(MONO, 11), bd=4,
        ).pack(fill="x", pady=(2, 8))

        # Port
        tk.Label(panel, text="Port", bg=COLORS["bg_panel"],
                 fg=COLORS["text_dim"], font=(SANS, 9)).pack(anchor="w")
        self.port_var = tk.StringVar(value="5000")
        tk.Entry(
            panel, textvariable=self.port_var,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief="flat", font=(MONO, 11), bd=4,
        ).pack(fill="x", pady=(2, 10))

        # Start / Stop buttons
        btn_row = tk.Frame(panel, bg=COLORS["bg_panel"])
        btn_row.pack(fill="x")

        self.start_btn = tk.Button(
            btn_row, text="▶  Start Server",
            bg=COLORS["accent"], fg="white",
            activebackground=COLORS["accent_hover"], activeforeground="white",
            relief="flat", font=(SANS, 10, "bold"), cursor="hand2",
            command=self._on_start,
        )
        self.start_btn.pack(side="left", fill="x", expand=True)

        self.stop_btn = tk.Button(
            btn_row, text="■  Stop",
            bg=COLORS["accent_stop"], fg="white",
            activebackground="#c9312e", activeforeground="white",
            relief="flat", font=(SANS, 10), cursor="hand2",
            command=self._on_stop,
        )
        self.stop_btn.pack(side="right", padx=(6, 0))

        # Status badge
        self.status_var = tk.StringVar(value="● Stopped")
        self.status_lbl = tk.Label(
            panel, textvariable=self.status_var,
            bg=COLORS["bg_panel"], fg=COLORS["text_error"],
            font=(SANS, 9, "bold"), anchor="w",
        )
        self.status_lbl.pack(anchor="w", pady=(8, 0))

    def _build_stats_panel(self, parent: tk.Widget) -> None:
        panel = self._panel(parent)
        panel.pack(fill="x", pady=(0, 6))

        self._section_label(panel, "LIVE STATISTICS").pack(anchor="w", pady=(0, 8))

        grid = tk.Frame(panel, bg=COLORS["bg_panel"])
        grid.pack(fill="x")
        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        def stat_widget(label: str, row: int, col: int):
            f = tk.Frame(grid, bg=COLORS["bg_input"], padx=8, pady=6)
            f.grid(row=row, column=col, sticky="nsew", padx=3, pady=3)
            var = tk.StringVar(value="0")
            tk.Label(f, textvariable=var, bg=COLORS["bg_input"],
                     fg=COLORS["text_primary"], font=(MONO, 18, "bold")).pack()
            tk.Label(f, text=label, bg=COLORS["bg_input"],
                     fg=COLORS["text_dim"], font=(SANS, 8)).pack()
            return var

        self.stat_total_conn  = stat_widget("Total Connections",  0, 0)
        self.stat_active      = stat_widget("Active Clients",      0, 1)
        self.stat_exchanges   = stat_widget("Public Keys Relayed", 1, 0)
        self.stat_messages    = stat_widget("Messages Forwarded",  1, 1)

    def _build_clients_panel(self, parent: tk.Widget) -> None:
        panel = self._panel(parent)
        panel.pack(fill="both", expand=True, pady=(0, 6))

        self._section_label(panel, "CONNECTED CLIENTS").pack(anchor="w", pady=(0, 6))

        list_frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        list_frame.pack(fill="both", expand=True)

        self.clients_list = tk.Listbox(
            list_frame,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            selectbackground=COLORS["accent_blue"],
            selectforeground="white",
            font=(MONO, 11), relief="flat", bd=0,
            activestyle="none",
        )
        self.clients_list.pack(fill="both", expand=True, padx=1, pady=1)

        # Key-exchange sessions panel (shows active pairs)
        self._section_label(panel, "KEY EXCHANGE PAIRS").pack(anchor="w", pady=(8, 4))

        pairs_frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        pairs_frame.pack(fill="x")

        self.pairs_list = tk.Listbox(
            pairs_frame,
            bg=COLORS["bg_input"], fg=COLORS["text_key"],
            font=(MONO, 10), relief="flat", bd=0,
            activestyle="none",
            height=4,
        )
        self.pairs_list.pack(fill="x", padx=1, pady=1)

        # Internal state: track which pairs are in an active exchange
        # key = frozenset({a, b}), value = display string
        self._exchange_pairs: dict[frozenset, str] = {}

    def _build_blind_relay_notice(self, parent: tk.Widget) -> None:
        """Educational notice reminding the viewer what the server never sees."""
        panel = self._panel(parent)
        panel.pack(fill="x")

        self._section_label(panel, "WHAT THIS SERVER NEVER SEES").pack(anchor="w", pady=(0, 6))

        items = [
            ("✕", "Private keys"),
            ("✕", "Shared secrets"),
            ("✕", "Session keys"),
            ("✕", "Plaintext messages"),
        ]
        for icon, label in items:
            row = tk.Frame(panel, bg=COLORS["bg_panel"])
            row.pack(fill="x", pady=1)
            tk.Label(row, text=icon, bg=COLORS["bg_panel"],
                     fg=COLORS["text_error"], font=(MONO, 9, "bold"), width=2).pack(side="left")
            tk.Label(row, text=label, bg=COLORS["bg_panel"],
                     fg=COLORS["text_dim"], font=(SANS, 9)).pack(side="left")

    def _build_traffic_panel(self, parent: tk.Widget) -> None:
        panel = self._panel(parent)
        panel.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        header = tk.Frame(panel, bg=COLORS["bg_panel"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        self._section_label(header, "MESSAGE TRAFFIC").pack(side="left")
        tk.Label(
            header,
            text="(ciphertext shown as bytes — server never decrypts)",
            bg=COLORS["bg_panel"], fg=COLORS["text_dim"], font=(SANS, 8),
        ).pack(side="left", padx=(8, 0))

        # Clear button
        tk.Button(
            header, text="Clear",
            bg=COLORS["bg_input"], fg=COLORS["text_dim"],
            activebackground=COLORS["bg_panel"], activeforeground=COLORS["text_primary"],
            relief="flat", font=(SANS, 8), cursor="hand2",
            command=self._clear_traffic,
        ).pack(side="right")

        frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        frame.grid(row=1, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.traffic_text = tk.Text(
            frame,
            bg=COLORS["bg_log"], fg=COLORS["text_primary"],
            font=(MONO, 9), relief="flat", bd=4,
            state="disabled", wrap="char",
            cursor="arrow",
        )
        self.traffic_text.grid(row=0, column=0, sticky="nsew")

        scroll = tk.Scrollbar(frame, command=self.traffic_text.yview,
                              bg=COLORS["bg_panel"], troughcolor=COLORS["bg_dark"],
                              relief="flat", bd=0)
        scroll.grid(row=0, column=1, sticky="ns")
        self.traffic_text.configure(yscrollcommand=scroll.set)

        # Color tags for each message type
        self.traffic_text.tag_configure("ts",        foreground="#444c56")
        self.traffic_text.tag_configure("arrow",     foreground=COLORS["text_dim"])
        self.traffic_text.tag_configure("request",   foreground=COLORS["traffic_request"])
        self.traffic_text.tag_configure("accept",    foreground=COLORS["traffic_accept"])
        self.traffic_text.tag_configure("reject",    foreground=COLORS["traffic_reject"])
        self.traffic_text.tag_configure("pubkey",    foreground=COLORS["traffic_pubkey"])
        self.traffic_text.tag_configure("encrypted", foreground=COLORS["traffic_encrypted"])
        self.traffic_text.tag_configure("disconnect",foreground=COLORS["traffic_disconnect"])
        self.traffic_text.tag_configure("other",     foreground=COLORS["traffic_other"])

    def _build_log_panel(self, parent: tk.Widget) -> None:
        panel = self._panel(parent)
        panel.grid(row=1, column=0, sticky="nsew")
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        header = tk.Frame(panel, bg=COLORS["bg_panel"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self._section_label(header, "SERVER EVENT LOG").pack(side="left")

        tk.Button(
            header, text="Clear",
            bg=COLORS["bg_input"], fg=COLORS["text_dim"],
            activebackground=COLORS["bg_panel"], activeforeground=COLORS["text_primary"],
            relief="flat", font=(SANS, 8), cursor="hand2",
            command=self._clear_log,
        ).pack(side="right")

        frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        frame.grid(row=1, column=0, sticky="nsew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            frame,
            bg=COLORS["bg_log"], fg=COLORS["text_dim"],
            font=(MONO, 9), relief="flat", bd=4,
            state="disabled", wrap="char",
            cursor="arrow",
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        scroll = tk.Scrollbar(frame, command=self.log_text.yview,
                              bg=COLORS["bg_panel"], troughcolor=COLORS["bg_dark"],
                              relief="flat", bd=0)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll.set)

        self.log_text.tag_configure("ts",   foreground="#444c56")
        self.log_text.tag_configure("ok",   foreground=COLORS["text_secret"])
        self.log_text.tag_configure("warn", foreground=COLORS["text_pending"])
        self.log_text.tag_configure("err",  foreground=COLORS["text_error"])
        self.log_text.tag_configure("info", foreground=COLORS["text_dim"])

    # -----------------------------------------------------------------------
    # Button handlers
    # -----------------------------------------------------------------------

    def _on_start(self) -> None:
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()

        try:
            port = int(port_str)
        except ValueError:
            self._append_log("Port must be an integer.", "err")
            return

        self.start_btn.configure(state="disabled", text="Starting…")
        threading.Thread(target=self._start_worker, args=(host, port), daemon=True).start()

    def _start_worker(self, host: str, port: int) -> None:
        """Create and start the server on a background thread."""
        try:
            server = ObservableChatServer((host, port))
        except OSError as exc:
            self.root.after(0, self._append_log, f"Failed to bind {host}:{port} — {exc}", "err")
            self.root.after(0, lambda: self.start_btn.configure(state="normal", text="▶  Start Server"))
            return

        # Wire up the callbacks — all GUI calls are safely scheduled via after().
        server.on_client_connected    = lambda name: self.root.after(0, self._on_client_connected, name)
        server.on_client_disconnected = lambda name: self.root.after(0, self._on_client_disconnected, name)
        server.on_message_forwarded   = lambda mt, s, r, info: self.root.after(
            0, self._on_message_forwarded, mt, s, r, info
        )
        server.on_server_log = lambda msg: self.root.after(0, self._append_log, msg, "info")

        self.server = server
        self.root.after(0, self._set_running_state, host, port)

        # serve_forever() blocks this thread until shutdown() is called.
        server.serve_forever()

    def _on_stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        self._set_stopped_state()
        self._append_log("Server stopped.", "warn")

    # -----------------------------------------------------------------------
    # Server event callbacks (always called on the main thread via after())
    # -----------------------------------------------------------------------

    def _on_client_connected(self, name: str) -> None:
        """A new client registered — add to the listbox and update stats."""
        existing = list(self.clients_list.get(0, "end"))
        if name not in existing:
            self.clients_list.insert("end", name)

        self._refresh_stats()
        self._append_log(f"'{name}' connected.", "ok")

    def _on_client_disconnected(self, name: str) -> None:
        """A client disconnected — remove from listbox, clean up pairs, update stats."""
        items = list(self.clients_list.get(0, "end"))
        if name in items:
            self.clients_list.delete(items.index(name))

        # Remove any exchange pairs involving this user.
        to_remove = [k for k in self._exchange_pairs if name in k]
        for k in to_remove:
            del self._exchange_pairs[k]
        self._refresh_pairs_list()

        self._refresh_stats()
        self._append_log(f"'{name}' disconnected.", "warn")

    def _on_message_forwarded(self, mtype: str, sender: str, receiver: str, info: str) -> None:
        """A message was forwarded — log it to the traffic panel and update pairs."""
        # Track key-exchange pairs (chat_request starts one, session_disconnect ends it).
        pair = frozenset({sender, receiver})
        if mtype == "chat_request":
            self._exchange_pairs[pair] = f"{sender}  ⇄  {receiver}"
            self._refresh_pairs_list()
        elif mtype == "session_disconnect":
            self._exchange_pairs.pop(pair, None)
            self._refresh_pairs_list()

        self._refresh_stats()
        self._append_traffic(mtype, sender, receiver, info)

    # -----------------------------------------------------------------------
    # Display helpers
    # -----------------------------------------------------------------------

    def _set_running_state(self, host: str, port: int) -> None:
        self.status_var.set(f"● Running on {host}:{port}")
        self.status_lbl.configure(fg=COLORS["text_secret"])
        self.start_btn.configure(state="disabled", text="▶  Start Server")
        self.stop_btn.configure(state="normal")
        self.host_var.set(host)
        self._append_log(f"Server started — listening on {host}:{port}", "ok")

    def _set_stopped_state(self) -> None:
        self.status_var.set("● Stopped")
        self.status_lbl.configure(fg=COLORS["text_error"])
        self.start_btn.configure(state="normal", text="▶  Start Server")
        self.stop_btn.configure(state="disabled")
        self.clients_list.delete(0, "end")
        self.pairs_list.delete(0, "end")
        self._exchange_pairs.clear()
        self._refresh_stats()

    def _refresh_stats(self) -> None:
        """Update the four statistic widgets from server counters."""
        if self.server:
            self.stat_total_conn.set(str(self.server.total_connections))
            self.stat_active.set(str(len(self.server.online_users())))
            self.stat_exchanges.set(str(self.server.total_key_exchanges))
            self.stat_messages.set(str(self.server.total_messages_fwd))
        else:
            for var in (self.stat_total_conn, self.stat_active,
                        self.stat_exchanges, self.stat_messages):
                var.set("0")

    def _refresh_pairs_list(self) -> None:
        """Repopulate the key-exchange pairs listbox."""
        self.pairs_list.delete(0, "end")
        for label in self._exchange_pairs.values():
            self.pairs_list.insert("end", label)

    def _append_log(self, message: str, level: str = "info") -> None:
        """Add a timestamped line to the event log."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        tag = level if level in ("ok", "warn", "err", "info") else "info"

        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{ts}  ", "ts")
        self.log_text.insert("end", f"{message}\n", tag)
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _append_traffic(self, mtype: str, sender: str, receiver: str, info: str) -> None:
        """
        Add a color-coded line to the traffic log.

        Format:
            HH:MM:SS  Alice → Bob   [message type label]   description
        """
        ts = datetime.datetime.now().strftime("%H:%M:%S")

        # Map message type to a display label and text tag.
        type_meta = {
            "chat_request":       ("KEY EXCHANGE REQ ", "request"),
            "chat_accept":        ("KEY EXCHANGE ACK ", "accept"),
            "chat_reject":        ("KEY EXCHANGE REJ ", "reject"),
            "public_key":         ("PUBLIC KEY       ", "pubkey"),
            "encrypted_message":  ("ENCRYPTED MSG    ", "encrypted"),
            "session_disconnect": ("SESSION CLOSED   ", "disconnect"),
        }
        label, tag = type_meta.get(mtype, (mtype.upper().ljust(17), "other"))

        route = f"{sender} → {receiver}"

        self.traffic_text.configure(state="normal")
        self.traffic_text.insert("end", f"{ts}  ", "ts")
        self.traffic_text.insert("end", f"{label}", tag)
        self.traffic_text.insert("end", f"  {route:<24}  ", "arrow")
        self.traffic_text.insert("end", f"{info}\n", tag)
        self.traffic_text.configure(state="disabled")
        self.traffic_text.see("end")

    def _clear_traffic(self) -> None:
        self.traffic_text.configure(state="normal")
        self.traffic_text.delete("1.0", "end")
        self.traffic_text.configure(state="disabled")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # -----------------------------------------------------------------------
    # Widget factory helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def _panel(parent: tk.Widget, **kwargs) -> tk.Frame:
        defaults = dict(bg=COLORS["bg_panel"], padx=12, pady=8, bd=0)
        defaults.update(kwargs)
        return tk.Frame(parent, **defaults)

    @staticmethod
    def _section_label(parent: tk.Widget, text: str) -> tk.Label:
        return tk.Label(
            parent,
            text=text,
            bg=COLORS["bg_panel"],
            fg=COLORS["text_dim"],
            font=(SANS, 8, "bold"),
            anchor="w",
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.2)
    except Exception:
        pass

    app = ServerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
