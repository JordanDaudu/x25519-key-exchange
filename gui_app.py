"""
gui_app.py — Tkinter GUI for the X25519 Secure Key Exchange Demo.

Run the server first:
    python server.py --host 127.0.0.1 --port 5000

Then open two GUI clients:
    python gui_app.py
    python gui_app.py

How to demonstrate Alice & Bob key exchange:
  1. Start the server.
  2. Open two GUI windows. Enter "Alice" in one, "Bob" in the other.
  3. In Alice's window, click "Connect to Server".
  4. In Bob's window, click "Connect to Server".
  5. Alice selects Bob from the list and clicks "Start Key Exchange".
  6. Bob's window shows an Accept/Reject dialog. Bob clicks "Accept".
  7. Both windows show the derived shared secret fingerprint.
  8. Alice and Bob can now type encrypted messages to each other.

Design sections (matching the project brief):
  ┌─ Connection ─────────────────────────────────────────────────────────┐
  │  Username / Host / Port / Connect button                             │
  ├─ My Key Information ─────────────────────────────────────────────────┤
  │  Public key for the current session (per-session, fresh each time)   │
  ├─ Connected Clients + Key Exchange Status ────────────────────────────┤
  │  Left: user list + Start Exchange button                             │
  │  Right: peer key, shared secret fingerprint, session status          │
  ├─ Secure Chat ────────────────────────────────────────────────────────┤
  │  Message history (locked until session established) + send box       │
  └─ Event Log ──────────────────────────────────────────────────────────┘
    Timestamped stream of all protocol events
"""

from __future__ import annotations

import datetime
import threading
import tkinter as tk
from tkinter import font as tkfont
from tkinter import messagebox, ttk

from gui_client import GUIClient

# ---------------------------------------------------------------------------
# Color palette — dark academic/cryptographic theme
# ---------------------------------------------------------------------------

COLORS = {
    # Backgrounds
    "bg_dark":       "#0d1117",   # main window background
    "bg_panel":      "#161b22",   # section panels
    "bg_input":      "#1c2128",   # input fields
    "bg_chat":       "#0d1117",   # chat area
    "bg_log":        "#0a0f14",   # event log

    # Text
    "text_primary":  "#e6edf3",   # main text
    "text_dim":      "#8b949e",   # secondary / placeholder text
    "text_key":      "#79c0ff",   # hex key display (blue-ish)
    "text_secret":   "#56d364",   # shared secret confirmed (green)
    "text_pending":  "#d29922",   # pending / warning (amber)
    "text_error":    "#f85149",   # errors (red)

    # Accents
    "accent":        "#238636",   # primary action button (green)
    "accent_hover":  "#2ea043",
    "accent_danger": "#b62324",   # reject / disconnect
    "accent_blue":   "#1f6feb",   # secondary actions
    "accent_amber":  "#bb8009",   # pending state

    # Borders
    "border":        "#30363d",
    "border_active": "#388bfd",   # focused / active element
}

# Monospace font used for key material display
MONO = "Courier New"
SANS = "Segoe UI" if tk.TkVersion else "Helvetica"

# ---------------------------------------------------------------------------
# Helper: create a styled label header for a section
# ---------------------------------------------------------------------------

def _section_label(parent: tk.Widget, text: str) -> tk.Label:
    """Return a styled section header label."""
    lbl = tk.Label(
        parent,
        text=text,
        bg=COLORS["bg_panel"],
        fg=COLORS["text_dim"],
        font=(SANS, 8, "bold"),
        anchor="w",
    )
    return lbl


def _panel(parent: tk.Widget, **kwargs) -> tk.Frame:
    """Return a styled panel frame."""
    defaults = dict(bg=COLORS["bg_panel"], padx=12, pady=8, bd=0)
    defaults.update(kwargs)
    return tk.Frame(parent, **defaults)


# ---------------------------------------------------------------------------
# Main application window
# ---------------------------------------------------------------------------

class X25519App:
    """
    The main Tkinter window for the X25519 Key Exchange GUI.

    This class creates all widgets and wires them to a GUIClient instance
    via the callback system.  All GUI updates happen on the Tk main thread
    using after() to avoid race conditions with the background network thread.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("X25519 Key Exchange — Educational Demo")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.minsize(900, 720)

        # The core client; created fresh on each "Connect" click.
        self.client: GUIClient | None = None

        # Track which peer is selected in the users list.
        self.selected_peer: str | None = None

        # Chat history per peer: { peer_name: [(sender, text), …] }
        self.chat_history: dict[str, list[tuple[str, str]]] = {}

        self._build_ui()
        self._set_disconnected_state()

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Build all UI sections and lay them out in the window."""

        # ── Top bar ─────────────────────────────────────────────────────────
        self._build_topbar()

        # ── Body: three columns ─────────────────────────────────────────────
        body = tk.Frame(self.root, bg=COLORS["bg_dark"])
        body.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        body.columnconfigure(0, weight=1, minsize=200)
        body.columnconfigure(1, weight=3)
        body.rowconfigure(0, weight=3)
        body.rowconfigure(1, weight=2)

        # Left column: connection + clients list
        left = tk.Frame(body, bg=COLORS["bg_dark"])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6), rowspan=2)
        self._build_connection_panel(left)
        self._build_clients_panel(left)

        # Right column top: key info + key exchange status
        right_top = tk.Frame(body, bg=COLORS["bg_dark"])
        right_top.grid(row=0, column=1, sticky="nsew", pady=(0, 6))
        self._build_key_info_panel(right_top)
        self._build_exchange_status_panel(right_top)

        # Right column bottom: chat + log
        right_bot = tk.Frame(body, bg=COLORS["bg_dark"])
        right_bot.grid(row=1, column=1, sticky="nsew")
        right_bot.columnconfigure(0, weight=3)
        right_bot.columnconfigure(1, weight=2)
        right_bot.rowconfigure(0, weight=1)
        self._build_chat_panel(right_bot)
        self._build_log_panel(right_bot)

    # ── Top bar (title) ──────────────────────────────────────────────────────

    def _build_topbar(self) -> None:
        bar = tk.Frame(self.root, bg=COLORS["bg_panel"], height=48)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        tk.Label(
            bar,
            text="⚿  X25519 Elliptic-Curve Diffie–Hellman Key Exchange",
            bg=COLORS["bg_panel"],
            fg=COLORS["text_primary"],
            font=(SANS, 13, "bold"),
            anchor="w",
            padx=16,
        ).pack(side="left", fill="y")

        tk.Label(
            bar,
            text="Educational Demo — not for production use",
            bg=COLORS["bg_panel"],
            fg=COLORS["text_dim"],
            font=(SANS, 9),
            anchor="e",
            padx=16,
        ).pack(side="right", fill="y")

        # Thin separator line
        sep = tk.Frame(self.root, bg=COLORS["border"], height=1)
        sep.pack(fill="x")

    # ── Connection panel ─────────────────────────────────────────────────────

    def _build_connection_panel(self, parent: tk.Widget) -> None:
        panel = _panel(parent)
        panel.pack(fill="x", pady=(0, 6))

        _section_label(panel, "CONNECTION").pack(anchor="w", pady=(0, 6))

        # Username
        tk.Label(panel, text="Username", bg=COLORS["bg_panel"],
                 fg=COLORS["text_dim"], font=(SANS, 9)).pack(anchor="w")
        self.name_var = tk.StringVar(value="Alice")
        tk.Entry(
            panel, textvariable=self.name_var, bg=COLORS["bg_input"],
            fg=COLORS["text_primary"], insertbackground=COLORS["text_primary"],
            relief="flat", font=(MONO, 11), bd=4,
        ).pack(fill="x", pady=(2, 8))

        # Host and port in a row
        row = tk.Frame(panel, bg=COLORS["bg_panel"])
        row.pack(fill="x")
        tk.Label(row, text="Host", bg=COLORS["bg_panel"],
                 fg=COLORS["text_dim"], font=(SANS, 9)).grid(row=0, column=0, sticky="w")
        tk.Label(row, text="Port", bg=COLORS["bg_panel"],
                 fg=COLORS["text_dim"], font=(SANS, 9)).grid(row=0, column=1, sticky="w", padx=(8, 0))

        self.host_var = tk.StringVar(value="127.0.0.1")
        tk.Entry(
            row, textvariable=self.host_var, width=14,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief="flat", font=(MONO, 10), bd=4,
        ).grid(row=1, column=0, sticky="ew", pady=(2, 0))

        self.port_var = tk.StringVar(value="5000")
        tk.Entry(
            row, textvariable=self.port_var, width=7,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief="flat", font=(MONO, 10), bd=4,
        ).grid(row=1, column=1, sticky="ew", pady=(2, 0), padx=(8, 0))
        row.columnconfigure(0, weight=2)
        row.columnconfigure(1, weight=1)

        # Connect / Disconnect buttons
        btn_row = tk.Frame(panel, bg=COLORS["bg_panel"])
        btn_row.pack(fill="x", pady=(10, 0))

        self.connect_btn = tk.Button(
            btn_row, text="Connect to Server",
            bg=COLORS["accent"], fg="white",
            activebackground=COLORS["accent_hover"], activeforeground="white",
            relief="flat", font=(SANS, 10, "bold"), cursor="hand2",
            command=self._on_connect_click,
        )
        self.connect_btn.pack(side="left", fill="x", expand=True)

        self.disconnect_btn = tk.Button(
            btn_row, text="Disconnect",
            bg=COLORS["accent_danger"], fg="white",
            activebackground="#c9312e", activeforeground="white",
            relief="flat", font=(SANS, 10), cursor="hand2",
            command=self._on_disconnect_click,
        )
        self.disconnect_btn.pack(side="right", padx=(6, 0))

        # Status badge
        self.conn_status_var = tk.StringVar(value="● Disconnected")
        tk.Label(
            panel, textvariable=self.conn_status_var,
            bg=COLORS["bg_panel"], fg=COLORS["text_error"],
            font=(SANS, 9, "bold"), anchor="w",
        ).pack(anchor="w", pady=(8, 0))

    # ── Connected clients list ────────────────────────────────────────────────

    def _build_clients_panel(self, parent: tk.Widget) -> None:
        panel = _panel(parent)
        panel.pack(fill="both", expand=True)

        _section_label(panel, "CONNECTED CLIENTS").pack(anchor="w", pady=(0, 6))

        # Listbox of online users
        list_frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        list_frame.pack(fill="both", expand=True)

        self.users_list = tk.Listbox(
            list_frame,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            selectbackground=COLORS["accent_blue"],
            selectforeground="white",
            font=(MONO, 11),
            relief="flat", bd=0,
            activestyle="none",
            cursor="hand2",
        )
        self.users_list.pack(fill="both", expand=True, padx=1, pady=1)
        self.users_list.bind("<<ListboxSelect>>", self._on_user_selected)
        self.users_list.bind("<Double-Button-1>", self._on_start_exchange_click)

        # Action buttons
        btn_frame = tk.Frame(panel, bg=COLORS["bg_panel"])
        btn_frame.pack(fill="x", pady=(8, 0))

        self.exchange_btn = tk.Button(
            btn_frame, text="⇄  Start Key Exchange",
            bg=COLORS["accent_blue"], fg="white",
            activebackground="#2079e3", activeforeground="white",
            relief="flat", font=(SANS, 9, "bold"), cursor="hand2",
            command=self._on_start_exchange_click,
        )
        self.exchange_btn.pack(fill="x")

        self.refresh_btn = tk.Button(
            btn_frame, text="↺  Refresh Users",
            bg=COLORS["bg_input"], fg=COLORS["text_dim"],
            activebackground=COLORS["bg_panel"], activeforeground=COLORS["text_primary"],
            relief="flat", font=(SANS, 9), cursor="hand2",
            command=self._on_refresh_click,
        )
        self.refresh_btn.pack(fill="x", pady=(4, 0))

    # ── My key information ────────────────────────────────────────────────────

    def _build_key_info_panel(self, parent: tk.Widget) -> None:
        panel = _panel(parent)
        panel.pack(fill="x", pady=(0, 6))

        _section_label(panel, "MY KEY INFORMATION").pack(anchor="w", pady=(0, 6))

        row = tk.Frame(panel, bg=COLORS["bg_panel"])
        row.pack(fill="x")

        # Identity name
        name_col = tk.Frame(row, bg=COLORS["bg_panel"])
        name_col.pack(side="left", padx=(0, 16))
        tk.Label(name_col, text="Identity", bg=COLORS["bg_panel"],
                 fg=COLORS["text_dim"], font=(SANS, 8)).pack(anchor="w")
        self.identity_label = tk.Label(
            name_col, text="—", bg=COLORS["bg_panel"],
            fg=COLORS["text_primary"], font=(SANS, 14, "bold"),
        )
        self.identity_label.pack(anchor="w")

        # Public key display (truncated with full on hover)
        key_col = tk.Frame(row, bg=COLORS["bg_panel"])
        key_col.pack(side="left", fill="x", expand=True)
        tk.Label(key_col, text="Session Public Key (32 bytes, shown for selected peer session)",
                 bg=COLORS["bg_panel"], fg=COLORS["text_dim"], font=(SANS, 8)).pack(anchor="w")

        self.my_pub_key_var = tk.StringVar(value="Select a peer and start a key exchange to see your session key")
        self.my_pub_key_label = tk.Label(
            key_col, textvariable=self.my_pub_key_var,
            bg=COLORS["bg_panel"], fg=COLORS["text_key"],
            font=(MONO, 8), anchor="w", wraplength=580, justify="left",
        )
        self.my_pub_key_label.pack(anchor="w")

    # ── Key exchange status panel ────────────────────────────────────────────

    def _build_exchange_status_panel(self, parent: tk.Widget) -> None:
        panel = _panel(parent)
        panel.pack(fill="x")

        _section_label(panel, "KEY EXCHANGE STATUS").pack(anchor="w", pady=(0, 8))

        grid = tk.Frame(panel, bg=COLORS["bg_panel"])
        grid.pack(fill="x")
        grid.columnconfigure(1, weight=1)

        def row_widgets(label_text: str, row_idx: int):
            tk.Label(grid, text=label_text, bg=COLORS["bg_panel"],
                     fg=COLORS["text_dim"], font=(SANS, 8), width=18, anchor="w"
                     ).grid(row=row_idx, column=0, sticky="w", pady=2)
            var = tk.StringVar(value="—")
            lbl = tk.Label(grid, textvariable=var, bg=COLORS["bg_panel"],
                           fg=COLORS["text_key"], font=(MONO, 8), anchor="w", wraplength=520)
            lbl.grid(row=row_idx, column=1, sticky="w", padx=(8, 0), pady=2)
            return var, lbl

        self.peer_name_var,    _  = row_widgets("Peer",                   0)
        self.peer_pk_var,      _  = row_widgets("Peer Public Key",        1)
        self.shared_secret_var, self.shared_secret_lbl = row_widgets("Shared Secret",  2)
        self.fingerprint_var,  self.fingerprint_lbl    = row_widgets("Fingerprint",    3)
        self.session_status_var, self.session_status_lbl = row_widgets("Session Status", 4)

        # Buttons: Accept and Reject incoming requests
        btn_row = tk.Frame(panel, bg=COLORS["bg_panel"])
        btn_row.pack(fill="x", pady=(10, 0))

        self.accept_btn = tk.Button(
            btn_row, text="✓  Accept Request",
            bg=COLORS["accent"], fg="white",
            activebackground=COLORS["accent_hover"], activeforeground="white",
            relief="flat", font=(SANS, 9, "bold"), cursor="hand2",
            command=self._on_accept_click,
        )
        self.accept_btn.pack(side="left")

        self.reject_btn = tk.Button(
            btn_row, text="✕  Reject",
            bg=COLORS["bg_input"], fg=COLORS["text_error"],
            activebackground=COLORS["accent_danger"], activeforeground="white",
            relief="flat", font=(SANS, 9), cursor="hand2",
            command=self._on_reject_click,
        )
        self.reject_btn.pack(side="left", padx=(6, 0))

        self.end_session_btn = tk.Button(
            btn_row, text="⊘  End Session",
            bg=COLORS["bg_input"], fg=COLORS["text_dim"],
            activebackground=COLORS["accent_danger"], activeforeground="white",
            relief="flat", font=(SANS, 9), cursor="hand2",
            command=self._on_end_session_click,
        )
        self.end_session_btn.pack(side="right")

    # ── Chat panel ────────────────────────────────────────────────────────────

    def _build_chat_panel(self, parent: tk.Widget) -> None:
        panel = _panel(parent)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        # Header
        header = tk.Frame(panel, bg=COLORS["bg_panel"])
        header.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        _section_label(header, "SECURE CHAT").pack(side="left")
        self.chat_peer_label = tk.Label(
            header, text="(no active session)",
            bg=COLORS["bg_panel"], fg=COLORS["text_dim"], font=(SANS, 8),
        )
        self.chat_peer_label.pack(side="left", padx=(8, 0))

        self.encryption_badge = tk.Label(
            header, text="",
            bg=COLORS["bg_panel"], fg=COLORS["text_secret"], font=(SANS, 8, "bold"),
        )
        self.encryption_badge.pack(side="right")

        # Chat history display
        chat_frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        chat_frame.grid(row=1, column=0, sticky="nsew")
        chat_frame.rowconfigure(0, weight=1)
        chat_frame.columnconfigure(0, weight=1)

        self.chat_text = tk.Text(
            chat_frame,
            bg=COLORS["bg_chat"], fg=COLORS["text_primary"],
            font=(MONO, 10), relief="flat", bd=4,
            state="disabled", wrap="word",
            cursor="arrow",
        )
        self.chat_text.grid(row=0, column=0, sticky="nsew")

        chat_scroll = tk.Scrollbar(chat_frame, command=self.chat_text.yview,
                                   bg=COLORS["bg_panel"], troughcolor=COLORS["bg_dark"],
                                   relief="flat", bd=0)
        chat_scroll.grid(row=0, column=1, sticky="ns")
        self.chat_text.configure(yscrollcommand=chat_scroll.set)

        # Text tags for message styling
        self.chat_text.tag_configure("me",   foreground=COLORS["accent_blue"])
        self.chat_text.tag_configure("peer", foreground=COLORS["text_primary"])
        self.chat_text.tag_configure("sys",  foreground=COLORS["text_dim"], font=(MONO, 9))

        # Locked overlay label (shown when chat is not yet available)
        self.chat_locked_label = tk.Label(
            panel,
            text="🔒  Complete the key exchange to unlock secure chat",
            bg=COLORS["bg_panel"], fg=COLORS["text_pending"],
            font=(SANS, 10),
        )
        self.chat_locked_label.grid(row=1, column=0)

        # Message input area
        input_row = tk.Frame(panel, bg=COLORS["bg_panel"])
        input_row.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        input_row.columnconfigure(0, weight=1)

        self.msg_entry = tk.Entry(
            input_row,
            bg=COLORS["bg_input"], fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            relief="flat", font=(MONO, 11), bd=4,
        )
        self.msg_entry.grid(row=0, column=0, sticky="ew", ipady=4)
        self.msg_entry.bind("<Return>", self._on_send_message)

        self.send_btn = tk.Button(
            input_row, text="Send",
            bg=COLORS["accent_blue"], fg="white",
            activebackground="#2079e3", activeforeground="white",
            relief="flat", font=(SANS, 10, "bold"), cursor="hand2",
            command=self._on_send_message,
            width=7,
        )
        self.send_btn.grid(row=0, column=1, padx=(6, 0))

    # ── Event log panel ──────────────────────────────────────────────────────

    def _build_log_panel(self, parent: tk.Widget) -> None:
        panel = _panel(parent)
        panel.grid(row=0, column=1, sticky="nsew")
        panel.rowconfigure(1, weight=1)
        panel.columnconfigure(0, weight=1)

        _section_label(panel, "EVENT LOG").grid(row=0, column=0, sticky="w", pady=(0, 6))

        log_frame = tk.Frame(panel, bg=COLORS["border"], bd=1)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_frame,
            bg=COLORS["bg_log"], fg=COLORS["text_dim"],
            font=(MONO, 8), relief="flat", bd=4,
            state="disabled", wrap="char",
            cursor="arrow",
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        log_scroll = tk.Scrollbar(log_frame, command=self.log_text.yview,
                                  bg=COLORS["bg_panel"], troughcolor=COLORS["bg_dark"],
                                  relief="flat", bd=0)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.tag_configure("ts",    foreground="#444c56")
        self.log_text.tag_configure("event", foreground=COLORS["text_dim"])
        self.log_text.tag_configure("key",   foreground=COLORS["text_key"])
        self.log_text.tag_configure("ok",    foreground=COLORS["text_secret"])
        self.log_text.tag_configure("warn",  foreground=COLORS["text_pending"])
        self.log_text.tag_configure("err",   foreground=COLORS["text_error"])

    # -----------------------------------------------------------------------
    # GUI state helpers
    # -----------------------------------------------------------------------

    def _set_disconnected_state(self) -> None:
        """Disable widgets that require an active server connection."""
        self.conn_status_var.set("● Disconnected")
        self.identity_label.configure(fg=COLORS["text_error"], text="—")

        self.exchange_btn.configure(state="disabled")
        self.refresh_btn.configure(state="disabled")
        self.accept_btn.configure(state="disabled")
        self.reject_btn.configure(state="disabled")
        self.end_session_btn.configure(state="disabled")
        self.send_btn.configure(state="disabled")
        self.msg_entry.configure(state="disabled")
        self.disconnect_btn.configure(state="disabled")
        self.connect_btn.configure(state="normal")
        self.name_var.set(self.name_var.get())  # keep name field editable

        self.users_list.delete(0, "end")
        self._clear_session_display()
        self.chat_locked_label.lift()

    def _set_connected_state(self) -> None:
        """Enable widgets after successful server connection."""
        name = self.client.name if self.client else "—"
        self.conn_status_var.set(f"● Connected as {name}")

        # Update the status label color to green
        for widget in self.root.winfo_children():
            pass  # we use StringVar + direct configure below

        self.identity_label.configure(fg=COLORS["text_secret"], text=name)

        self.exchange_btn.configure(state="normal")
        self.refresh_btn.configure(state="normal")
        self.disconnect_btn.configure(state="normal")
        self.connect_btn.configure(state="disabled")

        # Find and update the connection status label color
        self._update_status_color(COLORS["text_secret"])

    def _update_status_color(self, color: str) -> None:
        """Update the connection status label foreground color."""
        # Walk the panel to find our status label
        for widget in self.root.winfo_children():
            self._find_and_color(widget, self.conn_status_var, color)

    def _find_and_color(self, widget, var, color) -> None:
        """Recursively find the Label tied to a StringVar and set its fg."""
        if isinstance(widget, tk.Label):
            try:
                if widget.cget("textvariable") == str(var):
                    widget.configure(fg=color)
            except Exception:
                pass
        for child in widget.winfo_children():
            self._find_and_color(child, var, color)

    def _clear_session_display(self) -> None:
        """Reset all key-exchange status fields to blank."""
        self.peer_name_var.set("—")
        self.peer_pk_var.set("—")
        self.shared_secret_var.set("—")
        self.shared_secret_lbl.configure(fg=COLORS["text_dim"])
        self.fingerprint_var.set("—")
        self.fingerprint_lbl.configure(fg=COLORS["text_dim"])
        self.session_status_var.set("—")
        self.session_status_lbl.configure(fg=COLORS["text_dim"])
        self.accept_btn.configure(state="disabled")
        self.reject_btn.configure(state="disabled")
        self.end_session_btn.configure(state="disabled")
        self.my_pub_key_var.set("Select a peer and start a key exchange to see your session key")
        self.chat_peer_label.configure(text="(no active session)")
        self.encryption_badge.configure(text="")

    def _update_session_display(self, peer: str) -> None:
        """
        Refresh all key-exchange status widgets for the given peer.

        Called whenever a session changes state (request sent, key received,
        session established, etc.).
        """
        if self.client is None:
            return

        session = self.client.get_session(peer)
        pending = peer in self.client.get_pending_requests()

        self.peer_name_var.set(peer)

        if pending:
            # We have an incoming request we haven't acted on yet.
            self.session_status_var.set("⏳  Incoming request — Accept or Reject")
            self.session_status_lbl.configure(fg=COLORS["text_pending"])
            self.accept_btn.configure(state="normal")
            self.reject_btn.configure(state="normal")
            self.end_session_btn.configure(state="disabled")
            self.peer_pk_var.set("—")
            self.shared_secret_var.set("—")
            self.fingerprint_var.set("—")
            self.my_pub_key_var.set("(awaiting acceptance)")
            return

        if session is None:
            self._clear_session_display()
            self.peer_name_var.set(peer)
            return

        # Show our local public key for this session.
        my_pk_hex = self.client.get_my_public_key_hex(peer)
        if my_pk_hex:
            # Display in groups of 8 chars for readability
            self.my_pub_key_var.set(" ".join(my_pk_hex[i:i+8] for i in range(0, len(my_pk_hex), 8)))
        else:
            self.my_pub_key_var.set("—")

        if session.peer_public_key:
            pk_hex = session.peer_public_key.hex()
            self.peer_pk_var.set(" ".join(pk_hex[i:i+8] for i in range(0, len(pk_hex), 8)))
        else:
            self.peer_pk_var.set("Waiting for peer's public key…")
            self.peer_pk_var.set("Waiting…")

        if session.established:
            # Show only that a shared secret was derived — never its raw value.
            self.shared_secret_var.set("✓  Derived successfully (kept private)")
            self.shared_secret_lbl.configure(fg=COLORS["text_secret"])
            self.fingerprint_var.set(session.fingerprint or "—")
            self.fingerprint_lbl.configure(fg=COLORS["text_key"])
            self.session_status_var.set("🔒  Established — AES-GCM chat enabled")
            self.session_status_lbl.configure(fg=COLORS["text_secret"])
            self.end_session_btn.configure(state="normal")
            self.accept_btn.configure(state="disabled")
            self.reject_btn.configure(state="disabled")

            # Unlock chat for this peer
            self.send_btn.configure(state="normal")
            self.msg_entry.configure(state="normal")
            self.chat_locked_label.lower()
            self.chat_peer_label.configure(text=f"↔ {peer}")
            self.encryption_badge.configure(
                text="🔒 AES-GCM encrypted (session key from X25519 + HKDF)"
            )
        else:
            # Session created but awaiting peer's public key.
            self.shared_secret_var.set("Waiting for peer's public key…")
            self.shared_secret_lbl.configure(fg=COLORS["text_pending"])
            self.fingerprint_var.set("—")
            self.session_status_var.set("⏳  Handshake in progress")
            self.session_status_lbl.configure(fg=COLORS["text_pending"])
            self.accept_btn.configure(state="disabled")
            self.reject_btn.configure(state="disabled")
            self.end_session_btn.configure(state="normal")

    def _set_chat_for_peer(self, peer: str) -> None:
        """Load the chat history for a peer into the chat widget."""
        self.chat_text.configure(state="normal")
        self.chat_text.delete("1.0", "end")

        history = self.chat_history.get(peer, [])
        if not history:
            self.chat_text.insert("end", f"(no messages yet with {peer})\n", "sys")
        else:
            for sender, text in history:
                if sender == "__sys__":
                    self.chat_text.insert("end", f"  {text}\n", "sys")
                elif self.client and sender == self.client.name:
                    self.chat_text.insert("end", f"{sender}: {text}\n", "me")
                else:
                    self.chat_text.insert("end", f"{sender}: {text}\n", "peer")

        self.chat_text.configure(state="disabled")
        self.chat_text.see("end")

    # -----------------------------------------------------------------------
    # Button handlers (run on the main thread)
    # -----------------------------------------------------------------------

    def _on_connect_click(self) -> None:
        """Validate inputs and start the connection on a worker thread."""
        name = self.name_var.get().strip()
        host = self.host_var.get().strip()
        port_str = self.port_var.get().strip()

        if not name:
            messagebox.showerror("Error", "Please enter a username.")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Port must be an integer.")
            return

        self.connect_btn.configure(state="disabled", text="Connecting…")
        self._append_log(f"Connecting to {host}:{port} as '{name}'…")

        # Run the blocking connect() call on a background thread so the
        # Tkinter event loop stays responsive.
        threading.Thread(target=self._connect_worker, args=(name, host, port), daemon=True).start()

    def _connect_worker(self, name: str, host: str, port: int) -> None:
        """Worker thread: create and connect the GUIClient."""
        client = GUIClient(name, host, port)

        # Register all callbacks.  These will be called from the background
        # thread, so they must schedule GUI updates via root.after().
        client.on_log              = lambda msg: self.root.after(0, self._append_log, msg)
        client.on_users_updated    = lambda users: self.root.after(0, self._refresh_users, users)
        client.on_session_updated  = lambda peer: self.root.after(0, self._on_session_updated, peer)
        client.on_message_received = lambda peer, text: self.root.after(0, self._on_message_received, peer, text)
        client.on_connected        = lambda: self.root.after(0, self._on_client_connected)
        client.on_disconnected     = lambda: self.root.after(0, self._on_client_disconnected)
        client.on_incoming_request = lambda peer: self.root.after(0, self._on_incoming_request, peer)

        try:
            client.connect()
            self.client = client
        except Exception as exc:
            self.root.after(0, self._append_log, f"[error] Connection failed: {exc}")
            self.root.after(0, lambda: self.connect_btn.configure(state="normal", text="Connect to Server"))

    def _on_disconnect_click(self) -> None:
        """Close the connection."""
        if self.client:
            self.client.disconnect()
            self.client = None

    def _on_refresh_click(self) -> None:
        """Ask the server to resend the user list."""
        if self.client:
            self.client.request_users()

    def _on_user_selected(self, event=None) -> None:
        """Update the UI when the user clicks a name in the clients list."""
        if not self.users_list.curselection():
            return

        peer = self.users_list.get(self.users_list.curselection()[0])
        self.selected_peer = peer

        # Show session status for the selected peer.
        self._update_session_display(peer)

        # If we have an established session with this peer, switch chat.
        if self.client:
            session = self.client.get_session(peer)
            if session and session.established:
                self.client.action_set_active_peer(peer)
                self._set_chat_for_peer(peer)

    def _on_start_exchange_click(self, event=None) -> None:
        """Initiate a key exchange with the selected peer."""
        if not self.client or not self.selected_peer:
            self._append_log("Select a user from the list first.")
            return
        self.client.action_request_exchange(self.selected_peer)

    def _on_accept_click(self) -> None:
        """Accept the incoming key-exchange request from the selected peer."""
        if not self.client or not self.selected_peer:
            return
        self.client.action_accept_exchange(self.selected_peer)

    def _on_reject_click(self) -> None:
        """Reject the incoming key-exchange request from the selected peer."""
        if not self.client or not self.selected_peer:
            return
        self.client.action_reject_exchange(self.selected_peer)
        self._update_session_display(self.selected_peer)

    def _on_end_session_click(self) -> None:
        """Close the active session with the selected peer."""
        if not self.client or not self.selected_peer:
            return
        self.client.action_disconnect_session(self.selected_peer)
        self._clear_session_display()
        self.send_btn.configure(state="disabled")
        self.msg_entry.configure(state="disabled")
        self.chat_locked_label.lift()

    def _on_send_message(self, event=None) -> None:
        """Encrypt and send the typed message."""
        if not self.client:
            return

        text = self.msg_entry.get().strip()
        if not text:
            return

        self.msg_entry.delete(0, "end")

        # Find the active peer.
        peer = self.client.active_peer
        if peer is None:
            self._append_log("No active session. Select a peer and complete key exchange first.")
            return

        # Add to local chat history (we display it ourselves).
        self._append_chat_message(peer, self.client.name, text)

        # Actually send (encrypt) the message.
        self.client.action_send_message(text)

    # -----------------------------------------------------------------------
    # Callbacks (called by GUIClient via root.after, so safely on main thread)
    # -----------------------------------------------------------------------

    def _on_client_connected(self) -> None:
        """Called after successful server registration."""
        self._set_connected_state()
        self.connect_btn.configure(text="Connect to Server")

        # Highlight the connection status label green
        # We look for the label with our conn_status_var
        self._recolor_label_with_var(self.conn_status_var, COLORS["text_secret"])

    def _on_client_disconnected(self) -> None:
        """Called when the connection drops."""
        self.client = None
        self._set_disconnected_state()
        self._recolor_label_with_var(self.conn_status_var, COLORS["text_error"])

    def _on_session_updated(self, peer: str) -> None:
        """Called whenever a session changes state."""
        # Only update the display if this peer is currently selected.
        if peer == self.selected_peer:
            self._update_session_display(peer)

        # If the session just became established, load the chat view.
        if self.client:
            session = self.client.get_session(peer)
            if session and session.established and peer == self.selected_peer:
                self._set_chat_for_peer(peer)

    def _on_incoming_request(self, peer: str) -> None:
        """
        Called when we receive a chat_request from a peer.

        If the peer is already selected in our list, update the display
        immediately.  Either way, show a popup notification.
        """
        # Add the requester to the list if they aren't there.
        existing = list(self.users_list.get(0, "end"))
        if peer not in existing:
            self.users_list.insert("end", peer)

        # Auto-select the peer so the Accept button lights up.
        items = list(self.users_list.get(0, "end"))
        if peer in items:
            idx = items.index(peer)
            self.users_list.selection_clear(0, "end")
            self.users_list.selection_set(idx)
            self.selected_peer = peer
            self._update_session_display(peer)

        # Show a non-blocking notification
        self._append_log(f"⚡ Key-exchange request from '{peer}' — click Accept or Reject.")

    def _on_message_received(self, peer: str, text: str) -> None:
        """Display a received decrypted message in the chat panel."""
        self._append_chat_message(peer, peer, text)
        self._append_log(f"Message received from '{peer}' and decrypted successfully.")

    # -----------------------------------------------------------------------
    # Display helpers (always called on the main thread)
    # -----------------------------------------------------------------------

    def _refresh_users(self, users: list[str]) -> None:
        """Repopulate the connected-clients listbox."""
        # Remember the current selection.
        selected = self.selected_peer

        self.users_list.delete(0, "end")
        for user in sorted(users):
            self.users_list.insert("end", user)

        # Restore selection if still present.
        if selected:
            all_items = list(self.users_list.get(0, "end"))
            if selected in all_items:
                idx = all_items.index(selected)
                self.users_list.selection_set(idx)
            else:
                self.selected_peer = None
                self._clear_session_display()

    def _append_log(self, message: str) -> None:
        """Add a timestamped line to the event log."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")

        # Choose a tag based on keywords in the message.
        if any(k in message for k in ("error", "failed", "rejected", "invalid")):
            tag = "err"
        elif any(k in message for k in ("established", "derived", "success", "accepted", "✓", "🔒")):
            tag = "ok"
        elif any(k in message for k in ("Waiting", "request", "Connecting", "⚡", "⏳")):
            tag = "warn"
        elif any(k in message for k in ("public key", "Public key", "fingerprint", "Fingerprint")):
            tag = "key"
        else:
            tag = "event"

        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{ts}  ", "ts")
        self.log_text.insert("end", f"{message}\n", tag)
        self.log_text.configure(state="disabled")
        self.log_text.see("end")

    def _append_chat_message(self, peer: str, sender: str, text: str) -> None:
        """Add a message to the chat history and widget."""
        if peer not in self.chat_history:
            self.chat_history[peer] = []
        self.chat_history[peer].append((sender, text))

        # Only update the widget if this peer is the active chat.
        if self.client and self.client.active_peer == peer:
            self.chat_text.configure(state="normal")
            if self.client and sender == self.client.name:
                self.chat_text.insert("end", f"{sender}: {text}\n", "me")
            else:
                self.chat_text.insert("end", f"{sender}: {text}\n", "peer")
            self.chat_text.configure(state="disabled")
            self.chat_text.see("end")

    def _recolor_label_with_var(self, var: tk.StringVar, color: str) -> None:
        """Find and recolor the Label that uses the given StringVar."""
        self._find_and_recolor(self.root, var, color)

    def _find_and_recolor(self, widget: tk.Widget, var: tk.StringVar, color: str) -> None:
        if isinstance(widget, tk.Label):
            try:
                linked_var = widget.cget("textvariable")
                if str(linked_var) == str(var):
                    widget.configure(fg=color)
            except Exception:
                pass
        for child in widget.winfo_children():
            self._find_and_recolor(child, var, color)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    root = tk.Tk()
    root.tk.call("tk", "scaling", 1.2)  # sharper text on hi-DPI

    # Set the window icon if possible (silently ignore errors)
    try:
        root.iconbitmap(default="assets/icon.ico")
    except Exception:
        pass

    app = X25519App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
