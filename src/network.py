"""
Small JSON-over-TCP helpers used by the terminal chat demo.

The secure chat sends one JSON object per line. This is intentionally simple so
students can inspect the messages that move through the relay server:

    {"type": "public_key", "from": "Alice", "to": "Bob", ...}\n
The server only forwards public keys and encrypted payloads. It never receives
private keys, shared secrets, or decrypted plaintext messages.
"""

from __future__ import annotations

import json
import socket
from typing import Any, TextIO

JsonMessage = dict[str, Any]


class NetworkError(RuntimeError):
    """Raised when the JSON line protocol receives invalid data."""


# ---------------------------------------------------------------------------
# JSON line helpers
# ---------------------------------------------------------------------------

def send_json(sock: socket.socket, message: JsonMessage) -> None:
    """
    Send one JSON message over a socket.

    Args:
        sock:
            Connected TCP socket.

        message:
            Dictionary that can be serialized as JSON.
    """
    encoded = json.dumps(message, separators=(",", ":")) + "\n"
    sock.sendall(encoded.encode("utf-8"))


def read_json(reader: TextIO) -> JsonMessage | None:
    """
    Read one JSON message from a text-mode socket reader.

    Returns:
        A decoded JSON object, or None if the peer closed the connection.
    """
    line = reader.readline()

    if line == "":
        return None

    try:
        message = json.loads(line)
    except json.JSONDecodeError as exc:
        raise NetworkError("received invalid JSON") from exc

    if not isinstance(message, dict):
        raise NetworkError("received JSON value that is not an object")

    return message


def make_reader(sock: socket.socket) -> TextIO:
    """
    Create a text reader for line-based socket input.
    """
    return sock.makefile("r", encoding="utf-8", newline="\n")
