"""
Message helpers for the multi-user X25519 terminal chat demo.

This module contains only protocol-level structure: message types, small
builders, and username validation. It does not perform any cryptography.
"""

from __future__ import annotations

import re
from typing import Any

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def is_valid_username(name: str) -> bool:
    """
    Return True if a username is safe for this simple terminal protocol.

    Usernames are intentionally restricted to simple visible characters so that
    commands like `/connect Bob` remain easy to parse and demonstrate.
    """
    return isinstance(name, str) and USERNAME_PATTERN.fullmatch(name) is not None


def require_valid_username(name: str) -> None:
    """
    Validate a username and raise ValueError if it is invalid.
    """
    if not is_valid_username(name):
        raise ValueError("username must contain 1-32 letters, numbers, '_' or '-'")


def require_hex_bytes(hex_value: str, expected_length: int, field_name: str) -> bytes:
    """
    Decode and validate a hex string with an exact byte length.
    """
    if not isinstance(hex_value, str):
        raise ValueError(f"{field_name} must be a hex string")

    try:
        value = bytes.fromhex(hex_value)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be valid hexadecimal") from exc

    if len(value) != expected_length:
        raise ValueError(f"{field_name} must decode to exactly {expected_length} bytes")

    return value


# ---------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------

def register(name: str) -> dict[str, Any]:
    return {"type": "register", "name": name}


def registered(name: str) -> dict[str, Any]:
    return {"type": "registered", "name": name}


def list_users() -> dict[str, Any]:
    return {"type": "list_users"}


def users(usernames: list[str]) -> dict[str, Any]:
    return {"type": "users", "users": usernames}


def chat_request(sender: str, receiver: str) -> dict[str, Any]:
    return {"type": "chat_request", "from": sender, "to": receiver}


def chat_accept(sender: str, receiver: str) -> dict[str, Any]:
    return {"type": "chat_accept", "from": sender, "to": receiver}


def chat_reject(sender: str, receiver: str) -> dict[str, Any]:
    return {"type": "chat_reject", "from": sender, "to": receiver}


def public_key(sender: str, receiver: str, public_key_bytes: bytes) -> dict[str, Any]:
    return {
        "type": "public_key",
        "from": sender,
        "to": receiver,
        "public_key": public_key_bytes.hex(),
    }


def encrypted_message(sender: str, receiver: str, nonce: bytes, ciphertext: bytes) -> dict[str, Any]:
    return {
        "type": "encrypted_message",
        "from": sender,
        "to": receiver,
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
    }


def session_disconnect(sender: str, receiver: str) -> dict[str, Any]:
    return {"type": "session_disconnect", "from": sender, "to": receiver}


def user_disconnected(name: str) -> dict[str, Any]:
    return {"type": "user_disconnected", "name": name}


def error(message: str) -> dict[str, Any]:
    return {"type": "error", "message": message}


def info(message: str) -> dict[str, Any]:
    return {"type": "info", "message": message}
