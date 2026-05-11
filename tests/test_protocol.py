"""
Tests for protocol helpers and X25519 session-key derivation.
"""

import pytest

from src.key_exchange import X25519Party
from src.protocol import is_valid_username, require_hex_bytes
from src.secure_message import derive_session_key, fingerprint_session_key


def test_username_validation_accepts_simple_terminal_names():
    assert is_valid_username("Alice")
    assert is_valid_username("Bob_123")
    assert is_valid_username("X-Client")


def test_username_validation_rejects_spaces_and_empty_names():
    assert not is_valid_username("")
    assert not is_valid_username("Alice Bob")
    assert not is_valid_username("A" * 33)


def test_require_hex_bytes_decodes_exact_length():
    value = bytes(range(32))

    assert require_hex_bytes(value.hex(), 32, "public_key") == value


def test_require_hex_bytes_rejects_wrong_length():
    with pytest.raises(ValueError, match="32 bytes"):
        require_hex_bytes("00", 32, "public_key")


def test_require_hex_bytes_rejects_invalid_hex():
    with pytest.raises(ValueError, match="hexadecimal"):
        require_hex_bytes("not-hex", 32, "public_key")


def test_derive_session_key_matches_for_both_parties():
    alice = X25519Party("Alice")
    bob = X25519Party("Bob")

    alice_shared_secret = alice.derive_shared_secret(bob.public_key)
    bob_shared_secret = bob.derive_shared_secret(alice.public_key)

    alice_session_key = derive_session_key(
        alice_shared_secret,
        "Alice",
        "Bob",
        alice.public_key,
        bob.public_key,
    )
    bob_session_key = derive_session_key(
        bob_shared_secret,
        "Alice",
        "Bob",
        alice.public_key,
        bob.public_key,
    )

    assert alice_session_key == bob_session_key
    assert len(alice_session_key) == 32
    assert fingerprint_session_key(alice_session_key) == fingerprint_session_key(bob_session_key)


def test_derive_session_key_changes_when_transcript_changes():
    alice = X25519Party("Alice")
    bob = X25519Party("Bob")

    shared_secret = alice.derive_shared_secret(bob.public_key)

    normal_key = derive_session_key(
        shared_secret,
        "Alice",
        "Bob",
        alice.public_key,
        bob.public_key,
    )
    changed_transcript_key = derive_session_key(
        shared_secret,
        "Alice",
        "X",
        alice.public_key,
        bob.public_key,
    )

    assert normal_key != changed_transcript_key
