"""
Negative tests for the X25519 implementation.

Positive tests prove that valid input works.
Negative tests prove that invalid inputs or wrong keys are handled properly.

These tests check:
- wrong public key behavior
- invalid private key length
- invalid public key length
- invalid input types
- all-zero shared-secret rejection
"""

import os

import pytest

from src.key_exchange import X25519Party
from src.x25519 import KEY_SIZE, x25519


def test_wrong_public_key_produces_different_secret():
    """
    If Alice uses an attacker's public key instead of Bob's public key,
    the derived secret should be different from the real Alice/Bob secret.
    """
    alice = X25519Party("Alice")
    bob = X25519Party("Bob")
    attacker = X25519Party("Attacker")

    correct_secret = alice.derive_shared_secret(bob.public_key)
    wrong_secret = alice.derive_shared_secret(attacker.public_key)

    assert correct_secret != wrong_secret


def test_private_key_must_be_32_bytes():
    """
    x25519() should reject private keys that are not exactly 32 bytes.
    """
    invalid_private_key = os.urandom(KEY_SIZE - 1)
    valid_public_key = os.urandom(KEY_SIZE)

    with pytest.raises(ValueError, match="private_key"):
        x25519(invalid_private_key, valid_public_key)


def test_public_key_must_be_32_bytes():
    """
    x25519() should reject public keys that are not exactly 32 bytes.
    """
    valid_private_key = os.urandom(KEY_SIZE)
    invalid_public_key = os.urandom(KEY_SIZE - 1)

    with pytest.raises(ValueError, match="public_key"):
        x25519(valid_private_key, invalid_public_key)


def test_private_key_must_be_bytes():
    """
    x25519() should reject a private key that is not a bytes object.
    """
    invalid_private_key = "not bytes"
    valid_public_key = os.urandom(KEY_SIZE)

    with pytest.raises(TypeError, match="private_key"):
        x25519(invalid_private_key, valid_public_key)


def test_public_key_must_be_bytes():
    """
    x25519() should reject a public key that is not a bytes object.
    """
    valid_private_key = os.urandom(KEY_SIZE)
    invalid_public_key = "not bytes"

    with pytest.raises(TypeError, match="public_key"):
        x25519(valid_private_key, invalid_public_key)


def test_all_zero_shared_secret_is_rejected_by_high_level_protocol():
    """
    The low-level x25519() primitive may compute an all-zero result for certain
    invalid public inputs.

    The high-level key exchange wrapper rejects this because an all-zero shared
    secret is not safe to use as a session secret.
    """
    alice = X25519Party("Alice")

    all_zero_public_key = bytes(KEY_SIZE)

    with pytest.raises(ValueError, match="all-zero"):
        alice.derive_shared_secret(all_zero_public_key)