"""
Tests for the encrypted messaging layer used after X25519 key exchange.
"""

import os

import pytest

from src.secure_message import decrypt_message, encrypt_message


def test_encrypt_then_decrypt_text_message():
    session_key = os.urandom(32)
    nonce, ciphertext = encrypt_message(session_key, "hello Bob")

    assert len(nonce) == 12
    assert ciphertext != b"hello Bob"
    assert decrypt_message(session_key, nonce, ciphertext) == "hello Bob"


def test_encrypt_then_decrypt_empty_message():
    session_key = os.urandom(32)
    nonce, ciphertext = encrypt_message(session_key, "")

    assert decrypt_message(session_key, nonce, ciphertext) == ""


def test_encrypt_then_decrypt_unicode_message():
    session_key = os.urandom(32)
    message = "שלום Bob 🔐"
    nonce, ciphertext = encrypt_message(session_key, message)

    assert decrypt_message(session_key, nonce, ciphertext) == message


def test_tampered_ciphertext_is_rejected():
    session_key = os.urandom(32)
    nonce, ciphertext = encrypt_message(session_key, "attack at dawn")
    tampered = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_message(session_key, nonce, tampered)


def test_wrong_key_is_rejected():
    session_key = os.urandom(32)
    wrong_key = os.urandom(32)
    nonce, ciphertext = encrypt_message(session_key, "secret")

    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_message(wrong_key, nonce, ciphertext)


def test_same_plaintext_uses_different_nonce_and_ciphertext():
    session_key = os.urandom(32)

    nonce_1, ciphertext_1 = encrypt_message(session_key, "same message")
    nonce_2, ciphertext_2 = encrypt_message(session_key, "same message")

    assert nonce_1 != nonce_2
    assert ciphertext_1 != ciphertext_2
