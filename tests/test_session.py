"""
Tests for pairwise SecureSession objects.
"""

from src.secure_message import decrypt_message, encrypt_message
from src.session import SecureSession


def test_secure_session_establishes_same_key_for_initiator_and_responder():
    alice_session = SecureSession(
        local_name="Alice",
        peer_name="Bob",
        initiator_name="Alice",
        responder_name="Bob",
    )
    bob_session = SecureSession(
        local_name="Bob",
        peer_name="Alice",
        initiator_name="Alice",
        responder_name="Bob",
    )

    alice_session.set_peer_public_key(bob_session.local_public_key)
    bob_session.set_peer_public_key(alice_session.local_public_key)

    assert alice_session.established
    assert bob_session.established
    assert alice_session.session_key == bob_session.session_key
    assert alice_session.fingerprint == bob_session.fingerprint


def test_established_session_key_can_encrypt_between_parties():
    alice_session = SecureSession(
        local_name="Alice",
        peer_name="Bob",
        initiator_name="Alice",
        responder_name="Bob",
    )
    bob_session = SecureSession(
        local_name="Bob",
        peer_name="Alice",
        initiator_name="Alice",
        responder_name="Bob",
    )

    alice_session.set_peer_public_key(bob_session.local_public_key)
    bob_session.set_peer_public_key(alice_session.local_public_key)

    nonce, ciphertext = encrypt_message(alice_session.require_session_key(), "hello Bob")

    assert decrypt_message(bob_session.require_session_key(), nonce, ciphertext) == "hello Bob"
