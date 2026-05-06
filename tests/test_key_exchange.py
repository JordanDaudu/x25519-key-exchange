"""
Tests for the high-level Alice/Bob X25519 key exchange flow.

These tests check the protocol behavior around the core primitive:

    Alice public key = x25519(Alice private key, BASE_POINT)
    Bob public key   = x25519(Bob private key, BASE_POINT)

    Alice shared secret = x25519(Alice private key, Bob public key)
    Bob shared secret   = x25519(Bob private key, Alice public key)

The important property:
    Alice shared secret == Bob shared secret
"""

from src.key_exchange import X25519Party, generate_private_key


def test_generate_private_key_returns_32_bytes():
    """
    A generated private key should be exactly 32 bytes.

    This is important because X25519 expects 32-byte private keys.
    """
    private_key = generate_private_key()

    assert isinstance(private_key, bytes)
    assert len(private_key) == 32


def test_alice_and_bob_derive_same_shared_secret():
    """
    Alice and Bob should derive the same shared secret.

    This is the main correctness property of Diffie-Hellman-style key exchange.
    """
    alice = X25519Party("Alice")
    bob = X25519Party("Bob")

    alice_secret = alice.derive_shared_secret(bob.public_key)
    bob_secret = bob.derive_shared_secret(alice.public_key)

    assert alice_secret == bob_secret
    assert len(alice_secret) == 32


def test_different_key_exchanges_produce_different_secrets():
    """
    Two independent key exchanges should normally produce different secrets.

    This checks that fresh random private keys lead to fresh shared secrets.
    """
    alice_1 = X25519Party("Alice 1")
    bob_1 = X25519Party("Bob 1")

    alice_2 = X25519Party("Alice 2")
    bob_2 = X25519Party("Bob 2")

    secret_1 = alice_1.derive_shared_secret(bob_1.public_key)
    secret_2 = alice_2.derive_shared_secret(bob_2.public_key)

    assert secret_1 != secret_2