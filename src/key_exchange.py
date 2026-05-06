"""
High-level Alice/Bob wrapper around the X25519 primitive.

The file src/x25519.py contains the cryptographic core:
    x25519(private_key, public_key)

This file provides a cleaner interface for demonstrating an actual key exchange
between two parties.

Main idea:
    Alice creates a private key and public key.
    Bob creates a private key and public key.

    Alice computes:
        x25519(alice_private_key, bob_public_key)

    Bob computes:
        x25519(bob_private_key, alice_public_key)

    Both sides should get the same shared secret.
"""

import os

from src.x25519 import KEY_SIZE, generate_public_key, x25519


# ---------------------------------------------------------------------------
# Private key generation
# ---------------------------------------------------------------------------

def generate_private_key() -> bytes:
    """
    Generate a random 32-byte private key.

    Why this matters:
        X25519 private keys are 32 random bytes.
        The raw private key is later clamped inside x25519() before being used.

    Important:
        We use os.urandom(), which is suitable for generating cryptographic
        random bytes in Python.

    Returns:
        A random 32-byte private key.
    """
    return os.urandom(KEY_SIZE)


# ---------------------------------------------------------------------------
# X25519 party
# ---------------------------------------------------------------------------

class X25519Party:
    """
    Represents one participant in an X25519 key exchange.

    A party has:
        - a name
        - a private key
        - a public key

    The private key stays secret.
    The public key can be sent to another party.

    Example:
        alice = X25519Party("Alice")
        bob = X25519Party("Bob")

        alice_secret = alice.derive_shared_secret(bob.public_key)
        bob_secret = bob.derive_shared_secret(alice.public_key)

        assert alice_secret == bob_secret
    """

    def __init__(self, name: str, private_key: bytes | None = None):
        """
        Create a new X25519 party.

        Args:
            name:
                A readable name for the party, such as "Alice" or "Bob".

            private_key:
                Optional 32-byte private key.
                If not provided, a fresh random private key is generated.

        Why allow an optional private key?
            It makes the class easier to test because tests can use fixed keys
            when needed.
        """
        self.name = name

        if private_key is None:
            self.private_key = generate_private_key()
        else:
            self.private_key = private_key

        self.public_key = generate_public_key(self.private_key)

    def derive_shared_secret(self, other_public_key: bytes) -> bytes:
        """
        Derive a shared secret using another party's public key.

        This is the main operation in the key exchange.

        Args:
            other_public_key:
                The 32-byte public key received from the other party.

        Returns:
            A 32-byte shared secret.

        Example:
            Alice receives Bob's public key:
                alice_secret = alice.derive_shared_secret(bob.public_key)

            Bob receives Alice's public key:
                bob_secret = bob.derive_shared_secret(alice.public_key)

            The two secrets should be equal.
        """
        return x25519(self.private_key, other_public_key)