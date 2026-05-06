"""
Demo program for X25519 Alice/Bob key exchange.

This script shows the full high-level flow:

1. Alice generates a private/public key pair.
2. Bob generates a private/public key pair.
3. Alice receives Bob's public key.
4. Bob receives Alice's public key.
5. Both derive a shared secret.
6. The program checks that both shared secrets are equal.
"""

from src.key_exchange import X25519Party


def main() -> None:
    """
    Run a simple Alice/Bob X25519 key exchange demonstration.
    """
    alice = X25519Party("Alice")
    bob = X25519Party("Bob")

    alice_secret = alice.derive_shared_secret(bob.public_key)
    bob_secret = bob.derive_shared_secret(alice.public_key)

    print("X25519 Alice/Bob Key Exchange Demo")
    print("----------------------------------")

    print(f"Alice public key: {alice.public_key.hex()}")
    print(f"Bob public key:   {bob.public_key.hex()}")

    print()
    print(f"Alice shared secret: {alice_secret.hex()}")
    print(f"Bob shared secret:   {bob_secret.hex()}")

    print()

    if alice_secret == bob_secret:
        print("SUCCESS: Alice and Bob derived the same shared secret.")
    else:
        print("FAILURE: Shared secrets do not match.")


if __name__ == "__main__":
    main()