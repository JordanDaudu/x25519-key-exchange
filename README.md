<p align="center">
  <img src="assets/X25519-Banner.png" alt="GradeFlow GitHub README hero banner" width="100%" />
</p>

# X25519 Key Exchange Using the Montgomery Ladder

A documented educational implementation of **X25519 elliptic-curve Diffie-Hellman key exchange** in Python.

This project implements the core X25519 primitive manually, including:

- scalar clamping
- arithmetic modulo `p = 2^255 - 19`
- Montgomery ladder scalar multiplication
- public key generation
- Alice/Bob shared-secret derivation
- official test vector validation
- negative tests
- benchmarking

> This project was developed as part of a final project in Data Security / אבטחת נתונים.

---

## Project Goal

The goal of this project is to understand and implement a real modern cryptographic key-exchange primitive.

X25519 solves the following problem:

> How can two parties agree on the same shared secret over an insecure channel, without sending the secret itself?

In this project, Alice and Bob each generate a private/public key pair. They exchange public keys, and then both derive the same shared secret:

```text
Alice private key + Bob public key   -> shared secret
Bob private key + Alice public key   -> same shared secret