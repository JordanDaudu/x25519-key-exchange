<p align="center">
  <img src="assets/X25519-Banner.png" alt="X25519 Key Exchange GitHub README hero banner" width="100%" />
</p>

# X25519 Key Exchange — Final Project

## Implementation and Analysis of X25519 Elliptic-Curve Diffie-Hellman Using the Montgomery Ladder

A documented educational implementation of **X25519 elliptic-curve Diffie-Hellman key exchange** in Python for the **Data Security / אבטחת נתונים** final project.

This project implements the core X25519 primitive manually, including scalar clamping, arithmetic modulo `p = 2^255 - 19`, Montgomery ladder scalar multiplication, public key generation, Alice/Bob shared-secret derivation, official test vector validation, negative tests, and benchmarking.

---

## Quick Links

- [Project Goal](#project-goal)
- [What X25519 Does](#what-x25519-does)
- [Project Structure](#project-structure)
- [Implementation Overview](#implementation-overview)
- [Setup](#setup)
- [Run the Demo](#run-the-demo)
- [Run the Tests](#run-the-tests)
- [Run the Benchmark](#run-the-benchmark)
- [Testing Strategy](#testing-strategy)
- [Security Notice](#security-notice)
- [Academic Context](#academic-context)

---

## Project Goal

The goal of this project is to understand and implement a real modern cryptographic key-exchange primitive.

X25519 solves the following problem:

> How can two parties agree on the same shared secret over an insecure communication channel without sending the secret itself?

In this project, Alice and Bob each generate a private/public key pair. They exchange public keys, and then both derive the same shared secret:

```text
Alice private key + Bob public key   -> shared secret
Bob private key + Alice public key   -> same shared secret
```

An attacker may observe the exchanged public keys, but should not be able to efficiently derive the shared secret.

---

## What X25519 Does

X25519 is a **key exchange** primitive.

It does **not** encrypt messages by itself. Instead, it produces a shared secret. In real protocols, that shared secret is usually passed into a key derivation function, and the derived key is then used with a symmetric cipher such as AES or ChaCha20.

```text
X25519 shared secret
        ↓
KDF / hash
        ↓
symmetric encryption key
        ↓
AES / ChaCha20 / another symmetric cipher
```

---

## Project Structure

```text
x25519-key-exchange/
│
├── assets/
│   └── X25519-Banner.png
│
├── src/
│   ├── __init__.py
│   ├── x25519.py
│   └── key_exchange.py
│
├── tests/
│   ├── __init__.py
│   ├── test_key_exchange.py
│   ├── test_negative_cases.py
│   └── test_x25519_vectors.py
│
├── docs/
│   ├── final_report_outline.md
│   ├── interim_report_outline.md
│   └── references.md
│
├── benchmark.py
├── demo.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Implementation Overview

### `src/x25519.py`

This file contains the cryptographic core of the project.

Main functions:

- `_validate_32_bytes(value, name)`
- `clamp_scalar(private_key)`
- `decode_u_coordinate(public_key)`
- `conditional_swap(swap, first, second)`
- `x25519(private_key, public_key)`
- `generate_public_key(private_key)`

The central function is:

```python
x25519(private_key, public_key) -> bytes
```

It is used for both public key generation and shared-secret derivation:

```python
public_key = x25519(private_key, BASE_POINT)
shared_secret = x25519(my_private_key, other_public_key)
```

### `src/key_exchange.py`

This file provides a higher-level Alice/Bob interface around the low-level primitive.

It includes:

- random private key generation
- public key generation
- shared-secret derivation
- a simple `X25519Party` class

Example:

```python
alice = X25519Party("Alice")
bob = X25519Party("Bob")

alice_secret = alice.derive_shared_secret(bob.public_key)
bob_secret = bob.derive_shared_secret(alice.public_key)

assert alice_secret == bob_secret
```

### `demo.py`

Demonstrates a complete Alice/Bob key exchange flow.

### `benchmark.py`

Measures key/public-key generation time, shared-secret derivation time, and the fixed key/shared-secret sizes.

---

## Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

### macOS / Linux

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Run the Demo

```bash
python demo.py
```

Example output:

```text
X25519 Alice/Bob Key Exchange Demo
----------------------------------
Alice public key: ...
Bob public key:   ...

Alice shared secret: ...
Bob shared secret:   ...

SUCCESS: Alice and Bob derived the same shared secret.
```

The public keys and shared secret change on each run because fresh random private keys are generated.

---

## Run the Tests

```bash
pytest
```

Current test suite:

```text
11 passed
```

The tests cover:

- official X25519 test vectors
- Alice/Bob round-trip key exchange
- wrong public key behavior
- invalid private key length
- invalid public key length
- invalid private key type
- invalid public key type
- all-zero shared-secret rejection for invalid or unsafe public inputs

---

## Run the Benchmark

```bash
python benchmark.py
```

The benchmark measures:

- party creation / public key generation time
- shared-secret derivation time
- private key size
- public key size
- shared secret size

Example benchmark result from the development machine:

```text
X25519 Benchmark
================
Iterations per benchmark: 1000

Key and Shared Secret Sizes
---------------------------
Private key size:      32 bytes
Public key size:       32 bytes
Shared secret size:    32 bytes

Timing Results
--------------
Party creation / public key generation
  Average: 1.196584 ms
  Min:     1.152125 ms
  Max:     1.505916 ms

Shared secret derivation
  Average: 1.285050 ms
  Min:     1.239750 ms
  Max:     1.577542 ms
```

These numbers are from an educational pure-Python implementation and should not be compared directly to optimized production cryptographic libraries.

---

## Testing Strategy

Cryptographic code must be checked carefully because an implementation that only works in one demo is not enough.

This project uses three layers of testing:

### 1. Official test vectors

The low-level `x25519()` function is tested against known X25519 input/output pairs.

### 2. Round-trip key exchange tests

Alice and Bob independently derive the same shared secret.

### 3. Negative tests

The project checks that invalid inputs or wrong-key scenarios are handled properly.

---

## What Was Implemented Manually

The core X25519 operation was implemented directly in Python.

Implemented manually:

- scalar clamping
- public u-coordinate decoding
- conditional swap
- Montgomery ladder
- modular arithmetic over `p = 2^255 - 19`
- conversion from projective coordinates back to affine form
- public key generation
- shared-secret derivation
- At the high-level key exchange layer, the implementation rejects all-zero shared secrets produced by invalid or unsafe public inputs.

No cryptographic library is used to perform the X25519 operation.

---

## Security Notice

This project is for educational and academic purposes only.

It should **not** be used in production cryptographic systems.

Reasons:

- Python integer operations are not guaranteed to be constant-time.
- The implementation prioritizes readability and learning.
- Production cryptography requires carefully reviewed, hardened implementations.
- A full secure protocol also needs authentication, transcript binding, key derivation, message integrity, replay protection, and symmetric encryption.

---

## Academic Context

This project connects to several topics from the Data Security course:

- modular arithmetic
- public/private key cryptography
- Diffie-Hellman key exchange
- finite fields
- modular inverse
- comparison with RSA-style public-key systems
- use of shared secrets with symmetric encryption

X25519 extends these foundations into a modern elliptic-curve key exchange primitive used in real-world secure communication protocols.

---

## References

Main sources used for the project are collected in:

```text
docs/references.md
```

Key references include:

- Daniel J. Bernstein, *Curve25519: New Diffie-Hellman Speed Records*
- Bernstein and Lange, *Montgomery Curves and the Montgomery Ladder*
- Costello and Smith, *Montgomery Curves and Their Arithmetic*
- RFC 7748, *Elliptic Curves for Security*
- RFC 8446, *The Transport Layer Security Protocol Version 1.3*
