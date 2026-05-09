# Final Report Plan

## Implementation and Analysis of X25519 Elliptic-Curve Diffie-Hellman Key Exchange

This document is the working plan for the final report. It follows the natural story of the project: what X25519 solves, how it works, how it was implemented, how it was tested, and what was learned from the implementation.

## Quick Links

- [Introduction](#introduction)
- [Theoretical background](#theoretical-background)
- [Implementation](#implementation)
- [Testing and results](#testing-and-results)
- [Performance](#performance)
- [Analysis and reflection](#analysis-and-reflection)
- [Limitations and future work](#limitations-and-future-work)

## Introduction

The project implements X25519, a modern elliptic-curve Diffie-Hellman key exchange function based on Curve25519.

The goal is to demonstrate how two parties can derive the same shared secret over an insecure communication channel without directly sending the secret.

The basic scenario is:

```text
Alice creates a private/public key pair.
Bob creates a private/public key pair.
They exchange public keys.
Each side uses its own private key and the other side's public key.
Both derive the same shared secret.
```

The introduction should also explain that X25519 is not an encryption algorithm by itself. It is a key exchange primitive. In real systems, the shared secret is usually passed into a key derivation function and then used with a symmetric cipher such as AES or ChaCha20.

## Theoretical Background

### Key exchange problem

The key exchange problem asks how two parties can agree on a shared secret over a public channel.

X25519 solves this using elliptic-curve Diffie-Hellman. The public keys can be sent over the network, but the private scalars remain secret.

### Finite field arithmetic

X25519 operates over the finite field:

```text
p = 2^255 - 19
```

The implementation uses modular addition, subtraction, multiplication, squaring, and inversion over this prime field.

This connects directly to modular arithmetic studied in class.

### Curve25519 and X25519

Curve25519 is a Montgomery curve designed for efficient Diffie-Hellman key exchange.

X25519 is the function that performs scalar multiplication using the Montgomery u-coordinate. This gives it a compact x-only interface.

### Scalar clamping

Before using a private key, X25519 clamps the scalar by modifying specific bits.

The implementation performs:

```python
scalar[0] &= 248
scalar[31] &= 127
scalar[31] |= 64
```

This ensures that the private scalar has the expected X25519 format.

### Montgomery ladder

The Montgomery ladder is the core scalar multiplication algorithm used by X25519.

It processes the private scalar bit by bit and updates two internal states using modular arithmetic. Its regular structure is important for safer implementations because it helps avoid branches that depend directly on secret scalar bits.

### Security assumption

X25519 relies on the hardness of elliptic-curve Diffie-Hellman / discrete-logarithm style problems on Curve25519.

An attacker may see the public keys, but should not be able to efficiently compute the shared secret without knowing one of the private scalars.

## Implementation

### Project structure

```text
src/x25519.py
src/key_exchange.py
demo.py
benchmark.py
tests/
```

### Core implementation: `src/x25519.py`

This file contains the core X25519 primitive.

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

It is used in two ways:

```python
public_key = x25519(private_key, BASE_POINT)
shared_secret = x25519(my_private_key, other_public_key)
```

### High-level key exchange: `src/key_exchange.py`

This file provides a cleaner Alice/Bob interface around the primitive.

It includes:

- `generate_private_key()`
- `X25519Party`
- public key generation
- shared secret derivation

### Demo: `demo.py`

The demo shows a complete Alice/Bob key exchange.

It prints:

- Alice's public key
- Bob's public key
- Alice's shared secret
- Bob's shared secret
- success/failure message

### Libraries used

The core X25519 operation is implemented manually.

The project uses:

- `os` for random byte generation
- `pytest` for tests
- `time` and `statistics` for benchmarking

No cryptographic library is used to perform X25519.

## Testing and Results

### Official test vectors

The low-level X25519 function is tested against official test vectors. This is important because cryptographic code must match known correct input/output pairs, not only appear to work in one demo.

### Round-trip tests

The Alice/Bob tests confirm that both sides derive the same shared secret.

### Negative tests

The negative tests check that invalid or incorrect cases are handled properly:

- wrong public key
- invalid private key length
- invalid public key length
- private key is not bytes
- public key is not bytes

### Current test status

The current test suite contains 10 tests and passes successfully.

```text
10 passed
```

## Performance

The benchmark measures:

- party creation / public key generation
- shared-secret derivation
- private key size
- public key size
- shared-secret size

Current benchmark result from the development machine:

```text
Private key size:      32 bytes
Public key size:       32 bytes
Shared secret size:    32 bytes

Party creation / public key generation average: 1.196584 ms
Shared secret derivation average: 1.285050 ms
```

These timings reflect an educational Python implementation. They should not be compared directly to optimized production implementations written in C, Rust, or assembly.

## Analysis and Reflection

### Comparison to classical Diffie-Hellman

Classical Diffie-Hellman uses modular exponentiation in a multiplicative group modulo a large prime.

X25519 uses elliptic-curve scalar multiplication over Curve25519.

Both solve the key agreement problem, but elliptic-curve Diffie-Hellman can provide comparable security with much smaller public keys.

### Comparison to RSA

RSA is based on the difficulty of factoring large integers and uses modular exponentiation.

X25519 is based on elliptic-curve Diffie-Hellman assumptions and uses scalar multiplication on a Montgomery curve.

The comparison is useful because it shows how modern public-key cryptography moved toward smaller and more efficient elliptic-curve constructions for key agreement.

### Side-channel concerns

The Montgomery ladder has a regular structure that is useful for side-channel-resistant implementations.

However, this Python implementation is not production-safe because:

- Python big integers are not guaranteed to be constant-time
- interpreter behavior can introduce timing variation
- the code prioritizes clarity and education over hardened deployment

### Real-world protocol context

In real protocols, X25519 is only one part of a larger handshake.

A complete protocol normally also includes:

- authentication
- transcript binding
- key derivation
- symmetric encryption
- message integrity
- replay protection

## Limitations and Future Work

### Limitations

- educational implementation only
- not constant-time in Python
- no authentication layer
- no KDF step
- no symmetric encryption step
- no complete secure messaging protocol

### Future work

Possible extensions:

- add HKDF after shared-secret derivation
- derive an AES or ChaCha20 key from the shared secret
- compare results against a production cryptographic library
- add all-zero shared-secret rejection at the protocol layer
- implement a simple authenticated handshake
- add more edge-case tests
