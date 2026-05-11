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

The project also includes a multi-terminal secure chat demo. In this demo, different users can run in separate terminal processes, connect to a relay server, choose who they want to communicate with, exchange X25519 public keys, derive a shared session key, and continue sending encrypted messages until one side disconnects.

X25519 is not an encryption algorithm by itself. It is a key exchange primitive. In the chat demo, the X25519 shared secret is passed through HKDF-SHA256, and the derived session key is then used with AES-GCM to encrypt and authenticate messages.

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
src/protocol.py
src/secure_message.py
src/session.py
src/network.py
server.py
client.py
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
- all-zero shared-secret rejection at the high-level protocol layer

### Multi-terminal secure chat

The networked demo adds a practical protocol layer around the X25519 primitive:

- `server.py` runs a relay server.
- `client.py` runs an interactive terminal client.
- `src/network.py` sends JSON messages over TCP.
- `src/protocol.py` defines message formats and validation.
- `src/session.py` stores one pairwise secure session.
- `src/secure_message.py` derives the AES-GCM session key and encrypts/decrypts messages.

The server only forwards messages. It never receives private keys, shared secrets, session keys, or plaintext chat messages.

### Multi-user flow

```text
1. Alice, Bob, and X each open separate terminals.
2. All clients connect to the relay server.
3. Alice can type /connect Bob.
4. Bob can type /accept Alice.
5. Both sides exchange X25519 public keys through the server.
6. Both sides derive the same shared secret.
7. Both sides derive the same AES-GCM session key.
8. Alice and Bob can continue sending encrypted messages.
9. The session remains active until one side disconnects.
```

The system supports multiple pairwise sessions, for example:

```text
Alice <-> Bob
Bob   <-> X
Alice <-> X
```

Each pair receives a separate X25519 shared secret and a separate symmetric session key.

### Demo: `demo.py`

The simple demo shows a complete Alice/Bob key exchange in a single process.

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
- `socket` and `socketserver` for the terminal communication demo
- `cryptography` for HKDF-SHA256 and AES-GCM after the X25519 shared secret is derived

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
- all-zero shared-secret rejection

### Protocol and secure-message tests

Additional tests check the new terminal-chat layer:

- username validation
- public-key hex validation
- HKDF session-key derivation
- session fingerprint agreement
- AES-GCM encryption/decryption
- tampered ciphertext rejection
- wrong-key rejection
- empty and Unicode messages
- pairwise `SecureSession` establishment

### Current test status

The current test suite contains 26 tests and passes successfully.

```text
26 passed
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

The updated demo now includes transcript-bound session-key derivation and AES-GCM message encryption. It still does not include full peer authentication.

### Man-in-the-middle concern

Because the demo does not authenticate identities, a malicious relay could replace public keys and create separate shared secrets with each side.

The client prints a session fingerprint so Alice and Bob can manually compare it through a trusted channel. This is useful for demonstration, but a production system would need real authentication such as certificates, digital signatures, a pre-shared key, or a PAKE.

## Limitations and Future Work

### Limitations

- educational implementation only
- not constant-time in Python
- no full identity authentication layer
- no persistent accounts
- no replay window or message numbering
- no group chat; only pairwise secure sessions

### Future work

- add digital signatures to authenticate public keys
- add message sequence numbers for replay protection
- add persistent contacts / trusted fingerprints
- add a simple GUI
- add group-key agreement as a separate advanced extension
