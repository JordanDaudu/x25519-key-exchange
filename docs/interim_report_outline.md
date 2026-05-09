# Interim Literature Review Plan

## X25519 Key Exchange — Research and Theoretical Analysis

This document is the working plan for the interim literature review. The interim report should focus on why X25519 was chosen, what problem it solves, what literature supports it, and how the research connects to the prototype.

## Quick Links

- [Topic selection](#topic-selection)
- [Literature review](#literature-review)
- [Understanding and analysis](#understanding-and-analysis)
- [From research to prototype](#from-research-to-prototype)
- [Reference set](#reference-set)

## Topic Selection

The selected topic is X25519, a modern elliptic-curve Diffie-Hellman key exchange function based on Curve25519.

The project belongs to the key exchange category because X25519 allows two parties, usually described as Alice and Bob, to derive a shared secret over an insecure communication channel without directly sending the secret.

This makes X25519 a good project topic because it has:

- a clear cryptographic purpose
- a well-defined mathematical foundation
- a compact and practical interface
- official test vectors
- real-world protocol usage
- enough implementation depth for a meaningful prototype

## Literature Review

### Bernstein — Curve25519: New Diffie-Hellman Speed Records

Bernstein's Curve25519 paper introduces Curve25519 as a high-speed elliptic-curve Diffie-Hellman function designed for practical security. The source is important because it explains the motivation behind the curve: compact keys, efficient arithmetic, and implementation-oriented design.

This source supports the project because it shows that X25519 is not just a standard ECDH implementation on any curve. It is based on a curve and interface designed with speed and safer implementation in mind.

### Bernstein and Lange — Montgomery Curves and the Montgomery Ladder

This source explains the Montgomery ladder, which is the main algorithmic structure used in X25519 scalar multiplication.

The Montgomery ladder matters because scalar multiplication depends on private scalar bits. If an implementation branches differently depending on those bits, it may leak information through timing or other side channels. The ladder gives a regular computation pattern that is better suited for secure implementations.

This source is useful for explaining both the correctness and the security-oriented design of the implementation.

### Costello and Smith — Montgomery Curves and Their Arithmetic

Costello and Smith give broader mathematical background on Montgomery curves and x-only arithmetic.

This is relevant because X25519 public keys are not represented as full elliptic-curve points. Instead, they are represented using the Montgomery u-coordinate. This gives X25519 a compact interface: 32-byte public keys and 32-byte shared-secret outputs.

This source helps connect the mathematics of Montgomery curves to the actual code structure.

### Bernstein and Lange — Safe Curves for Elliptic-Curve Cryptography

Safe Curves is useful for the security discussion. It emphasizes that elliptic-curve cryptography depends not only on hard mathematical problems, but also on curve choices and implementation behavior.

This source supports discussion of:

- invalid inputs
- exceptional cases
- side-channel risks
- implementation discipline
- safer curve design

### RFC 7748 — Elliptic Curves for Security

RFC 7748 is the main specification for X25519. It defines the input and output format, scalar clamping, u-coordinate behavior, and official test vectors.

This is the main source for checking whether the implementation is correct.

### RFC 8446 — TLS 1.3

TLS 1.3 shows that X25519 is used in real secure communication systems. It helps connect the project to deployment and shows that the primitive is not only theoretical.

This source is useful for explaining how X25519 fits into larger protocols that also include authentication, key derivation, and symmetric encryption.

## Understanding and Analysis

### Problem solved by X25519

X25519 solves the key agreement problem. Alice and Bob want to agree on a shared secret while communicating over a channel that may be observed by an attacker.

The attacker can see the public keys, but should not be able to derive the shared secret.

### Attack model

The basic attack model is an eavesdropper who can observe public communication. In a full protocol, stronger attackers may also modify messages, which is why real systems combine X25519 with authentication and transcript binding.

The project focuses on the core unauthenticated key exchange primitive, while explaining that a complete secure protocol needs additional layers.

### Hardness assumption

The security of X25519 relies on the hardness of elliptic-curve Diffie-Hellman / discrete-logarithm style problems on Curve25519.

Informally:

```text
Easy:
private scalar + public point -> public key or shared secret

Hard:
public values only -> private scalar or shared secret
```

### Difference from classical Diffie-Hellman

Classical Diffie-Hellman works in a multiplicative group modulo a large prime and uses modular exponentiation.

X25519 uses elliptic-curve scalar multiplication on a Montgomery curve over the finite field:

```text
p = 2^255 - 19
```

The practical result is a smaller and more efficient interface, with 32-byte public keys and 32-byte shared-secret outputs.

### Implementation concerns

The main implementation concerns are:

- scalar clamping
- correct little-endian encoding and decoding
- Montgomery ladder correctness
- avoiding secret-dependent timing behavior
- handling invalid or low-order public inputs
- testing against official vectors

The Python implementation is educational and readable, but it should not be considered production-safe because Python integer operations are not guaranteed to be constant-time.

## From Research to Prototype

The prototype should demonstrate the key exchange flow in a way that matches the theory.

The implementation should show:

- separate Alice and Bob parties
- private scalar generation
- public key derivation
- public key exchange
- shared-secret derivation
- both parties deriving the same shared secret

The tests should show:

- official X25519 vector validation
- successful Alice/Bob round-trip exchange
- wrong public key behavior
- invalid key length handling
- invalid input type handling

The benchmark should report:

- public key generation time
- shared-secret derivation time
- private key size
- public key size
- shared-secret size

## Reference Set

The interim report can use the following main sources:

1. Bernstein, D. J. (2006). *Curve25519: New Diffie-Hellman Speed Records*.
2. Bernstein, D. J., & Lange, T. (2017). *Montgomery Curves and the Montgomery Ladder*.
3. Costello, C., & Smith, B. (2017). *Montgomery Curves and Their Arithmetic*.
4. Bernstein, D. J., & Lange, T. (2024). *Safe Curves for Elliptic-Curve Cryptography*.
5. Langley, A., Hamburg, M., & Turner, S. (2016). *RFC 7748: Elliptic Curves for Security*.
6. Rescorla, E. (2018). *RFC 8446: The Transport Layer Security Protocol Version 1.3*.
