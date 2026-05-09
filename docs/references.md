# References

This file collects the main sources used for the X25519 key exchange project. The focus is on sources that explain the design of Curve25519/X25519, the Montgomery ladder, implementation safety, and real-world deployment.

## Quick Links

- [Primary sources](#primary-sources)
- [Deployment references](#deployment-references)
- [Course connections](#course-connections)
- [How these sources support the project](#how-these-sources-support-the-project)

## Primary Sources

### [1] Bernstein — Curve25519: New Diffie-Hellman Speed Records

Daniel J. Bernstein. *Curve25519: New Diffie-Hellman Speed Records*. Public Key Cryptography — PKC 2006.

Link: https://cr.yp.to/ecdh/curve25519-20051115.pdf

This is the original Curve25519 paper and the main source for understanding why Curve25519 was designed. It explains the motivation behind a fast elliptic-curve Diffie-Hellman function with compact public keys and implementation-oriented security properties.

We used this source for:

- the motivation behind Curve25519
- performance and key-size advantages
- the design goal of making elliptic-curve Diffie-Hellman easier to implement safely
- explaining why X25519 is more than a generic ECDH construction on a random curve

### [2] Bernstein and Lange — Montgomery Curves and the Montgomery Ladder

Daniel J. Bernstein and Tanja Lange. *Montgomery Curves and the Montgomery Ladder*. Cryptology ePrint Archive, Paper 2017/293.

Link: https://eprint.iacr.org/2017/293

This source explains the Montgomery ladder, which is the core scalar multiplication method used in X25519. It is especially useful for understanding why the ladder has a regular structure and how that relates to side-channel-resistant implementations.

We used this source for:

- the Montgomery ladder
- scalar multiplication structure
- constant-time implementation ideas
- explaining why secret-dependent branches are dangerous

### [3] Costello and Smith — Montgomery Curves and Their Arithmetic

Craig Costello and Benjamin Smith. *Montgomery Curves and Their Arithmetic*. Cryptology ePrint Archive, Paper 2017/212; arXiv:1703.01863.

Link: https://arxiv.org/abs/1703.01863

This source gives broader mathematical background on Montgomery curves and their arithmetic. It helps explain the x-only style of computation used by X25519, where public keys are represented as Montgomery u-coordinates rather than full elliptic-curve points.

We used this source for:

- Montgomery curve arithmetic
- x-only Diffie-Hellman
- why X25519 public keys are compact 32-byte values
- connecting the mathematical curve representation to the implementation

### [4] Bernstein and Lange — Safe Curves for Elliptic-Curve Cryptography

Daniel J. Bernstein and Tanja Lange. *Safe Curves for Elliptic-Curve Cryptography*. Cryptology ePrint Archive, Paper 2024/1265.

Link: https://eprint.iacr.org/2024/1265

This source is useful for the security discussion. It shows that elliptic-curve security is not only about the hardness of the discrete logarithm problem, but also about the curve choices and implementation behavior that can create or avoid practical vulnerabilities.

We used this source for:

- curve-safety discussion
- implementation pitfalls
- invalid-curve and exceptional-case concerns
- explaining why careful engineering matters in elliptic-curve cryptography

### [5] RFC 7748 — Elliptic Curves for Security

Adam Langley, Mike Hamburg, and Sean Turner. *RFC 7748: Elliptic Curves for Security*. 2016.

Link: https://datatracker.ietf.org/doc/html/rfc7748

RFC 7748 is the main specification used for the implementation. It defines X25519 and X448, including scalar clamping, u-coordinate decoding, scalar multiplication behavior, and official test vectors.

We used this source for:

- the exact X25519 behavior
- scalar clamping rules
- input and output format
- official test vectors
- implementation correctness

## Deployment References

### [6] RFC 8446 — TLS 1.3

Eric Rescorla. *RFC 8446: The Transport Layer Security Protocol Version 1.3*. 2018.

Link: https://datatracker.ietf.org/doc/html/rfc8446

TLS 1.3 is useful for showing that X25519 is not only academic. It appears in modern secure communication protocols and helps explain the role of ephemeral Diffie-Hellman key exchange in real systems.

We used this source for:

- real-world deployment context
- modern protocol usage
- forward secrecy discussion
- explaining how key exchange fits into a full protocol

### Optional deployment examples

These are useful if more real-world context is needed later, but they are secondary compared to the academic and specification sources above.

- WireGuard whitepaper: https://www.wireguard.com/papers/wireguard.pdf
- Signal X3DH specification: https://signal.org/docs/specifications/x3dh/

## Course Connections

### Modular arithmetic

X25519 performs arithmetic modulo:

```text
p = 2^255 - 19
```

This connects directly to the modular arithmetic learned in class. The implementation repeatedly uses addition, subtraction, multiplication, squaring, and inversion modulo this prime.

### Euclidean algorithm and modular inverse

The implementation converts from projective coordinates back to a normal coordinate using a modular inverse. In the code this is computed with Fermat's little theorem:

```python
pow(z, p - 2, p)
```

Conceptually, this connects to the idea of modular inverses and number theory from the course.

### RSA comparison

RSA and X25519 are both public-key cryptographic mechanisms, but they rely on different hard problems:

- RSA relies on the difficulty of factoring large integers.
- X25519 relies on the hardness of elliptic-curve Diffie-Hellman / discrete logarithm style problems on Curve25519.

This comparison is useful for the analysis section of the final report.

### Hashing and symmetric encryption

X25519 does not encrypt messages by itself. In real protocols, the shared secret is usually passed into a key derivation function, and the result is used with a symmetric cipher such as AES or ChaCha20.

## How These Sources Support the Project

Together, these sources define the research direction and the implementation requirements:

- Bernstein explains why Curve25519 was designed.
- Bernstein and Lange explain the Montgomery ladder.
- Costello and Smith explain Montgomery arithmetic and x-only Diffie-Hellman.
- Safe Curves supports the security and implementation-safety discussion.
- RFC 7748 defines exactly what the implementation must compute.
- RFC 8446 shows how this kind of key exchange appears in real protocols.

The code should therefore demonstrate key generation, public-key exchange, shared-secret derivation, validation with official test vectors, negative tests, and performance measurements.
