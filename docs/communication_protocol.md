# Multi-Terminal Communication Protocol

This document describes the terminal chat layer added around the manual X25519 implementation.

The goal is to demonstrate that separate users in separate terminal processes can exchange public keys, derive the same shared secret, and then continue communicating through encrypted messages.

## Architecture

```text
Alice client  ─┐
Bob client    ─┼── Relay server
X client      ─┘
```

The server is only a relay. It tracks online usernames and forwards JSON messages between clients.

The server does not know:

- private keys
- X25519 shared secrets
- derived AES-GCM session keys
- plaintext chat messages

## Handshake Flow

Example: Alice starts a secure chat with Bob.

```text
1. Alice connects to the server.
2. Bob connects to the server.
3. Alice types: /connect Bob
4. Server forwards a chat_request to Bob.
5. Bob types: /accept Alice
6. Bob creates a fresh X25519 key pair for this session.
7. Bob sends his public key to Alice through the server.
8. Alice sends her public key to Bob through the server.
9. Alice computes X25519(Alice private key, Bob public key).
10. Bob computes X25519(Bob private key, Alice public key).
11. Both sides derive the same shared secret.
12. Both sides run HKDF-SHA256 over the shared secret and transcript.
13. Both sides get the same AES-GCM session key.
14. Encrypted chat can continue until one side disconnects.
```

## JSON Messages

### Register

```json
{
  "type": "register",
  "name": "Alice"
}
```

### List Users

```json
{
  "type": "list_users"
}
```

### Chat Request

```json
{
  "type": "chat_request",
  "from": "Alice",
  "to": "Bob"
}
```

### Chat Accept

```json
{
  "type": "chat_accept",
  "from": "Bob",
  "to": "Alice"
}
```

### Public Key

```json
{
  "type": "public_key",
  "from": "Alice",
  "to": "Bob",
  "public_key": "hex-encoded-32-byte-public-key"
}
```

### Encrypted Message

```json
{
  "type": "encrypted_message",
  "from": "Alice",
  "to": "Bob",
  "nonce": "hex-encoded-12-byte-aes-gcm-nonce",
  "ciphertext": "hex-encoded-ciphertext-and-tag"
}
```

### Session Disconnect

```json
{
  "type": "session_disconnect",
  "from": "Alice",
  "to": "Bob"
}
```

## Pairwise Sessions

The system supports multiple users online at once, but it does not implement group chat.

Instead, it creates separate pairwise sessions:

```text
Alice <-> Bob    session key 1
Bob   <-> X      session key 2
Alice <-> X      session key 3
```

Each pair has its own fresh X25519 key pair and derived AES-GCM session key.

## Session Lifetime

A secure session remains active until one of these events happens:

- one user types `/disconnect <name>`
- one user exits with `/quit`
- one user loses connection to the relay server

When a session closes, the client deletes the session state from memory.

## Security Limitation

This terminal chat demonstrates key exchange and encrypted communication, but it does not fully authenticate users.

That means a malicious relay or network attacker could perform a man-in-the-middle attack by replacing public keys. The printed session fingerprint is included as an educational mitigation: both users can manually compare it through another trusted channel.

A production protocol would need a real authentication mechanism such as certificates, digital signatures, a pre-shared key, or an authenticated key exchange protocol.
