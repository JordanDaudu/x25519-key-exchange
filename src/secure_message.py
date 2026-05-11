"""
Session-key derivation and authenticated encryption for the chat demo.

X25519 itself does not encrypt chat messages. It only produces a shared secret.
For the terminal demo we use:

    X25519 shared secret -> HKDF-SHA256 -> AES-GCM session key

This is allowed in the project because the manually implemented part remains
X25519. HKDF and AES-GCM are supporting primitives outside the focus of the
assignment.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SESSION_KEY_SIZE = 32
AES_GCM_NONCE_SIZE = 12
ASSOCIATED_DATA = b"x25519-terminal-chat-v1"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _build_transcript(
    initiator_name: str,
    responder_name: str,
    initiator_public_key: bytes,
    responder_public_key: bytes,
) -> bytes:
    """
    Build a stable transcript binding for the two-party handshake.

    Both clients must use the same ordering. We therefore use the role names
    from the request flow:
        initiator = the side that typed /connect
        responder = the side that typed /accept
    """
    return b"|".join(
        [
            b"x25519-terminal-chat-v1",
            initiator_name.encode("utf-8"),
            responder_name.encode("utf-8"),
            initiator_public_key,
            responder_public_key,
        ]
    )


def derive_session_key(
    shared_secret: bytes,
    initiator_name: str,
    responder_name: str,
    initiator_public_key: bytes,
    responder_public_key: bytes,
) -> bytes:
    """
    Derive a symmetric AES-GCM session key from an X25519 shared secret.

    The transcript is included so the key is bound to the two participants and
    the two public keys used in this specific handshake.
    """
    transcript = _build_transcript(
        initiator_name,
        responder_name,
        initiator_public_key,
        responder_public_key,
    )

    salt = hashlib.sha256(b"salt|" + transcript).digest()
    info = hashlib.sha256(b"info|" + transcript).digest()

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=salt,
        info=info,
    )

    return hkdf.derive(shared_secret)


def fingerprint_session_key(session_key: bytes, length: int = 16) -> str:
    """
    Return a short readable fingerprint for manual comparison.

    The fingerprint is not a secret. Alice and Bob can compare it verbally or
    visually to notice a possible man-in-the-middle replacement of public keys.
    """
    digest = hashlib.sha256(b"fingerprint|" + session_key).digest()
    selected = digest[:length]
    return ":".join(f"{byte:02X}" for byte in selected)


# ---------------------------------------------------------------------------
# Authenticated encryption
# ---------------------------------------------------------------------------

def encrypt_message(session_key: bytes, plaintext: str) -> tuple[bytes, bytes]:
    """
    Encrypt one text message with AES-GCM.

    Returns:
        (nonce, ciphertext_and_tag)
    """
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(session_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), ASSOCIATED_DATA)
    return nonce, ciphertext


def decrypt_message(session_key: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """
    Decrypt one AES-GCM encrypted text message.

    Raises:
        ValueError: if authentication fails or the message is malformed.
    """
    try:
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, ASSOCIATED_DATA)
    except (InvalidTag, ValueError) as exc:
        raise ValueError("encrypted message authentication failed") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("decrypted message is not valid UTF-8") from exc
