"""
Secure session state for one pair of chat clients.

Each pair of users gets its own independent X25519 key pair, shared secret,
HKDF-derived AES-GCM key, and fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.key_exchange import X25519Party
from src.secure_message import derive_session_key, fingerprint_session_key
from src.x25519 import KEY_SIZE


@dataclass
class SecureSession:
    """
    Represents one pairwise secure session.

    Example:
        Alice has a session object for Bob.
        Bob has a separate session object for Alice.

    Both objects hold different local private keys, but after the public-key
    exchange both derive the same shared secret and the same session key.
    """

    local_name: str
    peer_name: str
    initiator_name: str
    responder_name: str
    party: X25519Party = field(init=False)
    peer_public_key: bytes | None = None
    shared_secret: bytes | None = None
    session_key: bytes | None = None
    fingerprint: str | None = None

    def __post_init__(self) -> None:
        self.party = X25519Party(self.local_name)

    @property
    def local_public_key(self) -> bytes:
        """Return this session's fresh local public key."""
        return self.party.public_key

    @property
    def established(self) -> bool:
        """Return True after the peer public key has been received and processed."""
        return self.session_key is not None

    def set_peer_public_key(self, peer_public_key: bytes) -> None:
        """
        Complete the X25519 handshake using the peer's public key.
        """
        if not isinstance(peer_public_key, bytes):
            raise TypeError("peer_public_key must be bytes")

        if len(peer_public_key) != KEY_SIZE:
            raise ValueError(f"peer_public_key must be exactly {KEY_SIZE} bytes")

        self.peer_public_key = peer_public_key
        self.shared_secret = self.party.derive_shared_secret(peer_public_key)

        if self.local_name == self.initiator_name:
            initiator_public_key = self.local_public_key
            responder_public_key = peer_public_key
        else:
            initiator_public_key = peer_public_key
            responder_public_key = self.local_public_key

        self.session_key = derive_session_key(
            self.shared_secret,
            self.initiator_name,
            self.responder_name,
            initiator_public_key,
            responder_public_key,
        )
        self.fingerprint = fingerprint_session_key(self.session_key)

    def require_session_key(self) -> bytes:
        """
        Return the derived session key or raise if the handshake is incomplete.
        """
        if self.session_key is None:
            raise ValueError("secure session has not been established yet")
        return self.session_key
