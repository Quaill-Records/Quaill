"""Device keys for signing chain links (Ed25519).

A recorder signs each link with a key that does not live next to the log. Anyone can then check
that a chain was produced by that key, and nobody without the key can rebuild it. The key is
authentic only if it is known outside the file: supplied to the checker (--pubkey), registered
with the witness, or listed in the robot's technical file. A key announced inside the bag alone
only proves the chain is self-consistent.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

    CRYPTO = True
except Exception:  # pragma: no cover
    CRYPTO = False
    Ed25519PrivateKey = Ed25519PublicKey = None  # type: ignore


def key_id(pub_raw: bytes) -> str:
    """Short, stable identifier of a public key: first 16 hex chars of sha256(raw 32 bytes)."""
    return hashlib.sha256(pub_raw).hexdigest()[:16]


class Signer:
    def __init__(self, private_key: "Ed25519PrivateKey"):
        self.key = private_key
        self.pub_raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.key_id = key_id(self.pub_raw)

    @classmethod
    def from_seed(cls, seed: bytes) -> "Signer":
        if not CRYPTO:
            raise RuntimeError("the 'cryptography' package is required for signing")
        return cls(Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest()))

    @classmethod
    def generate(cls) -> "Signer":
        if not CRYPTO:
            raise RuntimeError("the 'cryptography' package is required for signing")
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: str) -> "Signer":
        if not CRYPTO:
            raise RuntimeError("the 'cryptography' package is required for signing")
        k = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(k, Ed25519PrivateKey):
            raise ValueError("private key is not Ed25519")
        return cls(k)

    def save(self, path: str) -> None:
        Path(path).write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

    def save_public(self, path: str) -> None:
        Path(path).write_bytes(self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def pub_hex(self) -> str:
        return self.pub_raw.hex()

    def sign_link(self, link_hex: str) -> str:
        return self.key.sign(bytes.fromhex(link_hex)).hex()


class Verifier:
    def __init__(self, pub_raw: bytes):
        if not CRYPTO:
            raise RuntimeError("the 'cryptography' package is required for signature checks")
        self.pub_raw = pub_raw
        self.key_id = key_id(pub_raw)
        self.key = Ed25519PublicKey.from_public_bytes(pub_raw)

    @classmethod
    def from_hex(cls, pub_hex: str) -> "Verifier":
        return cls(bytes.fromhex(pub_hex))

    @classmethod
    def load(cls, path: str) -> "Verifier":
        """PEM public key, or a file holding 64 hex chars."""
        data = Path(path).read_bytes()
        text = data.decode("ascii", errors="ignore").strip()
        if "-----BEGIN" in text:
            if not CRYPTO:
                raise RuntimeError("the 'cryptography' package is required for signature checks")
            k = serialization.load_pem_public_key(data)
            if not isinstance(k, Ed25519PublicKey):
                raise ValueError("public key is not Ed25519")
            return cls(k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        return cls.from_hex(text)

    def verify_link(self, link_hex: str, sig_hex: str) -> bool:
        try:
            self.key.verify(bytes.fromhex(sig_hex), bytes.fromhex(link_hex))
            return True
        except Exception:
            return False
