"""Cryptographic helpers for Slice 3: Hybrid / Envelope Encryption.

1. Bulk data encryption: AES-256-GCM.
2. Key wrapping: RSA-OAEP (SHA-256) wrapping the symmetric AES key.
"""

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------- Symmetric Bulk Encryption (AES-256-GCM) ----------------


def generate_file_key() -> bytes:
    """Generate a fresh 256-bit (32-byte) symmetric key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM, returns (ciphertext, 12-byte nonce)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt ciphertext using AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ---------------- Asymmetric Key Pairs & Wrapping (RSA-OAEP) ----------------


def generate_rsa_keypair() -> tuple[str, str]:
    """
    Generate an RSA 2048-bit key pair.
    Returns (private_key_pem, public_key_pem) as UTF-8 strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    return private_pem, public_pem


def wrap_key(file_key: bytes, recipient_public_pem: str) -> bytes:
    """
    Wrap (encrypt) the 32-byte file key using the recipient's RSA public key with OAEP padding.
    """
    public_key = serialization.load_pem_public_key(recipient_public_pem.encode("utf-8"))
    wrapped = public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped


def unwrap_key(wrapped_key: bytes, recipient_private_pem: str) -> bytes:
    """
    Unwrap (decrypt) the file key using the recipient's RSA private key.
    """
    private_key = serialization.load_pem_private_key(
        recipient_private_pem.encode("utf-8"),
        password=None,
    )
    file_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return file_key
