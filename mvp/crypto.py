"""Cryptographic helpers for Slice 2: AES-256-GCM authenticated encryption."""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_file_key() -> bytes:
    """Generate a fresh 256-bit (32-byte) symmetric key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-GCM.
    
    Returns:
        (ciphertext_with_tag, nonce)
        where ciphertext_with_tag is encrypted data + 16-byte authentication tag,
        and nonce is 12 bytes (96 bits).
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_file(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypt ciphertext bytes using AES-256-GCM.
    
    Raises InvalidTag if ciphertext, key, or nonce is tampered with.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
