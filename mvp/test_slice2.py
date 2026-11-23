"""Unit tests for Slice 2: AES-256-GCM file encryption and tamper detection (no external runner needed)."""

from cryptography.exceptions import InvalidTag
from crypto import decrypt_file, encrypt_file, generate_file_key


def test_encryption_roundtrip():
    plaintext = b"Confidential university exam paper content: Question 1..."
    key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, key)

    assert ciphertext != plaintext
    assert len(nonce) == 12

    decrypted = decrypt_file(ciphertext, key, nonce)
    assert decrypted == plaintext


def test_tamper_detection():
    plaintext = b"Grades: Alice=A, Bob=B"
    key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, key)

    # Flip one byte in ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF

    try:
        decrypt_file(bytes(tampered), key, nonce)
        assert False, "Expected InvalidTag on tampered ciphertext"
    except InvalidTag:
        pass


def test_wrong_key_fails():
    plaintext = b"Meeting minutes"
    key1 = generate_file_key()
    key2 = generate_file_key()

    ciphertext, nonce = encrypt_file(plaintext, key1)
    try:
        decrypt_file(ciphertext, key2, nonce)
        assert False, "Expected InvalidTag with wrong key"
    except InvalidTag:
        pass


if __name__ == "__main__":
    test_encryption_roundtrip()
    test_tamper_detection()
    test_wrong_key_fails()
    print("All Slice 2 cryptographic tests passed successfully.")

