"""Unit tests for Slice 3: Hybrid / Envelope Encryption with Multi-User Key Wrapping."""

from cryptography.exceptions import InvalidTag
from crypto import (
    decrypt_file,
    encrypt_file,
    generate_file_key,
    generate_rsa_keypair,
    unwrap_key,
    wrap_key,
)


def test_hybrid_envelope_flow():
    # 1. Setup Alice (Owner) and Bob (Recipient)
    alice_priv, alice_pub = generate_rsa_keypair()
    bob_priv, bob_pub = generate_rsa_keypair()
    eve_priv, eve_pub = generate_rsa_keypair()

    # 2. Bulk file encryption (AES-256-GCM)
    plaintext = b"Semester 1 Final Exam Questions - Highly Confidential"
    file_key = generate_file_key()
    ciphertext, nonce = encrypt_file(plaintext, file_key)

    # 3. Key Wrapping for Alice
    wrapped_for_alice = wrap_key(file_key, alice_pub)

    # 4. Sharing: Alice unwraps key and re-wraps for Bob
    unwrapped_by_alice = unwrap_key(wrapped_for_alice, alice_priv)
    assert unwrapped_by_alice == file_key
    wrapped_for_bob = wrap_key(unwrapped_by_alice, bob_pub)

    # 5. Bob unwraps and decrypts
    bob_recovered_key = unwrap_key(wrapped_for_bob, bob_priv)
    assert bob_recovered_key == file_key
    bob_plaintext = decrypt_file(ciphertext, bob_recovered_key, nonce)
    assert bob_plaintext == plaintext

    # 6. Eve (unauthorized) tries to unwrap Bob's key share -> fails
    try:
        unwrap_key(wrapped_for_bob, eve_priv)
        assert False, "Eve should not be able to unwrap Bob's key"
    except Exception:
        pass


if __name__ == "__main__":
    test_hybrid_envelope_flow()
    print("All Slice 3 envelope encryption tests passed successfully.")
