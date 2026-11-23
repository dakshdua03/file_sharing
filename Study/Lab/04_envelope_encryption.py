import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from labkit import title, step, show, ok, warn, note, human, short, outpath


def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
    )


def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def wrap_for(public_key, key):
    return public_key.encrypt(key, oaep())


def unwrap(private_key, wrapped):
    return private_key.decrypt(wrapped, oaep())


def main():
    title("04", "Envelope encryption: encrypt file with AES, key with RSA")

    step("1. Create a 'file' to share")
    body = (
        "UNIVERSITY EXAM COMMITTEE - CONFIDENTIAL\n"
        "Question 1 ...\n" * 4000
    ).encode()
    with open(outpath("exam_paper.txt"), "wb") as f:
        f.write(body)
    show("plaintext file", f"output/exam_paper.txt ({human(len(body))})")
    show("first line", body.decode().splitlines()[0])

    step("2. Two recipients each have an RSA key pair")
    alice = make_key()
    bob = make_key()
    for name, key in [("Alice", alice), ("Bob", bob)]:
        der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        show(f"{name} public key", f"{len(der)} bytes")

    step("3. Encrypt the FILE once with a random AES key")
    file_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(file_key).encrypt(nonce, body, None)
    stored = nonce + ciphertext
    with open(outpath("exam_paper.txt.enc"), "wb") as f:
        f.write(stored)
    show("AES file key", file_key.hex())
    show("nonce", nonce.hex())
    show("encrypted file saved", f"output/exam_paper.txt.enc ({human(len(stored))})")
    show("what a server sees", short(stored, 24))

    step("4. Wrap the SAME AES key once per recipient with RSA")
    wrapped = {}
    for name, key in [("Alice", alice), ("Bob", bob)]:
        wrapped[name] = wrap_for(key.public_key(), file_key)
        with open(outpath(f"exam_paper.key.{name.lower()}.enc"), "wb") as f:
            f.write(wrapped[name])
        show(f"wrapped key for {name}", f"{len(wrapped[name])} bytes -> output/exam_paper.key.{name.lower()}.enc")
    note("One encrypted file, N tiny wrapped keys. This is why RSA is only used")
    note("on the key, not on every copy of the file.")

    step("5. Alice downloads the file + her wrapped key and decrypts")
    with open(outpath("exam_paper.txt.enc"), "rb") as f:
        downloaded = f.read()
    with open(outpath("exam_paper.key.alice.enc"), "rb") as f:
        alice_wrapped = f.read()
    recovered_key = unwrap(alice, alice_wrapped)
    ok(f"Alice unwrapped the AES key: {recovered_key.hex()}")
    plaintext = AESGCM(recovered_key).decrypt(downloaded[:12], downloaded[12:], None)
    ok(f"Alice decrypted the file: {len(plaintext)} bytes, matches={plaintext == body}")

    step("6. Bob's wrapped key is useless to Alice")
    with open(outpath("exam_paper.key.bob.enc"), "rb") as f:
        bob_wrapped = f.read()
    try:
        unwrap(alice, bob_wrapped)
        warn("unexpectedly unwrapped Bob's key")
    except ValueError:
        ok("RSA-OAEP rejects it: only Bob's private key can unwrap his copy")

    step("7. The storage server cannot read the file")
    leaked_prefix = downloaded[:40]
    show("server bytes", short(leaked_prefix, 20))
    warn("Without the AES key, these bytes are just noise.")
    note("This is exactly Paper A's idea: AES encrypts the file, key distribution")
    note("is the hard problem (Paper A solves it with an access polynomial).")


if __name__ == "__main__":
    main()
