from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

from labkit import title, step, show, ok, warn, fail, note, hexs, short, human


def main():
    title("01", "HASHES (fingerprints) and AES (the padlock)")

    step("1. SHA-256: same input -> same fingerprint, tiny change -> totally new")
    for text in [b"hello", b"hello!", b"Hello"]:
        digest = sha256(text).digest()
        show(f"SHA-256({text.decode()!r})", digest.hex())
    note("Notice: 'hello' vs 'hello!' vs 'Hello' share no visible pattern.")
    note("That avalanche effect is what makes hashes useful for integrity.")

    step("2. Hashing a big thing is cheap and works on any size")
    blob = os.urandom(1_000_000)
    show("1 MB random blob", sha256(blob).hexdigest())
    note("The output is always 32 bytes (256 bits), no matter the input size.")

    step("3. AES-256-GCM: one key locks AND unlocks")
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    message = b"CSE department exam questions - top secret"

    show("AES key (32 bytes)", key.hex())
    show("nonce / IV (12 bytes)", nonce.hex())
    show("plaintext", message.decode())

    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, message, associated_data=None)
    show("ciphertext + GCM tag", short(ciphertext, 20))
    show("stored size", f"{len(ciphertext)} bytes = {len(message)} msg + 16 tag")

    recovered = aes.decrypt(nonce, ciphertext, associated_data=None)
    ok(f"decrypt -> {recovered.decode()!r}")

    step("4. Tamper with one ciphertext byte: GCM detects it")
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    try:
        aes.decrypt(nonce, bytes(tampered), associated_data=None)
        fail("tampering was NOT detected (should never happen)")
    except Exception:
        ok("tampering rejected by the authentication tag")

    step("5. Why you MUST never reuse a nonce (the classic beginner bug)")
    m1 = b"transfer 100 dollars to alice"
    m2 = b"transfer 900 dollars to bob!!"
    c1 = aes.encrypt(nonce, m1, None)[:-16]
    c2 = aes.encrypt(nonce, m2, None)[:-16]
    leaked = bytes(a ^ b for a, b in zip(c1, c2))
    note("With the same key+nonce, XOR of the two ciphertexts equals XOR of")
    note("the two plaintexts. An attacker can recover the message.")
    show("c1 XOR c2", leaked.hex())
    show("m1 XOR m2", bytes(a ^ b for a, b in zip(m1, m2)).hex())
    warn("Same result -> nonce reuse leaks the plaintext.")
    note("Rule: fresh random nonce for every encryption under the same key.")


if __name__ == "__main__":
    main()
