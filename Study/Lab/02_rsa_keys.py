import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from labkit import title, step, show, ok, warn, fail, note, short, outpath


def tiny_rsa():
    step("1. RSA from scratch with tiny numbers (the real maths, no library)")
    p, q = 61, 53
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 17
    d = pow(e, -1, phi)
    note("Choose two primes p and q.")
    show("p", p)
    show("q", q)
    show("n = p * q (modulus)", n)
    show("phi = (p-1)(q-1)", phi)
    show("e (public exponent)", e)
    show("d = e^-1 mod phi (private)", d)
    print()
    note("Public key  = (n, e)  -> can be given to anyone")
    note("Private key = (n, d)  -> only you")
    print()
    message = 65
    cipher = pow(message, e, n)
    decrypted = pow(cipher, d, n)
    show("message (as a number)", message)
    show("encrypt: c = m^e mod n", cipher)
    show("decrypt: m = c^d mod n", decrypted)
    ok("The same number came back. That is all RSA encryption is.")
    note("Real RSA uses n with ~2048 bits, so factoring n is infeasible.")


def main():
    title("02", "RSA: a public key everyone can use, a private key only you have")

    tiny_rsa()

    step("2. Generate a real 2048-bit RSA key pair")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.private_numbers()
    pub = numbers.public_numbers
    show("modulus n", f"{pub.n.bit_length()} bits")
    show("public exponent e", pub.e)
    show("private exponent d", f"{numbers.d.bit_length()} bits")
    show("prime p", f"{numbers.p.bit_length()} bits")
    show("prime q", f"{numbers.q.bit_length()} bits")
    note("Security rests on: given n, nobody can factor it back into p and q.")

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(outpath("rsa_private.pem"), "wb") as f:
        f.write(private_pem)
    with open(outpath("rsa_public.pem"), "wb") as f:
        f.write(public_pem)
    print()
    show("private file", "output/rsa_private.pem")
    show("public file", "output/rsa_public.pem")
    show("private PEM line 1", private_pem.decode().splitlines()[0])
    show("public PEM line 1", public_pem.decode().splitlines()[0])
    warn("Never share the private PEM. The public PEM is safe to publish.")

    step("3. Encrypt a small secret (here: an AES key) with the PUBLIC key")
    aes_key = os.urandom(32)
    show("AES key to protect", aes_key.hex())
    ciphertext = private_key.public_key().encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    show("RSA-OAEP ciphertext", short(ciphertext, 16))
    show("ciphertext size", f"{len(ciphertext)} bytes (one 2048-bit block)")
    recovered = private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    ok(f"decrypted with private key -> {recovered.hex()}")
    note("That is why RSA is used to protect KEYS, not files:")

    step("4. Try to encrypt a 500-byte file directly with RSA -> impossible")
    max_size = 2048 // 8 - 2 * 32 - 2
    show("max bytes per 2048-bit RSA block", max_size)
    try:
        private_key.public_key().encrypt(b"x" * 500, padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        fail("unexpectedly succeeded")
    except ValueError as exc:
        ok(f"library refused: {str(exc).splitlines()[0]}")
    warn("Big files need AES. RSA only wraps the small AES key (envelope encryption).")

    step("5. Digital signature: sign with PRIVATE key, verify with PUBLIC key")
    document = b"Exam paper v1 - approved"
    signature = private_key.sign(
        document,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    show("document", document.decode())
    show("signature size", f"{len(signature)} bytes")
    private_key.public_key().verify(
        signature,
        document,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    ok("signature verifies: document is authentic and unchanged")

    tampered_doc = b"Exam paper v2 - tampered!!"
    try:
        private_key.public_key().verify(
            signature,
            tampered_doc,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        fail("tampered document accepted")
    except Exception:
        ok("tampered document rejected: verification failed")


if __name__ == "__main__":
    main()
