from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from labkit import title, step, show, ok, warn, fail, note, short, outpath


def main():
    title("03", "ECC: same job as RSA, much smaller keys (ECDSA + ECDH)")

    step("1. Generate a P-256 elliptic-curve key pair")
    private_key = ec.generate_private_key(ec.SECP256R1())
    numbers = private_key.private_numbers()
    public_numbers = private_key.public_key().public_numbers()
    show("curve", "SECP256R1 (aka P-256 / prime256v1)")
    show("private key", f"{numbers.private_value.bit_length()} bits")
    show("public point x", f"{public_numbers.x.bit_length()} bits")
    show("public point y", f"{public_numbers.y.bit_length()} bits")
    note("A public key is literally a point (x, y) on the curve.")
    note("The private key is the number of times a start point was added to itself.")

    step("2. Key size comparison vs RSA at the same ~128-bit security level")
    ecc_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    show("ECC P-256 public key (DER)", f"{len(ecc_der)} bytes")
    try:
        with open(outpath("rsa_public.pem"), "rb") as f:
            rsa_pub = serialization.load_pem_public_key(f.read())
        rsa_der = rsa_pub.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        show("RSA-2048 public key (DER)", f"{len(rsa_der)} bytes")
        show("ratio", f"RSA key is {len(rsa_der) / len(ecc_der):.0f}x bigger")
    except FileNotFoundError:
        warn("run 02_rsa_keys.py first to compare RSA size here")

    step("3. ECDSA signature: sign with private, verify with public")
    document = b"Grade sheet - final"
    signature = private_key.sign(document, ec.ECDSA(hashes.SHA256()))
    show("document", document.decode())
    show("signature (DER)", short(signature, 20))
    show("signature size", f"{len(signature)} bytes (RSA was 256)")
    private_key.public_key().verify(signature, document, ec.ECDSA(hashes.SHA256()))
    ok("signature verifies")

    tampered = b"Grade sheet - changed"
    try:
        private_key.public_key().verify(signature, tampered, ec.ECDSA(hashes.SHA256()))
        fail("tampered document accepted")
    except Exception:
        ok("tampered document rejected")

    step("4. ECDH: two people derive the SAME secret without sending it")
    alice = ec.generate_private_key(ec.SECP256R1())
    bob = ec.generate_private_key(ec.SECP256R1())
    alice_sees = alice.exchange(ec.ECDH(), bob.public_key())
    bob_sees = bob.exchange(ec.ECDH(), alice.public_key())
    show("Alice computes", short(alice_sees, 12))
    show("Bob computes", short(bob_sees, 12))
    if alice_sees == bob_sees:
        ok("shared secret is identical on both sides")
    else:
        fail("shared secret mismatch")
    note("An eavesdropper has both public keys but cannot compute this value.")

    shared_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"file-share-v1"
    ).derive(alice_sees)
    show("AES key derived from it", shared_key.hex())
    note("That is how TLS turns a key exchange into a fast AES session key.")


if __name__ == "__main__":
    main()
