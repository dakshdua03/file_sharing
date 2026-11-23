# Lab — run the crypto from `01-Crypto-Basics-Primer.md` locally

This folder turns the primer's ideas into small, runnable Python programs. Each script
prints what it is doing and the real bytes/keys it produces, so you can watch the
concepts work instead of only reading about them.

## Run everything

```bash
cd Study/Lab
./run_all.sh
```

The full output is also saved to `output/transcript.txt`.

Requires Python 3 and the `cryptography` package (already installed here).

## Run one topic at a time

| Script | Primer section | What you will see |
| --- | --- | --- |
| `01_symmetric_and_hash.py` | A1 + A2 | SHA-256 fingerprints, avalanche effect, AES-256-GCM lock/unlock, tamper detection, **nonce reuse leaking plaintext** |
| `02_rsa_keys.py` | A3 + A4 | RSA worked from scratch with p=61, q=53; then a real 2048-bit key pair, PEM files, encrypt/decrypt, why RSA cannot encrypt a 500-byte file, sign/verify + tampering |
| `03_ecdsa_and_ecdh.py` | A3 + A4 | P-256 key pair, RSA-vs-ECC key sizes, ECDSA signatures, ECDH shared-secret agreement |
| `04_envelope_encryption.py` | A5 | AES encrypts one big file, RSA wraps the AES key separately for Alice and Bob, storage server sees only noise |
| `05_secret_sharing_and_access_polynomial.py` | C4 | Shamir 3-of-5 secret sharing, then Paper A's `f(x,r) = Kc + Π(x − h(Ki,r))`, recovery, outsider failure, and revocation without re-keying everyone |
| `06_blockchain_and_cid.py` | B1 + B2 | Hash-linked blocks, tampering breaking the chain, real CIDv1 content addresses, same content = same CID |

`labkit.py` is only formatting/output helpers; it has no crypto in it.

## Generated files (`output/`)

| File | Meaning |
| --- | --- |
| `rsa_private.pem`, `rsa_public.pem` | A real RSA key pair. Private = never share. |
| `exam_paper.txt` | Fake plaintext file |
| `exam_paper.txt.enc` | AES-256-GCM ciphertext (nonce prepended) |
| `exam_paper.key.alice.enc`, `exam_paper.key.bob.enc` | The same AES key wrapped with each recipient's RSA public key |
| `transcript.txt` | Full output of `run_all.sh` |

## Things to try yourself

1. Run a script twice. Notice hashes of fixed inputs stay the same, but keys, nonces,
   and ciphertexts change every time. That randomness is essential.
2. Open `output/rsa_private.pem` and `output/rsa_public.pem` and compare the headers and
   size. The public file is safe to hand out.
3. Inspect the real RSA key with OpenSSL:
   ```bash
   openssl rsa -in output/rsa_private.pem -text -noout
   openssl pkey -in output/rsa_public.pem -text -noout
   ```
   Look for `modulus`, `publicExponent`, `prime1`, `prime2`, `exponent1`.
4. In `06_blockchain_and_cid.py`, change an old block's data and re-run to watch the
   chain fail verification.
5. In `05_...py`, change `threshold=3` to `2` and see that two shares now reconstruct
   the secret (and understand why threshold choice matters).

## Important honesty note about the access polynomial

The access-polynomial demo shows the **algebra** used in Paper A: valid users evaluate
the public polynomial at their secret point and recover `Kc`; revoked users do not.
In the real paper the polynomial metadata ("KeyInfo") is itself protected (via ABE),
not simply published to the whole world. The demo is for understanding the mechanism,
not a production-secure construction.
 