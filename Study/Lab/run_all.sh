#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

for script in 01_symmetric_and_hash.py \
              02_rsa_keys.py \
              03_ecdsa_and_ecdh.py \
              04_envelope_encryption.py \
              05_secret_sharing_and_access_polynomial.py \
              06_blockchain_and_cid.py; do
  python3 "$script"
done | tee output/transcript.txt

echo
echo "Full transcript saved to output/transcript.txt"
