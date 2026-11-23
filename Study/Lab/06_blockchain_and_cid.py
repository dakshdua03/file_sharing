import base64
from hashlib import sha256

from labkit import title, step, show, ok, warn, fail, note, short


def block_hash(block):
    payload = f"{block['index']}|{block['data']}|{block['prev']}".encode()
    return sha256(payload).hexdigest()


def make_block(index, data, prev):
    block = {"index": index, "data": data, "prev": prev}
    block["hash"] = block_hash(block)
    return block


def chain_is_valid(chain):
    for i, block in enumerate(chain):
        if block["hash"] != block_hash(block):
            return False, f"block {i} hash does not match its contents"
        if i > 0 and block["prev"] != chain[i - 1]["hash"]:
            return False, f"block {i} does not point at block {i - 1}"
    return True, "all links and hashes are consistent"


def cid_v1_raw(data):
    digest = sha256(data).digest()
    multihash = bytes([0x12, 0x20]) + digest
    raw = bytes([0x01, 0x55]) + multihash
    encoded = base64.b32encode(raw).decode().lower().rstrip("=")
    return "b" + encoded


def main():
    title("06", "Blockchain (unerasable log) and IPFS CIDs (content addresses)")

    step("1. Build a tiny chain: each block stores the previous block's hash")
    genesis = make_block(0, "genesis: university file-sharing system", "0" * 64)
    chain = [genesis]
    events = [
        "alice uploaded exam.pdf CID=bafy...aaa",
        "alice granted bob access until 2026-11-01",
        "bob downloaded exam.pdf at 2026-10-19T10:00Z",
    ]
    for event in events:
        chain.append(make_block(len(chain), event, chain[-1]["hash"]))

    for block in chain:
        show(f"block {block['index']}", f"prev={short(block['prev'], 8)}  hash={short(block['hash'], 8)}")
        note(f"  data: {block['data']}")

    valid, reason = chain_is_valid(chain)
    if valid:
        ok(reason)

    step("2. Try to secretly edit block 1 (change bob's access time)")
    original = chain[1]["data"]
    chain[1]["data"] = "alice granted bob access until 2030-01-01"
    show("block 1 now says", chain[1]["data"])
    valid, reason = chain_is_valid(chain)
    if not valid:
        fail(reason)
    note("Block 1's stored hash no longer matches its contents.")
    note("Even if the attacker recomputed block 1's hash, block 2 still")
    note("contains the OLD hash, so the break would move one block forward.")
    chain[1]["data"] = original
    valid, _ = chain_is_valid(chain)
    if valid:
        ok("restored: chain valid again")

    step("3. IPFS-style CID: the address IS the fingerprint")
    file_a = b"lecture notes week 1: RSA and ECC"
    file_b = b"lecture notes week 1: RSA and ECC."
    cid_a = cid_v1_raw(file_a)
    cid_a2 = cid_v1_raw(file_a)
    cid_b = cid_v1_raw(file_b)
    show("content A", file_a.decode())
    show("CID(A)", cid_a)
    show("CID(A) again", cid_a2)
    if cid_a == cid_a2:
        ok("same content always gives the same CID (deduplication)")
    show("content B (one extra dot)", file_b.decode())
    show("CID(B)", cid_b)
    if cid_a != cid_b:
        ok("one changed character gives a completely different CID")
    note("This is a real CIDv1(raw, sha2-256), same format IPFS uses.")
    note("A blockchain can store this tiny CID; IPFS stores the big file.")

    step("4. Files on chain vs hashes on chain")
    show("file size", f"{len(file_a)} bytes")
    show("CID length", f"{len(cid_a)} characters")
    warn("Put the CID on-chain, keep the file off-chain. Storage is expensive.")


if __name__ == "__main__":
    main()
