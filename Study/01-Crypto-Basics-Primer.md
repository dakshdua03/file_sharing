 # 01 — Cryptography & Systems Basics (Zero-Knowledge Primer)

> **Who this is for:** someone with **no cryptography background** who needs to read
> Paper A (blockchain + Attribute-Based Encryption) and Paper B (IPFS + time-restricted
> access) and then build a secure file-sharing system.
>
> **How to read it:** every topic has a **plain-English analogy** first, then a slightly
> more technical explanation, then **"Why it matters for your papers."** Skip the maths
> boxes on a first pass.

---

## Table of Contents

1. [The problem we are solving](#1-the-problem-we-are-solving)
2. [Part A — Core cryptographic building blocks](#part-a--core-cryptographic-building-blocks)
   - A1. Symmetric encryption (AES) — the lock on the box
   - A2. Hash functions (SHA-256) — the fingerprint
   - A3. Asymmetric crypto / PKI (RSA, ECC) — a mailbox anyone can drop into
   - A4. Digital signatures (ECDSA) — a wax seal on a document
   - A5. Hybrid / envelope encryption — how real systems combine all of the above
3. [Part B — Decentralized systems building blocks](#part-b--decentralized-systems-building-blocks)
   - B1. IPFS — the library that finds books by their content
   - B2. Blockchain — the notebook nobody can erase
   - B3. Smart contracts, Ethereum, gas, MetaMask
4. [Part C — Access-control cryptography (the heart of Paper A)](#part-c--access-control-cryptography-the-heart-of-paper-a)
   - C1. Why we need more than one key
   - C2. Attribute-Based Encryption (ABE), CP-ABE vs KP-ABE
   - C3. Finite fields GF(p) and polynomials — 3 minutes of very gentle maths
   - C4. Access polynomial & Shamir's Secret Sharing
5. [Part D — Security vocabulary used in both papers](#part-d--security-vocabulary-used-in-both-papers)
6. [Part E — Cheat sheet (symbol → meaning)](#part-e--cheat-sheet-symbol--meaning)
7. [Self-test: 12 questions](#self-test-12-questions)

---

## 1. The problem we are solving

Imagine you are a professor. You want to share an exam paper with the exam committee, but:

- You don't want the cloud provider (Google Drive, etc.) to read it.
- You don't want a leaked link to work forever.
- You want to decide *"only 'CSE' department AND 'Faculty' role"* can open it.
- You want proof of *who downloaded it and when*.
- When someone leaves the committee, you want to cancel their access **without** having to
  re-send a new password to everyone else.

Every cryptographic tool below exists to answer one of those lines. That's it. Cryptography
is not one thing — it is a **toolbox**, and these papers pick tools from it.

---

## Part A — Core cryptographic building blocks

### A1. Symmetric encryption (AES) — "the lock on the box"

**Analogy.** You put a document in a box, snap the padlock, and keep the **one key**.
To open it, you use the **same key**. One key locks, one key unlocks.

**Technical.** *Symmetric* means **the same key encrypts and decrypts**.
The standard algorithm is **AES** (Advanced Encryption Standard).

```
plaintext  +  key  ---[ AES encrypt ]--->  ciphertext   (unreadable)
ciphertext +  key  ---[ AES decrypt ]--->  plaintext    (original)
```

- **AES-256** means the key is 256 bits long (about a 78-digit number). Brute-forcing it is
  physically impossible with today's computers.
- AES works on **blocks** (16 bytes at a time). A **mode of operation** decides *how* to
  chain blocks together. Two names you will see:
  - **CTR mode** — turns AES into a stream cipher; fast, but you must never reuse the
    starting counter value.
  - **GCM mode** — CTR **plus** a built-in tamper check (it *authenticates* the data).
    `AES-256-GCM` is the modern default and is used in Paper A ("AES in GCM or CTR mode")
    and heavily in the wider literature (e.g., QSS4, the AES-GCM paper).
- **IV / nonce.** A random starting number given to the mode so the *same* file encrypted
  twice does not produce the *same* ciphertext. **Rule that bites beginners:** *never reuse
  an IV with the same key.* Reusing it in CTR/GCM is catastrophic (it can leak the
  plaintext). This is the entire point of the paper *"Beyond Nonce Uniqueness."*

**Why it matters for your papers.**
- Paper A encrypts the **actual file** with AES using a random key it calls the
  **cipher-key Kc**.
- The whole file is *not* encrypted with a password — it's encrypted with a random key, and
  the hard problem becomes **"how do I safely give that key to the right person?"**
  That question drives the rest of Paper A.

> **One-liner to remember:** *AES is fast and strong — use it for the file itself.*

---

### A2. Hash functions (SHA-256) — "the fingerprint"

**Analogy.** A fingerprint identifies a person without revealing everything about them.
Change one hair and the fingerprint changes completely — but you cannot reconstruct the
person from the fingerprint.

**Technical.** A **hash function** takes *any* input and produces a **fixed-size**
output (the "digest" or "hash").

```
SHA-256("hello")   = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
SHA-256("hello!")  = ce06092fb948d9ffac7d1a376e404b26b7575bcc11ee05a4615fef4fec3a308b
                       ^ completely different, even though input changed by 1 character
```

Two properties you must internalise:

1. **One-way (preimage resistance):** given the hash, you cannot get the input back.
   So a *hash* is safe to publish; the *file* is not.
2. **Collision resistance:** it is practically impossible to find two different files with
   the same hash. This is what makes a hash a trustworthy **fingerprint / integrity check**.

**Where hashes appear in the papers:** 
- **IPFS (Paper B)** names every file by its hash, called a **CID** (Content Identifier).
  The "address" of the file *is* its fingerprint.
- **Blockchain** chains blocks by including the previous block's hash.
- Paper A computes `req_id = hash(Uid | Fid | Texpiry | Ktemp)` — a unique ticket number for
  each access request.
- Paper A also uses `h(Ki, r)` — a hash of a user's key with a random value — inside its
  polynomial (explained in Part C).

> **One-liner:** *A hash proves "this is exactly that file" without revealing the file.*

---

### A3. Asymmetric crypto / PKI (RSA, ECC) — "a mailbox anyone can drop into"

**Analogy.** A public mailbox: **anyone** can drop a letter in through the slot (public
key), but only the owner has the key to open it (private key). You can hand out copies of
the mailbox address to the whole world.

**Technical.** Asymmetric (public-key) cryptography gives each person a **key pair**:

- **Public key** — share with everyone. Used to *encrypt to you* or *verify your signature*.
- **Private key** — keep secret. Used to *decrypt* or *sign*.

```
Encrypt with someone's PUBLIC key  --> only their PRIVATE key can decrypt
Sign with your PRIVATE key         --> anyone verifies with your PUBLIC key
```

Two families you will see:

| Family | Maths | Typical use | Note |
| --- | --- | --- | --- |
| **RSA** | factoring huge numbers | encryption + signatures | Older; big keys; **broken by future quantum computers** |
| **ECC** (Elliptic Curve) | points on a curve | signatures (ECDSA), key exchange | Same security with **much smaller keys** — good for phones |

Public keys need to be trusted to be genuine, which is the job of **PKI** (Public Key
Infrastructure) and **certificates** (signed statements saying *"this public key belongs to
this person"*).

**Why it matters:**
- Paper A uses **ECDSA** to sign the encrypted file so downloaders can prove it came from
  the data owner, and uses the data owner's **public key** to encrypt each access request
  (so only the owner can read requests).
- The bigger literature warns that **RSA will be broken by quantum computers**, which is why
  newer papers use **post-quantum** algorithms (Kyber/ML-KEM, Dilithium/ML-DSA). These are
  *asymmetric* too — you don't strictly need them now, but know the term.

> **One-liner:** *Symmetric = one shared key (fast). Asymmetric = key pair (solves the "how
> do we share the key?" problem).*

---

### A4. Digital signatures (ECDSA) — "a wax seal on a document"

**Analogy.** A king's wax seal on a letter proves the letter is genuinely from the king and
has not been altered. Anyone can recognise the seal, nobody can forge it.

**Technical.** A signature is created with your **private key** over a hash of the message:

```
signature = Sign(private_key, hash(document))

verification succeeds only if:
  hash(document) matches AND signature was made by the matching private key
```

If **one byte** of the document changes, the hash changes and verification fails. So a
signature gives you:

- **Authenticity** — who sent it.
- **Integrity** — it wasn't changed.
- **Non-repudiation** — the sender cannot deny it later.

**Why it matters:** Paper A signs the ciphertext with **ECDSA** so a user can detect a
tampered/malicious file. Papers on *audit trails* sign every logged event.

> **One-liner:** *A signature = "I made this, and it's unchanged" — provable by anyone.*

---

### A5. Hybrid / envelope encryption — how real systems combine all of the above

**Analogy.** You lock a huge document in a heavy box with a cheap padlock (AES). The padlock
key is tiny, so you put **that key** inside a small strongbox that only the recipient can
open (asymmetric). You ship the heavy box + the small strongbox.

**Technical.** This is how essentially **every real system** works (TLS, cloud storage, and
both your papers in spirit):

```
1. Generate a random session key K                      (fast, per file)
2. Encrypt the BIG file with K using AES                (symmetric = fast)
3. Encrypt K with the recipient's public key            (asymmetric = solves key sharing)
4. Send encrypted file + encrypted K together
5. Recipient: decrypt K with private key, then decrypt file with K
```

This is sometimes called **envelope encryption** or the **"KEM + DEM"** model:

- **KEM** = Key Encapsulation Mechanism (share the small key safely).
- **DEM** = Data Encapsulation Mechanism (use that key to encrypt the big data).

Paper A's flow is exactly this idea, except the small key (`Kc`) is shared not via a simple
public key but via an **access polynomial + ABE** (Parts C and C2 below). If you understand
envelope encryption, you understand 80% of Paper A's architecture.

> **One-liner:** *Encrypt the file with a fast key; encrypt that key with a smart, safe
> method.*

---

## Part B — Decentralized systems building blocks

### B1. IPFS — "the library that finds books by their content"

**Analogy.** A normal URL says *"go to shelf 4, row 2 of library X"* (location-based). If the
library burns down, the book is gone. IPFS instead says *"find the book whose fingerprint is
ABC"* (content-based). If **anyone** anywhere has a copy, you can get it.

**Technical.** **IPFS = InterPlanetary File System**, a peer-to-peer storage network.

- Every file is hashed → that hash becomes its address, called a **CID**
  (Content Identifier), e.g. `QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco`.
- Files are split into blocks and arranged in a **Merkle DAG** — a tree of hashes where the
  top hash depends on every lower block (so tampering with any block changes the top hash).
- Because content is addressed by hash, **the same file anywhere has the same CID**
  (natural de-duplication) and **you can verify** what you downloaded is exactly what was
  shared.

**Terms you'll meet in Paper B:**

- **Pinning** — asking an IPFS node to *keep* your file and not garbage-collect it. A file
  nobody pins can disappear.
- **Pinata** — a paid "pinning service" (a friendly cloud for IPFS). Paper B uses
  `IPFS Pinata`.
- **CID** — the content hash; Paper B stores the CID on the blockchain and hands it to the
  recipient.

> **One-liner:** *IPFS stores files by their fingerprint, spread across many computers.*

---

### B2. Blockchain — "the notebook nobody can erase"

**Analogy.** A shared notebook, copied identically to thousands of people. To write a new
line, everyone must agree. Once written, nobody can quietly erase or change a past line —
because thousands of copies would disagree. So the notebook is **append-only and
tamper-evident**.

**Technical.** A blockchain is a **distributed, append-only ledger**:

- Data is grouped into **blocks**.
- Each block contains the **hash of the previous block** → a chain. Change an old block and
  every hash after it breaks. That's the tamper-evidence.
- Many copies exist across nodes; a **consensus** rule (Proof of Work, Proof of Stake,
  PBFT, Raft, …) decides which new block is accepted.
- **Public blockchain** — anyone can join (Ethereum). **Private/consortium blockchain** —
  only invited organisations (Hyperledger Fabric).

**Why it's used in these papers:** not to store the files, but to store **small, critical,
tamper-proof facts**: file hashes/CIDs, access permissions, expiry times, and **audit logs**
(who accessed what, when). Storing big files on-chain is expensive; they store the
*fingerprint* on-chain and the *file* on IPFS/cloud.

> **One-liner:** *Blockchain = a public, unerasable logbook for tiny pieces of truth.*

---

### B3. Smart contracts, Ethereum, gas, MetaMask

**Analogy.** A **vending machine**: you put in a coin and press a button; the machine
follows fixed rules and dispenses the item — no shopkeeper needed, no negotiation, cannot
be bribed. A **smart contract** is that machine, but for access rules.

**Technical.**

- **Smart contract** — a small program stored *on* the blockchain. It runs identically for
  everyone and its execution is recorded. Paper A's whole access-control logic is a smart
  contract (`SetRequest`, `SetResponse`, `Revoke`). Paper B's expiry logic is a smart
  contract.
- **Ethereum** — the most popular blockchain that runs smart contracts (usually written in
  a language called **Solidity**).
- **Gas** — each operation on Ethereum costs a small fee (gas); you pay for storage and
  computation. This is why you keep big files *off* the chain.
- **Wallet / MetaMask** — software holding your private key that lets you sign transactions
  (log in and pay gas). Paper B's first step is "connect MetaMask."
- **Hardhat** — a development tool to write, test, and deploy Ethereum smart contracts
  locally. Paper B uses it.

> **One-liner:** *A smart contract is code on the blockchain that automatically enforces
> the rules (e.g., "this file expires at 5 pm").*

---

## Part C — Access-control cryptography (the heart of Paper A)

### C1. Why we need more than one key

If you encrypt a file for 60 students with simple symmetric crypto, you have two bad options:

- Give all 60 students the **same file key** → you can't revoke just one; and they can read
  each other's stuff.
- Encrypt the file **60 times** (once per student's public key) → huge waste.

We want: *one* encrypted file, *different* keys per user, *policy-based* access, and *easy
revocation*. That is what **ABE** and the **access polynomial** provide.

---

### C2. Attribute-Based Encryption (ABE)

**Analogy.** Instead of a name on the lock, the lock reads **labels**. You write a rule on
the box: *"opens only if the opener's ID says Department = CSE AND Role = Faculty."* Each
person carries ID labels (**attributes**). Whoever's labels satisfy the rule can open the
box — the maths enforces it, not a server checking a database.

**Technical.** ABE is a public-key scheme where the **decryption key is tied to a set of
attributes** (not to a single identity). Two flavours:

| Type | Who sets the policy? | Policy lives in… | Mnemonic |
| --- | --- | --- | --- |
| **CP-ABE** (Ciphertext-Policy) | the **encryptor / data owner** | the ciphertext | *"The box carries the rule."* |
| **KP-ABE** (Key-Policy) | the **key issuer** | the user's key | *"The key carries the rule."* |

**CP-ABE is what you want for a university**: the *professor* (data owner) writes the rule
("CSE AND 3rd Year") when creating the file.

**The four CP-ABE algorithms** (you will see these names in every ABE paper):

| Algorithm | Inputs | Output | Plain meaning |
| --- | --- | --- | --- |
| `Setup()` | security parameter | **PK** (public params), **MK** (master key) | System is born. |
| `KeyGen(MK, S)` | master key + a user's attribute set `S` | **SK** (user secret key) | Give a user their label-key. |
| `Encrypt(PK, M, Γ)` | public params + message `M` + access policy `Γ` | **ciphertext CT** | Lock a message under a rule. |
| `Decrypt(PK, CT, SK)` | public params + ciphertext + user key | message `M` **or fail** | Open only if attributes match. |

A separate entity, the **Attribute Authority (AA)**, runs `Setup`/`KeyGen` and issues keys.
In Paper A the AA is **offline** and is *not* a single point of failure (multiple
registration authorities can exist).

**Why ABE is powerful here:**
- Fine-grained policy **enforced by mathematics**, not by a trusted server.
- Even if the cloud or blockchain is fully compromised, the file stays unreadable unless
  your attributes fit.
- Enables **user anonymity**: the owner never learns *who* requested, only that the
  attributes matched.

> **One-liner:** *ABE = a padlock that opens based on your labels/attributes, not your name.*

---

### C3. Finite fields GF(p) and polynomials — 3 minutes of gentle maths

You need this only because Paper A uses **polynomials** as its clever trick. Stay with the
analogy; the maths is optional.

**"Modulo" arithmetic.** On a clock, 10 + 5 = 3 (wrap around at 12). In crypto we often do
this with a prime number `p`: all answers wrap around `0 … p-1`. This finite set of numbers
with wrapping add/multiply is called a **finite field**, written **GF(p)** (Galois Field).
Wrapping keeps numbers small and is what makes the maths reversible and safe.

**Polynomial.** Something like `f(x) = 3 + 5x + 2x²`. A **degree-`n`** polynomial is
determined by `n+1` points — a fact that is the basis of secret sharing.

**Two facts that make the trick work:**
1. If you know `n+1` points on a degree-`n` polynomial, you can recover the whole polynomial.
2. If you know only `n` points, you learn **nothing** about the coefficients.

---

### C4. Access polynomial & Shamir's Secret Sharing

**Analogy (secret sharing).** To share a treasure map among 5 people so that **any 3** can
reconstruct it but any 2 learn nothing: give each person one point on a secret curve. A
straight line (degree 1) needs **2** points; a parabola (degree 2) needs **3**. Plant the
**secret in the constant term**; with fewer points than the degree, it stays hidden.

**Technical.** **Shamir's Secret Sharing** splits a secret `S` into `n` shares placed as
point values on a random polynomial of degree `t-1` whose constant term is `S`. Any `t`
shares reconstruct `S`; fewer than `t` reveal nothing.

**Paper A's "access polynomial"** is a relative of this. It defines

```
f(x, r) = Kc + (x - h(K1,r))·(x - h(K2,r))·…·(x - h(Kn,r))   (mod p)
```

- `Kc` = the **cipher-key** that decrypts the file (the secret to distribute).
- `Ki` = each user's secret **subscription key**; only user *i* knows `Ki`.
- `h` = a hash function; `r` = a random value refreshed whenever keys change.
- The **coefficients** of this polynomial are stored publicly as file metadata ("KeyInfo").

Now the magic:

- If user *i* plugs their value `h(Ki, r)` into `f`, every factor `(x − h(Kj,r))` becomes a
  number, and because `f` was built so that the product vanishes appropriately, the user
  recovers **`Kc`** by computing `Kc = f(h(Ki, r))`.
- A user who does **not** know any valid `Ki` cannot compute a point on the polynomial, so
  they cannot recover `Kc` — even though the coefficients are public.

**Why the hash + random `r` matter:** the *original* access-polynomial idea (1990s) had
flaws: a member who left could still derive future keys, and factorisation attacks could
expose others' keys. Paper A uses a **hash-based polynomial plus a random nonce `r`** to
close those holes, and refreshes `r` (and `Kc`) whenever something changes.

**Revocation becomes cheap:** to remove a user, the owner picks a **new** `Kc'` and a **new**
`r`, rebuilds the polynomial from the **remaining** users, re-encrypts the file once, and
updates the metadata. Non-revoked users are **not contacted at all** — they just use their
existing `Ki` with the new metadata. This is Paper A's headline contribution.

> **One-liner:** *The file key is hidden inside a curve; each user gets one point, and a
> valid point gives you the key back — so access control is done by geometry, not by a
> server.*

---

## Part D — Security vocabulary used in both papers

You will keep seeing these words. Learn them once and both papers read much faster.

| Term | Plain meaning | Why it appears |
| --- | --- | --- |
| **Threat model** | *Who* you assume is dangerous and what they can do | Sets the rules of the game. |
| **Semi-honest / honest-but-curious** | The server follows the protocol but *peeks* at data | Paper A assumes the cloud is like this. |
| **Untrusted / public** | Assume NO trust at all; anyone can read stored bytes | Paper A assumes cloud & blockchain are public. |
| **Authorization** | Who is allowed to do what | Core of both papers. |
| **Confidentiality** | Only authorised parties can read the data | What encryption provides. |
| **Integrity** | Data cannot be altered undetected | What hashes + signatures provide. |
| **Authenticity** | Proven source of data/action | Signatures. |
| **Availability** | Data is reachable when needed (no single point of failure) | IPFS/blockchain decentralisation. |
| **Non-repudiation** | A party can't deny an action | Signatures + on-chain log. |
| **Auditability** | There is a tamper-evident record of who did what | Blockchain log. |
| **Anonymity / privacy** | A party's identity is hidden | ABE + blockchain channel in Paper A. |
| **Revocation** | Withdrawing access from a user | Paper A's "Revoke" + polynomial update. |
| **Forward secrecy** | Past sessions stay safe even if a long-term key leaks later | Advanced; in the MLS paper. |
| **Post-compromise security** | System *self-heals* after a key theft | Advanced; MLS/QSS4 papers. |
| **DoS attack** | Flooding a server to make it unavailable | Paper A shields the owner via the blockchain channel. |
| **Collusion** | Two or more users combining keys to cheat | Threshold PRE schemes defend against it. |
| **Nonce / IV** | A "number used once" per encryption | Prevents identical ciphertexts. |
| **KEM / DEM** | Split of key-sharing vs bulk data encryption | The envelope model. |
| **Key wrapping** | Encrypting a key with another key | How `Kc`/`Kid` get protected. |
| **Gas** | Fee for blockchain computation | Paper B (Ethereum). |
| **CID** | IPFS content address (a hash) | Paper B. |
| **Pinning** | Telling an IPFS node to keep a file | Paper B (Pinata). |
| **Threshold (t-of-n)** | Need `t` of `n` parties to act | Secret-sharing schemes. |

---

## Part E — Cheat sheet (symbol → meaning)

| Symbol in the papers | Meaning | Where |
| --- | --- | --- |
| `Kc` / `KC` | **cipher-key** that AES-decrypts the file | Paper A |
| `Ki` / `Kid` | a user's **subscription key** (their secret point) | Paper A |
| `Ktemp` / `KTemp` | a temporary key chosen by the requesting user | Paper A |
| `Kpu(OW)` / `Kpr(OW)` | data owner's **public / private** key | Paper A |
| `h(...)` | a **hash** function | Both |
| `r`, `rnew` | a **random nonce**, refreshed on changes | Paper A |
| `Γ` (Gamma) | the **access policy** (a set of attributes) | Paper A |
| `EncSYM / DecSYM` | symmetric (AES) encrypt / decrypt | Paper A |
| `EncPKI / DecPKI` | asymmetric (public-key) encrypt / decrypt | Paper A |
| `EncABE / DecABE` | attribute-based encrypt / decrypt | Paper A |
| `pk`, `sk` | public key / secret key (generic) | Both |
| `PK`, `MK`, `SK` | public params / master key / user secret key (ABE) | Paper A |
| `CT` | ciphertext | Both |
| `Setup, KeyGen, Encrypt, Decrypt` | the 4 ABE algorithms | Paper A |
| `CID` | IPFS content identifier (a hash) | Paper B |
| `IPFS`, `dApp` | decentralized file system; decentralized app | Paper B |
| `KEM`, `DEM` | key encapsulation; data encapsulation | Literature |
| `ML-KEM / Kyber`, `ML-DSA / Dilithium` | NIST **post-quantum** KEM and signature | Literature/future |

---

## Self-test: 12 questions

Answer these before moving on. If you can, you're ready for the paper breakdown.

1. What is the difference between symmetric and asymmetric encryption, and why do we need
   both?
2. Why is it safe to publish a **hash** of a file but not the file?
3. What does a digital signature prove? Which key creates it, which verifies it?
4. In envelope encryption, why do we encrypt the **file** with AES but the **key** with
   something else?
5. What is a **CID** in IPFS, and why is it called "content addressing"?
6. What does a blockchain store in these systems — the files or something else? Why?
7. What is a **smart contract**, and what is **gas**?
8. In CP-ABE, **who writes the access policy**? What are the four algorithms?
9. In the access polynomial `f(x,r) = Kc + Π(...)`, which value is the *secret*, and what
   does a user need to recover it?
10. Why does revoking one user not force re-keying for all other users in Paper A?
11. What does "DoS-resistant" mean here, and how does blockchain help?
12. What is the difference between a **public** and a **private/consortium** blockchain?

Answers are implied throughout this document — try to say each answer out loud in one
sentence. If you can't, re-read that section.

---

**Next:** open `02-Research-Papers-Breakdown.md` with the PDFs beside you.
