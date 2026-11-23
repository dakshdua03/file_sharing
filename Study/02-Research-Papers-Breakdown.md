# 02 — The Two Research Papers, Broken Down

Read each section **with the PDF open beside it**. For every PDF section, this document
tells you: *what it is, what it actually says in plain English, and whether you can skip it.*

> Prerequisite: read `01-Crypto-Basics-Primer.md` first. Terms like ABE, `Kc`, CID, smart
> contract, and access polynomial are defined there.

---

# PART I — Paper A

**Title:** *Secure cloud file sharing scheme using blockchain and attribute-based encryption*
**Authors:** Mohammadpayam Almasian, Alireza Shafieinejad (Tarbiat Modares University, Iran)
**Venue:** Computer Standards & Interfaces 87 (2024) 103745, Elsevier
**File:** `../Downloads/1-s2.0-S0920548923000260-main.pdf`

---

## A.0 One-line summary

> Encrypt a file with a random key, hide that key inside a **polynomial**, let people
> recover their point on the polynomial only if a **smart contract + ABE** grants them
> access, and make **revocation** cheap by simply rebuilding the polynomial.

---

## A.1 Real-world analogy

Picture a **members-only reading room**:

- The **book** is in a locked glass case (the encrypted file on the cloud). Anyone can see
  the case, nobody can read the book.
- The **key to the case** is not handed out. Instead, there is a **public chart** on the
  wall with a curve drawn on it (the **access polynomial coefficients**).
- Each **member** is given a personal **dot** on that curve (their subscription key `Ki`).
  Only a member can read off the key from the chart using their dot.
- To **ask for access**, you fill a form and drop it in a locked box that only the owner
  can open (encrypt request with owner's public key), and the request is posted on a public
  **notice board** (blockchain).
- The **owner** posts back an answer encrypted so that only people with the right
  **badges** (attributes) can read it (**ABE**).
- If a member **misbehaves or expires**, the owner **redraws the chart** (new random `r`,
  new key `Kc'`), hands out no new dots to existing members — old members' dots still line
  up on the new curve only for those still authorised.

That last sentence is the paper's clever part.

---

## A.2 The problem it attacks

The paper opens by listing what's wrong with ordinary cloud file sharing:

- Cloud servers are **untrusted** (assume "semi-honest-but-curious": they follow rules but
  snoop).
- A **link/URL** is public — anyone who has it can download.
- **Key management, distribution, and revocation** are hard.
- You also want **user anonymity** (owner need not learn who requested).
- You want a **tamper-proof audit log**.
- The owner's server must not be a **DoS** target.

Its goal: a **fine-grained access-control framework** that is **decentralised, fault
tolerant, and DoS-resistant**, where the **cloud and blockchain are assumed untrusted**.

> **Nice line to quote in your report:** *"The cloud is public and anyone who knows the URL
> or address of a file can download it."* This is exactly the motivation for your university
> project.

---

## A.3 The actors (components)

From Section 3.2 / Fig. 1:

| Actor | Job |
| --- | --- |
| **Data owner** | Uploads the encrypted file, creates their own smart contract, grants/revokes access. |
| **User** | Requests access, downloads, decrypts. |
| **Cloud storage** | Public, untrusted. Stores the *encrypted* file + `KeyInfo` metadata. |
| **Smart contract** | One per data owner, on a public blockchain. Handles request/response/revoke. |
| **Attribute Authority (AA)** | Offline. Issues attribute keys to users. Not a single point of failure (multiple RAs). |

Key design decision: **the user and owner never talk directly** — all messages go through
the blockchain. That is what gives DoS-resistance and anonymity.

---

## A.4 The full flow, step by step

### Step 0 — Setup
- The **AA** generates the ABE public parameters `PK` and master key `MK`, then issues
  attribute keys to users over a secure channel.
- Each **data owner** deploys their **own smart contract** on the public blockchain and
  tells users about it.

### Step 1 — Owner uploads a file (Section 3.3.2)
1. Pick a random **cipher-key `Kc`**.
2. Encrypt the file: `C = AES-Encrypt(Kc, file)` using **AES-GCM or AES-CTR**.
3. **Sign** the ciphertext with the owner's private key using **ECDSA** (authenticity).
4. Upload `C` to the cloud.
5. Set the file's `KeyInfo` metadata to NULL for now (it will hold the polynomial).

### Step 2 — User requests access (Algorithm 1, Section 3.3.3)
1. User generates a random temporary key **`Ktemp`**.
2. Builds `Req_info = Uid | Fid | Texpiry | Ktemp`
   (user id, file id, desired expiry, temp key).
3. Encrypts it with the **owner's public key**: `req = EncPKI(Kpu(OW), Req_info)`.
   → only the owner can read it.
4. Computes a ticket number `req_id = h(Req_info)`.
5. Calls smart-contract function **`SetRequest(req_id, req)`** — the request is now on the
   blockchain.

### Step 3 — Owner grants access (Algorithm 2, Section 3.3.4)
1. Owner decrypts `req` with their private key → learns `Uid, Fid, Texpiry, Ktemp`.
2. Generates a random **subscription key `Kid`** for this user (their point on the curve)
   and a fresh **nonce `rnew`**.
3. Adds row `(Uid, Fid, Kid, Texpiry)` to the owner's private **Subscription table**.
4. Rebuilds the **access polynomial** from all current subscription keys + `Kc` + `rnew`
   (Algorithm 5), computes coefficients `(α0 … αn-1)`, and writes them into the file's
   `KeyInfo` metadata on the cloud.
5. Encrypts the pair `(Kid | req_id)` **first symmetrically** with `Ktemp`, **then** with
   **CP-ABE** under the file's access policy `Γ`:
   ```
   res = EncABE(PK,  EncSYM(Kid | req_id, Ktemp),  Γ)
   ```
6. Calls smart-contract function **`SetResponse(req_id, res)`**.

> **Why the double encryption?** ABE is slow to run on long data, so it wraps the tiny
> `(Kid | req_id)` message; `Ktemp` ensures only the requesting user (who chose `Ktemp`) can
> unwrap it, while `Γ` ensures only users with the right attributes can even read it.

### Step 4 — User downloads & decrypts (Algorithm 3 & 6, Section 3.3.5)
1. User reads `res` from the blockchain, runs `DecABE(PK, res, SK)` → `TK`.
   Fails unless the user's attributes satisfy `Γ`. *(ABE gate #1.)*
2. Runs `DecSYM(Ktemp, TK)` → recovers `(Kid, req_id')`. Checks `req_id' == req_id`
   (authentication/tamper check).
3. Downloads the encrypted file from the cloud and verifies the owner's **ECDSA signature**.
4. Reads `KeyInfo = (α0…αn-1, r)` from cloud metadata and evaluates the polynomial at their
   own point: **`Kc = F(h(Kid, r))`** (Algorithm 6). *(This is the key-recovery magic.)*
5. Decrypts the file with `Kc`.

### Step 5 — Revocation (Algorithm 3 in paper = Sec 3.3.6)
When a user's subscription expires or they misbehave:
1. Remove `Uid` from the **Subscription table**.
2. Generate a **new `Kc'`** and **new `rnew`**.
3. Rebuild the polynomial from the **remaining** users only.
4. Re-encrypt the file **once** with `Kc'` and upload the new version.
5. Update `KeyInfo`.
→ **No messages are sent to the remaining users.** They keep their old `Kid` and simply use
the refreshed metadata. This is the **fast, low-overhead revocation**.

---

## A.5 The clever bit: the access polynomial

Defined in Section 3.1, in the finite field **GF(p)**:

```
        n
f(x,r) = Kc + ∏ ( x − h(Ki, r) )      (mod p)
       i=1
       = α0 + α1·x + … + α(n-1)·x^(n-1) + x^n
```

- `Kc` — the file's cipher-key (secret to distribute).
- `h(Ki, r)` — hash of user *i*'s subscription key with nonce `r`.
- Coefficients `α0…α(n-1)` and `r` are **public** (stored as `KeyInfo`).

**How a valid user gets the key:** user *i* computes `Kc = f(h(Ki, r))`.
Every factor involving user *i* collapses so that `Kc` falls out. A user with **no valid
`Ki`** has no evaluatable point and cannot recover `Kc`, even though the coefficients are
public.

**Why the hash + random nonce?** The classic access-polynomial scheme (reference [4] in the
paper) had two known flaws (Section 2.1):
1. a member who left could still derive the **new** group key (breaks forward secrecy);
2. a member could **factorise** `f(x) − f(Ki)` to steal others' keys.

Paper A fixes both by using a **hash-based polynomial** `h(Ki, r)` and a **random `r`** that
is regenerated every time the polynomial changes. This is a *small idea with a big payoff*:
security is restored, and revocation stays cheap.

**Cost note:** computing the coefficients is `O(n²)` (Algorithm 5, incremental multiply).
For a university course (dozens–hundreds of users) this is trivial; the paper tested up to
**20,000 users**.

---

## A.6 Security properties claimed (Section 5)

| Property | How it's achieved |
| --- | --- |
| **Confidentiality** | AES + ABE + polynomial; cloud/blockchain need not be trusted. |
| **Authenticity / integrity** | ECDSA signature on the file; `req_id` check on responses. |
| **Fast revocation** | New `Kc'`, new `r`, rebuild polynomial — **no re-keying of others**. |
| **DoS resistance** | Owner never exposed directly; requests flow through the blockchain. |
| **User anonymity** | Owner sees attributes match, not user identity/IP; requests encrypted to owner. |
| **Auditable log** | All requests/responses are blockchain transactions. |
| **Decentralisation & fault tolerance** | Public blockchain + public cloud; no central keeper. |
| **Collusion resistance of the polynomial** | Hash-based + random nonce defeats the old factorisation attack. |

**Formal verification:** the paper provides formal proofs (ProVerif-style / cryptographic
arguments) that the credential info stays secret and participants are authenticated.
→ **You can skip Section 5's proofs on a first read; just remember *what* is claimed.**

---

## A.7 Results & performance (Section 6)

- Scalable to **~20,000 users**.
- Batch processing supported for granting and revoking.
- Uses polynomial evaluation which is cheap at the user side (Horner's method, Algorithm 6).
- Compared to prior ABE+blockchain schemes, it adds **revocation** (most prior works had
  none) and **user anonymity**, while keeping overhead acceptable.

---

## A.8 Strengths

- **Real revocation** without re-keying everyone — the standout contribution.
- Assumes **no** trust in cloud or blockchain (strong threat model).
- Combines **ABE + access polynomial + blockchain** in one coherent flow.
- Provides **auditability and anonymity** simultaneously.
- Provides **formal verification**.

## A.9 Limitations / critique (be honest in your report)

- **Polynomial degree grows with number of users**; recomputation is `O(n²)` per change —
  fine for a university, but a scaling concern for millions of users.
- **AES key `Kc` changes on every revocation → the whole file must be re-encrypted and
  re-uploaded.** Fine for a few-MB exam paper; costly for huge files. (Mitigation: use
  chunking + re-encrypt only the key, as later papers do with PRE.)
- **Metadata `KeyInfo` lives on the (untrusted) cloud**; correctness relies on the user
  verifying the signature.
- Requires deploying a **smart contract per owner** — gas cost and complexity.
- Assumes an **honest AA** that issues attribute keys correctly (offline trust anchor).
- No **search over encrypted files** and no **post-quantum** protection in this scheme.

---

## A.10 What to reuse in YOUR university project

| Feature | How to reuse Paper A |
| --- | --- |
| Fine-grained policy | CP-ABE policy from dropdowns: `Dept=CSE AND Role=Student AND Course=CS301`. |
| The "public URL is insecure" argument | Cite Section 1 as your problem statement. |
| Fast revocation | Steal the polynomial-refresh idea, or (simpler) the subscription-table + re-key idea. |
| Audit log | Record every request/response on-chain (or in an append-only DB for an MVP). |
| Anonymity | Route requests through the contract; don't expose user→file mapping. |
| Time limits | Paper A already includes `Texpiry` per user — combine with Paper B's enforcement. |

> **Realistic MVP advice:** adopting *full* CP-ABE + smart contracts is heavy for a first
> build. Start with **plain AES + a key-distribution table + expiry**, then upgrade to
> CP-ABE (e.g., via a library) once the pipeline works. Use Paper A as the *target
> architecture* and Paper B as the *achievable first version.*

---

## A.11 Paper A: section-by-section reading map

| PDF section | Read it? | Why |
| --- | --- | --- |
| Abstract + Intro (§1) | **Yes, carefully** | Best motivation/quotable lines. |
| §1.1 Prior work | **Skim** | Understand what came before; note the gap = no revocation. |
| §1.2 Contributions | **Yes** | 4 bullet contributions — cite these. |
| §2 Preliminaries (access polynomial, ABE, blockchain) | **Yes** | Matches primer Parts A–C. |
| §3 Proposed framework | **Yes, most important** | The actual design + algorithms. |
| §3.4 / Alg. 5–6 (polynomial math) | **Skim** | Understand *what* they compute, not every index. |
| §4 Smart-contract functions | **Yes** | `SetRequest`, `SetResponse`, `Revoke`. |
| §5 Security proof | **Skip detail** | Read only the list of properties claimed. |
| §6 Evaluation | **Yes, results only** | 20,000 users, overhead comparisons. |
| §7 Conclusion | **Yes** | Clean summary to quote. |
| References | Skim | Find follow-up papers (PRE, chunking). |

---
---

# PART II — Paper B

**Title:** *Blockchain Based File Storage and File Sharing System with Time-Restricted Access
using InterPlanetary File System*
**Authors:** M. Venkat Prashanth, K. Hemesh Verma, Jaykishor Prasad Chauhan, Shinu M Rajagopal
(Amrita School of Computing, Bangalore)
**Venue:** IEEE IDCIoT 2025 (DOI 10.1109/IDCIOT64235.2025.10915130)
**File:** `../Downloads/Blockchain_Based_File_Storage_and_File_Sharing_System_with_Time-Restricted_Access_Using_InterPlanetary_File_System.pdf`

---

## B.0 One-line summary

> A **working app**: upload a file to **IPFS (Pinata)**, store its **CID + recipient +
> expiry** in an **Ethereum smart contract**, and let the contract **automatically deny
> access after the deadline** — with a **React** front end and **MetaMask** login.

This paper is **engineering, not new cryptography**. It builds a system from existing
parts. That makes it *easy to copy* and perfect for an MVP.

---

## B.1 Real-world analogy

A **cryptographically addressed locker**:

- You drop your parcel at a **global parcel network** that identifies parcels by their
  contents' fingerprint (IPFS).
- You get back a **ticket** (the CID).
- You write on a **public rules board** (smart contract): *"person X may collect this ticket
  until 5 pm."*
- Anyone can *see* the board, but the rules can't be edited or deleted.
- At 5 pm, the board **automatically stops accepting the ticket** — no shopkeeper, no phone
  call. The parcel still exists, but the app refuses to hand it over.

---

## B.2 The problem it attacks (Abstract + §1)

- Centralised storage has **single points of failure** (hacks, outages, data loss).
- Conventional systems are **opaque** — you can't tell who tampered with data.
- There is **no automatic way to grant/withdraw access** over time.
- This is dangerous for **time-sensitive** data (contracts, reports, assignments, exams).

Their fix: use **blockchain immutability + IPFS distributed storage + smart-contract time
limits** to give a **secure, auditable, low-cost, time-restricted** sharing system.

---

## B.3 The technology stack

| Component | Role |
| --- | --- |
| **IPFS** | Distributed, content-addressed file storage. |
| **Pinata** | A pinning service so files persist on IPFS. |
| **Ethereum** | Public blockchain holding permissions/expiry. |
| **Smart contract (Solidity)** | Stores `CID`, recipient address, expiry; enforces rules. |
| **Hardhat** | Dev environment to build/test/deploy the contract. |
| **React.js** | Front-end UI for upload/share. |
| **MetaMask** | Wallet; user authentication + transaction signing. |

If a term is unfamiliar, see primer Part B.

---

## B.4 The flow, step by step (§III Methodology, Fig. 1–2)

### A. MetaMask Authentication
User connects their MetaMask wallet to the dApp. Private keys stay in the wallet; the app
just asks it to sign. **No MetaMask connection → nothing else can happen.** This is the
login.

### B. File Upload
User picks a file. It is sent to **IPFS via Pinata**, which returns a **CID**. The CID (or a
hash) is slated to be stored on-chain. *(Note: this paper stores the file **unencrypted** on
IPFS — a known weakness; see limitations.)*

### C. IPFS Storage
IPFS splits the file into blocks, hashes each, and builds a **Merkle DAG**, producing one
CID. Content is replicated across nodes → resilient, no single point of failure.

### D. Smart Contract Interaction
Through the dApp, the user sets, for that file:
- the **recipient's address** (who may access), and
- the **expiry time** (when access ends).

These are tied to the file's CID in the contract.

### E. MetaMask Transaction Approval
MetaMask asks the user to **confirm the transaction** (pay gas) that writes the permission +
expiry to the blockchain. This explicit approval is itself a security/consent step.

### F. Access Granted
When someone requests the file, the contract checks:
1. Is the requester's **address authorised**? and
2. Is the **current time within the expiry window**?
Only if both pass can they use the CID to fetch the file from IPFS.

### G. Expiry Time Reached
After the deadline, the contract **automatically denies** access. No manual action needed —
the rule is code. This is the paper's headline feature: **time-restricted access**.

```
Upload ─▶ IPFS ──► CID ──► Smart contract(CID, recipient, expiry) ──► Grant until time T
                                                                        │
                                                          time > T ─────┘──► Denied (automatic)
```

---

## B.5 Results claimed (§IV)

- **Decentralised storage:** CID-based, resilient even if nodes go offline; no single point
  of failure.
- **Automated access control:** smart contract enforced permissions + expiry; only authorised
  addresses within the window can access.
- **User-friendly:** simple React UI for upload and permission-setting.
- **Efficiency:** off-chain storage keeps the blockchain log small; content-hash lookup makes
  retrieval fast; time limits reduce unnecessary resource usage.
- Demonstrated **automatic revocation at expiry** (Fig. 2 "Access Expired") with no human
  intervention.

---

## B.6 Strengths

- **A complete, buildable system** — not just theory. Great skeleton for your project.
- **Time-restricted access** enforced automatically by a contract.
- **Cheap + scalable-ish** because heavy files stay off-chain (IPFS), only small metadata
  on-chain.
- **Transparent, tamper-evident** permission records.
- **Low barrier**: React + Hardhat + Pinata are all well-documented.

## B.7 Limitations / critique (important!)

- **No real encryption of file content.** The file is uploaded to IPFS **as-is**; anyone who
  obtains the CID can fetch it. This is the **biggest weakness** — and exactly what **Paper
  A fixes**.
- Access control is **wallet-address allowlist + time**, not attribute/policy based.
  Coarse-grained: you cannot say *"CSE AND 3rd Year"*, only "these addresses until time T".
- **No revocation before expiry** except waiting for the deadline.
- **Tied to Ethereum**; gas costs and network throughput are constraints.
- **IPFS persistence depends on pinning**; if unpinned, content can vanish (they propose
  *adaptive pinning* as future work).
- **No audit of downloads** beyond permission events; and a leaked CID during the valid
  window is still usable.
- Small-scale evaluation (a student project demo), not a large benchmark.

---

## B.8 What to reuse in YOUR university project

| Feature | How to reuse Paper B |
| --- | --- |
| IPFS storage | Store encrypted files on IPFS via Pinata (or a local IPFS node). |
| Expiry links | Store `expiry_time` in a smart contract (or DB for MVP) and check on every download. |
| CID integrity | Hand out the CID; downloader verifies the hash matches. |
| Wallet login | Use MetaMask (or university SSO for a non-crypto-friendly MVP). |
| React + Hardhat stack | Proven, copyable architecture for a demo. |
| Audit events | Log permission events on-chain. |

> **Combine A + B:** use **Paper B's stack** (IPFS + contract + React) and inject **Paper A's
> encryption** (AES file + ABE/expiry policy). Result: files stored on IPFS are *encrypted*,
> and the contract stores **who/until-when**, giving you the best of both.

---

## B.9 Paper B: section-by-section reading map

| PDF section            | Read it?                | Why                                                            |     |
| ---------------------- | ----------------------- | -------------------------------------------------------------- | --- |
| Abstract + Intro (§I)  | **Yes**                 | Motivation: centralisation = single point of failure.          |     |
| §I contributions       | **Yes**                 | 2 bullets: decentralised design + cost/security.               |     |
| §II Literature survey  | **Skim**                | Just see the trend (IPFS+blockchain). No need for all 18 refs. |     |
| §III Methodology (A–G) | **Yes, heart of paper** | The step-by-step flow.                                         |     |
| §IV Results (A–E)      | **Yes**                 | What they claim works.                                         |     |
| §V Conclusion & Future | **Yes**                 | Lists their own weaknesses (encryption, multi-chain, pinning). |     |
| Figures 1–2            | **Look**                | Block diagram + "access expired" screenshot.                   |     |
| References             | Skim                    | —                                                              |     |

---
---

# PART III — Comparing the two papers

| Dimension | Paper A (ABE + blockchain) | Paper B (IPFS + time expiry) |
| --- | --- | --- |
| **Type** | Academic/security | Engineering/system |
| **Storage** | Cloud (encrypted) + `KeyInfo` metadata | IPFS (unencrypted in the paper) |
| **File encryption** | Yes — AES with random `Kc` | **No** (stated future work) |
| **Access rule** | CP-ABE attributes + expiry per user | Wallet address + expiry |
| **Revocation** | Fast polynomial refresh | Only at expiry |
| **Blockchain use** | Smart contract: request/response/revoke | Smart contract: CID + recipient + expiry |
| **Anonymity** | Yes | No |
| **Audit log** | Yes | Partial |
| **Build difficulty** | High (crypto + contracts) | Medium (standard web3) |
| **Best used for** | The *security model* | The *implementation skeleton* |

**How they fit into one project:**

```
Paper B gives you:   upload → IPFS(CID) → smart contract(recipient, expiry) → React UI
Paper A adds:        AES-encrypt the file BEFORE upload
                     CP-ABE / policy to decide WHO gets the file key
                     Subscription table + fast revocation (before expiry)
                     Tamper-evident audit of requests
```

---

# PART IV — Your combined target architecture (in words)

```
                     ┌─────────────────────────────────────────────┐
   Professor         │  University file-sharing app (React)         │
   (Data Owner) ───▶ │  - login (SSO / MetaMask)                    │
                     │  - upload (choose Dept/Role/Course policy)   │
                     └───────────────┬─────────────────────────────┘
                                     │ 1. AES-encrypt file with random Kc
                                     ▼
                     ┌─────────────────────────────┐
                     │  IPFS (Pinata) → CID         │  ◀── stores ENCRYPTED file
                     └───────────────┬─────────────┘
                                     │ 2. store CID + policy + expiry (on-chain or DB)
                                     ▼
                     ┌─────────────────────────────┐
                     │  Smart contract / audit log  │
                     │  - who may access            │
                     │  - until when (Texpiry)      │
                     │  - request/response events   │
                     └───────────────┬─────────────┘
                                     │ 3. user requests → owner grants
                                     ▼
                     ┌─────────────────────────────┐
                     │  Key delivery = ABE(policy)  │  ◀── Paper A's crypto
                     │  + subscription key Ki       │
                     └───────────────┬─────────────┘
                                     │ 4. user recovers Kc, verifies signature, decrypts
                                     ▼
                              plaintext file (only on user's device)
```

Full build plan, first steps, SRS and feasibility study → **`03-Project-Roadmap.md`**.
