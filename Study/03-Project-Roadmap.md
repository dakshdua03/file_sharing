# 03 — Project Roadmap: from zero to a working system

This answers your questions directly:

1. **What is the flow of the project?**
2. **What is the very first step?** (Answer: a **scope + feasibility study**, then **SRS**.)
3. **Do I do SRS or feasibility first?** (Answer: a *quick* feasibility check first; a *full*
   feasibility study in parallel with the SRS. Details below.)
4. **How do I develop it, phase by phase, given I'm new to cryptography?**

---

## 0. The 10,000-foot view

```
Phase 0  SCOPE        ── decide exactly what you're building (and NOT building)
Phase 1  FEASIBILITY  ── can it be done? (technical / economic / operational / schedule / legal)
Phase 2  SRS          ── write down every requirement formally
Phase 3  DESIGN       ── architecture, diagrams, data model, crypto choices
Phase 4  BUILD (MVP)  ── smallest end-to-end demo that works
Phase 5  BUILD (V2)   ── add the hard crypto (ABE, revocation, on-chain audit)
Phase 6  TEST & EVAL  ── security tests + performance numbers
Phase 7  DOCS & DEMO  ── report, user manual, presentation, viva
```

> **Common beginner mistake:** jumping to Phase 4 (code) immediately. You will thrash. The
> reason the two papers look impressive is that their *design* (Phases 0–3) is solid.

---

## 1. FIRST STEP: Phase 0 — Scope (do this today, ~1 page)

You cannot do feasibility or an SRS until you know **what** you're building. Write a one-page
**Scope Statement** answering:

**1.1 Goal (one sentence)**
> Build a secure file-sharing system for a university where professors, students and scholars
> can share files with limited, encrypted, time-bound, revocable access.

**1.2 Users / roles**
- **Data Owner** = Professor / Admin (uploads, sets policy, grants/revokes).
- **Data User** = Student / Scholar / Committee member (requests, downloads).
- **Authority** = department admin (issues accounts/attributes). *(In MVP, the app plays this
  role.)*

**1.3 In-scope (MVP)**
- Login/identity.
- Upload file.
- Encrypt file before storage.
- Share to a chosen person or group.
- Expiry date/time on access.
- Download + decrypt.
- Revoke access.
- Activity log.

**1.4 Explicitly OUT of scope (say this so you don't over-promise!)**
- Mobile app.
- Cross-university federation.
- Post-quantum crypto (mention as future scope).
- Full searchable encryption (mention as future scope).
- Production-grade IPFS cluster (use Pinata).

**1.5 The one-line novelty / justification**
> *"Ordinary cloud links (e.g., a Google Drive URL) grant permanent, identity-blind access.
> This system encrypts files client-side, enforces attribute/time-based access via
> cryptography, and records a tamper-evident audit trail — as demonstrated by Papers A and
> B."*

✅ **Deliverable:** `01-Scope.md` (~1 page).
⏱ **Time:** half a day.

---

## 2. Phase 1 — Feasibility Study

A feasibility study answers *"is this achievable, affordable, sensible, and legal?"* in 5
dimensions. Keep it short — 2–4 pages — and do it **right after** scope. You update it in
parallel with the SRS.

### 2.1 Technical feasibility
| Question | Answer for your project |
| --- | --- |
| Do libraries exist? | Yes: **PyCryptodome** (AES-GCM), **cryptography**, `py-ipfs-http-client` / `pinatapy`, **Web3.py**, Solidity + Hardhat, for ABE: **Charm-Crypto**, **OpenABE**, or a Python CP-ABE lib. |
| Do we have the skills? | Learn crypto basics (see `01-Crypto-Basics-Primer.md`); start with AES + expiry (easy), add ABE later. |
| Is IPFS easy? | Pinata gives a simple HTTP API + free tier. |
| Is the blockchain part required? | For an MVP you can *simulate* the audit log with an append-only table, then move on-chain. |
| Biggest risk | CP-ABE tooling is fiddly. Mitigation: implement the MVP with AES + policy table first, treat CP-ABE as a stretch goal. |

### 2.2 Economic feasibility
- Pinata free tier; Ethereum testnet (Sepolia) free gas via faucets; local Hardhat chain free.
- No paid infra required. Cost ≈ your time.

### 2.3 Operational feasibility
- Would a university actually use it? It maps to real needs: distributing assignments/exam
  papers, thesis drafts, committee documents, with auto-expiry.
- Usability risk: crypto wallets (MetaMask) are unfriendly to non-technical staff. Mitigation:
  keep login as normal SSO for the MVP; treat wallet login as optional.

### 2.4 Schedule feasibility
- A realistic student timeline of **10–14 weeks** (see §3). If the deadline is shorter,
  **shrink scope**, don't add features.

### 2.5 Legal / ethical feasibility
- Complying with data-protection norms: encrypt at rest, minimal logging, consent for audit,
  ability to delete. Note you are **not** building a system for real sensitive data; use
  synthetic data for the demo.

✅ **Deliverable:** `02-Feasibility-Study.md`.
⏱ **Time:** 1–2 days.

> **SRS vs Feasibility — the actual answer to your question:** Do a **quick feasibility check
> immediately** (a paragraph per dimension: "yes libraries exist, yes it's affordable…"). Then
> write the **SRS**. Finish with a **full feasibility study** once the SRS has frozen the
> requirements — because you can't fully assess feasibility until you know exactly what's
> required. In practice: **light feasibility → SRS → full feasibility**, or write them in
> parallel, feeding each other. Many university rubrics want *both* documents; the order
> above is the sensible one.

---

## 3. Phase 2 — SRS (Software Requirements Specification)

Use the classic **IEEE 830** structure. This is the document your report and marks depend
on. Keep it precise and testable ("the system **shall** …").

### 3.1 SRS outline (copy this)

```
1. Introduction
   1.1 Purpose
   1.2 Scope
   1.3 Definitions, acronyms, abbreviations   (pull from the primer's cheat sheet)
   1.4 References                             (the two papers + your lit survey)
   1.5 Overview
2. Overall Description
   2.1 Product perspective   (how it differs from Drive/WeTransfer)
   2.2 Product functions     (upload, share, expire, revoke, audit)
   2.3 User characteristics  (professor, student, scholar, admin)
   2.4 Constraints           (browser only, testnet, Pinata free tier)
   2.5 Assumptions & dependencies
3. Specific Requirements
   3.1 Functional requirements  (FR-1, FR-2, …)
   3.2 Non-functional requirements (NFR: performance, security, usability, reliability)
   3.3 External interfaces     (UI, IPFS API, blockchain API, DB)
4. System Models (often split out)
   4.1 Use-case diagram
   4.2 Data-flow diagrams (DFD level 0/1)
   4.3 ER diagram
   4.4 Sequence diagrams (upload, request, revoke)
5. Appendices
```

### 3.2 Draft functional requirements (adapt freely)

| ID | Requirement |
| --- | --- |
| FR-1 | The system **shall** let a user authenticate (SSO/wallet). |
| FR-2 | A data owner **shall** upload a file and choose an access policy (recipient or attributes). |
| FR-3 | The system **shall** encrypt every file client-side before it leaves the device. |
| FR-4 | The system **shall** store encrypted files on IPFS and receive a CID. |
| FR-5 | The system **shall** record file CID, owner, policy and expiry time in a tamper-evident store. |
| FR-6 | A data owner **shall** set an expiry time; access **shall** be denied automatically after it. |
| FR-7 | An authorised user **shall** request access; a granted user **shall** download and decrypt. |
| FR-8 | The data owner **shall** be able to revoke access before expiry. |
| FR-9 | The system **shall** log every access request/grant/download with timestamp. |
| FR-10 | The system **shall** verify file integrity on download (hash/signature check). |
| FR-11 | The system **shall** allow attributes (Dept/Role/Course) to drive the policy (V2). |
| FR-12 | Unauthorised users **shall** be unable to read file contents even with the CID. |

### 3.3 Draft non-functional requirements

| ID | Requirement |
| --- | --- |
| NFR-1 | Encryption uses AES-256-GCM with a unique 96-bit IV per encryption. |
| NFR-2 | File key Kc is never stored in plaintext anywhere. |
| NFR-3 | Revocation takes effect without re-keying other users (goal). |
| NFR-4 | File upload of ≤10 MB completes in ≤ a few seconds on a normal connection. |
| NFR-5 | The UI must be usable by a non-technical user (no crypto knowledge required). |
| NFR-6 | The audit log must be append-only and tamper-evident. |
| NFR-7 | The system must remain available if any single IPFS node goes offline. |

✅ **Deliverable:** `03-SRS.md` (or `.doc/.pdf`).
⏱ **Time:** 3–5 days. **This is the most important document to get reviewed early.**

---

## 4. Phase 3 — Design

Now choose *how*. Output diagrams + the crypto decisions.

### 4.1 Architecture (recommended, combining Papers A + B)

```
┌────────────┐   upload(encrypted)     ┌──────────────┐
│  React UI   │ ──────────────────────▶ │   IPFS/Pinata │  stores ciphertext → CID
│  (browser)  │ ◀────────────────────── │              │
└─────┬───────┘        CID              └──────────────┘
      │  id, policy, expiry
      ▼
┌────────────────────────┐    ┌──────────────────────────┐
│  Backend (FastAPI)      │───▶│  Metadata DB (students,   │
│  - auth, policy engine  │    │  files, subscriptions)    │
│  - key mgmt (AES/KEM)   │    └──────────────────────────┘
│  - expiry enforcement   │    ┌──────────────────────────┐
│  - audit writer         │───▶│  Audit store (append-only │
└────────────────────────┘    │  table, or Ethereum log)  │
                              └──────────────────────────┘
```

For the MVP the "tamper-evident store" can be a Postgres table with chained hashes (each row
includes the hash of the previous row — a mini-blockchain). Move to a real chain in V2.

### 4.2 Crypto decisions (start simple, upgrade later)

| Layer | MVP (weeks 1–5) | V2 (weeks 6+) |
| --- | --- | --- |
| File encryption | AES-256-GCM, random key `Kc`, random 96-bit IV | same |
| Key wrapping | `Kc` encrypted to recipient's public key (hybrid/HPKE-like) | same + CP-ABE for policy |
| Access policy | recipient allowlist + expiry (Paper B) | attribute policy (Paper A) |
| Revocation | rotate `Kc`, re-encrypt metadata | polynomial refresh / PRE |
| Audit | hash-chained DB rows | Ethereum/smart-contract log |
| Storage | Pinata (IPFS) | same, add local node |

### 4.3 Diagrams to produce
- Use-case diagram (actors → functions).
- DFD level 0 and 1.
- ER diagram: `User`, `File`, `Policy`, `Subscription`, `AccessLog`.
- Sequence diagrams: **Upload**, **Request→Grant→Download**, **Revoke**.

✅ **Deliverable:** `04-Design.md` + diagrams.
⏱ **Time:** 3–4 days.

---

## 5. Phase 4 — Build the MVP (minimal, end-to-end, NO fancy crypto yet)

The goal: **"professor uploads → student downloads, link expires."** Nothing more.

Recommended **first working slice** (in this order):

1. **Plain upload/download without crypto** to local storage. Prove the pipeline.
2. **Add AES-256-GCM client-side encryption** (PyCryptodome). Prove it round-trips.
3. **Move storage to IPFS/Pinata** → get a CID. Prove retrieval by CID.
4. **Add expiry**: store `expiry_time`; backend denies after it. Prove auto-expiry.
5. **Add users + sharing**: professor shares a file to a student who can decrypt.
6. **Add audit log**: write a row per request/download.

> At the end of the MVP you already have something **demonstrable and defensible**, even if
> you never finish CP-ABE. This is the single most important strategic advice in this file.

✅ **Deliverable:** working local demo.
⏱ **Time:** 2–3 weeks.

---

## 6. Phase 5 — V2: add the research-grade parts

In priority order (each is independently valuable, so you can stop at any point):

1. **Attribute-based policy** (replace "recipient allowlist" with `Dept AND Role AND Course`).
   Simplest path: implement a **policy check + key release** first, then attempt true CP-ABE
   with a library (Charm-Crypto / OpenABE).
2. **Fast revocation** — adopt Paper A's subscription-key + re-key (or polynomial) idea.
3. **On-chain audit** — deploy a Solidity contract (Hardhat) recording `{fileId, hash,
   owner, expiry}` and access events; use Sepolia testnet.
4. **Signature verification** — ECDSA-sign the ciphertext; verify on download.
5. **Stretch (future scope section of your report):** post-quantum (Kyber), ZKP, searchable
   encryption, chunked parallel encryption.

⏱ **Time:** 3–5 weeks (V2 is where most research projects spend their effort).

---

## 7. Phase 6 — Test & Evaluate

You must produce **numbers** for your report. Both papers do; you should too.

### 7.1 Functional tests
- Upload → download → decrypt → byte-identical file.
- Wrong recipient cannot decrypt.
- Expired link is denied automatically.
- Revoked user loses access immediately.
- Tampered ciphertext is detected (GCM auth tag / signature fails).
- Unauthorised user with CID still cannot read content (encryption check).

### 7.2 Security tests (map them to the papers' claims)
| Claim | Your test |
| --- | --- |
| Confidentiality | Fetch CID without key → unreadable. |
| Integrity | Flip a byte → decryption fails. |
| Authenticity | Verify signature; forge attempt fails. |
| Expiry | Clock past deadline → denied. |
| Revocation | After revoke → denied; others unaffected. |
| Audit | Events appear in append-only log; altering a row breaks the chain. |

### 7.3 Performance tests (produce a table)
- Encryption/decryption time vs file size (1 MB, 10 MB, 100 MB).
- Upload/download latency vs IPFS.
- Policy-check / key-release time.
- (If on-chain) gas cost per share/revoke, and transactions per second.
Present results like the papers' §IV/§6 tables.

✅ **Deliverable:** `05-Test-Report.md` + results tables and graphs.
⏱ **Time:** 1–2 weeks.

---

## 8. Phase 7 — Documentation & Demo

- **Final report**: Introduction → Literature (use your `Papers/` survey — cite Papers A & B!)
  → Problem statement → Methodology → Design → Implementation → Results → Conclusion →
  Future scope → References (IEEE format).
- **User manual** (screenshots).
- **Demo script** (5 minutes: upload with policy → share → student downloads → expiry →
  revoke → audit view).
- **Presentation slides**.
⏱ **Time:** 1–2 weeks.

---

## 9. Suggested 12-week schedule (adjust to your deadline)

| Week | Focus | Milestone |
| --- | --- | --- |
| 1 | Study primer + paper breakdowns; write Scope; light feasibility | Scope + feasibility draft |
| 2 | SRS writing + review | **SRS frozen** |
| 3 | Design: architecture, diagrams, ERD, sequence diagrams | Design doc |
| 4 | Stack setup (Python/FastAPI/React), plain upload/download | Pipeline works |
| 5 | AES encryption + IPFS/Pinata + CID retrieval | Encrypted storage works |
| 6 | Expiry enforcement + sharing + audit log | **MVP complete** |
| 7 | Attribute policy engine | Policy-based sharing |
| 8 | Fast revocation | Revocation works |
| 9 | Smart contract + Hardhat (testnet) | On-chain audit |
| 10 | Signature verification + hardening | Security features done |
| 11 | Full test & evaluation; collect numbers | Test report |
| 12 | Report, demo, slides, buffer | **Submission** |

If short on time: **weeks 1–6 alone (Scope → SRS → Design → MVP)** are a complete, gradeable
project. V2 is bonus.

---

## 10. Tech stack recommendation (beginner-friendly)

| Layer | Choice | Why |
| --- | --- | --- |
| Backend | **Python + FastAPI** | Simple, lots of crypto libraries. |
| Frontend | **React.js** | Same as Paper B → copy their patterns. |
| File crypto | **PyCryptodome** (AES-256-GCM) | Easy, well-documented. |
| Asymmetric | **`cryptography`** lib (X25519/ECDSA) or **PyNaCl** | For key wrapping + signatures. |
| ABE (V2) | **Charm-Crypto** / **OpenABE** | Reference implementations exist. |
| Storage | **IPFS via Pinata** | Free tier, HTTP API. |
| Blockchain (V2) | **Solidity + Hardhat** → Sepolia testnet | Matches Paper B. |
| DB | **PostgreSQL** (or SQLite to start) | Users, files, subscriptions, logs. |
| Password hashing | **Argon2id** | Modern standard. |

---

## 11. Key risks & mitigations

| Risk | Mitigation |
| --- | --- |
| CP-ABE tooling hard | Do policy + key-release first; treat true CP-ABE as stretch. |
| Wallet UX too complex | Use normal SSO login for MVP; optional MetaMask. |
| IPFS files vanish | Use Pinata + pin explicitly; note "adaptive pinning" as future work. |
| Blockchain gas/cost | Use testnet; simulate audit with hash-chained DB in MVP. |
| Scope creep | Freeze the SRS; put extras in "Future Scope". |
| "Not novel enough" | Your novelty = combining Paper A's crypto with Paper B's practical system for a **university** context + a custom policy UI. Make that explicit. |

---

## 12. Do this next (concrete checklist)

1. [ ] Read `01-Crypto-Basics-Primer.md` (1–2 sittings).
2. [ ] Skim both PDFs' Abstract/Intro/Conclusion.
3. [ ] Read `02-Research-Papers-Breakdown.md` with the PDFs open.
4. [ ] Write `01-Scope.md` (one page) — do it today.
5. [ ] Write the light feasibility notes (a paragraph per dimension).
6. [ ] Draft `03-SRS.md` using the outline in §3.
7. [ ] Get the SRS reviewed by your guide; freeze it.
8. [ ] Produce design diagrams (§4.3).
9. [ ] Build the MVP slices in §5, in order.

---

**Cross-references**
- Basics: `01-Crypto-Basics-Primer.md`
- Paper details: `02-Research-Papers-Breakdown.md`
- Your existing literature survey: `../Papers/📄-Download-Secure_File_Sharing_Literature_Survey_15_Papers.docx` and `../Papers/Research Papers.pdf`
