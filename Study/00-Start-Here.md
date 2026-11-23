# START HERE — How to study the two papers & build the project

You said you have **no background in cryptography**. That is completely fine — almost
everyone who reads these papers starts there. The trick is to learn a **small set of
building blocks** first, then the papers stop looking like magic and start looking like
Lego instructions.

This `Study/` folder contains 4 documents. Read them **in this order**:

| Order | File | What it is | When to read |
| --- | --- | --- | --- |
| 1 | `00-Start-Here.md` (this file) | Map of everything. | Now. |
| 2 | `01-Crypto-Basics-Primer.md` | Teaches the ~12 ideas from zero. **No prior knowledge assumed.** | Before touching the papers. |
| 3 | `02-Research-Papers-Breakdown.md` | The two downloads, explained line-by-line in plain English. | After the primer. |
| 4 | `03-Project-Roadmap.md` | How to actually build *your* system: first step, SRS, feasibility, phases, stack. | After you understand the papers. |

## Optional hands-on lab (do this while reading the primer)

`Lab/` contains six small Python programs that **run** the ideas above and print the real
keys, ciphertexts, signatures and hashes. Watch RSA work with tiny numbers, see a file
encrypt with AES, see why the AES key is wrapped with RSA, see Shamir secret sharing and
Paper A's access polynomial, and see a blockchain reject a tampered block.

```bash
cd Study/Lab
./run_all.sh
```

Read `Lab/README.md` for what each script shows and what to try yourself.

---

## The two papers you downloaded

Both live in `../Downloads/`. Both are **already referenced in your own literature survey**
(`../Papers/📄-Download-Secure_File_Sharing_Literature_Survey_15_Papers.docx`), so they are
not random — they are two of the core sources for your project.

| Short name | Full title | Venue / Year |
| --- | --- | --- |
| **Paper A** | *Secure cloud file sharing scheme using blockchain and attribute-based encryption* (Almasian & Shafieinejad) | Computer Standards & Interfaces (Elsevier), 2024 |
| **Paper B** | *Blockchain Based File Storage and File Sharing System with Time-Restricted Access using IPFS* (Venkat Prashanth et al., Amrita Univ.) | IEEE IDCIoT, 2025 |

Files:
- Paper A → `../Downloads/1-s2.0-S0920548923000260-main.pdf`
- Paper B → `../Downloads/Blockchain_Based_File_Storage_and_File_Sharing_System_with_Time-Restricted_Access_Using_InterPlanetary_File_System.pdf`

---

## One-paragraph summary of each (for orientation only)

- **Paper A** solves: *"If I put a file on cloud storage, anyone with the link can open it.
  How do I lock it so only the right people (and only for a limited time) can read it —
  using a blockchain and attribute-based cryptography?"* It is the **security-heavy,
  academic** paper. It is where the real maths lives.

- **Paper B** solves: *"How do I store files without a central server, and make a sharing
  link that expires automatically?"* It is the **engineering-heavy, practical** paper —
  a working app built with IPFS + Ethereum smart contracts + React. It is easier to
  understand and easier to copy for a demo.

Think of it this way:
- **Paper A = the vault and the lock.** (Attribute-Based Encryption, revocation, audit.)
- **Paper B = the delivery truck and the self-destructing timer.** (IPFS storage, expiry.)

Your project (a **secure file-sharing system for a university** — professors, students,
scholars) will combine both.

---

## The 60-second "why this matters" version

A normal Google Drive link is dangerous:

```
https://drive.google.com/file/d/abc123   ← anyone who sees this can open the file,
                                           forever, with no check on who they are.
```

Both papers replace that with two ideas:

1. **The file is encrypted** (scrambled with a secret key) *before* it is stored, so even
   the storage provider cannot read it. → *Paper A does the sophisticated version of this.*
2. **Access is controlled by code (a smart contract) and can expire** automatically, so a
   leaked link dies on its own. → *Paper B does the simple, working version of this.*

---

## Suggested study rhythm

1. Read `01-Crypto-Basics-Primer.md` once, **without stressing about the maths**.
   Focus on the analogies (locks, boxes, fingerprints, receipts).
2. Skim the two PDFs' **Abstract + Introduction + Conclusion** only. You will recognise
   words from the primer. This is a confidence check, not deep reading.
3. Read `02-Research-Papers-Breakdown.md` alongside the PDFs. It tells you what each
   section of the PDF is doing and what to ignore (proofs, heavy notation).
4. Read `03-Project-Roadmap.md` and pick your **first deliverable** (it's the feasibility
   study + scope, not code).
5. Only then start implementing.

> **Golden rule while reading:** whenever you hit a symbol or a formula, jump to the
> "Cheat Sheet" at the end of `01-Crypto-Basics-Primer.md`. 90% of what looks scary in
> these papers is just *"a number that only the right person can turn back into the
> original message."*
