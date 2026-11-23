Here's a curated set of recent research papers and technical publications on secure file sharing, organized by the technical approach they take. I've grouped them so you can see where the field's genuine breakthroughs are clustering.

### Blockchain + Decentralized Storage (IPFS)

**Secure File Sharing Using Blockchain and IPFS with Smart Contracts** (2025, IJFMR)  
This survey examines recent advances in decentralized file storage using blockchain to strengthen data confidentiality, integrity, and transparency, centered on a system that combines blockchain-based access control, encryption, and IPFS for distributed storage.  
🔗 [https://www.ijfmr.com/papers/2025/6/59624.pdf](https://www.ijfmr.com/papers/2025/6/59624.pdf) [IJFMR](https://www.ijfmr.com/papers/2025/6/59624.pdf)

**Blockchain-based secure and verifiable storage scheme for IPFS-assisted IoT with homomorphic encryption** (2025, _Computing_, Springer)  
Addresses the storage limitations of IoT devices by combining blockchain, IPFS, and homomorphic encryption for verifiable, secure storage.  
🔗 [https://link.springer.com/article/10.1007/s00607-025-01506-y](https://link.springer.com/article/10.1007/s00607-025-01506-y) [Springer](https://link.springer.com/article/10.1007/s00607-025-01506-y)

**A Decentralized and Secure Blockchain-IPFS Framework for Efficient Data Storage in Web3** (2025)  
🔗 [https://www.researchgate.net/publication/395281853\_A\_Decentralized\_and\_Secure\_Blockchain-IPFS\_Framework\_for\_Efficient\_Data\_Storage\_in\_Web3](https://www.researchgate.net/publication/395281853_A_Decentralized_and_Secure_Blockchain-IPFS_Framework_for_Efficient_Data_Storage_in_Web3)

### End-to-End Encryption & Post-Compromise Security

**Securing End-to-End Encrypted File Sharing Services With the Messaging Layer Security Protocol** (2025, _Concurrency and Computation: Practice and Experience_, Wiley — also in Springer's _Intelligent Distributed Computing XVII_)  
This is one of the more technically substantial papers I found. It tackles a core weakness in current E2EE file-sharing systems: if an attacker steals a client's keys, they can often decrypt both past and future content. The authors propose a new architecture integrating the Messaging Layer Security (MLS) protocol to strengthen post-compromise security while staying practical. A distinguishing feature is automatic key distribution based on access rights whenever a file is uploaded or modified, rather than requiring pre-shared encrypted folders.  
🔗 [https://onlinelibrary.wiley.com/doi/10.1002/cpe.70414](https://onlinelibrary.wiley.com/doi/10.1002/cpe.70414)  
🔗 [https://link.springer.com/chapter/10.1007/978-3-031-87639-4\_7](https://link.springer.com/chapter/10.1007/978-3-031-87639-4_7) [Wiley Online Library](https://onlinelibrary.wiley.com/doi/10.1002/cpe.70414)[ResearchGate](https://www.researchgate.net/publication/397061323_Securing_End-To-End_Encrypted_File_Sharing_Services_With_the_Messaging_Layer_Security_Protocol)

### Attribute-Based Encryption & Fine-Grained Access Control

**Secure cloud file sharing scheme using blockchain and attribute-based encryption** (ScienceDirect / reprinted 2025 in _Iranian Journal of Science and Technology_)  
Proposes using blockchain smart contracts for decentralized access control combined with ABE — each data owner runs a smart contract where users request access, and the cipher-key is embedded into an "access polynomial" that authorized users can compute.  
🔗 [https://www.sciencedirect.com/science/article/abs/pii/S0920548923000260](https://www.sciencedirect.com/science/article/abs/pii/S0920548923000260) [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0920548923000260)

**Secure cloud file sharing using sharding, zero-knowledge proofs and blockchain** (2025, _Lecture Notes in Networks and Systems_)  
Combines sharding, encryption, zero-knowledge proofs, and blockchain for secure data retrieval and access control, using user-specific digital wallets to manage encryption keys before cloud storage.  
🔗 [https://ouci.dntb.gov.ua/en/works/4yOMGEg9/](https://ouci.dntb.gov.ua/en/works/4yOMGEg9/) [DNTB](https://ouci.dntb.gov.ua/en/works/4yOMGEg9/)

### Post-Quantum Cryptography (the most "breakthrough"-flavored area right now)

**Enterprise-Ready Post-Quantum Zero Trust Storage: The QSS4 Architecture** (Jan 2026, _SN Computer Science_, Springer) — most novel find  
Addresses two concurrent threats simultaneously: "harvest-now-decrypt-later" attacks from future quantum computers, and the failure of perimeter security against insider threats. Its novelty is combining explicit Zero Trust enforcement (per NIST SP 800-207) with verifiable accountability and demonstrated crypto-agility, validated through a deployable prototype.  
🔗 [https://link.springer.com/article/10.1007/s42979-025-04705-8](https://link.springer.com/article/10.1007/s42979-025-04705-8) [Springer](https://link.springer.com/article/10.1007/s42979-025-04705-8)

**Practical Post-Quantum Secure Publicly Verifiable Secret Sharing and Applications** (2026, IACR ePrint)  
Presents a new framework for efficient publicly verifiable secret sharing where the dealer can go offline after one message and isn't needed for verification, using identity-based encryption and commitments instead of costly zero-knowledge proofs.  
🔗 [https://eprint.iacr.org/2026/813](https://eprint.iacr.org/2026/813) [IACR](https://eprint.iacr.org/2026/813)

**Post-Quantum Cryptography and Quantum-Safe Security: A Comprehensive Survey** (2025, arXiv)  
🔗 [https://arxiv.org/pdf/2510.10436](https://arxiv.org/pdf/2510.10436)

### Zero Trust Architecture

**Zero Trust Architectures in Modern Enterprises: Principles, Challenges, Applications** (2025, IJCTT)  
Explores ZTA's foundational principles — continuous authentication, least-privilege access, and attack-surface reduction via micro-segmentation — applied to enterprise resource access.  
🔗 [https://www.ijcttjournal.org/2025/Volume-73/Issue-6/IJCTT-V73I6P107.pdf](https://www.ijcttjournal.org/2025/Volume-73/Issue-6/IJCTT-V73I6P107.pdf) [Ijcttjournal](https://www.ijcttjournal.org/2025/Volume-73/Issue-6/IJCTT-V73I6P107.pdf)

### Foundational Systematic Review (good starting point if you want the landscape first)

**Secure Data Storage and Sharing Techniques for Data Protection in Cloud Environments: A Systematic Review, Analysis, and Future Directions** — _IEEE Access_ (Gupta, Singh, Lee, Buyya)  
A wide-ranging systematic review covering data protection solutions across cloud environments, useful as a map of the field before diving into individual mechanisms.  
🔗 [https://doi.org/10.1109/access.2022.3188110](https://doi.org/10.1109/access.2022.3188110) [doaj](https://doaj.org/article/f003ce2d1e294442836cda6164c43937)

___

A few notes on how to use this list: the **MLS-based paper** and the **QSS4 post-quantum zero-trust architecture** are the two strongest candidates if you're specifically looking for genuine _technical breakthroughs_ rather than incremental blockchain-recombination papers (there's a large volume of near-identical "blockchain + IPFS + encryption" student/capstone papers circulating in 2025 that mostly repackage the same architecture). If you want, I can go deeper into any one category — e.g., pull more papers specifically on quantum-resistant key exchange, or on zero-knowledge-proof-based access control — or fetch full-text detail from any of these links.