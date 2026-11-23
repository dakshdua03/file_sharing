Recent advancements in secure file sharing have largely shifted away from centralized architectures (like traditional cloud servers) toward decentralized, cryptographically enforced networks. Based on recent literature, the major breakthroughs center around eliminating single points of failure, tying decryption directly to user identities, and immutably tracking data access.

Here is an overview of the core technological advancements and the foundational papers driving them:

### 1\. Decentralized Storage Networks (IPFS & Blockchain)

Traditional file sharing relies heavily on centralized cloud providers, which creates distinct targets for data breaches and server outages. Recent systems mitigate this by replacing central servers with the InterPlanetary File System (IPFS)—a distributed, peer-to-peer storage network that uses cryptographic hashes (content-addressing) instead of location-based URLs.

Because anyone can theoretically access nodes on IPFS, researchers pair it with consortium blockchains (like Hyperledger Fabric) to govern the data. The blockchain acts as an immutable ledger that records access logs, dynamic encryption keys, and file metadata, ensuring total data provenance and preventing unauthorized tampering during file transmission (Wen et al., 2024).

### 2\. Attribute-Based Encryption (ABE)

Rather than relying on static passwords, tokens, or traditional public/private key pairs, cutting-edge access control utilizes Attribute-Based Encryption (ABE). In an ABE framework, a file is encrypted based on an access policy, and a user's decryption key is tied mathematically to their specific real-world attributes (e.g., "Role: Auditor" AND "Department: Finance").

This allows data owners to execute fine-grained access control on decentralized networks. Even if a decentralized storage node is fully compromised, the data remains unreadable to anyone whose cryptographic attributes do not satisfy the file's original access policy (Wu et al., 2024).

### 3\. Hybrid Cryptography for Scale and Performance

A historical limitation of advanced cryptography like ABE is the computational overhead required to process complex mathematical access policies, which traditionally slowed down the sharing of large files or high-frequency data (like sensor outputs).

Recent breakthroughs resolve this bottleneck by employing hybrid models. Highly efficient symmetric algorithms, such as the Advanced Encryption Standard (AES), are used to encrypt the actual heavy file payload. Meanwhile, Key-Policy Attribute-Based Encryption (KP-ABE) is used solely to encrypt and protect the lightweight AES key. This allows the system to achieve high-throughput file sharing speeds while maintaining the strict, mathematically enforced security of attribute constraints (Wang et al., 2024).

**References**

Wang, T., Chen, K., Zheng, Z., Guo, J., Zhao, X., & Zhang, S. (2024). PrivShieldROS: An Extended Robot Operating System Integrating Ethereum and Interplanetary File System for Enhanced Sensor Data Privacy. _Sensors_, _24_(10), 3241. [https://doi.org/10.3390/s24103241](https://doi.org/10.3390/s24103241) Cited by: 20

Wen, F., Wang, Z., Qu, L., Huang, H., & Hu, X. (2024). Enhancing secure multi-group data sharing through integration of IPFS and hyperledger fabric. _PeerJ Computer Science_, _10_, e1962. [https://doi.org/10.7717/peerj-cs.1962](https://doi.org/10.7717/peerj-cs.1962) Cited by: 13

Wu, H., Liu, Y., Zhu, K., & Zhang, L. (2024). Data-Sharing System with Attribute-Based Encryption in Blockchain and Privacy Computing. _Symmetry_, _16_(11), 1550. [https://doi.org/10.3390/sym16111550](https://doi.org/10.3390/sym16111550) Cited by: 11