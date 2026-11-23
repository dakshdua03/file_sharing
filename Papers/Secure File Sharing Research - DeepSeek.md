Based on the search results, I have found several recent research papers that detail significant advancements in secure file-sharing systems. These papers cover a range of innovative approaches, from next-generation encryption protocols to decentralized architectures.

Here is a curated list of the most relevant papers with their URLs:

### 📄 Featured Research Papers

**1\. Securing End-To-End Encrypted File Sharing Services With the Messaging Layer Security Protocol**

-   **Authors:** Roland Helmich, Lars Braubach
    
-   **Published in:** _Concurrency and Computation: Practice and Experience_, 2025
    
-   **Key Contribution:** This paper proposes a novel architecture that integrates the **Messaging Layer Security (MLS) protocol** with attribute-based access control to achieve both **Post-Compromise Security (PCS)** and **Forward Secrecy (FS)** for file sharing. This means that even if a client's keys are stolen, the system can "self-heal" and secure future communications, while past data remains confidential. The authors present a working prototype and benchmark its key distribution scalability, finding it efficient for large groups (e.g., distributing 10,000 keys to 1000 clients is only about 40% slower than to 100 clients)[\-1](https://onlinelibrary.wiley.com/doi/full/10.1002/cpe.70414).
    
-   **URL:** [https://onlinelibrary.wiley.com/doi/full/10.1002/cpe.70414](https://onlinelibrary.wiley.com/doi/full/10.1002/cpe.70414)
    

**2\. VeriGuard-MPFS: Metadata-Protecting File Sharing with Provable Integrity and Malicious Security**

-   **Conference:** 2026 IEEE (Date of Conference: April 2026)
    
-   **Key Contribution:** This paper addresses the core dilemma of achieving strong security against malicious adversaries while maintaining efficiency for dynamic group sharing. It introduces VeriGuard-MPFS, which features a **verifiable lightweight key rotation mechanism** that reduces revocation overhead from O(N) to O(1) using proxy re-encryption. This allows for efficient user changes without sacrificing security[\-2](https://ieeexplore.ieee.org/abstract/document/11540666).
    
-   **URL:** [https://ieeexplore.ieee.org/abstract/document/11540666](https://ieeexplore.ieee.org/abstract/document/11540666)
    

**3\. DeSecShare: A Secure Decentralized File Sharing System Using Encrypted Data Chunking and Distributed Node Storage**

-   **Conference:** 2025 IEEE (Date of Conference: December 2025)
    
-   **Key Contribution:** DeSecShare is a proof-of-concept decentralized system that avoids the single point of failure and privacy risks of centralized cloud storage. It protects data by **encrypting files using AES, splitting them into smaller encrypted chunks, and distributing those chunks across independent storage nodes**. Only the uploader possesses the unique encryption key, preventing unauthorized access and ensuring resilience[\-8](https://ieeexplore.ieee.org/document/11346300).
    
-   **URL:** [https://ieeexplore.ieee.org/document/11346300](https://ieeexplore.ieee.org/document/11346300)
    

**4\. SFDS: Selective File Disclosure System**

-   **Authors:** Aditya Mitra, Quazi Fariha Tasnim, Hristina Mihajloska Trpcheska
    
-   **Published on arXiv:** July 2026
    
-   **Key Contribution:** This paper proposes a novel architecture for securely sharing read-only files based on the **Selective Disclosure JSON Web Token (SD-JWT)** standard. The system simplifies access control by embedding cryptographic signatures and integrity protection directly into the shared file, eliminating the need for complex centralized user databases or authentication services. It enables verifiable authenticity and selective disclosure of file contents[\-11](https://arxiv-org.ezproxy.obspm.fr/html/2607.09370v1).
    
-   **URL:** [https://arxiv-org.ezproxy.obspm.fr/html/2607.09370v1](https://arxiv-org.ezproxy.obspm.fr/html/2607.09370v1)
    

**5\. CloudShare: A Passwordless Cloud-Based File Storage and Sharing Framework**

-   **Conference:** 2025 IEEE (Date of Conference: June 2025)
    
-   **Key Contribution:** CloudShare eliminates common password-based vulnerabilities (like credential theft and reuse) by using a **challenge-response authentication protocol with asymmetric cryptography**. It also introduces **time-based access control** mechanisms, enabling users to restrict file availability to specific time windows for enhanced security[\-4](https://ieeexplore.ieee.org/document/11118777).
    
-   **URL:** [https://ieeexplore.ieee.org/document/11118777](https://ieeexplore.ieee.org/document/11118777)
    

**6\. AI-Powered File Security System with Facial Biometrics, QR Code, and OTP Verification**

-   **Authors:** Xinyi Loi, Ming Man Chan, Yuk Yii Chan
    
-   **Published in:** _Journal of Informatics and Web Engineering_, 2026
    
-   **Key Contribution:** This paper describes an AI-driven system that uses a multi-layered authentication strategy. It combines **AES-128 encryption with live facial recognition** (achieving 99% accuracy and 100% rejection against static image spoofing), unique QR codes, and OTP verification to mitigate impersonation and credential theft risks, guaranteeing confidentiality[\-6](https://journals.mmupress.com/index.php/jiwe/article/view/2023).
    
-   **URL:** [https://journals.mmupress.com/index.php/jiwe/article/view/2023](https://journals.mmupress.com/index.php/jiwe/article/view/2023)
    

___

### 🔍 Key Research Themes & Trends

The recent breakthroughs in secure file-sharing research are converging around several key themes:

-   **Next-Generation Security Guarantees:** Moving beyond basic encryption, research like the MLS-based system focuses on **Post-Compromise Security (PCS)** and **Forward Secrecy (FS)** to protect data even if long-term keys are stolen[\-1](https://onlinelibrary.wiley.com/doi/full/10.1002/cpe.70414)[\-2](https://ieeexplore.ieee.org/abstract/document/11540666).
    
-   **Decentralized & User-Controlled Architectures:** To mitigate the risks of centralized cloud providers, new systems use **decentralized storage (like IPFS) combined with blockchain** for transparent and immutable access control, or **encrypted data chunking** distributed across nodes[\-8](https://ieeexplore.ieee.org/document/11346300)[\-10](https://www.semanticscholar.org/paper/Design-and-Implementation-of-a-Decentralized-File-Ragav-Avadhani/80f506c299c6caf43137d7ffc59e5a374c3caac8)[\-13](https://www.semanticscholar.org/paper/DAGShare%3A-a-DAG-based-personal-file-sharing-with-Arshad-Bhutta/d6fe6279d5fdf3630db77bd7bad55ef24846d67d).
    
-   **Passwordless & Biometric Authentication:** To fight credential theft, new frameworks are moving away from vulnerable passwords toward **cryptographic authentication** (e.g., challenge-response) and **multi-factor systems using AI-driven facial biometrics and OTPs**[\-4](https://ieeexplore.ieee.org/document/11118777)[\-6](https://journals.mmupress.com/index.php/jiwe/article/view/2023).
    
-   **Enhanced Privacy & Sovereign Cloud:** Driven by data privacy regulations, research emphasizes **"server-blind" architecture** where the cloud provider cannot access content, even during collaboration. This is linked to growing interest in **sovereign cloud** solutions to ensure data stays within a jurisdiction[\-14](https://www.eurekalert.org/news-releases/1127321).
    
-   **Integrating File Security with Identity:** New models are exploring the use of **Verifiable Credentials (SD-JWT)** to ensure files are not only delivered securely but also carry cryptographic proof of authenticity and integrity, simplifying access management[\-11](https://arxiv-org.ezproxy.obspm.fr/html/2607.09370v1).
    

I hope this curated list of papers and trends provides a strong foundation for your research. If you need to focus on a specific aspect, like decentralized storage or post-compromise security, I can help find more targeted resources.

This response is AI-generated, for reference only.