# 🔐 AES Secure Chat System (End-to-End Encrypted Messaging)

A minimal end-to-end encrypted chat system built using Python sockets and AES encryption (via the Fernet protocol).  
This project demonstrates secure communication fundamentals including symmetric encryption, key derivation, message integrity verification, and encrypted TCP transport.

Developed as a cybersecurity engineering portfolio project to showcase real-world secure protocol design and implementation.

---

## 🚀 Features
- End-to-end encrypted 2-way messaging
- AES-256 encryption (via Fernet)
- PBKDF2 password-based key derivation
- Randomized IV for every message
- HMAC-SHA256 integrity protection (tamper-proof messages)
- Works over any network using TCP sockets
- Multi-threaded: send and receive simultaneously

---

## 🧠 How It Works (High-Level Architecture)

Client Input → Encrypt (AES + HMAC) → Token → Socket → Decrypt (AES + Verify HMAC) → Display

### Key Steps
- Password + Salt → PBKDF2 → Strong 256-bit key
- Fernet encrypts plaintext → generates token containing:
  - IV (initialization vector)
  - Ciphertext
  - HMAC authentication tag
  - Timestamp
- Token sent over socket → decrypted safely on receiver

---

## 🔐 Cryptography Used
| Component | Purpose |
|-----------|---------|
| AES-256   | Confidentiality |
| PBKDF2-HMAC-SHA256 | Derive strong key from password |
| HMAC | Detect message tampering |
| Base64 Token | Safe network transmission |

---
Run Server
python server.py

Run Client
python client.py


Enter the same shared password on both ends to begin encrypted communication.

🧪 Example Terminal Session
Server:
=== AES Encrypted Chat Server ===
Enter shared password: ********
[+] Client connected
[Client]: hello!

Client:
=== AES Encrypted Chat Client ===
Enter shared password: ********
[Server]: hi there!

⚠ Security Notes

Strong AES encryption, but password must be strong to resist brute-force attacks.

Salt exchange is static in v1 for simplicity — will be dynamic in v2.

Educational project: not production hardened (no authentication, MITM protection, or E2E identity verification yet).
