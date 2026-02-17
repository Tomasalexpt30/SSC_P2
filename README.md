<div align="center">

# Oblivious Decentralized IAM Integrated with Secure Encrypted Block Storage

![Java](https://img.shields.io/badge/Java-17-blue?style=for-the-badge&logo=openjdk)
![TLS](https://img.shields.io/badge/TLS-1.2%2F1.3-green?style=for-the-badge&logo=letsencrypt)
![ECDSA](https://img.shields.io/badge/ECDSA-P--256-purple?style=for-the-badge)
![JWT](https://img.shields.io/badge/JWT-ES256-orange?style=for-the-badge)
![AES](https://img.shields.io/badge/AES-256--GCM-red?style=for-the-badge)

### Course – Computer Systems Security  

*Distributed, Oblivious Identity & Access Management system integrated with a secure encrypted block storage service.*

</div>

## Project Overview

This project implements a **decentralized, oblivious Identity and Access Management (IAM) architecture** integrated with a **secure searchable encrypted block storage service (OBSS)**.

The system is composed of three independent distributed servers:

- **OAS** – Oblivious Authentication Server  
- **OAMS** – Oblivious Access Management Server  
- **OBSS** – Oblivious Block Storage Server  

All components communicate over **TLS-secured channels**, and all sensitive data remains encrypted end-to-end.

## Main Goals

- Oblivious identity registration using **public-key based identifiers**
- Strong authentication using **ECDSA + challenge-response**
- Secure authorization via **JWT (ES256)**
- Fine-grained access control and sharing (GET / SEARCH)
- Encrypted block storage with deduplication
- Privacy-preserving keyword search
- Full client-side encryption (zero plaintext on server)


## System Architecture

### OAS – Oblivious Authentication Server

Responsible for:
- User registration based on **EC public keys**
- Password protection using **PBKDF2 (HmacSHA256, 200k iterations)**
- Challenge-response authentication
- JWT generation using **ES256 (ECDSA P-256)**
- Anti-replay protections (timestamps + nonces)

### OAMS – Oblivious Access Management Server

Responsible for:
- Managing sharing registrations (ACLs)
- Enforcing authorization for: `GET`, `SEARCH`
- Verifying JWT issued by OAS
- Verifying client ECDSA signatures
- Signing responses to guarantee authenticity

All ACL metadata is stored encrypted using **AES-256-GCM**.

### OBSS – Oblivious Block Storage Server

Responsible for:
- Storing encrypted file blocks
- Supporting: `STORE_BLOCK`, `GET_BLOCK`, `SEARCH`, `GET_DOC_BLOCKS`
- Deduplication using **SHA-256**
- Encrypted metadata persistence
- Token-based blind search

## Security Features

#### End-to-End Encryption
- AES-256-GCM per file
- Random IV per block
- Authenticated encryption (AEAD)

#### Strong Authentication
- ECDSA (P-256)
- Challenge-response protocol
- Public-key fingerprint identities
- Anti-replay protection

#### Secure Authorization
- JWT (ES256)
- Scoped permissions: `obss:get`, `obss:search`, `obss:share`
- Token expiration enforcement

#### Privacy-Preserving Search
- Keywords hashed (SHA-256)
- Server matches tokens without knowing plaintext
- Access filtered via OAMS ACL validation

#### Encrypted Persistence
- All server metadata encrypted using AES-GCM
- Integrity automatically verified via GCM tag
- No plaintext user database

## Technologies Used

| Technology | Purpose |
|------------|----------|
| **Java 17** | Core implementation |
| **TLS 1.2 / 1.3** | Secure communication |
| **ECDSA (P-256)** | Digital signatures |
| **JWT (ES256)** | Authentication tokens |
| **AES-256-GCM** | Authenticated encryption |
| **PBKDF2 (HmacSHA256)** | Password hashing |
| **SHA-256** | Deduplication & blind search |
| **SecureRandom** | Cryptographic randomness |

---

## Setup Instructions

```bash
# 1 - Generate TLS Certificates

keytool -genkeypair -alias server -keyalg RSA -keysize 2048 \
-keystore serverkeystore.jks -storepass changeit -keypass changeit \
-dname "CN=localhost, OU=Dev, O=Dev, L=City, S=State, C=PT" -validity 3650

keytool -exportcert -alias server -keystore serverkeystore.jks \
-storepass changeit -rfc -file server.cer

keytool -importcert -alias server -file server.cer \
-keystore clienttruststore.jks -storepass changeit -noprompt

# 2 - Compile

javac *.java

# 3 - Start Servers (in separate terminals)

java ObliviousAuthServer
java ObliviousAccessServer
java BlockStorageServer

# 4 - Start Client

java Project2Client
```

## Academic Context

This project was developed as part of the **Computer Systems Security** course in the **MSc in Computer Engineering** program at **NOVA School of Science and Technology**.

With the Authors:
- **Tomás Alexandre**  
- **Nicolae Iachimovschi**
