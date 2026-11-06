# How Public-Key Cryptography Works

## 1. Introduction

Public-key cryptography, also called asymmetric cryptography, is a cryptographic system that uses two mathematically related keys:

- **Public key:** Can be distributed to other users and systems.
- **Private key:** Must remain confidential and under the control of its owner.

The two keys have different roles. A public key can be used to encrypt information for its owner or verify a digital signature created with the corresponding private key.

The private key can decrypt appropriately encrypted information or create digital signatures that can be verified using the corresponding public key.

Public-key cryptography addresses important security requirements:

| Security requirement | Mechanism |
|---|---|
| Confidentiality | Encryption with the recipient's public key |
| Authentication | Digital signature verification |
| Integrity | Cryptographic hash and signature verification |
| Non-repudiation evidence | Digital signatures combined with identity and key-management controls |
| Trust establishment | Certificates and trusted certificate authorities |
| Secure key establishment | Public-key cryptographic mechanisms |

Public-key cryptography does not automatically establish the identity of a public-key owner. A system must establish trust in the relationship between an identity and its public key.

## 2. Symmetric and Asymmetric Cryptography

### Symmetric cryptography

Symmetric encryption uses the same secret key for encryption and decryption.

A simplified representation is:

`Ciphertext = Encrypt(SecretKey, Plaintext)`

`Plaintext = Decrypt(SecretKey, Ciphertext)`

The communicating parties must securely obtain the same secret key.

AES is a widely used symmetric encryption algorithm.

### Asymmetric cryptography

Asymmetric cryptography uses separate public and private keys.

For confidentiality:

`Ciphertext = Encrypt(PublicKey, Plaintext)`

`Plaintext = Decrypt(PrivateKey, Ciphertext)`

For digital signatures:

`Signature = Sign(PrivateKey, Message)`

`Verification = Verify(PublicKey, Message, Signature)`

The public key does not reveal the private key through any practically feasible computation when secure algorithms and suitable key sizes are used.

### Comparison

| Property | Symmetric cryptography | Asymmetric cryptography |
|---|---|---|
| Keys | Shared secret | Public/private pair |
| Encryption speed | Generally faster | Generally slower |
| Key distribution | Requires secure secret distribution | Public key can be distributed openly |
| Digital signatures | Not provided by ordinary symmetric encryption | Supported |
| Typical algorithms | AES | RSA, elliptic-curve cryptography |
| Common application | Data encryption | Key establishment and signatures |

The two approaches are frequently combined.

## 3. Mathematical Foundation of RSA

RSA is a public-key cryptographic algorithm based on modular arithmetic and the computational difficulty of factoring sufficiently large products of prime numbers.

### Prime numbers

A prime number has exactly two positive divisors: one and itself.

Examples:

- 7
- 11
- 13
- 17
- 19

RSA begins with two distinct large prime numbers.

Let:

- \(p\) = first prime number
- \(q\) = second prime number

Calculate the modulus:

\[
n=pq
\]

Calculate Euler's totient for this modulus:

\[
\phi(n)=(p-1)(q-1)
\]

Choose a public exponent \(e\) satisfying:

\[
1<e<\phi(n)
\]

and:

\[
\gcd(e,\phi(n))=1
\]

Calculate the private exponent \(d\):

\[
ed\equiv 1\pmod{\phi(n)}
\]

The private exponent is the modular multiplicative inverse of the public exponent.

### Educational example

Use:

\[
p=61,\quad q=53
\]

Then:

\[
n=61\times53=3233
\]

\[
\phi(n)=60\times52=3120
\]

Choose:

\[
e=17
\]

The modular inverse is:

\[
d=2753
\]

Verification:

\[
17\times2753=46801
\]

\[
46801\bmod3120=1
\]

The resulting keys are:

| Key | Components |
|---|---|
| Public key | \((3233,17)\) |
| Private key | \((3233,2753)\) |

These deliberately small values are used only to demonstrate RSA mathematics.

### RSA encryption

For a message represented by an integer \(m\), where:

\[
0\leq m<n
\]

Encryption is:

\[
c=m^e\bmod n
\]

### RSA decryption

The private key recovers the original message:

\[
m=c^d\bmod n
\]

The mathematical relationship between the exponents makes decryption possible.

The C++ implementation demonstrates these operations using small educational integers.

**Important security distinction:** Textbook RSA is not secure for real-world encryption. Production RSA encryption requires secure padding such as RSA-OAEP. Production signatures should use RSA-PSS.

## 4. Public and Private Key Generation

The Python, JavaScript, and Java implementations generate actual RSA key pairs using established cryptographic libraries.

A typical key-generation workflow is:

1. Select a permitted RSA key size.
2. Generate two cryptographically suitable prime factors.
3. Calculate the RSA modulus and exponents.
4. Construct the private key.
5. Derive the corresponding public key.
6. Calculate a public-key fingerprint.
7. Register the public key with its owner and purpose.

The implementations use RSA key sizes of 2048 bits or greater.

### Public-key representation

The implementations support PEM serialization.

PEM is a textual encoding commonly used to represent cryptographic objects.

Two important formats are:

| Format | Purpose |
|---|---|
| SubjectPublicKeyInfo (SPKI) | Public-key representation |
| PKCS#8 | Private-key representation |

The public key can be distributed to other participants.

The private key should be protected using encrypted storage, access controls, hardware security modules, or managed key-management services.

The private key must never be distributed alongside the public key.

### Key fingerprints

A fingerprint is a digest calculated from a public-key representation.

The implementations use SHA-256:

\[
Fingerprint=SHA256(PublicKey)
\]

A fingerprint provides a compact identifier for comparing public keys.

It does not independently prove that a key belongs to a particular person.

An attacker can distribute a different public key and falsely claim ownership. Identity verification requires an appropriate trust mechanism.

## 5. RSA Encryption and Decryption

### Encryption workflow

Consider Alice sending confidential information to Bob.

Bob generates a key pair and shares his public key with Alice.

Alice:

1. Obtains Bob's public key.
2. Verifies that the key is associated with Bob.
3. Encrypts the message using Bob's public key.
4. Sends the ciphertext to Bob.

Bob:

1. Receives the ciphertext.
2. Uses his private key to decrypt it.
3. Obtains the original plaintext.

Plain-text representation:

    Bob generates:
        Public Key
        Private Key

    Bob ---------------- Public Key ----------------> Alice

    Alice:
        Plaintext
            |
            v
        RSA-OAEP Encryption
            |
            v
        Ciphertext
            |
            v
        Sends to Bob

    Bob:
        Ciphertext
            |
            v
        RSA Private-Key Decryption
            |
            v
        Original Plaintext

An attacker who intercepts the ciphertext should not be able to recover the plaintext without Bob's private key.

### RSA-OAEP

OAEP stands for Optimal Asymmetric Encryption Padding.

It provides randomized padding for RSA encryption.

The Python and JavaScript implementations use RSA-OAEP with SHA-256.

The Java implementation uses:

`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

The C++ implementation demonstrates the underlying RSA mathematics without OAEP. Its encryption mechanism is intentionally unsuitable for production.

### RSA encryption limitations

RSA cannot efficiently encrypt arbitrary large files or messages directly.

The maximum plaintext length depends on the modulus size and padding configuration.

For RSA-OAEP with SHA-256:

\[
mLen\leq k-2hLen-2
\]

Where:

- \(k\) is the RSA modulus length in bytes.
- \(hLen\) is the SHA-256 digest length, 32 bytes.
- \(mLen\) is the maximum plaintext length.

For a 2048-bit RSA key:

\[
mLen\leq256-64-2=190
\]

This limitation motivates hybrid encryption.

## 6. Hybrid Encryption

Hybrid encryption combines asymmetric and symmetric cryptography.

Instead of encrypting a large document directly with RSA, the sender generates a random symmetric session key.

The session key encrypts the document using AES.

RSA encrypts the session key for the recipient.

### Hybrid encryption workflow

    Sender
       |
       v
    Generate random AES-256 session key
       |
       +------------------------------+
       |                              |
       v                              v
    Original document             RSA-OAEP
       |                              |
       v                              v
    AES-256-GCM encryption       Encrypt session key
       |                              |
       v                              v
    Encrypted document           Encrypted session key
       |                              |
       +---------------+--------------+
                       |
                       v
                Encrypted envelope
                       |
                       v
                    Recipient

The recipient:

1. Uses the private RSA key to recover the session key.
2. Uses the recovered AES key to decrypt the document.
3. Verifies the AES-GCM authentication tag.
4. Accepts the plaintext only when authentication succeeds.

### AES-256-GCM

GCM stands for Galois/Counter Mode.

AES-GCM provides authenticated encryption with associated data.

It provides:

- Confidentiality.
- Ciphertext integrity.
- Authentication of encrypted data.
- Authentication of additional associated data.

The envelope implementations contain:

| Field | Purpose |
|---|---|
| Encrypted session key | AES key protected by RSA |
| Nonce | Unique encryption input for the AES-GCM key |
| Ciphertext | Encrypted application data |
| Authentication tag | Detects modification |
| Recipient fingerprint | Identifies the intended public-key recipient |
| Algorithm identifier | Identifies the encryption configuration |

The examples use a 256-bit AES key, a 96-bit nonce, and a 128-bit authentication tag.

A nonce must not be reused with the same AES-GCM key.

Authentication failure must result in rejection of the plaintext.

### Additional authenticated data

Additional authenticated data (AAD) is not encrypted, but its integrity is protected.

The implementations bind the recipient's public-key fingerprint to the AES-GCM operation.

This prevents an envelope from being silently reassigned to another recipient identity without detection.

## 7. Cryptographic Hash Functions

A cryptographic hash function converts input data of arbitrary length into a fixed-length digest.

SHA-256 produces 256-bit output.

\[
Digest=SHA256(Message)
\]

Important hash properties include:

- Deterministic output.
- Fixed output length.
- Preimage resistance.
- Second-preimage resistance.
- Collision resistance.

A small change in the input should produce a substantially different digest.

### Hashing versus encryption

| Property | Hashing | Encryption |
|---|---|---|
| Primary purpose | Integrity fingerprint | Confidentiality |
| Output | Fixed-length digest | Ciphertext |
| Reversible | No practical reversal | Yes, with appropriate key |
| Secret key required | Not for ordinary SHA-256 | Yes |
| Typical use | Signature processing | Secure communication |

Hashing does not conceal information.

A hash is not an encryption algorithm.

## 8. Digital Signatures

A digital signature provides cryptographic evidence that a message was signed using a particular private key.

It supports:

- Authentication of the signing key.
- Integrity verification.
- Evidence of authorization when combined with appropriate identity controls.

### Signing workflow

Alice wants to sign a payment authorization.

1. Alice prepares the document.
2. A SHA-256 digest is calculated.
3. The signing algorithm uses Alice's private key to generate a signature.
4. Alice sends the document and signature to Bob.
5. Bob obtains Alice's trusted public key.
6. Bob verifies the signature.
7. Bob accepts the document only when verification succeeds.

Representation:

    Original Document
           |
           v
       SHA-256
           |
           v
        Digest
           |
           v
    Alice's Private Key
           |
           v
    Digital Signature

    Document + Signature
           |
           v
          Bob
           |
           v
    Alice's Public Key
           |
           v
    Signature Verification
           |
       +---+---+
       |       |
       v       v
     Valid   Invalid

### RSA-PSS

Probabilistic Signature Scheme (PSS) is a standardized RSA signature-padding scheme.

It uses hashing and randomized padding to provide secure RSA signatures.

The Python and JavaScript implementations use RSA-PSS with SHA-256.

The Java implementation uses the `RSASSA-PSS` algorithm with explicit SHA-256 parameters.

The C++ implementation uses simplified modular exponentiation for educational demonstration. It does not implement RSA-PSS.

### Signature verification

A signature verification operation considers:

- The original message.
- The signature.
- The corresponding public key.
- The signature algorithm and its parameters.

If the message changes after signing, verification should fail.

A valid signature does not independently prove that the person controlling the signing key is the claimed individual. That requires identity binding and key protection.

## 9. Digital Certificates and PKI

A public key alone does not establish its owner's identity.

Public Key Infrastructure (PKI) provides mechanisms for establishing and managing trust relationships between identities and public keys.

### Certificate authority

A Certificate Authority (CA) is an entity that issues digital certificates.

A certificate typically associates:

- Subject identity.
- Subject public key.
- Issuer identity.
- Serial number.
- Validity period.
- Signature algorithm.
- Issuer's digital signature.

A CA signs the certificate using its private signing key.

The certificate recipient verifies that signature using the CA's trusted public key.

### Certificate trust workflow

    Root Certificate Authority
             |
             v
       Issues or signs
             |
             v
    Intermediate Certificate Authority
             |
             v
       Issues certificate
             |
             v
       Subject Certificate
             |
             v
       Subject Public Key

A certificate chain must be validated according to applicable trust and certificate policies.

### Certificate validation

A complete certificate-validation process considers:

- Certificate signature.
- Issuer trust.
- Certificate validity period.
- Subject identity.
- Key usage and extended key usage.
- Basic constraints.
- Name constraints where applicable.
- Certificate revocation information.
- Certificate chain construction.
- Applicable cryptographic algorithms and policies.

The Python and JavaScript examples implement simplified signed certificate records.

They are educational representations, not complete X.509 implementations.

The SQL implementation stores certificate metadata and models trust and expiry checks. It does not independently verify certificate signatures.

## 10. Key Management and Lifecycle

Secure cryptography depends on secure key management.

A cryptographically strong algorithm cannot compensate for an exposed private key.

### Key lifecycle

    Key Generation
          |
          v
      Registration
          |
          v
       Active Use
          |
          v
     Monitoring
          |
          v
      Rotation
          |
          v
    Historical Retention
          |
          v
       Expiration

Revocation is an alternative transition that invalidates a key for future authorized operations.

### Key states

| State | Meaning |
|---|---|
| ACTIVE | Permitted for authorized operations |
| ROTATED | Superseded by a replacement key |
| REVOKED | Explicitly invalidated |
| EXPIRED | Validity period has ended |

A rotated key may still be required to decrypt historical data.

Revocation must be distinguished from deleting historical cryptographic records.

### Key rotation

Key rotation replaces an existing key pair with a new key pair.

The process should:

1. Generate the replacement key pair.
2. Validate its algorithm and strength.
3. Register its public key.
4. Update dependent certificates and systems.
5. Transition the old key into its historical state.
6. Preserve required access to historical encrypted information.
7. Audit the rotation.

An application must not assume that an old encrypted message can be decrypted with a replacement private key.

### Private-key protection

Important controls include:

- Encrypted private-key storage.
- Hardware security modules.
- Managed key-management services.
- Role-based access control.
- Multi-person administrative approval.
- Audit logging.
- Backup and recovery controls.
- Separation of signing and encryption keys.
- Key rotation and revocation procedures.

## 11. Implementation Architecture

The five source files approach the subject from different engineering perspectives.

| File | Implementation perspective | Main functionality |
|---|---|---|
| Python | Cryptographic application | RSA, AES-GCM, certificates, serialization and tests |
| JavaScript | Event-driven security service | Asynchronous key generation, registry events and hybrid encryption |
| C++17 | Mathematical implementation | Modular arithmetic and educational RSA |
| Java 17 | Enterprise security architecture | Domain models, policies, authorization and audit |
| PostgreSQL | Persistent security workflow | Key registry, certificates, messages and verification records |

### Python implementation

The Python program uses the `cryptography` package.

Its major components are:

| Component | Responsibility |
|---|---|
| `KeyPair` | RSA key generation and serialization |
| `RSAService` | Encryption, decryption and signatures |
| `EncryptedEnvelope` | Structured encrypted-message representation |
| `HybridEncryption` | AES-GCM and RSA-OAEP integration |
| `KeyStore` | Key registration and lifecycle |
| `DigitalCertificate` | Simplified certificate issuance and verification |
| `CryptographyTests` | Functional and tampering tests |

The implementation includes malformed-envelope validation, wrong-recipient rejection, revoked-key rejection, and authenticated-decryption failure handling.

The private-key serialization example uses password-protected PKCS#8.

Its sample password is for demonstration only.

### JavaScript implementation

The JavaScript program uses the built-in Node.js `crypto` module.

Its engineering focus is asynchronous processing and event-driven auditing.

| Component | Responsibility |
|---|---|
| `KeyPair` | RSA key generation |
| `KeyRegistry` | Key inventory and lifecycle |
| `PublicKeyService` | RSA encryption and signatures |
| `HybridCipher` | AES-GCM and RSA-OAEP |
| `CertificateAuthority` | Simplified certificate issuance |
| `AuditService` | Security event recording |

The registry uses a private `Map` to prevent direct external modification of its key inventory.

The event system records registration and revocation events.

The implementation validates envelope fields and rejects modified ciphertext.

### C++17 implementation

The C++ implementation concentrates on the mathematical operations underlying RSA.

| Component | Responsibility |
|---|---|
| `NumberTheory` | GCD, modular inverse and modular exponentiation |
| `RSAEngine` | Key construction and RSA operations |
| `KeyRegistry` | Key lifecycle |
| `TransactionService` | Signature verification before transaction acceptance |
| `RSAKeyPair` | Public and private key representation |
| `CipherMessage` | Encrypted message blocks |

Modular exponentiation uses repeated squaring.

Its complexity is approximately:

\[
O(\log e)
\]

modular multiplication operations for exponent \(e\).

The modular multiplication routine avoids ordinary multiplication overflow within its supported integer range.

The implementation uses small primes and unpadded RSA.

It does not implement secure production-grade RSA, cryptographic hashing, OAEP, PSS, or secure random prime generation.

Its purpose is mathematical understanding rather than real communication security.

### Java 17 implementation

The Java program models an enterprise security service.

| Component | Responsibility |
|---|---|
| `CryptoPolicy` | Enforces algorithm and key-strength rules |
| `KeyPairRecord` | Immutable key identity and controlled lifecycle |
| `KeyRegistry` | Concurrent key inventory |
| `HybridEncryptionService` | RSA-OAEP and AES-GCM |
| `DigitalSignatureService` | RSA-PSS signing and verification |
| `CertificateAuthority` | Simplified certificate workflow |
| `TransactionAuthorizationService` | Signature-based transaction authorization |
| `AuditService` | Concurrent audit-event storage |

The implementation uses Java records for audit events and certificates.

It also uses defensive copies when storing and exposing byte arrays in encrypted envelopes.

This reduces unintended mutation of cryptographic data.

## 12. PostgreSQL Data Model

The database implementation models a persistent enterprise cryptographic workflow.

### Main entities

| Table | Purpose |
|---|---|
| `organizations` | Organization records |
| `identities` | Users and service identities |
| `algorithm_policies` | Permitted algorithms and minimum strengths |
| `cryptographic_keys` | Public-key registry |
| `certificate_authorities` | Trusted certificate issuers |
| `digital_certificates` | Certificate metadata |
| `encrypted_messages` | Encrypted message envelopes |
| `signed_documents` | Signed document records |
| `signature_verifications` | Verification outcomes |
| `security_audit_events` | Security event history |

### Relationship model

    Organizations
          |
          v
       Identities
          |
          v
    Cryptographic Keys
          |
          +--------------------+
          |                    |
          v                    v
    Digital Certificates   Encrypted Messages
          |
          v
    Certificate Authorities

    Identities
          |
          v
    Signed Documents
          |
          v
    Signature Verifications
          |
          v
    Security Audit Events

### Database integrity

The SQL implementation uses:

- Primary keys for record identity.
- Foreign keys for relationship integrity.
- Unique constraints for fingerprints and references.
- Check constraints for valid cryptographic metadata.
- Indexes for key lookup and reporting.
- Triggers for key-registration validation and lifecycle auditing.
- Functions for key eligibility and state changes.
- Procedures for encrypted-message registration.
- Transactions for key rotation.

The database validates metadata and workflow conditions.

Cryptographic operations remain the responsibility of application cryptographic libraries.

The sample PEM strings, signatures, ciphertexts and fingerprints are illustrative database records, not cryptographically valid generated artifacts.

## 13. Security Failure Conditions

Public-key systems must account for more than successful encryption and decryption.

| Failure condition | Security consequence | Appropriate control |
|---|---|---|
| Private-key disclosure | Unauthorized decryption or signing | Revoke and replace affected key |
| Public-key substitution | Communication with an attacker | Authenticate key ownership |
| Modified ciphertext | Corrupted or manipulated data | Authenticated encryption |
| Invalid signature | Untrusted document | Reject verification |
| Expired certificate | Certificate no longer valid | Check validity period |
| Revoked certificate | Trust relationship invalidated | Check revocation information |
| Weak RSA key | Reduced cryptographic security | Enforce key-strength policy |
| Reused GCM nonce | Potential confidentiality and integrity failure | Enforce nonce uniqueness |
| Incorrect recipient key | Decryption failure | Verify recipient fingerprint |
| Algorithm downgrade | Reduced security | Enforce approved algorithms |
| Insecure private-key backup | Unauthorized key recovery | Protect backups and access |

Error messages should not reveal sensitive decryption details to unauthorized parties.

Cryptographic failure should be logged without recording private keys, session keys, plaintext credentials, or other confidential material.

## 14. Performance Considerations

Public-key operations are computationally more expensive than symmetric encryption.

For this reason, hybrid encryption is the normal approach for large application messages.

| Operation | Performance consideration |
|---|---|
| RSA key generation | Expensive prime generation |
| RSA encryption | Relatively expensive asymmetric operation |
| RSA decryption | Computationally expensive private-key operation |
| RSA signing | Private-key computation |
| RSA verification | Public-key computation |
| AES-GCM | Efficient for large messages |
| SHA-256 | Efficient digest calculation |
| Key fingerprint lookup | Efficient indexed lookup |

A public-key infrastructure must also account for:

- Key-generation frequency.
- Certificate issuance volume.
- Certificate validation latency.
- Revocation-checking latency.
- Hardware cryptographic capacity.
- Concurrent signing and decryption requests.
- Secure key backup and recovery.
- Audit retention requirements.

Database indexes support metadata retrieval but do not improve the mathematical performance of RSA itself.

## 15. Practical Applications

Public-key cryptography is used in many security systems.

| Application | Cryptographic use |
|---|---|
| HTTPS and TLS | Authentication and secure key establishment |
| Secure email | Message confidentiality and signatures |
| Software distribution | Publisher authentication and integrity |
| Digital document signing | Verification of signed documents |
| Banking systems | Transaction authorization and secure communication |
| API authentication | Asymmetric signing and token verification |
| Device authentication | Device identity and certificate-based trust |
| PKI | Certificate issuance and trust management |
| Secure enterprise messaging | Hybrid encryption |

### HTTPS and TLS

In modern TLS, public-key cryptography is used primarily for authentication and secure key establishment.

Modern TLS 1.3 commonly uses ephemeral elliptic-curve Diffie-Hellman key exchange rather than RSA key transport.

RSA can still be used for certificate-based digital signatures.

This distinction is important:

- RSA encryption protects information using a recipient's public key.
- Digital signatures authenticate signed data.
- Diffie-Hellman establishes shared secret material.
- Symmetric authenticated encryption protects the actual application traffic.

These mechanisms serve different purposes.

## 16. Limitations and Implementation Boundaries

The implementations deliberately distinguish real cryptographic operations from educational models.

| Implementation | Real cryptographic operations | Limitations |
|---|---|---|
| Python | RSA-OAEP, RSA-PSS, AES-GCM, SHA-256 | Simplified certificate model |
| JavaScript | RSA-OAEP, RSA-PSS, AES-GCM, SHA-256 | Simplified certificate model |
| C++17 | Educational RSA arithmetic | Small keys, textbook RSA, no secure padding |
| Java 17 | RSA-OAEP, RSA-PSS, AES-GCM, SHA-256 | Simplified certificate model |
| PostgreSQL | Key metadata, lifecycle and verification records | Does not perform RSA or AES encryption |

The C++ implementation must never be used to protect real data.

The certificate representations in the programming examples do not implement complete X.509 certificate processing.

The PostgreSQL database must receive actual cryptographic artifacts from a trusted application service rather than treating illustrative records as valid cryptographic material.

Production deployments should use maintained cryptographic libraries, secure random-number generation, approved algorithm configurations, protected private-key storage, and formal key-management procedures.

## 17. Execution Requirements

| Deliverable | Runtime | Dependency |
|---|---|---|
| Python | Python 3.10+ | `cryptography` |
| JavaScript | Node.js 20+ | Built-in modules |
| C++17 | C++17 compiler | Standard library |
| Java | Java 17 | Java standard library |
| PostgreSQL | PostgreSQL 15+ | PostgreSQL database |

Python requires installation of the `cryptography` package.

The JavaScript program runs using Node.js.

The C++ program can be compiled with a C++17-compatible compiler.

The Java program uses Java's built-in cryptographic architecture.

The SQL script creates its schema, tables, constraints, functions, procedures, triggers, views, sample data, and reporting queries within a transaction.
