# Public Keys and Private Keys

## 1. Introduction

Public-key cryptography, also called asymmetric cryptography, uses mathematically related keys to perform cryptographic operations.

A key pair contains:

- **Public key:** Shared with other users, applications, or systems.
- **Private key:** Kept secret by its owner and protected against unauthorized access.

The public key and private key are mathematically related, but deriving the private key from a properly generated public key must be computationally infeasible under the security assumptions of the chosen algorithm.

Public-key cryptography supports confidentiality, authentication, digital signatures, and secure key establishment.

## 2. Core Concepts

### 2.1 Public keys

A public key can be distributed to other parties. Its permitted operations depend on the cryptographic algorithm.

Examples include:

- Encrypting information for the private-key owner using RSA-OAEP.
- Verifying a digital signature using RSA-PSS or Ed25519.
- Establishing a shared secret using X25519.

A public key does not need to be confidential. It does need to be authentic.

An attacker who substitutes a different public key can potentially impersonate the intended recipient or establish an attacker-controlled communication session.

### 2.2 Private keys

A private key must remain under the control of its authorized owner.

Its responsibilities include:

- Decrypting information encrypted with the corresponding public key.
- Producing digital signatures.
- Participating in cryptographic key-agreement operations.

Private-key compromise can undermine confidentiality, authenticity, or both, depending on the algorithm and protocol.

Private keys should not be committed to source repositories, included in application logs, transmitted through ordinary messaging channels, or stored in plaintext database columns.

### 2.3 Public and private key relationship

| Operation | Public key | Private key |
|---|---|---|
| RSA encryption | Encrypts | Decrypts |
| RSA-PSS signature | Verifies | Signs |
| Ed25519 signature | Verifies | Signs |
| X25519 key agreement | Peer public input | Local private input |
| Public-key fingerprint | Calculated from public material | Not required |

The direction of the operation is important.

Encryption and signing are different cryptographic operations. A digital signature is not simply encryption performed with a private key.

## 3. Asymmetric Cryptographic Algorithms

### 3.1 RSA

RSA is based on the mathematical difficulty of factoring a large composite integer.

Its public key contains:

- Modulus `n`.
- Public exponent `e`.

Its private key contains:

- Modulus `n`.
- Private exponent `d`.

The modulus is calculated as:

`n = p × q`

where `p` and `q` are large prime numbers.

The Euler totient for the basic RSA construction is:

`φ(n) = (p - 1)(q - 1)`

The public and private exponents satisfy:

`e × d ≡ 1 mod φ(n)`

A simplified mathematical encryption operation is:

`c = m^e mod n`

The corresponding decryption operation is:

`m = c^d mod n`

These equations describe the mathematical construction, not a complete secure encryption protocol.

**RSA-OAEP** introduces probabilistic padding for encryption. It prevents the weaknesses associated with directly encrypting unpadded messages.

**RSA-PSS** provides a probabilistic digital signature scheme.

The Python implementation includes educational textbook RSA mathematics. The JavaScript and Java implementations use actual RSA-OAEP and RSA-PSS operations through cryptographic providers.

The C++ implementation uses small integers to demonstrate RSA relationships. It must not be used for real encryption or signatures.

### 3.2 Elliptic-curve cryptography

Elliptic-curve cryptography uses mathematical operations over elliptic-curve groups.

It provides security based on the difficulty of the elliptic-curve discrete logarithm problem.

Important advantages include:

- Smaller key representations than conventional RSA at comparable security levels.
- Efficient signing and verification with appropriate algorithms.
- Efficient key agreement.

Two algorithms are implemented in the JavaScript and Java deliverables:

| Algorithm | Primary purpose |
|---|---|
| Ed25519 | Digital signatures |
| X25519 | Shared-secret establishment |

Ed25519 and X25519 are not interchangeable.

Ed25519 signs and verifies messages. X25519 establishes a shared secret between parties.

### 3.3 Diffie-Hellman key exchange

Diffie-Hellman enables two parties to establish a common secret without transmitting that secret directly.

Its basic mathematical model uses:

- A public prime number `p`.
- A public generator `g`.
- Alice's private value `a`.
- Bob's private value `b`.

Their public values are:

`A = g^a mod p`

`B = g^b mod p`

Their shared secrets are:

`S_A = B^a mod p`

`S_B = A^b mod p`

Both produce:

`S = g^(ab) mod p`

The Python and C++ implementations demonstrate this mathematical process using small parameters.

The JavaScript and Java implementations use X25519 through their cryptographic providers.

Unauthenticated Diffie-Hellman alone does not prevent man-in-the-middle attacks. Public keys or ephemeral exchange values must be authenticated through an appropriate protocol.

## 4. Encryption and Decryption

### 4.1 Asymmetric encryption

Asymmetric encryption provides a mechanism for protecting information for an intended recipient.

The workflow is:

1. The recipient generates a public/private key pair.
2. The recipient distributes the public key.
3. The sender obtains and authenticates the recipient's public key.
4. The sender encrypts the information using that public key.
5. The sender transmits the ciphertext.
6. The recipient decrypts it using the corresponding private key.

The sender does not need access to the recipient's private key.

### 4.2 Why hybrid encryption is used

Asymmetric algorithms are computationally more expensive than symmetric encryption and impose message-size limitations.

Practical systems therefore use hybrid encryption.

A typical workflow is:

`Recipient public key`

`        ↓`

`Authenticated key establishment or key encapsulation`

`        ↓`

`Shared symmetric key`

`        ↓`

`AES-256-GCM encryption`

`        ↓`

`Ciphertext + nonce + authentication tag`

The recipient derives or recovers the same symmetric key and decrypts the ciphertext.

The JavaScript and Java implementations demonstrate X25519, HKDF-SHA256, and AES-256-GCM.

AES-256-GCM provides both confidentiality and authentication of encrypted data. The nonce must never be reused with the same AES-GCM key.

## 5. Digital Signatures

A digital signature establishes whether a signed message has been modified and whether it was signed using the corresponding private key.

The workflow is:

1. A signer prepares a document.
2. A cryptographic hash is calculated.
3. The signing algorithm processes the document or its digest with the private key.
4. The resulting signature is distributed with the document.
5. A verifier obtains the corresponding public key.
6. The verifier checks the signature.

A valid signature provides evidence of integrity and possession or use of the corresponding private key.

It does not automatically prove the real-world identity of the signer. That requires a trustworthy identity-to-key binding and appropriate identity verification.

### 5.1 RSA-PSS

RSA-PSS is a probabilistic RSA signature scheme.

The JavaScript and Java implementations use SHA-256 and RSA-PSS with a 32-byte salt.

The verifier checks the signature using the RSA public key.

### 5.2 Ed25519

Ed25519 is a modern elliptic-curve signature algorithm.

It uses a fixed-size signature and public-key representation.

The JavaScript and Java implementations demonstrate:

- Key generation.
- Message signing.
- Signature verification.
- Rejection of modified messages.

### 5.3 Signature failure conditions

A verification operation can fail when:

- The document has changed.
- The signature has been corrupted.
- The wrong public key is supplied.
- The signature format is invalid.
- The signing key has been compromised or revoked.
- The verification algorithm does not match the signing algorithm.

## 6. Public-Key Distribution and Authentication

Public-key distribution is a separate security problem from key generation.

Receiving a public key does not establish that it belongs to the intended party.

### 6.1 Public-key fingerprints

A fingerprint is a short identifier derived from public-key material using a cryptographic hash function.

The implementations use SHA-256 for fingerprint generation.

Fingerprints support:

- Key comparison.
- Key identification.
- Duplicate detection.
- Verification of exported public-key material.
- Key inventory and auditing.

Fingerprints do not independently establish identity. They must be compared against a trusted reference.

### 6.2 Public-key certificates

A digital certificate binds a public key to an identity through a certificate authority.

An X.509 certificate commonly includes:

- Subject identity.
- Issuer identity.
- Public-key information.
- Validity period.
- Serial number.
- Signature algorithm.
- Issuer signature.
- Extensions and usage restrictions.

Certificate validation involves more than checking the certificate's expiration date.

A relying party must also consider:

- Certificate-chain validation.
- Issuer trust.
- Name constraints.
- Key usage.
- Extended key usage.
- Revocation status.
- Algorithm restrictions.
- Certificate policy.

The PostgreSQL implementation models certificate records and their lifecycle.

It does not implement X.509 parsing, certificate-chain verification, or certificate-authority signing.

## 7. Key Management Lifecycle

Cryptographic key management covers the entire lifecycle of a key.

### 7.1 Generation

Keys must be generated using suitable cryptographic random-number generators.

Security depends on:

- Adequate entropy.
- Appropriate algorithms.
- Suitable key sizes.
- Correct random-number generation.
- Secure provider implementations.

The JavaScript and Java implementations use platform cryptographic providers.

The Python and C++ demonstrations use educational mathematical constructions and must not be treated as production key generators.

### 7.2 Registration

Registration records important metadata:

- Key identifier.
- Owner.
- Algorithm.
- Purpose.
- Public-key fingerprint.
- Creation timestamp.
- Expiration timestamp.
- Storage reference.
- Current lifecycle state.

The PostgreSQL implementation enforces relational integrity using primary keys, foreign keys, unique constraints, and check constraints.

### 7.3 Activation

A key becomes eligible for authorized cryptographic operations after registration and applicable security checks.

Activation should consider:

- Key-generation success.
- Policy compliance.
- Owner authorization.
- Key purpose.
- Expiration.
- Secure private-key custody.

### 7.4 Rotation

Rotation replaces an existing key with a new key.

Typical reasons include:

- Scheduled key replacement.
- Cryptographic policy changes.
- Algorithm migration.
- Suspected exposure.
- Expiration planning.

A rotation should preserve the relationship between old and new key versions.

A system must consider historical signature verification, encrypted data recovery, certificate replacement, and dependent application updates.

The implementations include key-version tracking or rotation state transitions.

### 7.5 Revocation

Revocation invalidates a key before its planned expiration.

Possible reasons include:

- Private-key compromise.
- Unauthorized access.
- Personnel or service-account changes.
- Incorrect key distribution.
- Certificate revocation.
- Policy violations.

Revocation should prevent future unauthorized use.

Revocation does not automatically recover information previously decrypted by an attacker or invalidate every historical signature.

### 7.6 Expiration and destruction

Expiration identifies a key that has reached the end of its approved validity period.

Destruction is a separate lifecycle operation involving the removal or cryptographic erasure of protected key material.

A database status change alone does not prove that private-key material has been destroyed from an HSM, KMS, backup, or replicated keystore.

## 8. Security Controls

| Security control | Purpose |
|---|---|
| Cryptographic random generation | Prevent predictable keys |
| RSA-OAEP | Protect RSA-encrypted messages |
| RSA-PSS | Provide RSA digital signatures |
| Ed25519 | Provide elliptic-curve signatures |
| X25519 | Establish shared secrets |
| HKDF | Derive application-specific symmetric keys |
| AES-256-GCM | Provide authenticated symmetric encryption |
| SHA-256 | Calculate fingerprints and digests |
| HSM | Protect sensitive private-key operations |
| KMS | Centralize key lifecycle and access management |
| Certificate validation | Establish public-key identity bindings |
| Revocation | Restrict use of compromised keys |
| Audit logging | Record security-relevant key operations |

### 8.1 Private-key custody

Private-key material should be protected through controlled storage and access.

Common approaches include:

- Hardware Security Modules.
- Cloud Key Management Services.
- Operating-system keystores.
- Encrypted application keystores.
- Dedicated cryptographic appliances.

The PostgreSQL schema stores references to secure key storage rather than storing plaintext private-key bytes.

### 8.2 Access control

Key access must be based on identity, purpose, and authorization.

A service permitted to verify signatures does not necessarily need permission to sign documents.

A service permitted to encrypt information does not automatically need permission to decrypt it.

The SQL implementation separates key ownership, key purpose, access policies, and access grants.

### 8.3 Auditability

Key operations should produce traceable events.

Relevant events include:

- Key registration.
- Key activation.
- Key rotation.
- Key revocation.
- Key destruction.
- Signature creation.
- Signature verification.
- Encryption failure.
- Access denial.

The database implementation uses triggers and audit tables to record key lifecycle changes.

Audit records should be protected against unauthorized modification and deletion.

## 9. Python Implementation

The Python file provides an educational mathematical model of public-key cryptography.

| Component | Implementation |
|---|---|
| Prime generation | Miller-Rabin probable-prime testing |
| RSA | Modular exponentiation |
| Modular inverse | Extended mathematical operation through Python's modular inverse |
| Encryption | Character-based textbook RSA demonstration |
| Decryption | Private-exponent modular operation |
| Signatures | Educational raw RSA signature |
| Key exchange | Diffie-Hellman |
| Fingerprinting | SHA-256 |
| Serialization | JSON public-key export and import |
| Lifecycle | Registration, rotation, revocation, expiration |
| Validation | Custom exceptions |
| Testing | `unittest` and assertions |

### Important implementation limitations

The RSA implementation uses raw textbook RSA without OAEP.

The signature implementation does not use RSA-PSS or the standard RSA signature encoding.

The prime sizes are deliberately small.

The Diffie-Hellman parameters are also small.

These implementations illustrate the underlying mathematical relationships. They are not suitable for protecting production data.

The Python key registry demonstrates metadata management, not secure private-key custody.

## 10. JavaScript Implementation

The JavaScript file uses Node.js built-in cryptographic capabilities.

| Component | Implementation |
|---|---|
| RSA key generation | `crypto.generateKeyPairSync` |
| Encryption | RSA-OAEP with SHA-256 |
| Decryption | RSA private-key decryption |
| Signatures | RSA-PSS |
| Modern signatures | Ed25519 |
| Key agreement | X25519 |
| Key derivation | HKDF-SHA256 |
| Symmetric encryption | AES-256-GCM |
| Fingerprinting | SHA-256 |
| Key registry | Private `Map` state |
| Events | `EventEmitter` |
| Validation | Explicit type and policy checks |

### Event-driven key lifecycle

The registry emits events when key state changes.

The event model includes:

- `key:registered`
- `key:rotated`
- `key:revoked`
- `key:expired`

Applications can use these events to trigger audit workflows, notify dependent services, or initiate credential replacement.

The registry intentionally stores public metadata rather than private-key bytes.

The demonstration uses synchronous cryptographic APIs for clarity. Production services handling substantial concurrent workloads should consider asynchronous cryptographic operations and appropriate worker capacity.

## 11. C++17 Implementation

The C++ program demonstrates cryptographic mathematics through a domain-oriented design.

| Component | Implementation |
|---|---|
| RSA key model | Public and private key structures |
| Modular arithmetic | Modular multiplication and exponentiation |
| Prime generation | Random candidate selection and primality testing |
| RSA encryption | Modular exponentiation |
| RSA decryption | Private exponent operation |
| Digital signatures | Educational RSA signing and verification |
| Diffie-Hellman | Shared-secret calculation |
| Key registry | `unordered_map` |
| Lifecycle | Explicit status transitions |
| Policy evaluation | Security rule checks |
| Reporting | Owner-based key inventory |

### Performance considerations

Modular exponentiation uses repeated squaring, requiring logarithmically many exponentiation iterations.

The multiplication implementation uses `unsigned __int128` to avoid intermediate overflow for the small integer demonstration.

Prime generation uses trial division and is intentionally restricted to small values.

The use of `random_device` and `mt19937_64` does not establish production-grade cryptographic randomness across all platforms.

The program is an educational model and should not be used for real cryptographic operations.

## 12. Java 17 Enterprise Implementation

The Java implementation uses JCA and JCE cryptographic providers.

Its design separates cryptographic operations, policy enforcement, storage interfaces, and lifecycle services.

### Domain types

The application defines:

- `KeyPurpose`
- `KeyStatus`
- `Algorithm`
- `KeyMetadata`
- `KeyMaterial`
- `EncryptionEnvelope`
- `PolicyResult`

Java records provide compact immutable data structures.

### Service architecture

`KeyGenerationService` generates RSA, Ed25519, and X25519 key pairs.

`RSAEncryptionService` implements RSA-OAEP.

`RSASignatureService` implements RSA-PSS.

`Ed25519Service` implements Ed25519 signatures.

`X25519Service` establishes shared secrets.

`HKDFService` derives symmetric keys using HMAC-SHA256.

`AESGCMService` performs authenticated encryption and decryption.

`EnterpriseKeyService` manages key registration, policy validation, rotation, and revocation.

`KeyRepository` defines the storage contract, while `InMemoryKeyRepository` supplies a concurrent in-memory implementation.

### Enterprise design decisions

The application distinguishes cryptographic key material from key metadata.

It also separates:

- Algorithm selection.
- Key-purpose validation.
- Lifecycle state.
- Access eligibility.
- Cryptographic operations.
- Persistence.

The in-memory repository is suitable for demonstrating application structure but is not a durable or distributed production repository.

A production implementation would require persistent storage, secure key custody, authorization controls, transaction handling, audit protection, and concurrency-aware lifecycle operations.

## 13. PostgreSQL Database Implementation

The PostgreSQL file models an enterprise cryptographic key-management system.

### Relational model

The main relationships are:

`Organizations`

`    ↓`

`Identities`

`    ↓`

`Cryptographic Keys`

`    ├── Key Policies`

`    ├── Key Certificates`

`    ├── Key Access Grants`

`    ├── Cryptographic Operations`

`    ├── Digital Signatures`

`    ├── Key Agreement Sessions`

`    └── Key Audit Events`

### Main tables

| Table | Responsibility |
|---|---|
| `organizations` | Organization ownership |
| `identities` | Human and service identities |
| `algorithm_catalog` | Cryptographic algorithm definitions |
| `key_policies` | Algorithm and lifecycle requirements |
| `cryptographic_keys` | Public-key and lifecycle metadata |
| `key_certificates` | Certificate records |
| `key_access_policies` | Authorization rules |
| `key_access_grants` | Identity-specific permissions |
| `cryptographic_operations` | Operation history |
| `digital_signatures` | Signature metadata |
| `signature_verifications` | Verification results |
| `key_agreement_sessions` | Key-agreement session metadata |
| `key_audit_events` | Lifecycle audit history |

### Integrity enforcement

The schema uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Partial indexes.
- Lifecycle triggers.
- Audit triggers.
- Stored functions.
- Stored procedures.
- Transactions.

The `validate_key_transition` trigger prevents certain invalid lifecycle transitions.

The `audit_key_changes` trigger records changes to key status.

The `register_public_key` function checks registration requirements.

The `rotate_public_key` procedure creates a successor key and updates the previous key's status.

The `revoke_public_key` function invalidates a key and its associated valid certificate records.

The `is_key_eligible` function evaluates whether a key is suitable for a requested purpose.

The `evaluate_key_access` function evaluates access grants and identity permissions.

The `expire_inactive_keys` procedure processes expired keys, certificates, and key-agreement sessions.

### Reporting

The SQL implementation includes reports for:

- Active key inventory.
- Key lifecycle distribution.
- Expiring keys.
- Invalid or inactive keys.
- Signature verification.
- Cryptographic operation performance.
- Audit history.
- Key access decisions.
- Key risk classification.
- Key-version relationships.

The CTE-based risk report assigns risk scores to key states and expiration conditions.

These scores are operational classifications, not cryptographic security measurements.

### Database limitations

PostgreSQL constraints can enforce metadata integrity, but they cannot independently verify the mathematical correctness of arbitrary public-key material.

The sample PEM values and signature values are illustrative records, not actual usable cryptographic artifacts.

The database does not implement private-key encryption, HSM integration, RSA operations, X.509 certificate-chain validation, or cryptographic signature verification.

Those operations belong in a trusted cryptographic service or hardware-backed security component.

## 14. Important Technical Distinctions

| Concept | Meaning |
|---|---|
| Encryption | Protects information confidentiality |
| Decryption | Recovers encrypted information |
| Digital signature | Provides integrity and signer-key evidence |
| Hashing | Produces a fixed-length digest |
| Fingerprinting | Identifies public-key material through a digest |
| Key exchange | Establishes shared secret material |
| Key derivation | Produces application-specific keys |
| Certificate | Binds a public key to an identity |
| Key rotation | Replaces an existing key |
| Key revocation | Invalidates a key before planned expiration |
| Key expiration | Ends the approved validity period |
| Key destruction | Removes protected key material |

The distinction between public-key cryptography and symmetric cryptography is equally important.

Public-key algorithms use mathematically related public and private keys. Symmetric algorithms use shared secret keys.

Hybrid cryptographic systems combine both approaches.

## 15. Edge Cases and Failure Handling

The implementations address several important failure conditions.

| Failure condition | Expected handling |
|---|---|
| Invalid RSA parameters | Reject key construction or operation |
| Message exceeds RSA capacity | Reject encryption |
| Invalid ciphertext | Reject decryption |
| Modified signed message | Signature verification fails |
| Incorrect peer public value | Reject key agreement input |
| All-zero X25519 secret | Reject shared secret |
| Duplicate public-key fingerprint | Reject registration |
| Expired key | Reject use |
| Revoked key | Reject use |
| Rotated key | Reject new operations under the retired version |
| Incorrect key purpose | Reject operation |
| Modified AES-GCM ciphertext | Authentication fails |
| Unauthorized identity | Deny access |
| Invalid lifecycle transition | Reject state change |

These failure conditions should be recorded through controlled audit events without exposing private keys, symmetric secrets, passwords, or sensitive plaintext.

## 16. Performance and Operational Considerations

### RSA

RSA encryption and verification generally use the public exponent, while decryption and signing use private-key operations.

Private-key operations are typically more computationally expensive.

RSA is useful for compatibility and established cryptographic workflows, but large payloads should not be encrypted directly.

### Ed25519

Ed25519 offers compact signatures and efficient signing and verification.

It is suitable for signature-based authentication and document integrity workflows where the relevant protocols support it.

### X25519

X25519 provides efficient shared-secret establishment.

The resulting secret should be processed through a key derivation function before use as an application encryption key.

### AES-GCM

AES-GCM provides authenticated encryption and is suitable for bulk data encryption.

Its nonce management is security-critical. Reusing a nonce with the same key can compromise confidentiality and authentication.

### Database operations

The PostgreSQL indexes support frequent queries involving:

- Key owner.
- Key status.
- Key purpose.
- Algorithm.
- Expiration.
- Fingerprint.
- Audit timestamp.

Partial indexes reduce index storage and maintenance for selected lifecycle states.

Large key inventories require appropriate archival, retention, and partitioning strategies for operational records.

## 17. Practical Key Management Workflow

A typical enterprise lifecycle follows this sequence:

1. Define an approved algorithm and key-purpose policy.
2. Generate the key pair inside an approved cryptographic environment.
3. Protect the private key using an HSM, KMS, or secure keystore.
4. Calculate the public-key fingerprint.
5. Register the key and its metadata.
6. Validate the public-key identity binding.
7. Activate the key.
8. Grant access to authorized identities.
9. Monitor cryptographic operations and key usage.
10. Rotate keys according to policy.
11. Revoke compromised or unauthorized keys.
12. Destroy retired private-key material when retention and recovery requirements permit.

The central security principle is that public keys may be distributed, but private-key material must remain protected throughout its lifecycle.
