# Digital Signatures: Cryptography, Verification, and Trust Governance

## 1. Introduction

A digital signature is a cryptographic mechanism used to establish the authenticity and integrity of digital information. It allows a recipient to verify that a particular private key was used to sign a message or document and that the signed content has not changed since signing.

Digital signatures are based on asymmetric cryptography. Each signer possesses a mathematically related key pair:

- **Private key:** Used to create digital signatures. It must remain confidential.
- **Public key:** Distributed to recipients and used to verify signatures.

A digital signature is not an encrypted copy of a document. Encryption protects confidentiality, whereas digital signatures primarily provide authenticity, integrity, and evidence supporting non-repudiation.

The five implementations examine cryptographic operations, key management, document integrity, verification, revocation, audit records, and enterprise trust governance.

## 2. Fundamental Concepts

### 2.1 Asymmetric Cryptography

Asymmetric cryptography uses two related cryptographic keys.

The private key is retained by its owner. The corresponding public key can be distributed to other parties.

The mathematical relationship between the keys allows a signature produced using the private key to be checked using the public key.

The public key does not provide a practical means of recovering the private key when an appropriate cryptographic algorithm and secure parameters are used.

### 2.2 Digital Signature Creation

A typical signing workflow consists of:

1. Obtain the original document.
2. Calculate its cryptographic hash.
3. Apply the signing algorithm using the private key.
4. Produce a digital signature.
5. Store or transmit the signature with the document and relevant metadata.

Conceptually:

`Document → SHA-256 → Message Digest`

`Message + Private Key → Digital Signature Algorithm → Signature`

For Ed25519, the signature algorithm internally performs the required message processing. Applications should use the established cryptographic API rather than implement the underlying mathematics themselves.

### 2.3 Digital Signature Verification

Verification uses the corresponding public key.

The verifier checks whether the signature is mathematically valid for the supplied message and public key.

A successful verification establishes that:

- The signature corresponds to the supplied document.
- The signature was generated using the corresponding private key.
- The signed message has not been modified relative to the signature.

It does not independently establish the real-world identity of the signer. That requires a trustworthy association between the public key and the claimed identity.

### 2.4 Cryptographic Hash Functions

A cryptographic hash function converts arbitrary-length input into a fixed-length digest.

The implementations use SHA-256, which produces a 256-bit digest.

Important properties include:

| Property | Meaning |
|---|---|
| Deterministic output | Identical input produces identical output |
| Preimage resistance | Recovering an input from its digest is computationally infeasible |
| Second-preimage resistance | Finding another input with the same digest is computationally infeasible |
| Collision resistance | Finding any two different inputs with the same digest is computationally infeasible |
| Fixed output size | SHA-256 always produces 256 bits |

A document hash provides an efficient integrity fingerprint. It is not itself a digital signature.

### 2.5 Digital Signature and Encryption Distinction

| Characteristic | Digital signature | Encryption |
|---|---|---|
| Main objective | Authenticity and integrity | Confidentiality |
| Primary operation | Signing | Encryption |
| Verification or recovery | Public-key verification | Decryption |
| Key relationship | Private signing key and public verification key | Depends on symmetric or asymmetric encryption |
| Confidentiality | Not provided by signing alone | Provided when correctly implemented |
| Integrity | Cryptographically authenticated | Depends on the encryption construction |

A signed document can remain readable by anyone who possesses it.

## 3. Cryptographic Algorithms

### 3.1 RSA

RSA is an asymmetric cryptographic algorithm based on the computational difficulty of factoring large composite integers.

Its key generation process involves:

1. Selecting large prime numbers.
2. Computing their product.
3. Calculating the relevant mathematical parameters.
4. Selecting a public exponent.
5. Computing the corresponding private exponent.

RSA signatures should use a standardized signature scheme.

Two important constructions are:

- RSA-PSS: A probabilistic signature scheme using randomized padding.
- RSA PKCS#1 v1.5: A deterministic, older signature construction that remains supported in established systems.

RSA-PSS is generally preferred for new RSA signature deployments.

The C++ implementation demonstrates modular arithmetic, SHA-256, and RSA-style signing mechanics using deliberately small demonstration parameters. It is not a production implementation of RSA-PSS or PKCS#1 v1.5. Its reduced key size and simplified encoding are unsuitable for security-sensitive use.

### 3.2 Ed25519

Ed25519 is a digital signature algorithm based on Edwards-curve elliptic-curve cryptography.

Its characteristics include:

- 256-bit private-key seed material.
- Compact public keys.
- 64-byte signatures.
- Deterministic signing.
- Efficient signing and verification.
- No separate application-level nonce generation.

The Python, JavaScript, and Java implementations use actual Ed25519 operations through established cryptographic libraries.

### 3.3 Algorithm Comparison

| Characteristic | RSA-PSS | Ed25519 |
|---|---|---|
| Cryptographic family | Integer factorization | Elliptic-curve cryptography |
| Private-key operation | Modular exponentiation | Edwards-curve operations |
| Public-key operation | Modular exponentiation | Edwards-curve verification |
| Signature format | Modulus-sized integer encoding | 64 bytes |
| Randomized signing | Yes, through PSS salt | No |
| Typical application | Existing RSA infrastructures | Modern application signing |

Algorithm selection should consider interoperability, system support, cryptographic policy, key-management infrastructure, and expected operational lifetime.

## 4. Digital Signature Lifecycle

A digital signature lifecycle includes more than creating and verifying a signature.

<escape>
Key Generation
      |
      v
Public-Key Registration
      |
      v
Private-Key Protection
      |
      v
Document Preparation
      |
      v
Document Hashing
      |
      v
Signature Creation
      |
      v
Signature Distribution
      |
      v
Public-Key Retrieval
      |
      v
Cryptographic Verification
      |
      v
Trust and Revocation Evaluation
      |
      v
Audit and Evidence Retention
</escape>

### 4.1 Key Generation

A key pair is generated using an appropriate cryptographic provider.

The key must be associated with an identity through a trustworthy process.

Key generation must use a cryptographically secure random-number generator where the selected algorithm requires random key material.

### 4.2 Public-Key Registration

A public key must be associated with the correct person, organization, or system.

Registration may use:

- Public-key infrastructure.
- X.509 certificates.
- Organizational identity verification.
- Managed cryptographic key registries.
- Trusted key-distribution mechanisms.

Possessing a public key does not automatically establish the identity of its owner.

### 4.3 Private-Key Protection

Private-key compromise can invalidate the security assumptions of a signing system.

Appropriate protections include:

- Hardware Security Modules.
- Secure key-management services.
- Access-control policies.
- Encryption of private-key material at rest.
- Authentication before signing.
- Key-use auditing.
- Separation of signing and administrative responsibilities.

A public-key registry must never be treated as a private-key repository.

### 4.4 Document Preparation

The document must be represented consistently.

The signing and verification processes must use the same byte sequence.

Potential sources of disagreement include:

- Character encoding changes.
- Line-ending conversion.
- File-format conversion.
- Whitespace modification.
- Metadata modification.
- Serialization differences.

If an application signs structured JSON, it must define a consistent representation before signing.

### 4.5 Signature Creation

The signing service accepts the document and an authorized private key.

It produces a signature that is stored independently or embedded in an appropriate document format.

Detached signatures are useful when the original document should remain unchanged.

### 4.6 Verification

Verification checks both cryptographic validity and the associated trust information.

A robust verifier considers:

- Public-key identity.
- Signature algorithm.
- Document identity.
- Document integrity.
- Key status.
- Certificate validity.
- Revocation information.
- Trusted timestamp information where available.

Cryptographic verification and identity validation are separate operations.

## 5. Key Management and Revocation

### 5.1 Key Lifecycle

| State | Meaning | Signing permitted |
|---|---|---|
| Active | Key is authorized for use | Yes, subject to policy |
| Suspended | Temporarily unavailable | No |
| Expired | Validity period has ended | No |
| Revoked | Key has been withdrawn from trust | No |

The implementations distinguish active, expired, and revoked states. JavaScript, Java, and PostgreSQL also represent suspension or equivalent governance conditions where applicable.

### 5.2 Key Expiration

An expiration date limits the period during which a key may be used.

Expiration does not necessarily invalidate signatures created while the key was valid.

A verifier should distinguish:

- The time when the signature was created.
- The time when the signature was verified.
- The key's validity period.
- The time at which revocation became effective.

### 5.3 Key Revocation

A key may need to be revoked when:

- Private-key compromise is suspected.
- An employee leaves an organization.
- A signing device is lost.
- Unauthorized signing is detected.
- A cryptographic algorithm becomes unacceptable.
- An organizational authorization is withdrawn.

Revocation prevents subsequent use of the key under the applicable trust policy.

Historical verification requires additional evidence. A signature that was valid when created may still require a trusted timestamp, certificate history, and revocation evidence to establish its historical validity.

### 5.4 Key Rotation

Key rotation replaces an existing key with a new key.

A controlled rotation process should:

1. Generate the replacement key.
2. Register its public key.
3. Validate its identity association.
4. Update signing services.
5. Stop using the previous private key.
6. Preserve historical verification material.
7. Revoke or retire the old key according to policy.

Key rotation should not destroy historical signature records.

## 6. Certificates and Public-Key Infrastructure

### 6.1 X.509 Certificates

An X.509 certificate binds a public key to an identity through a digital signature issued by a Certificate Authority.

Typical certificate information includes:

- Subject identity.
- Issuer identity.
- Public key.
- Serial number.
- Validity period.
- Key usage.
- Extended key usage.
- Signature algorithm.
- Certificate signature.

### 6.2 Certificate Authority

A Certificate Authority issues and signs certificates.

The certificate signature allows relying parties to verify that the certificate was issued by the corresponding authority.

A certificate does not make an otherwise invalid document signature valid. It provides evidence concerning the public key's identity and authorization.

### 6.3 Certificate Chain

A certificate chain establishes trust through a hierarchy of certificates.

<escape>
End-Entity Certificate
          |
          v
Intermediate CA Certificate
          |
          v
Root CA Certificate
          |
          v
Locally Trusted Root Store
</escape>

Certificate validation involves:

- Chain construction.
- Signature verification.
- Certificate validity periods.
- Key-usage restrictions.
- Name constraints.
- Revocation checking.
- Trust-anchor selection.

The five implementations focus on public-key registration and lifecycle management. They do not implement a complete X.509 certificate-chain validator.

## 7. Code Review and Approval of Cryptographic Changes

Digital signature systems require careful software governance because mistakes in cryptographic implementation can create serious security weaknesses.

Code review should examine:

- Cryptographic algorithm selection.
- Key-generation practices.
- Private-key exposure.
- Signature input consistency.
- Verification error handling.
- Algorithm downgrade possibilities.
- Certificate validation.
- Revocation processing.
- Audit completeness.
- Concurrency and transaction handling.

An approval decision represents a reviewer's decision about a particular change or document.

An approval does not itself prove cryptographic validity.

A cryptographic verification result does not automatically constitute organizational approval.

These are separate decisions with separate responsibilities.

## 8. Python Implementation

### 8.1 Architecture

The Python program uses a service-oriented design.

| Component | Responsibility |
|---|---|
| `KeyManager` | Key generation, registration, retrieval, export, and revocation |
| `DocumentStore` | Document validation and SHA-256 fingerprinting |
| `SignatureService` | Signing and verification |
| `SignatureArchive` | Detached signature persistence |
| `SignatureTests` | Automated validation |

The implementation uses the `cryptography` package for Ed25519 operations.

### 8.2 Key Generation

`generate_key_pair()` creates an Ed25519 key pair.

The private key remains inside the key manager. The public key is retained in the corresponding key record.

The implementation uses random key identifiers to separate key identity from document identity.

### 8.3 Document Fingerprinting

`DocumentStore.fingerprint()` calculates the SHA-256 digest of the original document bytes.

This allows the application to detect document modifications before cryptographic verification.

The digest is useful for integrity comparison, but the signature verification operation remains essential.

### 8.4 Signing and Verification

`SignatureService.sign()` performs the following operations:

1. Validates the document.
2. Retrieves the authorized signing key.
3. Signs the document bytes.
4. Creates a signature record.
5. Stores signature metadata.

`SignatureService.verify()` checks the registered public key, document fingerprint, key status, expiration, and actual Ed25519 signature.

### 8.5 Detached Signature Persistence

The archive stores:

- Signature identifier.
- Key identifier.
- Signer identity.
- Algorithm.
- Hash algorithm.
- Document fingerprint.
- Base64-encoded signature.
- Signing timestamp.
- Document name.

The original document is not embedded in the signature archive.

The archive uses exclusive file creation to prevent accidental overwriting.

The example is a demonstration of serialization rather than a complete secure archival system. Production implementations also require authenticated metadata, controlled permissions, encryption where appropriate, backup, and tamper-evident retention.

### 8.6 Validation and Testing

The Python tests cover:

- Successful verification.
- Modified document detection.
- Key revocation.
- Incorrect public-key verification.
- Empty-document rejection.
- Public-key export and import.
- Signature archive round trips.

The implementation also enforces a maximum document size of 10 MB.

## 9. JavaScript Implementation

### 9.1 Event-Driven Architecture

The JavaScript implementation uses Node.js built-in cryptographic and event-handling capabilities.

Its components include:

| Component | Responsibility |
|---|---|
| `Document` | Immutable document representation |
| `KeyRegistry` | Key registration and lifecycle |
| `SignatureEngine` | Cryptographic signing and verification |
| `AuditLog` | Event-driven audit collection |
| `SignatureArchive` | Asynchronous persistence |

### 9.2 Native Cryptographic Operations

The implementation uses:

- `crypto.generateKeyPairSync()` for Ed25519 key generation.
- `crypto.sign()` for signing.
- `crypto.verify()` for verification.
- `crypto.createHash()` for SHA-256 fingerprints.
- `crypto.randomUUID()` for identifiers.

Using Node.js cryptographic primitives avoids introducing unnecessary third-party packages.

### 9.3 Event-Driven Auditing

The `AuditLog` extends `EventEmitter`.

Signing and verification operations generate events that can be consumed by other application components.

This provides a foundation for integrating:

- Security monitoring.
- Compliance reporting.
- Alerting.
- Operational dashboards.
- Centralized audit collection.

The example maintains audit events in memory. Production systems require durable storage and protection against unauthorized modification.

### 9.4 Asynchronous Persistence

The archive uses asynchronous filesystem operations.

Exclusive file creation reduces the possibility of accidentally replacing existing signature evidence.

File permissions are restricted during creation, although actual operating-system permissions and deployment policies must also be reviewed.

### 9.5 Failure Handling

The implementation distinguishes:

- Invalid document content.
- Unknown keys.
- Revoked keys.
- Expired keys.
- Invalid signatures.
- Unsupported algorithms.
- Archive errors.

This prevents every verification failure from being represented as the same generic condition.

## 10. C++17 Implementation

### 10.1 Mathematical Foundation

The C++ program implements a bounded demonstration of RSA-style digital signatures.

It includes:

- SHA-256 compression.
- Prime checking.
- Greatest common divisor.
- Extended Euclidean modular inverse.
- Modular exponentiation.
- RSA public and private exponents.
- Signature verification.

The modular exponentiation operation uses repeated squaring.

Its complexity is logarithmic in the exponent:

`O(log e)` modular multiplication operations.

The implementation uses a wider intermediate integer type for multiplication to reduce overflow risks within its demonstration bounds.

### 10.2 SHA-256

The SHA-256 implementation processes data in 512-bit blocks.

Each block undergoes:

1. Message padding.
2. Message schedule expansion.
3. Sixty-four compression rounds.
4. State accumulation.

A known-answer test using the input `abc` checks the implementation against the standard SHA-256 digest.

### 10.3 RSA Demonstration

The program creates a bounded RSA key using demonstration prime values.

The signature operation uses modular exponentiation with the private exponent.

Verification uses the public exponent.

The implementation is deliberately not production-safe:

- Its modulus is extremely small.
- Its hash encoding is a demonstration mapping.
- It does not implement RSA-PSS.
- It does not implement standards-compliant PKCS#1 v1.5 encoding.
- Its demonstration key generation is deterministic.
- It does not use protected private-key storage.

It illustrates the mathematical relationship between RSA signing and verification, not a deployable cryptographic implementation.

### 10.4 Governance Engine

The same program implements a repository governance model.

The governance engine evaluates:

- Pull request state.
- Source and target branches.
- Proposed changeset fingerprint.
- Signed commit verification.
- Reviewer eligibility.
- Current approval decisions.
- Required status checks.
- Unresolved conversations.
- Base-branch synchronization.
- Merge eligibility.

This demonstrates the distinction between cryptographic verification and organizational authorization.

A cryptographically valid signature does not independently authorize a repository merge.

## 11. Java 17 Enterprise Implementation

### 11.1 Domain Modeling

The Java program uses records, classes, enumerations, and service objects to represent an enterprise signature-management system.

Important domain types include:

| Type | Purpose |
|---|---|
| `Document` | Immutable document information |
| `KeyMetadata` | Public key lifecycle information |
| `DigitalSignature` | Detached signature evidence |
| `VerificationResult` | Verification outcome |
| `AuditEvent` | Audit information |
| `Reviewer` | Authorized reviewer identity |
| `Review` | Review decision |
| `BranchProtectionPolicy` | Governance requirements |
| `Eligibility` | Merge eligibility result |

Records provide concise data structures. Defensive copying of document bytes prevents callers from modifying the stored document through an external reference.

### 11.2 Service Separation

The implementation separates responsibilities into services.

**KeyManagementService**

Controls key generation, registration, retrieval, and revocation.

**DigitalSignatureService**

Performs cryptographic signing and verification.

**AuditService**

Stores operational events.

**RepositoryGovernanceService**

Evaluates review decisions and merge conditions.

This separation reduces coupling between cryptographic operations and organizational approval workflows.

### 11.3 Review Decisions

The governance engine recognizes:

- `COMMENTED`
- `APPROVED`
- `CHANGES_REQUESTED`
- `DISMISSED`

A review is associated with a reviewer and a decision timestamp.

When a reviewer submits a new decision, the previous decision is marked non-current.

This prevents multiple historical approvals from being counted as independent current approvals.

### 11.4 Merge Eligibility

The policy engine checks:

1. Pull request state.
2. Merge conflicts.
3. Target-branch synchronization.
4. Signed commit verification.
5. Required approvals.
6. Reviewer authorization.
7. Requested changes.
8. Required status checks.
9. Conversation resolution.

The final result is an `Eligibility` record containing the decision, violations, and approval count.

### 11.5 Enterprise Tradeoffs

The Java implementation favors explicit domain objects and service boundaries.

This structure is useful when signature workflows need integration with identity providers, compliance systems, document-management services, and centralized auditing.

The in-memory implementation is intended for domain and workflow demonstration. Production systems require persistent transactional storage, concurrency control, secure key custody, and authenticated service boundaries.

## 12. PostgreSQL Implementation

### 12.1 Relational Architecture

The PostgreSQL script establishes the `digital_trust` schema.

Its principal relationships are:

<escape>
Principals
   |
   +---- Principal Roles
   |
   +---- Cryptographic Keys
   |
   +---- Documents
              |
              +---- Digital Signatures
              |          |
              |          +---- Verification Attempts
              |
              +---- Approval Assignments
                         |
                         +---- Approval Policies

All major operations
        |
        v
Trust Audit Log
</escape>

### 12.2 Core Tables

| Table | Responsibility |
|---|---|
| `principals` | Identity records |
| `principal_roles` | Role assignments |
| `cryptographic_keys` | Public-key registry |
| `documents` | Document content and integrity fingerprints |
| `digital_signatures` | Signature evidence |
| `verification_attempts` | Verification history |
| `approval_policies` | Approval requirements |
| `approval_assignments` | Document approval decisions |
| `trust_audit_log` | Operational audit history |

### 12.3 Database Integrity

The database uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Partial indexes.
- Generated columns.
- Triggers.
- Stored procedures.
- Views.
- Common Table Expressions.

The document fingerprint is generated using PostgreSQL `pgcrypto`.

The generated `content_hash` column is derived from the stored document bytes using SHA-256.

This ensures that the fingerprint is calculated from the actual stored document content rather than being independently supplied by an application.

### 12.4 Signature Integrity

The signature validation trigger checks:

- Whether the key exists.
- Whether the signer owns the key.
- Whether the key is active.
- Whether the key has expired.
- Whether the algorithm matches.
- Whether the signature's document fingerprint matches the registered document.

These checks establish database-level consistency.

They do not establish the mathematical validity of the signature.

That operation must be performed by an authorized cryptographic verification service.

### 12.5 Immutable Signature Evidence

The signature immutability trigger prevents modification and deletion of existing signature records.

If a new signature is required, the application creates a separate record.

This preserves historical evidence and reduces the risk of silently changing an earlier signature.

Database administrators can still alter database structures or disable triggers. Stronger audit guarantees therefore require restricted privileges, independent audit storage, and operational controls.

### 12.6 Verification History

The `verification_attempts` table records:

- Signature identifier.
- Document identifier.
- Verifier identity.
- Verification result.
- Submitted document fingerprint.
- Verification service.
- Timestamp.
- Structured diagnostic information.

Historical records allow repeated verification attempts to be analyzed without overwriting earlier outcomes.

### 12.7 Approval Eligibility

The `approval_eligibility()` function evaluates the number of valid approval assignments against the policy's required approval count.

It distinguishes:

- Approved assignments.
- Pending assignments.
- Rejected assignments.
- Disabled approval policies.

This is an organizational workflow calculation, not a cryptographic signature verification operation.

### 12.8 Indexing and Performance

The implementation creates indexes for frequently queried relationships:

- Principal and key status.
- Document ownership.
- Document status.
- Signature history.
- Key association.
- Verification history.
- Pending approvals.
- Audit history.

Indexes improve retrieval performance but increase storage requirements and write overhead.

Large deployments should evaluate index selectivity and query plans using `EXPLAIN ANALYZE`.

Storing large documents directly in PostgreSQL may increase database size and backup costs. Object storage can be used for document content while retaining immutable fingerprints and controlled references in the relational database.

## 13. Distinguishing Cryptographic Verification from Organizational Approval

These mechanisms solve different problems.

| Mechanism | Question answered |
|---|---|
| Digital signature | Does this signature authenticate the supplied document under the registered public key? |
| Key identity validation | Does this public key belong to the claimed identity? |
| Certificate validation | Is the public-key identity association trusted under the certificate policy? |
| Revocation checking | Has the key or certificate been withdrawn from trust? |
| Document approval | Has the authorized person approved the document? |
| Repository code review | Have proposed software changes been evaluated? |
| Repository branch protection | Are the required repository-level conditions satisfied? |

A system must not treat these outcomes as interchangeable.

For example, a document may have a valid cryptographic signature but still lack a required compliance approval.

Similarly, a document may have an organizational approval record but contain an invalid digital signature.

## 14. Security Considerations

### 14.1 Private-Key Compromise

If an attacker obtains a private key, the attacker may create signatures that verify successfully.

Mitigations include:

- Hardware-backed key storage.
- Strict signing authorization.
- Multi-factor authentication.
- Key-use monitoring.
- Rapid revocation.
- Controlled key rotation.

### 14.2 Algorithm Downgrade

An attacker may attempt to cause a system to accept a weaker signature algorithm.

Mitigations include:

- Explicit algorithm allowlists.
- Policy-controlled algorithm selection.
- Rejection of unknown algorithms.
- Secure algorithm migration.
- Cryptographic configuration auditing.

### 14.3 Replay and Substitution

A valid signature may be copied into an inappropriate context.

Applications should bind signatures to meaningful document identifiers, versions, transaction identifiers, and relevant contextual information.

A cryptographic signature does not automatically prevent an otherwise valid signed document from being reused in another transaction.

### 14.4 Verification Time

A signature's current verification result and its historical validity are different questions.

Long-term validation may require:

- Trusted timestamps.
- Certificate-chain evidence.
- Historical revocation information.
- Algorithm-strength assessment.
- Retained validation material.

### 14.5 Audit Protection

Audit records should be protected from unauthorized modification.

Useful controls include:

- Append-only application interfaces.
- Restricted database permissions.
- Independent audit storage.
- Hash-linked audit records.
- Periodic integrity checks.
- Secure backups.
- Retention policies.

A normal database table is not automatically tamper-proof.

## 15. Edge Cases and Failure Conditions

| Condition | Expected handling |
|---|---|
| Empty document | Reject signing and verification |
| Modified document | Reject verification |
| Incorrect public key | Cryptographic verification fails |
| Unknown key | Return unknown-key status |
| Revoked key | Reject under the applicable trust policy |
| Expired key | Apply historical or current-time validation rules |
| Missing private key | Reject signing |
| Invalid key encoding | Reject registration |
| Unsupported algorithm | Reject processing |
| Duplicate archive | Prevent accidental overwrite |
| Duplicate approval | Enforce uniqueness or supersession |
| Unauthorized reviewer | Reject the review decision |
| Conflicting policy | Reject or escalate the operation |
| Missing verification service | Do not claim successful verification |
| Concurrent key revocation | Recheck authorization before committing sensitive operations |

Failure handling should preserve diagnostic information without exposing private-key material or sensitive document contents.

## 16. Performance Considerations

Cryptographic operations and database operations have different performance characteristics.

| Operation | Performance consideration |
|---|---|
| SHA-256 | Linear in document size |
| Ed25519 signing | Fixed-size key and signature operations |
| Ed25519 verification | Public-key verification cost |
| RSA signing | Modular exponentiation |
| RSA verification | Modular exponentiation, often faster with standard exponents |
| Key registry lookup | Efficient with indexed identifiers |
| Signature history | Requires indexed document and key relationships |
| Audit reporting | Can become expensive as event volume increases |
| Document storage | Depends on content size and retention |

For large documents, hashing should be performed incrementally or through streaming APIs where supported.

Database transactions should be kept short, especially when cryptographic verification is performed by an external service.

## 17. Testing Strategy

The five source files provide different testing perspectives.

| Implementation | Validation approach |
|---|---|
| Python | Unit tests using `unittest` |
| JavaScript | Assertions using `node:assert/strict` |
| C++17 | SHA-256 known-answer test and executable demonstrations |
| Java 17 | Cryptographic and governance assertions |
| PostgreSQL | Constraints, triggers, stored procedures, and reporting queries |

A comprehensive deployment test suite should also cover:

- Cross-platform signature interoperability.
- Public-key serialization.
- Incorrect signature lengths.
- Invalid Base64 input.
- Key rotation.
- Historical signature verification.
- Concurrent signing.
- Concurrent revocation.
- Certificate expiration.
- Certificate-chain validation.
- Unauthorized signing attempts.
- Audit integrity.
- Recovery after service failure.

## 18. Execution Requirements

| File | Runtime | Dependency |
|---|---|---|
| Python | Python 3.10+ | `cryptography` |
| JavaScript | Node.js 20+ | Built-in Node.js modules |
| C++17 | C++17 compiler | Standard library |
| Java | Java 17 | Java standard library |
| PostgreSQL | PostgreSQL 15+ | `pgcrypto` extension |

The Python implementation requires installation of the `cryptography` package.

The JavaScript implementation can run directly under Node.js.

The C++ implementation can be compiled with a C++17-compatible compiler. Its cryptographic implementation is strictly educational and unsuitable for production.

The Java implementation requires no third-party dependency.

The PostgreSQL script requires permission to create the `pgcrypto` extension and the database objects in the selected schema.

## 19. Practical Applications

Digital signatures are applicable to:

- Electronic contracts.
- Government document authentication.
- Financial transaction authorization.
- Software release signing.
- Package integrity verification.
- Research publication workflows.
- Digital certificates.
- Enterprise identity systems.
- Procurement approvals.
- Secure document exchange.
- Electronic records management.
- API request authentication.

In each application, the cryptographic operation must be integrated with identity management, authorization, key lifecycle controls, and audit requirements.

## 20. Implementation Limitations

The implementations deliberately distinguish educational models from complete production systems.

| Implementation | Limitation |
|---|---|
| Python | In-memory key registry; no complete certificate infrastructure |
| JavaScript | In-memory audit records and key registry |
| C++17 | Deliberately insecure bounded RSA demonstration; no production padding or secure key generation |
| Java 17 | In-memory enterprise services; no persistent transactional infrastructure |
| PostgreSQL | Stores verification evidence but does not independently perform Ed25519 or RSA-PSS verification |

Production deployment requires a vetted cryptographic provider, secure key custody, identity validation, authorization, certificate or public-key trust management, revocation processing, trusted timestamps where required, and durable audit infrastructure.

The most important engineering distinction is that a digital signature is a cryptographic proof associated with particular content and a key. Trust in the signer, authorization to perform an action, and acceptance of the signed content must be established through separate governance mechanisms.
