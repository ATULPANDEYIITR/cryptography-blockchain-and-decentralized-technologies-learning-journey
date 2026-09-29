# Non-Repudiation

## 1. Topic Introduction

Non-repudiation is the property of a system that provides evidence intended to make it difficult for a participant to credibly deny a previous action, transaction, statement, approval, or communication.

In a technical system, non-repudiation is usually associated with digital signatures, authenticated identities, protected signing keys, trustworthy timestamps, audit records, controlled evidence retention, and reliable verification procedures.

Non-repudiation is broader than simply attaching a signature to a message. A useful evidence model must answer questions such as:

- What exactly was signed?
- Which identity was associated with the signing key?
- Which key was used?
- Was the key valid at the relevant time?
- Was the signed content modified?
- When did the event occur?
- Can another party independently verify the evidence?
- Can an old valid request be replayed?
- How are revoked or expired keys handled?
- How is evidence preserved?
- Who can modify, delete, or replace the evidence?
- What policies and legal rules govern interpretation of the evidence?

The Python, JavaScript, and C++ implementations in this study demonstrate these questions from different technical perspectives.

## 2. Fundamental Terminology

### 2.1 Repudiation

Repudiation is the denial of having performed or authorized an action.

For example, an employee might claim:

> "I never approved that purchase order."

A non-repudiation system attempts to preserve evidence that can be independently examined when such a dispute occurs.

### 2.2 Non-repudiation

Non-repudiation is the ability of a system to provide evidence about the origin, integrity, and history of an action in a way that supports accountability and dispute resolution.

The exact legal effect of technical evidence depends on jurisdiction, contracts, organizational policies, identity assurance, and the evidence itself. A cryptographic signature should not automatically be treated as a universal legal conclusion.

### 2.3 Integrity

Integrity concerns whether information has been changed without authorization.

Cryptographic hashes are commonly used to detect modifications.

### 2.4 Authentication

Authentication establishes or verifies the identity of a participant or credential.

A signature can demonstrate possession of a private signing key, but identity binding requires additional evidence connecting the public key to an identity.

### 2.5 Authorization

Authorization determines what an authenticated identity is allowed to do.

A valid signature does not automatically mean the signer was authorized to perform the particular action.

A complete system therefore needs both identity evidence and authorization rules.

### 2.6 Digital Signature

A digital signature is a cryptographic value generated using a private signing key and verified using the corresponding public key.

The basic model is:

1. Construct the exact data to be signed.
2. Hash or otherwise process the data according to the signature algorithm.
3. Generate a signature using the private key.
4. Preserve the signed data and signature.
5. Obtain the public verification key.
6. Verify the signature.

### 2.7 Private Key

A private key is secret cryptographic material used to create signatures.

Compromise of a signing key can seriously weaken evidence because an attacker may be able to produce apparently valid signatures.

Private keys require strong protection, controlled access, lifecycle management, and appropriate backup or recovery procedures.

### 2.8 Public Key

A public key is distributed to parties that need to verify signatures.

The public key itself does not need to remain secret, but the system must establish that it actually belongs to the claimed identity.

### 2.9 Certificate

A digital certificate can bind identity information to a public key through a trusted certificate authority.

A simplified certificate contains information such as:

- Subject identity
- Public key
- Issuer
- Serial number
- Validity period
- Extensions
- Signature from the issuer

The Python and JavaScript examples model certificate-like identity records and public-key fingerprints.

## 3. Core Security Relationships

Non-repudiation commonly involves several related security properties.

| Property | Primary concern | Typical mechanism |
|---|---|---|
| Integrity | Was data modified? | Cryptographic hash |
| Authentication | Who possesses a credential? | Digital signature, certificate |
| Authorization | Was the action permitted? | Access-control policy |
| Confidentiality | Can unauthorized parties read data? | Encryption |
| Freshness | Is the request new? | Nonce, timestamp, sequence |
| Accountability | Can actions be traced to actors? | Audit records |
| Non-repudiation | Can an actor credibly deny an evidenced action? | Signatures plus identity, time, policy, and preserved evidence |

These properties overlap but are not interchangeable.

A hash can provide integrity evidence without proving who produced the data.

Encryption can provide confidentiality without proving who approved a document.

Authentication can identify a user without proving that a particular document remained unchanged.

Authorization can establish that a user was allowed to approve a transaction without proving that the user actually performed the action.

Non-repudiation is therefore normally a system-level property rather than a single cryptographic primitive.

## 4. Cryptographic Hashing

A cryptographic hash function maps input data to a fixed-size digest.

For example:

`message -> SHA-256 digest`

A small modification to the input should produce a substantially different digest.

The Python implementation uses the standard library's `hashlib.sha256`.

The JavaScript implementation uses Node.js's `crypto.createHash("sha256")`.

The C++ implementation uses an explicitly labeled educational deterministic digest because the C++ standard library does not provide SHA-256.

The C++ digest is not cryptographically secure and must not be used for production security.

### 4.1 Why Hashing Helps

Suppose a system stores a document and its hash.

Later it calculates the hash again.

If the values differ, the document has changed.

This provides integrity evidence.

### 4.2 Why Hashing Alone Does Not Provide Non-Repudiation

Suppose Alice publishes:

`hash(document)`

Anyone who has the document can calculate the same hash.

The hash does not prove that Alice generated it.

A digital signature adds a private-key operation that can be independently verified with a public key.

## 5. HMAC and Its Important Distinction

HMAC is a keyed authentication mechanism.

Conceptually:

`HMAC(secret, message) -> authentication tag`

It provides strong integrity and authentication between parties that share the secret.

The Python and JavaScript implementations demonstrate HMAC.

HMAC is different from ordinary public-key signatures because both parties possess the same secret.

If Alice and Bob share an HMAC secret, a valid HMAC demonstrates possession of the secret but generally cannot prove to a third party whether Alice or Bob generated it.

For this reason, HMAC should not automatically be treated as equivalent to public-key non-repudiation.

## 6. Digital Signatures

A digital signature separates signing and verification roles.

The signer has:

`private key`

The verifier has:

`public key`

The signer produces:

`signature = Sign(private_key, data)`

The verifier checks:

`Verify(public_key, data, signature)`

If the signed data changes, verification should fail.

### 6.1 Python Demonstration

The Python program includes an educational RSA-style signature class.

It demonstrates:

- Public and private mathematical key components
- Hashing before signing
- Signature creation
- Signature verification
- Verification failure after message modification

The implementation is intentionally educational and should not be used as production cryptography.

Production applications should use established cryptographic libraries and standardized algorithms.

### 6.2 JavaScript Demonstration

The JavaScript implementation uses Node.js's built-in Ed25519 support.

It demonstrates a more realistic application-level signature workflow:

- Generate an Ed25519 key pair
- Sign a message
- Verify the signature
- Modify the message
- Observe verification failure

This illustrates how a web or backend application can integrate digital signatures into its business logic.

### 6.3 C++ Demonstration

The C++ program defines a signature service interface and uses an educational deterministic digest internally.

This design choice demonstrates an important architectural principle: cryptographic functionality should be isolated behind a well-defined interface.

A production implementation can replace the educational service with a security-reviewed cryptographic provider without redesigning the entire business evidence model.

## 7. What Exactly Should Be Signed?

One of the most important design decisions is defining the signed representation.

A system should not vaguely sign "the document."

It should define the exact data structure.

For a transaction, the signed representation might contain:

- Transaction ID
- Document ID
- Version
- Actor identity
- Operation
- Amount
- Currency
- Decision
- Timestamp
- Request identifier
- Relevant policy version

The Python and JavaScript implementations use canonical JSON.

The C++ implementation uses an explicitly ordered string representation.

The important principle is that the same logical record must produce the same signed byte sequence whenever independent systems verify it.

## 8. Canonicalization

Two objects can represent the same logical information but serialize differently.

For example:

`{"amount":100,"currency":"INR"}`

and

`{"currency":"INR","amount":100}`

may represent the same information but can produce different raw JSON strings.

A signature is calculated over bytes, not abstract meaning.

Therefore:

`signature(data_A) != signature(data_B)`

may occur even when a human considers the two representations equivalent.

Canonicalization establishes deterministic representation rules.

The JavaScript implementation explicitly sorts object keys before creating the canonical representation.

The Python implementation uses sorted JSON keys and compact separators.

The C++ implementation defines field order directly.

## 9. Signed Business Records

A signed record can contain:

- Record ID
- Signer ID
- Key ID
- Event type
- Payload
- Payload hash
- Creation time
- Sequence number
- Previous-record hash
- Signature
- Metadata

The Python `SignedRecord`, JavaScript `SignedRecord`, and C++ `EvidenceRecord` demonstrate this structure.

The payload is hashed separately.

The complete unsigned record representation is then signed.

This creates multiple layers of evidence:

1. The payload hash protects payload integrity.
2. The signature protects the signed record representation.
3. The previous-record hash links the record to earlier evidence.
4. Identity and key information identifies the claimed signer context.
5. Time metadata provides temporal context.

## 10. Append-Only Evidence Chains

The Python, JavaScript, and C++ implementations connect records using the hash of the previous record.

Conceptually:

`Record 1 -> hash(Record 1) -> Record 2 -> hash(Record 2) -> Record 3`

If an earlier record changes, later chain validation can detect the inconsistency.

This is useful for audit evidence.

It does not mean the implementation is automatically a blockchain.

A hash-linked audit trail can be centralized and can use ordinary database storage.

The security of the chain depends on:

- How hashes are calculated
- Whether records can be deleted
- Who controls storage
- Whether signatures remain verifiable
- Whether access controls are effective
- Whether backups preserve historical evidence
- Whether administrators can replace evidence
- Whether external witnesses or timestamps are used

## 11. Tamper Detection

The examples deliberately modify signed records.

For example, a legitimate approval might contain:

`amount=250000`

An attacker changes it to:

`amount=999999`

The payload hash no longer matches.

Even if the attacker recalculates the payload hash, the signed record representation will no longer match the original signature.

This illustrates why signing only an isolated hash is not enough unless the hash itself is properly bound to the exact business context.

## 12. Identity Binding

A digital signature proves that a particular private key was used.

The difficult question can then become:

"Who controls that private key?"

Identity binding addresses this problem.

Possible mechanisms include:

- Digital certificates
- Enterprise identity systems
- Hardware-backed credentials
- Controlled key issuance
- Strong enrollment procedures
- Certificate authorities
- Public-key directories
- Documented key ownership
- Organizational signing policies

The Python program creates a certificate-like data structure.

The JavaScript program calculates a public-key fingerprint.

The C++ case study associates a signing key identifier with the actor.

These examples demonstrate the architectural concept without claiming that a simple local record constitutes a complete production identity system.

## 13. Authorization Versus Signature

A valid signature does not automatically prove that an action was authorized.

Consider:

- Alice owns a valid signing key.
- Alice signs a payment for INR 50 million.
- Alice's role allows payments only up to INR 1 million.

The signature may be cryptographically valid while the transaction is unauthorized.

A production system therefore needs an authorization check such as:

`identity + role + policy + resource + action -> authorization decision`

The authorization decision should itself be recorded when it materially affects the transaction.

## 14. Replay Attacks

A replay attack occurs when an attacker captures a valid signed request and submits it again.

For example:

`RELEASE_PAYMENT(PAY-1007)`

may have a valid signature.

An attacker could copy the signed message and send it a second time.

The signature may still verify because the original message was not modified.

Therefore, signature validity does not automatically provide freshness.

The Python, JavaScript, and C++ implementations demonstrate replay protection using:

- Nonces
- Request identifiers
- Issued-at timestamps
- Expiration timestamps
- Server-side storage of consumed nonces

A robust request may contain:

`request_id`

`nonce`

`issued_at`

`expires_at`

`operation`

`parameters`

The server should verify these before executing the operation.

## 15. Nonces

A nonce is a value intended to be used once.

The server stores previously accepted nonces.

If a previously accepted nonce appears again, the request is rejected.

The Python implementation uses a set of nonces.

The JavaScript implementation uses a `Set`.

The C++ implementation uses a `std::set`.

The implementation choice differs by language, but the security principle is the same.

## 16. Timestamp Evidence

A timestamp provides temporal context.

A basic application timestamp is not automatically a trusted timestamp.

A server can write:

`2026-09-29T10:00:00Z`

but a later administrator may potentially alter the server database.

A stronger evidence model can use an independent trusted timestamp authority.

The Python, JavaScript, and C++ programs therefore create timestamp-authority-like evidence structures while explicitly treating the local token generation as a simulation.

A production timestamping architecture would use an independently protected authority and a standardized verifiable timestamp token.

## 17. Key Lifecycle

Signing keys have a lifecycle.

Important states include:

- Generated
- Registered
- Active
- Rotated
- Expired
- Revoked
- Archived
- Destroyed

The Python `KeyRegistry`, JavaScript key identity example, and C++ `KeyRegistry` demonstrate lifecycle concepts.

### 17.1 Key Generation

Keys should be generated using approved cryptographic mechanisms.

### 17.2 Key Protection

Private signing keys require strong protection.

Possible controls include:

- Hardware security modules
- Hardware-backed credentials
- Restricted operating-system access
- Encryption at rest
- Strong administrative controls
- Separation of duties
- Monitoring

### 17.3 Key Rotation

Keys should not necessarily remain active indefinitely.

Rotation limits exposure and supports operational maintenance.

### 17.4 Revocation

A compromised or invalid key may need to be revoked.

Revocation creates an important historical question:

Was a signature generated before or after the key became invalid?

A verification system must therefore consider key status and relevant time evidence.

## 18. Historical Verification

Suppose:

1. Alice signs a contract on January 1.
2. Her key is revoked on February 1.
3. The organization verifies the contract on March 1.

A simplistic verifier might see that the key is currently revoked and reject the historical signature.

That can be incorrect if policy allows signatures created before revocation to remain valid.

Historical verification may need evidence showing:

- Key identity
- Key validity interval
- Signature time
- Revocation time
- Timestamp evidence
- Certificate status
- Signature algorithm
- Relevant verification policy

The C++ case study explicitly distinguishes current key status from historical evidence.

## 19. Audit Trails

Audit trails record security-relevant events.

Typical fields include:

- Event ID
- Actor
- Action
- Resource
- Timestamp
- Result
- Evidence hash

The examples record events such as:

`SIGN`

`VERIFY`

A useful audit trail should be:

- Consistent
- Tamper-evident
- Access-controlled
- Time-aware
- Searchable
- Retained according to policy
- Protected from unauthorized deletion

Audit logs are not automatically trustworthy merely because they are called logs.

The system must protect the logging infrastructure itself.

## 20. Evidence Preservation

A technically valid signature is only useful if the evidence remains available and verifiable.

Evidence preservation can involve:

- Original signed data
- Signature value
- Public key or certificate
- Certificate chain
- Key status information
- Timestamp evidence
- Algorithm identifiers
- Verification metadata
- Audit records
- Relevant authorization decisions
- Policy versions
- Retention metadata

Long-lived evidence also creates algorithm-agility concerns.

A cryptographic algorithm that is secure today may eventually become unsuitable.

Long-term systems therefore need migration and archival strategies.

## 21. Python Implementation

The Python program is structured as a teaching environment.

### 21.1 Hashing

`sha256_hex()` demonstrates standard-library hashing.

It is used for payload integrity and evidence chaining.

### 21.2 Canonical JSON

`canonical_json()` sorts keys and uses deterministic separators.

This demonstrates why serialization must be defined before signing.

### 21.3 Educational Signature Scheme

`SignatureScheme` models public-key signing and verification.

It demonstrates mathematical relationships between private and public key operations.

It is explicitly not a production cryptographic implementation.

### 21.4 SignedRecord

`SignedRecord` represents a business evidence object.

The unsigned representation is separated from the signature itself so the signed data is deterministic.

### 21.5 EvidenceLedger

`EvidenceLedger` demonstrates:

- Record creation
- Payload hashing
- Signature generation
- Previous-record linking
- Signature verification
- Chain verification

### 21.6 Replay Protection

`RequestValidator` rejects reused nonces and stale or invalid requests.

### 21.7 KeyRegistry

`KeyRegistry` demonstrates registration and revocation.

### 21.8 TimestampEvidence

`TimestampEvidence` represents external timestamp evidence.

The authority token is explicitly a simulation.

### 21.9 AuditLog

`AuditLog` stores actor, action, resource, result, and evidence hash.

### 21.10 Tests

The Python program includes executable assertions covering:

- Valid signatures
- Modified messages
- Valid records
- Tampered payloads
- First-use nonces
- Replayed nonces

## 22. JavaScript Implementation

The JavaScript implementation emphasizes application and runtime behavior.

### 22.1 Node.js Cryptography

Node.js provides the `crypto` module.

The implementation uses Ed25519 for actual public-key signing operations.

The flow is:

`generateKeyPairSync("ed25519")`

then:

`crypto.sign(...)`

and:

`crypto.verify(...)`

This makes the JavaScript example closer to a real application cryptography workflow than the educational signature implementation in Python.

### 22.2 Canonical JSON

The JavaScript implementation recursively sorts object properties.

This addresses a common problem in distributed applications where independently constructed objects may have different property insertion orders.

### 22.3 Signed Records

`SignedRecord` represents signed business evidence.

`EvidenceLedger` manages the sequence of records.

### 22.4 Tampering

The program changes a payload and metadata after signing.

Verification detects the modifications.

### 22.5 Replay Protection

`ReplayGuard` maintains a `Set` of consumed nonces.

This demonstrates a server-side freshness mechanism.

### 22.6 Asynchronous Verification

`verifyRecordAsync()` demonstrates how verification can participate in Promise-based application workflows.

Real systems may need to combine signature verification with asynchronous operations such as:

- Database lookup
- Certificate retrieval
- Revocation checking
- Audit storage
- External timestamp verification

## 23. C++ Industry Case Study

The C++ program models a financial contract-approval system.

### 23.1 Business Problem

A financial organization needs evidence showing that an authorized employee approved a high-value contract.

The evidence needs to preserve:

- Contract identity
- Version
- Vendor
- Amount
- Currency
- Decision
- Signer
- Signing key
- Signature
- Payload hash
- Previous evidence link
- Timestamp context

### 23.2 Contract

The `Contract` structure contains the business facts.

Its `canonical()` function creates a deterministic representation.

This illustrates the principle that the system must explicitly define which business facts are part of the signed statement.

### 23.3 KeyRegistry

`KeyRegistry` models key lifecycle management.

It supports:

- Key creation
- Active state
- Revocation
- Signing eligibility checks

### 23.4 SignatureService

`SignatureService` isolates signing operations.

This is an architectural boundary.

A production implementation could replace the educational implementation with a cryptographic provider without changing the evidence ledger's conceptual interface.

### 23.5 EvidenceRecord

`EvidenceRecord` stores the evidence necessary for verification.

The `unsignedCanonical()` function ensures that the signed representation excludes the signature itself while including all other relevant fields.

### 23.6 EvidenceLedger

The ledger provides:

- Append operation
- Record verification
- Payload verification
- Signature verification
- Previous-record verification

This demonstrates a modular evidence architecture.

### 23.7 ReplayGuard

`ReplayGuard` uses a set of consumed nonces.

The request also contains issuance and expiration times.

The implementation rejects:

- Previously used nonces
- Invalid lifetimes
- Expired requests
- Requests too far in the future

### 23.8 AuditLog

`AuditLog` preserves application-level security events.

The audit event stores an evidence hash rather than requiring every event to contain a complete copy of the underlying business document.

### 23.9 TimestampEvidence

The timestamp object records:

- Record hash
- Timestamp
- Authority
- Authority token

Again, the authority token is only an educational simulation.

### 23.10 Tamper Demonstration

The program changes the contract amount after signing.

The recalculated payload hash no longer matches the stored hash.

This causes verification failure.

## 24. Important Comparison: Hash, HMAC, and Digital Signature

| Mechanism | Secret required? | Public verification? | Integrity | Authentication | Typical non-repudiation role |
|---|---:|---:|---:|---:|---|
| Hash | No | Yes | Yes | No | Supporting evidence |
| HMAC | Shared secret | No | Yes | Shared-secret authentication | Limited for third-party attribution |
| Digital signature | Private signing key | Yes | Yes | Public-key authentication | Core technical mechanism |

The distinction between HMAC and digital signatures is particularly important.

If both participants know an HMAC secret, either participant can potentially create a valid HMAC.

With a digital signature, the private signing key is controlled by the signer while the public key is distributed for verification.

That separation supports stronger origin evidence.

## 25. Important Comparison: Authentication and Non-Repudiation

Authentication asks:

"Can this system establish the identity or credential associated with this action?"

Non-repudiation asks a broader evidence question:

"Does the system preserve sufficient trustworthy evidence that this actor or credential performed or authorized this action, and can that evidence withstand later dispute?"

Authentication is therefore an important component but not a complete non-repudiation architecture.

## 26. Important Comparison: Signature and Encryption

Digital signatures and encryption solve different primary problems.

A signature provides evidence about integrity and origin.

Encryption protects confidentiality.

A confidential message can still be unauthenticated.

A signed message can be publicly readable.

A system may need both:

`Encrypt(data) + Sign(data or standardized protected representation)`

The exact construction must follow a well-defined protocol rather than being improvised.

## 27. Edge Cases

### 27.1 Modified Payload

Any modification to signed content should cause verification failure.

### 27.2 Modified Metadata

If metadata affects interpretation, it must be included in the signed representation.

Leaving important metadata outside the signature can create ambiguity.

### 27.3 Different Serialization

Two systems may serialize the same information differently.

Canonicalization reduces this risk.

### 27.4 Unicode

Text normalization can create difficult cases.

Visually identical Unicode strings may have different underlying representations.

A protocol should define encoding and normalization rules where relevant.

### 27.5 Floating-Point Numbers

Financial records should generally avoid ambiguous binary floating-point representations.

Amounts should use a precise representation such as integer minor units or a formally defined decimal format.

### 27.6 Time Zones

Timestamps should use an unambiguous representation, commonly UTC.

### 27.7 Clock Drift

Distributed systems can have inconsistent clocks.

Timestamp validation should allow an explicitly defined clock-skew tolerance.

### 27.8 Duplicate Requests

Unique request identifiers and nonces should be checked before executing sensitive operations.

### 27.9 Key Revocation

Current key status is not necessarily sufficient to evaluate historical signatures.

Historical validity requires time-aware evidence.

### 27.10 Missing Evidence

A signature without its corresponding signed content cannot normally be meaningfully verified.

A signature value should therefore be preserved together with the exact signed representation.

## 28. Exceptions and Failure Conditions

A verification service should fail closed when critical evidence is missing or invalid.

Examples include:

- Unknown signer
- Unknown key
- Revoked key
- Expired certificate
- Invalid signature
- Modified payload
- Invalid canonical representation
- Missing timestamp evidence when policy requires it
- Replay detected
- Expired request
- Invalid request lifetime
- Missing audit evidence
- Unsupported signature algorithm

A system should distinguish cryptographic failure from policy failure.

For example:

`signature_valid = true`

does not necessarily mean:

`transaction_authorized = true`

## 29. Common Mistakes

### Mistake 1: Treating a Hash as a Signature

A hash does not prove who generated the data.

### Mistake 2: Treating HMAC as a Public-Key Signature

Shared secrets do not provide the same third-party attribution model.

### Mistake 3: Signing an Ambiguous Representation

If the exact signed bytes are not defined, independent verification can fail.

### Mistake 4: Ignoring Key Compromise

A compromised private key can undermine future signatures.

### Mistake 5: Ignoring Revocation

A verification process must understand the key lifecycle.

### Mistake 6: Assuming Signatures Prevent Replay

A copied valid signature can sometimes be submitted again.

### Mistake 7: Trusting Local Timestamps Without Qualification

A locally recorded timestamp is not automatically independently trustworthy.

### Mistake 8: Assuming Audit Logs Are Immutable

A conventional database log can potentially be modified by privileged administrators.

### Mistake 9: Signing Only Human-Readable Text

Important machine-readable metadata may remain outside the signed representation.

### Mistake 10: Treating Cryptographic Validity as Legal Finality

The legal significance of electronic signatures and evidence depends on applicable law, contracts, procedures, and the circumstances of a dispute.

## 30. Security Considerations

A production non-repudiation architecture should consider:

### Private-Key Protection

The private key is one of the most important security assets.

Access should be restricted and monitored.

### Algorithm Selection

Use standardized, reviewed algorithms.

Do not invent cryptographic primitives.

### Randomness

Cryptographic key generation and nonce generation require appropriate cryptographically secure randomness.

### Algorithm Agility

Evidence systems with long retention periods should support migration when cryptographic algorithms become unsuitable.

### Certificate Validation

If certificates are used, the verification process must validate relevant certificate properties, trust chains, validity periods, and revocation status according to policy.

### Authorization

A valid signature must be evaluated together with the signer's authority.

### Replay Protection

Sensitive operations should include freshness controls.

### Evidence Access

Evidence itself may contain sensitive business or personal information.

Access to evidence must therefore be controlled.

### Evidence Deletion

Retention and deletion policies must be explicit.

Deleting evidence may undermine later verification or violate organizational or legal requirements.

## 31. Performance Considerations

Hash functions are generally efficient for large amounts of data.

Public-key signatures are more computationally expensive than ordinary hashing.

A common design is:

1. Serialize the document.
2. Calculate a cryptographic digest.
3. Sign an appropriate digest or standardized signature structure.
4. Store the document, signature, and verification metadata.

For a sequence of `n` evidence records, basic sequential verification is generally proportional to the number of records:

`O(n)`

If each record is independently verified, the signature verification cost dominates the cryptographic portion.

Hash-chain verification also requires processing each relevant record.

Database indexing can improve retrieval of individual records, while chain verification may still require checking predecessor relationships.

Replay protection using a hash set or balanced tree can provide efficient nonce lookup.

The exact complexity depends on the data structure and persistence layer.

## 32. Production Design Considerations

A production architecture should separate:

1. Business application
2. Identity service
3. Authorization service
4. Signing service
5. Key-management infrastructure
6. Evidence store
7. Audit system
8. Timestamping infrastructure
9. Verification service
10. Monitoring and incident response

This separation reduces the risk that a single application component can silently rewrite the entire evidence history.

### Signing Service

Applications can send a precisely defined signing request to a protected signing service.

The private key need not be directly accessible to ordinary application code.

### Evidence Store

Evidence should be stored with controlled write and read permissions.

Append-only or write-once mechanisms can strengthen evidence preservation.

### Verification Service

Verification should produce an explicit result explaining:

- What was verified
- Which key was used
- Which identity was associated with it
- Which algorithm was used
- Whether the signature was valid
- Whether the key was valid at the relevant time
- Whether the evidence chain was intact
- Whether replay checks passed

## 33. Data Model Example

A production evidence record might conceptually contain:

`record_id`

`event_type`

`actor_id`

`key_id`

`algorithm`

`payload_hash`

`canonicalization_method`

`signature`

`created_at`

`sequence_number`

`previous_record_hash`

`timestamp_token`

`authorization_decision`

`application_id`

`policy_version`

`verification_metadata`

The exact schema should be designed according to the application's security, operational, retention, and compliance requirements.

## 34. End-to-End Evidence Workflow

A complete transaction can follow this sequence:

1. Authenticate the user.
2. Determine the user's identity.
3. Check authorization.
4. Construct the exact business record.
5. Canonically serialize the record.
6. Calculate its cryptographic hash.
7. Sign the appropriate representation using a protected private key.
8. Attach key and algorithm metadata.
9. Record a timestamp.
10. Store the signed evidence.
11. Record an audit event.
12. Return the transaction result.
13. Preserve evidence according to retention policy.
14. Later verify the complete evidence package when required.

The important idea is that non-repudiation is an evidence lifecycle rather than a single API call.

## 35. Practical Applications

Non-repudiation concepts are relevant to:

- Electronic contract approval
- Financial transaction authorization
- Purchase-order approval
- Digital invoices
- Software release signing
- Secure document workflows
- Regulatory audit systems
- Enterprise approval systems
- Electronic procurement
- Certificate-based enterprise authentication
- Legal document workflows
- High-value transaction systems
- Supply-chain documentation
- Secure API requests
- Administrative actions
- Long-term archival evidence

The required evidence strength differs according to the application.

A low-risk internal event may require an ordinary authenticated audit record.

A high-value contract approval may require strong identity proofing, protected signing keys, timestamp evidence, authorization evidence, and long-term preservation.

## 36. Why the Three Languages Demonstrate Different Aspects

### Python

Python is useful for conceptual exploration because its syntax makes data structures, cryptographic operations, validation logic, and test cases easy to express.

The Python program emphasizes:

- Fundamental concepts
- Educational cryptographic mechanics
- Data modeling
- Verification
- Testing
- Evidence workflow

### JavaScript

JavaScript is particularly relevant to application and web ecosystems.

The JavaScript program emphasizes:

- Node.js cryptographic APIs
- Ed25519 signatures
- Canonical object serialization
- Application-level records
- Promise-based verification
- Runtime behavior
- Replay protection

### C++

C++ is useful for demonstrating systems-oriented design.

The C++ case study emphasizes:

- Strongly typed data structures
- Explicit architecture
- Resource-oriented design
- Verification services
- Key lifecycle modeling
- Error handling
- Audit infrastructure
- Performance-aware data structures

The cryptographic implementation in the C++ program is intentionally educational because production C++ applications should rely on a reviewed cryptographic library rather than implementing security primitives themselves.

## 37. Implementation Limitations

The Python educational RSA-like implementation is not a production cryptographic system.

The C++ educational digest and signature service are also not production cryptography.

The timestamp authority implementations are simulations.

The evidence ledgers are in-memory examples rather than durable databases.

The key registries do not implement full certificate validation or real hardware-backed key storage.

These limitations are deliberate so that the core architecture remains understandable while clearly separating educational mechanisms from production cryptographic infrastructure.

## 38. Best Practices

A robust non-repudiation implementation should:

- Define exactly what is signed.
- Use deterministic serialization.
- Use standardized cryptographic algorithms.
- Protect private keys.
- Bind keys to identities through trustworthy mechanisms.
- Record authorization decisions where important.
- Include freshness controls for sensitive requests.
- Preserve timestamps where required.
- Protect audit records.
- Separate current key status from historical verification.
- Maintain algorithm identifiers.
- Support cryptographic migration.
- Validate all evidence before accepting a transaction.
- Fail closed on critical verification errors.
- Preserve sufficient evidence for independent verification.
- Apply appropriate access controls to evidence.
- Test tampering and failure cases.
- Avoid inventing cryptographic algorithms.
- Document operational and legal assumptions.

## 39. Verification Checklist

When examining a non-repudiation record, verify:

- [ ] The exact signed content is available.
- [ ] The signature is present.
- [ ] The signature algorithm is identified.
- [ ] The public verification key is available.
- [ ] The public key is bound to the claimed identity.
- [ ] The certificate or identity evidence is valid according to policy.
- [ ] The signed content has not changed.
- [ ] The signing key was appropriate at the relevant time.
- [ ] Revocation status is considered.
- [ ] Timestamp evidence is available when required.
- [ ] Replay controls are applicable where relevant.
- [ ] Authorization evidence exists where required.
- [ ] Audit records are intact.
- [ ] Evidence retention requirements are satisfied.
- [ ] The verification procedure itself is trustworthy.

## 40. Relationship Between Technical Evidence and Legal Evidence

Technical non-repudiation mechanisms create evidence.

They do not, by themselves, determine every legal question that may arise from a dispute.

A legal or regulatory assessment can depend on:

- Applicable jurisdiction
- Electronic-signature legislation
- Contractual terms
- Organizational policies
- Identity assurance
- Consent
- Signature intent
- Key custody
- Evidence preservation
- Time of signing
- Revocation information
- Audit records
- Procedural controls

Therefore, technical architecture and legal requirements should be aligned rather than treated as interchangeable.

## 41. Core Mental Model

A useful technical model is:

`Identity`

plus

`Authorization`

plus

`Exact signed content`

plus

`Protected private key`

plus

`Digital signature`

plus

`Trusted time`

plus

`Audit evidence`

plus

`Evidence preservation`

plus

`Independent verification`

equals a much stronger non-repudiation evidence system.

No single component should be treated as sufficient in isolation.

The implementations demonstrate this layered approach by combining cryptographic integrity, signatures, identity metadata, key lifecycle information, replay protection, timestamps, audit events, and verification logic.
