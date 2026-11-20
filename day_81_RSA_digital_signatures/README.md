# RSA Digital Signatures

## 1. Introduction

RSA digital signatures provide a mechanism for authenticating digital messages, documents, software artifacts, and electronic transactions.

RSA is an asymmetric cryptographic algorithm. It uses two mathematically related keys:

- **Private key:** Used to create digital signatures. It must remain confidential.
- **Public key:** Used to verify signatures. It can be distributed to authorized recipients.

A digital signature establishes evidence that a message was signed using the corresponding private key and that the signed message has not changed since signing.

RSA signatures support three important security properties:

| Property | Meaning |
|---|---|
| Authentication | Provides evidence of the signing key's involvement |
| Integrity | Detects modifications to signed content |
| Non-repudiation support | Provides cryptographic evidence that can support accountability |

Non-repudiation is not established by mathematics alone. It also depends on private-key control, identity verification, key ownership, authorization, timestamps, and audit procedures.

## 2. Mathematical Foundations

RSA is based on the computational difficulty of factoring a sufficiently large composite integer.

### 2.1 Key generation

Two large, distinct prime numbers are selected:

\[
p,\ q
\]

The RSA modulus is:

\[
n=pq
\]

Euler's totient for distinct prime factors is:

\[
\phi(n)=(p-1)(q-1)
\]

A public exponent \(e\) is selected such that:

\[
1<e<\phi(n)
\]

and:

\[
\gcd(e,\phi(n))=1
\]

The private exponent \(d\) is calculated using the modular multiplicative inverse:

\[
d=e^{-1}\pmod{\phi(n)}
\]

The resulting keys are:

\[
PublicKey=(n,e)
\]

\[
PrivateKey=(n,d)
\]

The public key can be distributed. The private exponent must remain secret.

Modern implementations use secure prime generation, appropriate RSA key sizes, and carefully implemented cryptographic libraries.

### 2.2 Hashing the message

A digital signature normally operates on a cryptographic digest rather than directly processing an arbitrarily large document.

For SHA-256:

\[
h=SHA256(M)
\]

Where:

- \(M\) represents the original message.
- \(h\) represents its 256-bit digest.

A cryptographic hash produces a fixed-length digest and is designed to make it computationally infeasible to find practical collisions or reverse the digest.

Hashing and signing are distinct operations. SHA-256 alone does not authenticate the message.

### 2.3 Signature generation

Conceptually, RSA signing applies the private-key operation to an encoded message representative:

\[
S=EM(M)^d \bmod n
\]

Here, \(EM\) represents a secure encoding procedure.

For the implementations in this repository, RSA-PSS supplies the encoding and randomized padding mechanism.

### 2.4 Signature verification

The verifier uses the public key and the original message.

Conceptually:

\[
EM'=S^e \bmod n
\]

The verifier independently calculates the expected encoding and checks whether the signature is valid.

With RSA-PSS, verification also checks the required padding structure, message hash, mask-generation function, and salt-related parameters.

A successful verification means that the signature is mathematically consistent with the supplied message and public key.

It does not independently establish that the public key belongs to the person or organization claiming ownership.

## 3. RSA-PSS

RSA-PSS stands for RSA Probabilistic Signature Scheme.

It is a modern RSA signature encoding designed to provide stronger security properties than deterministic textbook RSA signatures.

The implementations use:

| Parameter | Configuration |
|---|---|
| Asymmetric algorithm | RSA |
| Signature encoding | RSA-PSS |
| Message digest | SHA-256 |
| Mask generation | MGF1 |
| MGF1 digest | SHA-256 |
| Salt | Library-defined maximum in Python; 32 bytes in JavaScript and Java |
| Recommended key sizes | 2048, 3072, 4096 bits |

RSA-PSS incorporates randomness through its salt. Consequently, signing the same message with the same private key can produce different signatures.

This behavior is expected. Verification does not require the original salt to be separately supplied because it is encoded within the signature representation.

### RSA-PSS versus PKCS#1 v1.5

| Feature | RSA-PSS | RSA PKCS#1 v1.5 |
|---|---|---|
| Encoding | Probabilistic | Deterministic |
| Salt | Included | Not used |
| Modern preference | Preferred | Used where compatibility requires it |
| Verification | Strict encoding validation | Structured digest encoding validation |

Textbook RSA, which simply raises an arbitrary message integer to the private exponent, is not a secure digital-signature construction.

## 4. Digital Signature Lifecycle

The complete workflow separates key management, message processing, signing, verification, and authorization.

Document Creation
       |
       v
Canonicalization
       |
       v
SHA-256 Digest
       |
       v
Private-Key Signing
       |
       v
Digital Signature
       |
       v
Signature Envelope
       |
       v
Transmission
       |
       v
Public-Key Verification
       |
       v
Integrity and Authenticity Checks
       |
       v
Identity and Authorization Checks
       |
       v
Acceptance or Rejection
       |
       v
Audit Record

### **4.1 Document preparation**

The sender prepares the exact bytes that must be signed.

A document's representation matters.

Two JSON documents may represent equivalent information while having different byte sequences because of:

- Property ordering.
- Whitespace.
- Character encoding.
- Number formatting.
- Escaping rules.

A canonical serialization procedure creates a deterministic representation before signing.

The Python, JavaScript, and Java implementations include canonical JSON mechanisms for their demonstration documents.

These implementations are examples of deterministic serialization, not complete implementations of every canonical JSON standard.

Independent systems must use identical canonicalization rules.

### **4.2 Signature creation**

The signing service:

1. Validates the private-key configuration.
2. Processes the exact document bytes.
3. Applies SHA-256.
4. Performs RSA-PSS encoding.
5. Produces the RSA signature.
6. Creates a signature record.

The private key must never be included in the signature envelope.

### **4.3 Signature transmission**

A signature envelope may contain:

| Field | Purpose |
|---|---|
| Algorithm | Identifies the signature algorithm |
| Key fingerprint | Identifies the expected public key |
| Message digest | Identifies the signed content |
| Signature | Contains the binary signature encoded as Base64 |
| Creation timestamp | Records the claimed signing time |
| Document identifier | Associates the signature with a document |

The envelope is metadata surrounding the signature. Its fields must be validated independently.

A claimed timestamp is not trusted evidence of signing time unless supported by an appropriate trusted timestamping mechanism.

### **4.4 Signature verification**

The recipient:

1. Retrieves the expected public key.
2. Validates its trust and identity.
3. Checks the algorithm and parameters.
4. Reconstructs the exact original message bytes.
5. Verifies the RSA-PSS signature.
6. Checks key status and authorization.
7. Records the result.

A valid signature does not automatically mean that a business transaction should be accepted. Application authorization rules remain necessary.

## **5. Key Management**

Key management is a major part of a reliable RSA deployment.

### **5.1 Key generation**

The implementations use cryptographically secure RSA key generation where supported.

Recommended configurations include:

| RSA modulus | Typical application |
|---|---|
| 2048 bits | Existing systems and compatibility |
| 3072 bits | Strong general-purpose configuration |
| 4096 bits | Higher computational security margin |

A larger modulus increases the computational cost of signing and verification.

RSA keys must be generated using secure random-number sources.

### **5.2 Private-key protection**

Private keys should be protected using:

- Encrypted PKCS#8 storage.
- Hardware security modules.
- Strict access controls.
- Dedicated signing services.
- Secure backup procedures.
- Key rotation.
- Monitoring of key usage.

Encryption of a private-key file does not replace proper access management.

The password protecting the file must itself be managed securely.

### **5.3 Public-key distribution**

Public-key distribution requires trust.

A public key can be authenticated using:

- X.509 certificates.
- Certificate authorities.
- Public-key fingerprints.
- Enterprise identity registries.
- Explicitly managed trust relationships.

An attacker who substitutes a public key may cause a verifier to trust signatures associated with the wrong identity.

### **5.4 Key revocation**

A key may need to be revoked because of:

- Suspected private-key compromise.
- Employee departure.
- Unauthorized use.
- Expiration.
- Policy changes.
- Cryptographic algorithm migration.

Revocation prevents a key from being treated as currently authorized.

Historical signature validation requires more care. A revoked key may have produced legitimate signatures before its compromise or revocation. Trusted timestamps, historical certificate status, and incident information are needed to evaluate such signatures.

## **6. Python Implementation**

**File:** `rsa_signatures.py`

The Python implementation models a complete signing and verification workflow using the `cryptography` package.

### **6.1 Main components**

| Component | Responsibility |
|---|---|
| `RSASignatureManager` | Key generation, signing, verification, and serialization |
| `SignatureRecord` | Immutable signature metadata |
| `SignatureStatus` | Verification result states |
| `KeyValidationError` | Key configuration failures |
| `SignatureError` | Signing and verification operation failures |

### **6.2 Key generation**

The implementation supports RSA key sizes of 2048, 3072, and 4096 bits.

It uses public exponent 65537.

The key manager rejects unsupported key sizes and mismatched public and private key pairs.

### **6.3 Signing**

The `sign()` method accepts bytes and creates an RSA-PSS signature using SHA-256.

The result includes:

- Algorithm identifier.
- Public-key fingerprint.
- SHA-256 digest.
- Base64-encoded signature.
- UTC creation timestamp.

The `verify_record()` method checks the algorithm, fingerprint, digest, signature encoding, and cryptographic validity.

### **6.4 Serialization**

The implementation supports:

- PEM-encoded public keys.
- PKCS#8 private keys.
- Optional encrypted private-key serialization.
- Restoration of signing and verification services.

Encrypted private-key export is preferred for file-based storage.

### **6.5 File signing**

The file operations read content in binary mode.

This is important because text-mode processing can modify line endings or character representations.

The signature must correspond to the exact bytes that the recipient later verifies.

### **6.6 Validation cases**

The demonstration checks:

- Valid signature.
- Modified document.
- Modified signature.
- Public-key-only verification.
- Attempted signing without a private key.
- Private-key serialization and restoration.

The implementation also uses assertions to detect unexpected behavior.

## **7. JavaScript Implementation**

**File:** `rsa_signatures.js`

The JavaScript implementation uses the Node.js built-in `crypto` module.

It provides an event-oriented and asynchronous engineering perspective.

### **7.1 Main components**

| Component | Responsibility |
|---|---|
| `SignatureService` | RSA key operations |
| `canonicalJSON()` | Deterministic JSON representation |
| `sign()` | RSA-PSS signature creation |
| `verify()` | Cryptographic verification |
| `verifyEnvelope()` | Complete envelope validation |
| `signFile()` | Asynchronous file signing |
| `verifyFile()` | Asynchronous file verification |

### **7.2 Asynchronous key generation**

RSA key generation is computationally expensive.

The implementation uses Node.js asynchronous key generation through `generateKeyPair`.

This avoids unnecessarily blocking the main event loop while generating keys.

### **7.3 Signature envelopes**

The JavaScript implementation returns a frozen signature envelope.

The envelope contains the algorithm, hash, fingerprint, digest, signature, and timestamp.

The verification method validates the expected RSA signature length before invoking cryptographic verification.

### **7.4 Error handling**

The implementation distinguishes:

- Invalid input.
- Missing private keys.
- Missing public keys.
- Unsupported key sizes.
- Malformed signatures.
- Invalid signatures.
- File access failures.

Cryptographic verification failures return `false` rather than exposing sensitive internal details to ordinary callers.

### **7.5 Security considerations**

The implementation uses:

- RSA-PSS padding.
- SHA-256.
- MGF1.
- A fixed salt length.
- Encrypted PKCS#8 private-key export.
- Public-key fingerprints.
- Strict signature-envelope validation.

The canonical JSON function is intended for the demonstrated data model. It does not implement every Unicode normalization, floating-point, or number-serialization requirement of a universal canonical JSON standard.

## **8. C++17 Implementation**

**File:** `rsa_signatures.cpp`

The C++ implementation provides a mathematical demonstration of RSA operations and a repository-oriented signature registry.

It deliberately does not implement production-grade RSA cryptography.

### **8.1 Mathematical operations**

The program includes:

| Function | Purpose |
|---|---|
| `gcd()` | Computes the greatest common divisor |
| `modularMultiply()` | Performs multiplication modulo an integer |
| `modularPower()` | Uses exponentiation by squaring |
| `modularInverse()` | Calculates a modular multiplicative inverse |
| `isPrime()` | Checks demonstration prime factors |

Exponentiation by squaring reduces the number of multiplication operations.

Its time complexity is:

\[
O(\log e)
\]

where \(e\) represents the exponent.

The modular multiplication implementation uses a wider integer type to avoid intermediate overflow for the demonstration's integer range.

### **8.2 Domain model**

The implementation includes:

- `RSAKey`
- `RSAKeyPair`
- `SignatureRecord`
- `RSAArithmetic`
- `RSAKeyGenerator`
- `RSASignatureEngine`
- `RepositorySignatureRegistry`

The registry demonstrates signature registration, verification, duplicate-document rejection, and key revocation.

### **8.3 Important security limitation**

The C++ implementation uses small prime factors and an FNV-1a demonstration hash.

Neither is appropriate for real digital signatures.

Its modular RSA operations illustrate the mathematical relationship between private and public exponents. They do not implement secure signature encoding.

Production RSA signatures require:

- Cryptographically secure prime generation.
- At least appropriately sized RSA keys.
- SHA-256 or a suitable modern digest.
- RSA-PSS.
- Secure random salt generation.
- Constant-time private-key operations.
- Side-channel protections.
- Secure key storage.

The small-key implementation must never be used to authenticate production documents, software, financial transactions, or API requests.

## **9. Java 17 Implementation**

**File:** `RsaDigitalSignatures.java`

The Java implementation models an enterprise signing service.

It uses Java's standard cryptographic architecture and immutable domain objects.

### **9.1 Domain types**

| Type | Responsibility |
|---|---|
| `KeyMetadata` | Key ownership and lifecycle metadata |
| `SignatureRecord` | Signature information |
| `AuditEvent` | Verification and registration history |
| `KeyStatus` | Active, revoked, and expired states |
| `VerificationStatus` | Verification outcomes |
| `SignaturePurpose` | Business purpose of a signature |
| `KeyRegistry` | Public-key registration and retrieval |
| `SignatureService` | Cryptographic signing and verification |
| `SignatureGovernanceService` | Signature records and audit management |

Java records provide immutable representations of key metadata, signature records, and audit events.

### **9.2 Java Cryptography Architecture**

The implementation uses:

- `KeyPairGenerator`
- `PrivateKey`
- `PublicKey`
- `Signature`
- `MessageDigest`
- `PSSParameterSpec`
- `MGF1ParameterSpec`

The selected algorithm is `RSASSA-PSS`.

The implementation explicitly configures SHA-256, MGF1-SHA256, a 32-byte salt, and a trailer field of 1.

### **9.3 Enterprise key governance**

The key registry controls whether a public key can be retrieved for current verification.

A revoked key is rejected by the governance service.

This separates cryptographic validity from current organizational authorization.

### **9.4 Audit management**

Verification attempts produce audit events.

The audit history captures:

- Document identifier.
- Key identifier.
- Timestamp.
- Verification result.
- Operation details.

The implementation returns defensive, unmodifiable audit-list copies.

In a production environment, audit storage would normally be durable and protected against unauthorized modification.

## **10. PostgreSQL Implementation**

**File:** `rsa_signatures.sql`

The PostgreSQL implementation models a centralized signature registry for multiple repositories and signing principals.

The schema separates document records, key metadata, authorization, signature values, verification events, and audit information.

### **10.1 Relational structure**

Repositories
    |
    +---- Signature Policies
    |          |
    |          +---- Signer Authorizations
    |
    +---- Signed Documents
                 |
                 +---- Document Signatures
                 |          |
                 |          +---- Signing Keys
                 |          |
                 |          +---- Principals
                 |
                 +---- Verification Events
                 |
                 +---- Signature Audit

  ### **10.2 Main tables**

| Table | Purpose |
|---|---|
| `repositories` | Repository ownership and identity |
| `principals` | Users and service identities |
| `signing_keys` | Public-key metadata |
| `signature_policies` | Signing requirements |
| `signer_authorizations` | Repository-level signing permissions |
| `signed_documents` | Document identifiers and digests |
| `document_signatures` | Binary signature records |
| `verification_events` | Verification history |
| `signature_audit` | Security audit information |

### **10.3 Integrity constraints**

The schema uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated types.
- Timestamp validation.
- Digest-format validation.
- Signature-length validation.

A signature created using a 2048-bit RSA key must contain a 256-byte signature. A 3072-bit RSA signature occupies 384 bytes, and a 4096-bit RSA signature occupies 512 bytes.

The database enforces the relationship between the recorded modulus size and signature length through the accepted signature-length values and policy validation.

### **10.4 Key authorization**

A registered public key is not automatically authorized for every repository.

The `signer_authorizations` table associates a principal with a repository and signature policy.

The signature-submission trigger checks:

- Key existence.
- Key status.
- Key validity period.
- Key ownership.
- Document existence.
- Digest consistency.
- Policy activation.
- Minimum key size.
- Signer authorization.

### **10.5 Verification workflow**

The `record_verification()` procedure accepts a verification result produced by an external cryptographic service.

It records the result and checks whether the verified digest matches the registered document digest.

The verification trigger updates the current signature status and writes an audit event.

The database therefore records cryptographic decisions without claiming to perform RSA-PSS verification itself.

### **10.6 Eligibility determination**

The `document_is_eligible()` function evaluates whether a document has the required number of distinct authorized signers with qualifying verification records and active keys.

The eligibility result is separate from cryptographic verification.

A document may have valid signatures but still fail policy requirements.

For example:

- The required number of signers has not been reached.
- A signing key has been revoked.
- A key is below the required modulus size.
- A signer authorization has been withdrawn.
- The policy is inactive.

### **10.7 Performance design**

Indexes support common operational queries:

- Documents by repository and submission date.
- Documents by digest.
- Signatures by document.
- Signatures by key.
- Signatures by verification status.
- Verification history by signature.
- Audit history by entity.

The verification report uses a lateral join to retrieve the most recent verification event for each signature.

The CTE reporting example uses `ROW_NUMBER()` to identify the latest verification event.

## **11. Distinguishing Cryptographic and Governance Decisions**

A digital signature system must distinguish several related but different decisions.

| Decision | Meaning |
|---|---|
| Digest calculation | Identifies the message bytes |
| Signature generation | Uses the private key to create a signature |
| Signature verification | Tests mathematical validity using the public key |
| Key trust | Determines whether the public key is associated with a trusted identity |
| Key authorization | Determines whether the key owner is permitted to perform the operation |
| Key lifecycle | Determines whether the key is currently active |
| Policy evaluation | Determines whether organizational requirements have been met |
| Final acceptance | Determines whether the application accepts the document |

These decisions must not be treated as interchangeable.

A cryptographically valid signature does not establish that the signer has business authorization.

A valid public key does not establish that its associated owner is trusted.

A valid signature from a revoked key may require historical evaluation rather than automatic acceptance or rejection.

## **12. Common Failure Modes**

| Failure | Cause | Appropriate response |
|---|---|---|
| Invalid signature | Message or signature was modified | Reject verification |
| Wrong public key | Incorrect key selection | Resolve trusted key identity |
| Missing private key | Signing credentials unavailable | Stop signing |
| Weak RSA modulus | Key violates policy | Reject key |
| Revoked key | Key lifecycle restriction | Reject current authorization |
| Expired key | Validity period ended | Apply historical verification rules |
| Digest mismatch | Different document bytes | Reject signature |
| Serialization mismatch | Different canonicalization | Reconstruct agreed byte representation |
| Malformed Base64 | Corrupted signature envelope | Reject input |
| Unauthorized signer | Missing authorization | Reject operation |
| Unsupported algorithm | Algorithm policy violation | Reject operation |
| Missing verification record | Incomplete processing | Keep document pending |

## **13. Security and Performance Considerations**

### **Security**

Production deployments should enforce the following:

- Keep private keys outside the relational database.
- Use an HSM or managed cryptographic key service for high-value signing operations.
- Use RSA-PSS rather than textbook RSA.
- Use SHA-256 or an appropriately approved modern hash.
- Verify the public-key identity before trusting a signature.
- Validate all algorithm parameters.
- Protect private-key export and backup.
- Apply key rotation and revocation procedures.
- Record verification failures.
- Use trusted timestamps when historical signing-time evidence is required.
- Avoid accepting arbitrary signature algorithms from untrusted envelopes.
- Protect audit records against unauthorized modification.
- Avoid exposing private-key or verification internals through error messages.

### **Performance**

RSA signing and verification have different computational costs.

Signing involves the private-key operation and is generally more expensive than public-key verification.

Performance depends on:

- RSA modulus size.
- Cryptographic provider.
- Hardware acceleration.
- HSM configuration.
- Number of concurrent signing requests.
- Message preparation and serialization.
- Signature-verification workload.

For large documents, applications normally hash the content incrementally rather than loading the entire document into memory.

A single RSA signature has a fixed byte length determined by the modulus size, independent of the message length.

## **14. Implementation Comparison**

| Capability | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| RSA key generation | Yes | Yes | Educational | Yes | No |
| RSA-PSS signing | Yes | Yes | No | Yes | No |
| SHA-256 | Yes | Yes | Demonstration hash only | Yes | Digest function available |
| Signature verification | Yes | Yes | Educational | Yes | External result |
| Public-key management | Yes | Yes | Basic | Yes | Yes |
| Private-key serialization | Yes | Yes | No | No | No |
| Key revocation | Basic key handling | Basic key handling | Registry | Registry | Trigger and policy |
| Audit history | Demonstration | Demonstration | Registry | In-memory service | Persistent tables |
| Policy evaluation | Key validation | Envelope validation | Registry checks | Governance service | SQL functions |

The C++ implementation is intentionally limited to demonstrating RSA arithmetic. It must not be considered equivalent to the production-capable RSA-PSS implementations.

## **15. Execution Requirements**

### **Python**

Requires Python 3.10 or later and the `cryptography` package.

Install the dependency using:

`python -m pip install cryptography`

Execute using:

`python rsa_signatures.py`

To generate encrypted key files, use the `--generate` option with a key size, output directory, and password.

### **JavaScript**

Requires a supported Node.js release with the built-in `crypto` and `fs` modules.

Execute using:

`node rsa_signatures.js`

No third-party npm packages are required.

### **C++17**

Requires a compiler supporting C++17 and the `__int128` extension available in GCC and Clang.

Compile using the C++17 standard and execute the resulting program.

The arithmetic demonstration is not a production cryptographic library.

### **Java 17**

Requires JDK 17.

Compile using:

`javac RsaDigitalSignatures.java`

Execute using:

`java RsaDigitalSignatures`

No external dependencies are required.

### **PostgreSQL**

Requires PostgreSQL 14 or later.

Execute the SQL script using a database account permitted to create schemas, tables, functions, triggers, and the `pgcrypto` extension.

The sample public keys and signatures are deliberately synthetic. They demonstrate relational workflows and must not be interpreted as valid cryptographic credentials.

A production deployment must register real public keys and signatures obtained from the external RSA-PSS signing service.

## **16. Practical Applications**

RSA digital signatures are useful in systems where document integrity, signing-key authentication, and traceable authorization decisions are required.

Examples include:

- Software release authentication.
- Signed software packages.
- Electronic document approval.
- Enterprise API authentication.
- Secure configuration distribution.
- Financial transaction authorization.
- Certificate-based identity systems.
- Digital contract workflows.
- Audit-sensitive business operations.

For software distribution, the recipient can verify a release signature before installing or executing the artifact.

For enterprise document workflows, the signature establishes cryptographic evidence of the signed content while the governance layer determines whether the signing identity and approval process satisfy organizational policy.

The cryptographic layer and the authorization layer must remain separate, independently testable components.
