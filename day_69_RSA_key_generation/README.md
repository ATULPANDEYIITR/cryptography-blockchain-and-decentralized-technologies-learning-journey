# RSA Key Generation and Enterprise Key Management

## 1. Introduction

RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm based on the mathematical properties of large prime numbers.

RSA uses two mathematically related keys:

- **Public key:** Distributed to parties that need to encrypt information or verify digital signatures.
- **Private key:** Kept confidential and used to decrypt information or create digital signatures.

The security of RSA depends on the computational difficulty of factoring a sufficiently large composite integer into its prime factors.

This project implements RSA key generation, mathematical validation, cryptographic operations, and enterprise key lifecycle management across Python, JavaScript, C++17, Java 17, and PostgreSQL.

## 2. RSA Mathematical Foundations

RSA key generation involves selecting two distinct prime numbers and constructing a mathematically related public and private key.

### 2.1 Prime number selection

Select two large, independently generated prime numbers:

- \(p\): First prime.
- \(q\): Second prime.

The primes must be distinct and generated using a cryptographically secure random source.

### 2.2 Modulus calculation

Calculate the RSA modulus:

\[
n=pq
\]

The modulus is part of both the public and private keys.

Its bit length determines the RSA key size.

### 2.3 Euler's totient function

For distinct prime factors:

\[
\phi(n)=(p-1)(q-1)
\]

Euler's totient represents the number of positive integers smaller than \(n\) that are relatively prime to \(n\).

### 2.4 Public exponent

Select an integer \(e\) satisfying:

\[
1<e<\phi(n)
\]

\[
\gcd(e,\phi(n))=1
\]

The implementations use:

\[
e=65537
\]

This exponent is widely used because it provides an efficient public-key operation while avoiding the weaknesses associated with very small exponents.

### 2.5 Private exponent

Calculate the modular multiplicative inverse of \(e\):

\[
d=e^{-1}\pmod{\phi(n)}
\]

The defining relationship is:

\[
ed\equiv1\pmod{\phi(n)}
\]

The private exponent must remain confidential.

### 2.6 RSA key structure

| Component | Mathematical representation | Purpose |
|---|---|---|
| Prime 1 | \(p\) | Private factor |
| Prime 2 | \(q\) | Private factor |
| Modulus | \(n=pq\) | Shared key parameter |
| Totient | \(\phi(n)\) | Supports private exponent calculation |
| Public exponent | \(e\) | Public operation |
| Private exponent | \(d\) | Private operation |

The public key contains \((n,e)\).

The private key contains the private exponent and additional private mathematical parameters required for efficient cryptographic operations.

## 3. RSA Key Generation Workflow

The complete mathematical workflow is:

Prime generation
    |
    v
Select distinct p and q
    |
    v
Calculate n = p * q
    |
    v
Calculate Euler's totient
    |
    v
Select public exponent e
    |
    v
Calculate private exponent d
    |
    v
Validate mathematical relationships
    |
    v
Serialize private and public keys
    |
    v
Calculate public-key fingerprint
    |
    v
Register key metadata
    |
    v
Activate key

The implementation separates key generation from activation. A generated key is not automatically treated as an approved operational key.

## 4. Prime Generation and Primality Testing

RSA security requires prime factors that are sufficiently large and unpredictable.

### 4.1 Candidate generation

A prime candidate must be generated using a cryptographically secure random-number generator.

The candidate is then tested for primality.

### 4.2 Miller-Rabin primality testing

Miller-Rabin is a probabilistic primality-testing algorithm.

For an odd candidate \(n\), express:

\[
n-1=2^s d
\]

where \(d\) is odd.

For selected test bases, modular exponentiation determines whether the candidate behaves consistently with a prime number.

Repeated independent rounds reduce the probability of accepting a composite candidate.

The C++ implementation uses a deterministic set of Miller-Rabin bases valid for unsigned 64-bit integers. Its prime-size restriction is intentional.

Production implementations should use vetted cryptographic libraries that provide appropriate random generation and primality testing.

### 4.3 Randomness requirements

Randomness is a critical part of RSA security.

Weak random generation can cause predictable prime factors or repeated keys.

The implementations use:

| Language | Randomness and cryptographic mechanism |
|---|---|
| Python | `cryptography` RSA backend |
| JavaScript | Node.js `crypto` module |
| C++17 | `std::random_device` for the educational demonstration |
| Java 17 | JCA RSA key-pair generator |

The C++ random-number generator is not a production cryptographic random-number implementation.

## 5. Key Sizes and Security Policy

RSA key length determines the approximate size of the modulus.

| RSA modulus | Intended project classification |
|---|---|
| 2048 bits | Standard minimum for contemporary RSA deployments |
| 3072 bits | Stronger security margin |
| 4096 bits | Higher computational cost and longer-term policy option |

The Python implementation accepts 2048, 3072, and 4096 bits.

The JavaScript implementation defines development, standard, and high-assurance policies.

The Java implementation uses explicit security-policy enumerations.

The PostgreSQL implementation stores approved key-generation policies and checks generated-key metadata against those policies.

The C++ implementation uses much smaller primes because it is restricted to 64-bit integer arithmetic. It does not provide production-strength RSA.

## 6. RSA Encryption and Decryption

RSA supports public-key encryption and private-key decryption.

For a valid message representative \(m\), where \(0 \leq m < n\):

Encryption:

\[
c=m^e\bmod n
\]

Decryption:

\[
m=c^d\bmod n
\]

Here:

- \(m\) is the original message representative.
- \(c\) is the ciphertext representative.
- \(e\) is the public exponent.
- \(d\) is the private exponent.
- \(n\) is the modulus.

The mathematical equations explain RSA, but production implementations must use secure padding.

### 6.1 OAEP padding

The Python, JavaScript, and Java implementations use RSA-OAEP with SHA-256.

OAEP provides randomized encryption and prevents the use of textbook RSA for ordinary application messages.

The maximum plaintext size is limited by the modulus size and hash length:

\[
m_{\max}=k-2hLen-2
\]

Where:

- \(k\) is the modulus length in bytes.
- \(hLen\) is the hash output length in bytes.

For SHA-256, \(hLen=32\).

RSA encryption should normally encrypt a randomly generated symmetric key rather than an entire large document. The document can then be encrypted using an authenticated symmetric encryption algorithm.

The C++ implementation uses textbook RSA only to demonstrate the underlying mathematical operation. It must never be used to encrypt real information.

## 7. RSA Digital Signatures

RSA also supports digital signatures.

A private key signs information, while the corresponding public key verifies the signature.

The project uses RSA-PSS with SHA-256 in Python, JavaScript, and Java.

The signature process is conceptually:

Message
    |
    v
SHA-256 hashing
    |
    v
RSA-PSS encoding
    |
    v
Private-key signing
    |
    v
Digital signature

Verification uses the public key and the original message.

RSA-PSS is preferred for new RSA signature applications because it incorporates randomized encoding.

A valid signature establishes that the signed content has not been modified and that the signing operation was performed using the corresponding private key. Trust in the signer still requires an appropriate identity and public-key validation process.

## 8. Public-Key Fingerprinting

A fingerprint provides a compact identifier for a public key.

The implementations calculate:

\[
F=\operatorname{SHA256}(\text{DER-encoded public key})
\]

The Python implementation serializes the public key using DER SubjectPublicKeyInfo.

Node.js uses the public key's DER representation.

Java uses the encoded public-key representation.

The PostgreSQL model stores the resulting SHA-256 fingerprint as a unique identifier.

Fingerprints support:

- Key identification.
- Duplicate detection.
- Public-key comparison.
- Key inventory management.
- Integrity verification.
- Audit reporting.

A fingerprint does not independently establish that a public key belongs to a trusted organization. Trust requires a separate authentication or certificate-validation process.

## 9. Python Implementation

The Python implementation provides a structured RSA key-management workflow using the `cryptography` package.

### Main components

| Component | Responsibility |
|---|---|
| `RSAConfig` | Validates key-generation parameters |
| `RSAKeyPair` | Represents the generated key pair |
| `RSAKeyManager` | Handles generation and cryptographic operations |
| `RSAConfigurationError` | Represents invalid configuration |
| `RSAOperationError` | Represents operation failures |

### Implemented operations

- RSA key generation.
- Key-size validation.
- Public exponent validation.
- Prime-factor validation.
- Public/private key consistency checks.
- SHA-256 fingerprint calculation.
- PEM serialization.
- Encrypted PKCS#8 private-key export.
- Public-key export.
- Private-key loading.
- Public-key loading.
- RSA-PSS signatures.
- RSA-OAEP encryption and decryption.
- Automated cryptographic assertions.

### Private-key serialization

The implementation uses:

- PKCS#8 for private-key serialization.
- SubjectPublicKeyInfo for public-key serialization.
- PEM for readable key-file representation.
- BestAvailableEncryption for encrypted private-key export.

The private-key file is created with restrictive permissions on supported POSIX systems.

The implementation prevents accidental replacement of existing key files.

Production systems should also use secure passphrase handling, protected backups, key-management services, and controlled key destruction.

### Execution

Install the dependency using `pip install cryptography`.

Run the script using Python 3.

The `--bits` argument controls the RSA modulus size, while `--output` controls the output directory.

The `--test-only` argument executes generation and cryptographic verification without exporting key files.

## 10. JavaScript Implementation

The JavaScript implementation uses Node.js built-in cryptographic and filesystem capabilities.

### Main components

| Component | Responsibility |
|---|---|
| `RSAKeyRecord` | Represents key metadata and lifecycle state |
| `RSAKeyService` | Provides cryptographic and registry operations |
| `KEY_POLICIES` | Defines modulus-size policies |
| `KEY_STATE` | Defines key lifecycle states |
| `RSAError` | Represents application-level failures |

### JavaScript-specific mechanisms

**Asynchronous key generation**

Node.js key generation uses an asynchronous Promise-based API.

This prevents the application from needing to perform a synchronous key-generation operation.

**Map-based key registry**

The registry uses a `Map` indexed by UUID.

This provides efficient lookup and separation between key identifiers and key material.

**Event-oriented audit history**

The service records events for:

- Key generation.
- Key activation.
- Signing.
- Key revocation.

**Filesystem controls**

Private-key export uses restrictive file permissions and exclusive file creation.

The implementation rejects attempts to overwrite an existing key file.

**Lifecycle enforcement**

Keys must be active before signing, encryption, or decryption.

Revoked keys are rejected by the service.

### Cryptographic implementation

Node.js provides:

- RSA key-pair generation.
- SPKI public-key representation.
- PKCS#8 private-key representation.
- RSA-PSS signing.
- RSA-OAEP encryption.
- SHA-256 fingerprints.

The implementation uses AES-256-CBC to encrypt the exported PKCS#8 PEM representation. A production deployment should use an approved key-storage service and should carefully manage the passphrase independently of the key file.

## 11. C++17 Implementation

The C++ implementation focuses on the underlying mathematical construction of RSA.

Unlike the other implementations, it does not depend on an external cryptographic library.

### Main components

| Component | Responsibility |
|---|---|
| `ModularArithmetic` | Modular multiplication, exponentiation, and inversion |
| `PrimeGenerator` | Prime candidate generation and primality testing |
| `RSAKeyGenerator` | Constructs and validates RSA parameters |
| `RSAEngine` | Performs educational encryption and decryption |
| `RSAParameters` | Holds RSA mathematical values |
| `KeyPolicy` | Controls the educational key-generation configuration |

### Modular exponentiation

RSA requires efficient computation of:

\[
a^b\bmod n
\]

Repeated multiplication would be inefficient for large exponents.

The implementation uses square-and-multiply modular exponentiation.

Its complexity is logarithmic in the exponent:

\[
O(\log b)
\]

The implementation also uses an unsigned 128-bit intermediate result for modular multiplication to avoid 64-bit multiplication overflow.

### Extended Euclidean algorithm

The private exponent requires the modular inverse of the public exponent.

The extended Euclidean algorithm calculates integers satisfying:

\[
ax+my=\gcd(a,m)
\]

When the greatest common divisor is one, the coefficient \(x\), reduced modulo \(m\), provides the modular inverse.

### Important limitation

The C++ implementation supports only 64-bit RSA modulus values.

It is an educational mathematical demonstration, not secure RSA.

It does not implement:

- Production-size RSA key generation.
- Secure private-key serialization.
- OAEP padding.
- PSS signatures.
- Secure cryptographic random-number generation.
- Production key protection.

The implementation deliberately exposes mathematical parameters to demonstrate the RSA construction. Those parameters must not be exposed in production systems.

## 12. Java 17 Implementation

The Java implementation models RSA as an enterprise cryptographic service.

It uses the Java Cryptography Architecture rather than implementing the underlying large-integer algorithms manually.

### Main components

| Component | Responsibility |
|---|---|
| `RSAKeyService` | Generates keys and manages cryptographic operations |
| `KeyRecord` | Represents key material and lifecycle |
| `SecurityPolicy` | Defines approved RSA configurations |
| `KeyMetadata` | Provides immutable key metadata |
| `AuditEvent` | Represents key-management events |
| `KeyState` | Defines lifecycle transitions |
| `RSAException` | Represents application failures |

### Domain modeling

The implementation uses Java records for immutable metadata and audit information.

The key record maintains its own lifecycle state.

The service maintains a concurrent registry using `ConcurrentHashMap`.

This provides thread-safe access to registry entries. Production systems must also coordinate key rotation and authorization across distributed application instances.

### Java cryptographic mechanisms

The implementation uses:

- `KeyPairGenerator` for RSA generation.
- `RSAPublicKey` for RSA parameter inspection.
- `Signature` for RSA-PSS.
- `Cipher` for RSA-OAEP.
- `MessageDigest` for SHA-256 fingerprints.
- `HexFormat` for fingerprint representation.

The Java implementation explicitly configures SHA-256 for OAEP and MGF1.

It also configures RSA-PSS with SHA-256, MGF1-SHA256, a 32-byte salt, and a trailer field of 1.

Explicit parameter configuration helps avoid accidental differences between cryptographic providers.

### Enterprise lifecycle

The Java service supports:

- Key generation.
- Parameter validation.
- Key activation.
- Signing.
- Signature verification.
- Encryption.
- Decryption.
- Key revocation.
- Metadata retrieval.
- Audit-event collection.

Revoked keys cannot perform cryptographic operations through the service.

## 13. PostgreSQL Implementation

The PostgreSQL implementation provides the relational management layer for RSA key generation.

It does not generate cryptographic keys itself. Key generation and cryptographic verification belong to the application or an approved cryptographic service.

### Relational model

The main entities are:

| Entity | Purpose |
|---|---|
| `users` | Identifies users and organizational roles |
| `key_policies` | Stores approved RSA generation configurations |
| `generation_requests` | Tracks key-generation requests |
| `rsa_keys` | Stores public-key metadata and lifecycle information |
| `key_validations` | Stores key-validation results |
| `key_audit_events` | Maintains key-management event history |

### Entity relationships

Users
    |
    v
Generation Requests
    |
    v
Key Policies
    |
    v
RSA Keys
    |
    +---- Key Validations
    |
    +---- Audit Events
    |
    +---- Rotation History

### Key-generation requests

A request identifies:

- Requesting user.
- Approved policy.
- Application.
- Deployment environment.
- Intended purpose.
- Processing status.
- Completion or failure information.

The request workflow separates administrative approval and request tracking from actual cryptographic generation.

### Key registry

The `rsa_keys` table stores:

- Key identifier.
- Owner.
- Policy.
- Public-key PEM.
- Modulus length.
- Public exponent.
- SHA-256 fingerprint.
- Lifecycle state.
- Creation timestamp.
- Activation timestamp.
- Expiration information.
- Revocation information.

The schema does not contain private-key columns.

This separation reduces exposure of private-key material through ordinary database queries and reporting.

### Constraints

The database enforces:

- Unique key identifiers.
- Unique fingerprints.
- Valid modulus sizes.
- Public exponent restrictions.
- Foreign-key relationships.
- Valid lifecycle states.
- Consistent revocation timestamps.
- Consistent activation timestamps.
- Valid generation-request states.

### Triggers

The SQL implementation contains three important trigger mechanisms.

**Key registration validation**

The insertion trigger checks whether the key matches the enabled policy and whether its generation request is processing.

**Lifecycle transition enforcement**

The transition trigger rejects invalid changes to key states.

**Audit generation**

The audit trigger records key generation and lifecycle transitions.

### Functions and procedures

The database includes:

- `create_generation_request()`
- `register_generated_key()`
- `activate_rsa_key()`
- `request_key_rotation()`
- `revoke_rsa_key()`

These operations implement request processing, registration, activation, rotation, and revocation.

Activation requires a successful validation record.

Revocation requires an authorized user and a documented reason.

### Views

The project defines:

- `active_key_inventory`
- `key_validation_report`

These views support operational monitoring and validation reporting.

### Transaction management

Key registration and request completion are executed within a transaction.

The transaction ensures that the registration operation and request-state update succeed together or are rolled back together.

The example also demonstrates savepoints and rollback for a rotation operation.

## 14. RSA Key Lifecycle Management

Key generation is only one part of cryptographic key management.

A production RSA key should pass through a controlled lifecycle.

| State | Description |
|---|---|
| REQUESTED | A key-generation request has been submitted |
| GENERATED | Cryptographic key material has been created |
| VALIDATED | Mathematical and cryptographic validation has succeeded |
| ACTIVE | The key is approved for operational use |
| ROTATION_PENDING | A replacement key is being prepared |
| REVOKED | The key is no longer trusted for operational use |
| EXPIRED | The key has reached its configured expiration |
| FAILED | Generation or processing has failed |

The lifecycle implemented by the project is:

REQUESTED
    |
    v
GENERATED
    |
    v
VALIDATED
    |
    v
ACTIVE
    |
    +------> ROTATION_PENDING
    |                 |
    |                 v
    +--------------> REVOKED
    |
    +--------------> EXPIRED

A failed generation request is recorded separately from a successfully generated key.

A generated key must not be activated without successful validation.

## 15. Security Controls

### Private-key confidentiality

Private keys must never be stored in plaintext in ordinary application databases.

Suitable production storage approaches include:

- Hardware security modules.
- Managed key-management services.
- Encrypted and access-controlled key vaults.
- Secure cryptographic services.

### Key access control

Only authorized identities should be permitted to:

- Generate keys.
- Activate keys.
- Rotate keys.
- Revoke keys.
- Export private-key material.
- Change cryptographic policies.

### Key rotation

Rotation replaces an existing operational key with a newly generated key.

A rotation process should include:

- Generating replacement key material.
- Validating the replacement.
- Distributing the replacement public key.
- Updating dependent applications.
- Migrating encrypted data where necessary.
- Revoking or retiring the old key according to policy.

### Revocation

Revocation prevents further operational use of a compromised or unauthorized key.

The revocation event should contain the responsible identity, timestamp, and reason.

### Auditability

Audit records support investigation of:

- Unauthorized key access.
- Failed generation attempts.
- Validation failures.
- Key activation.
- Key rotation.
- Revocation.
- Policy changes.

Audit storage should be protected against unauthorized modification and deletion.

## 16. Validation and Failure Scenarios

The implementations demonstrate several failure conditions.

| Failure condition | Expected behavior |
|---|---|
| Unsupported RSA modulus | Reject configuration |
| Invalid public exponent | Reject configuration |
| Identical prime factors | Reject generated parameters |
| Invalid modular inverse | Reject key construction |
| Invalid private-key passphrase | Reject private-key loading |
| Invalid signature | Return failed verification |
| Modified signed message | Reject signature verification |
| Invalid ciphertext | Reject decryption |
| Empty message | Reject the operation |
| Oversized OAEP plaintext | Reject encryption |
| Unknown key identifier | Reject registry lookup |
| Inactive key | Reject cryptographic operation |
| Revoked key | Reject further operational use |
| Missing validation record | Reject activation |
| Unauthorized rotation | Reject lifecycle transition |
| Duplicate key fingerprint | Reject database insertion |
| Invalid lifecycle transition | Reject database update |

The implementations use exceptions, validation conditions, and transactional operations to prevent invalid states from being accepted silently.

## 17. Performance Considerations

RSA operations have different computational costs.

| Operation | General performance characteristics |
|---|---|
| Key generation | Expensive |
| Public-key encryption | Relatively efficient |
| Private-key decryption | More computationally expensive |
| Public-key verification | Relatively efficient |
| Private-key signing | More computationally expensive |
| Fingerprint calculation | Linear in encoded public-key size |

The public exponent 65537 allows efficient public-key exponentiation.

Private-key operations can use the Chinese Remainder Theorem to improve performance.

For large data volumes, hybrid encryption is more efficient than encrypting complete documents with RSA.

The JavaScript implementation uses asynchronous key generation to avoid unnecessary synchronous processing.

The JavaScript and Java registries use efficient identifier-based lookup structures.

The PostgreSQL indexes support common operational queries involving ownership, state, expiration, fingerprints, and audit history.

## 18. Implementation Comparison

| Area | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Key generation | Cryptography library | Node.js crypto | Educational implementation | JCA | Not performed |
| Prime generation | Library | Library | Miller-Rabin | JCA | Not performed |
| Modular inverse | Library | Library | Extended Euclidean algorithm | JCA | Not performed |
| OAEP | Yes | Yes | No | Yes | No |
| PSS signatures | Yes | Yes | No | Yes | No |
| Fingerprinting | SHA-256 | SHA-256 | Not implemented | SHA-256 | Stored metadata |
| Lifecycle management | Key manager | Service and records | State engine | Enterprise service | Relational workflow |
| Audit records | Logging | Event collection | Console output | Event collection | Persistent records |

## 19. Execution Requirements

| Deliverable | Runtime | Dependency |
|---|---|---|
| Python | Python 3.10+ | `cryptography` |
| JavaScript | Node.js 20+ | Built-in modules |
| C++17 | C++17 compiler | Standard library |
| Java | Java 17 | JDK |
| PostgreSQL | PostgreSQL 15+ | PostgreSQL database |

The PostgreSQL script creates its schema, types, tables, indexes, functions, procedures, triggers, views, and demonstration records.

The SQL demonstration PEM values are intentionally invalid and must not be treated as actual public keys.

## 20. Practical Applications

RSA key generation and management support several enterprise security applications:

- Digital document signing.
- Secure application communication.
- Public-key infrastructure.
- Certificate-based authentication.
- Secure symmetric-key distribution.
- Software-signing systems.
- Secure archival systems.
- Enterprise identity systems.
- Cryptographic key rotation.
- Data-protection workflows.

The key-management layer must coordinate cryptographic operations with identity verification, authorization, auditing, backup, rotation, and revocation.

## 21. Technical Limitations

The project distinguishes between mathematical education, application-level cryptography, and enterprise key management.

The C++ implementation is intentionally limited to small integers and textbook RSA operations. It demonstrates the mathematics but does not provide secure production RSA.

The Python, JavaScript, and Java implementations rely on established cryptographic providers for production-sized RSA operations.

The PostgreSQL implementation manages metadata and lifecycle records. It does not validate the mathematical contents of arbitrary PEM strings independently.

The database's demonstration public-key values are not cryptographically valid.

Production deployments must implement actual public-key parsing, fingerprint verification, private/public key correspondence checks, authorization enforcement, secure key storage, backup controls, and protected audit infrastructure.

The distinction between generating a mathematically valid key pair and securely operating a complete key-management system is fundamental to enterprise RSA deployment.
