# Public-Key Cryptography Practice Project

## Project Description

This project demonstrates public-key cryptography through mathematical implementations, cryptographic application programming interfaces, enterprise key management, and relational governance.

The central subject is asymmetric cryptography: a cryptographic system that uses related public and private keys to support encryption, decryption, digital signatures, and verification.

Five implementations provide different engineering perspectives:

| Implementation | Primary focus |
|---|---|
| Python | RSA mathematics, educational key generation, encryption, signatures, and key registration |
| JavaScript | Node.js cryptographic APIs, RSA-OAEP, RSA-PSS, asynchronous operations, and identity rotation |
| C++17 | Modular arithmetic, primality testing, RSA operations, and key-state management |
| Java 17 | Enterprise cryptographic services, immutable domain types, policy enforcement, and lifecycle management |
| PostgreSQL | Key metadata, permissions, signature records, audit events, and eligibility determination |

## 1. Foundations of Public-Key Cryptography

### 1.1 Symmetric and Asymmetric Cryptography

Symmetric cryptography uses the same secret key for encryption and decryption.

Asymmetric cryptography uses two mathematically related keys:

- Public key: distributed to other parties.
- Private key: retained by its owner and protected against unauthorized access.

The two keys perform different operations depending on the cryptographic protocol.

| Property | Symmetric cryptography | Asymmetric cryptography |
|---|---|---|
| Keys | Shared secret | Public and private pair |
| Distribution | Secret distribution required | Public key can be distributed |
| Encryption | Same secret key for both directions | Public-key encryption and private-key decryption |
| Signatures | Not provided directly by ordinary symmetric encryption | Private-key signing and public-key verification |
| Performance | Generally faster | Generally more computationally expensive |
| Common applications | Bulk data protection | Key establishment, signatures, identity verification |

Asymmetric cryptography does not eliminate key-distribution problems. Public keys must still be associated with their legitimate owners.

### 1.2 RSA

RSA is an asymmetric cryptographic algorithm based on modular arithmetic and the computational difficulty of factoring large composite integers.

Its mathematical construction involves two prime numbers.

Let:

- \(p\) = first prime number
- \(q\) = second prime number
- \(n\) = RSA modulus
- \(\phi(n)\) = Euler's totient
- \(e\) = public exponent
- \(d\) = private exponent

The modulus is:

\[
n=pq
\]

For distinct primes:

\[
\phi(n)=(p-1)(q-1)
\]

The public exponent must satisfy:

\[
1<e<\phi(n)
\]

and:

\[
\gcd(e,\phi(n))=1
\]

The private exponent is the modular multiplicative inverse:

\[
d=e^{-1}\pmod{\phi(n)}
\]

Therefore:

\[
ed\equiv1\pmod{\phi(n)}
\]

The public key is:

\[
(n,e)
\]

The private key is:

\[
(n,d)
\]

### 1.3 Modular Arithmetic

RSA operations use modular exponentiation.

For an integer message \(m\), textbook RSA encryption is:

\[
c=m^e\bmod n
\]

Decryption is:

\[
m=c^d\bmod n
\]

The mathematical relationship between the public and private exponents enables recovery of the original message.

The implementations demonstrate modular exponentiation using efficient repeated squaring.

Instead of calculating an extremely large power directly, the algorithm repeatedly squares intermediate values and reduces them modulo \(n\).

This significantly reduces intermediate numerical growth.

### 1.4 Prime Number Generation

RSA security depends on sufficiently large, independently generated prime numbers.

The project demonstrates the Miller-Rabin primality test.

The test expresses an odd candidate number as:

\[
n-1=2^s d
\]

where \(d\) is odd.

It then evaluates modular exponentiation using selected bases.

A candidate that fails a test is composite. A candidate that passes several probabilistic rounds is considered probably prime.

The Python implementation uses random Miller-Rabin bases. The C++ implementation uses deterministic bases suitable for testing the full unsigned 64-bit integer range.

The small primes used in the practice implementations are not appropriate for protecting actual information.

## 2. Public-Key Encryption

### 2.1 Encryption Workflow

Public-key encryption allows a sender to encrypt information using the recipient's public key.

The recipient decrypts it using the corresponding private key.

The workflow is:

1. The recipient generates a public/private key pair.
2. The recipient distributes the public key.
3. The sender obtains and validates the recipient's public key.
4. The sender encrypts the message.
5. The recipient decrypts the ciphertext.
6. The application validates the recovered information.

The public key does not need to be confidential, but its authenticity and integrity are essential.

An attacker who substitutes a malicious public key can potentially intercept encrypted communications.

### 2.2 RSA-OAEP

RSA-OAEP means RSA Optimal Asymmetric Encryption Padding.

It provides randomized padding for RSA encryption and helps prevent attacks associated with deterministic textbook RSA.

The JavaScript, Java, and Python-related mathematical demonstrations have deliberately different implementation approaches.

The JavaScript implementation uses:

- Node.js `crypto.publicEncrypt`
- Node.js `crypto.privateDecrypt`
- RSA-OAEP
- SHA-256
- MGF1 with SHA-256

The Java implementation uses:

- Java Cryptography Architecture
- `Cipher`
- `OAEPParameterSpec`
- `MGF1ParameterSpec`
- SHA-256

These implementations use established cryptographic libraries rather than manually implementing OAEP.

### 2.3 RSA Message Size Limitations

RSA encryption cannot efficiently handle arbitrarily large messages.

For RSA-OAEP:

\[
mLen\leq k-2hLen-2
\]

Where:

- \(mLen\) = maximum message length in bytes
- \(k\) = RSA modulus length in bytes
- \(hLen\) = digest output length in bytes

For a 3072-bit RSA key and SHA-256:

\[
k=384
\]

\[
hLen=32
\]

Therefore:

\[
mLen\leq384-64-2
\]

\[
mLen\leq318\text{ bytes}
\]

For larger information, hybrid encryption is preferable.

### 2.4 Hybrid Encryption

Hybrid encryption combines asymmetric and symmetric cryptography.

The process is:

1. Generate a random symmetric data-encryption key.
2. Encrypt the actual information using an authenticated symmetric algorithm such as AES-256-GCM.
3. Encrypt or wrap the symmetric key using the recipient's public key.
4. Transmit the encrypted data, wrapped key, and required metadata.
5. The recipient uses the private key to recover the symmetric key.
6. The recipient decrypts and authenticates the data.

Conceptual workflow:

`Plaintext → AES-256-GCM → Encrypted data`

`AES key → RSA-OAEP → Encrypted AES key`

`Encrypted data + Encrypted AES key → Recipient`

The authenticated encryption mechanism protects data confidentiality and integrity.

The project focuses on asymmetric operations and does not implement a complete hybrid-encryption transport protocol.

## 3. Digital Signatures

### 3.1 Purpose

Digital signatures establish evidence that a message or artifact was signed using a particular private key.

They support:

- Integrity verification
- Signer authentication when the public key is trusted
- Detection of unauthorized modification
- Evidence of signing activity

A digital signature does not automatically provide confidentiality.

### 3.2 Signing Workflow

The signing process uses a private key.

The verification process uses the corresponding public key.

The conceptual workflow is:

1. Calculate a cryptographic digest of the artifact.
2. Sign the digest using an approved signature algorithm and the private key.
3. Distribute the artifact and signature.
4. Obtain the corresponding trusted public key.
5. Verify the signature.
6. Reject the artifact if verification fails.

The signature must be associated with the exact artifact and relevant signing metadata.

### 3.3 RSA-PSS

RSA-PSS means RSA Probabilistic Signature Scheme.

It is a modern RSA signature-padding mechanism.

The JavaScript implementation uses:

- `crypto.sign`
- `crypto.verify`
- SHA-256
- RSA-PSS padding
- A 32-byte salt

The Java implementation uses:

- `Signature`
- `RSASSA-PSS`
- `PSSParameterSpec`
- SHA-256
- MGF1 with SHA-256

PSS incorporates randomized padding and is preferred over manually applying textbook RSA to a digest.

### 3.4 Hash Functions

A cryptographic hash function maps input data to a fixed-length digest.

SHA-256 produces a 256-bit output.

\[
H=SHA256(M)
\]

Where:

- \(M\) = original message
- \(H\) = resulting digest

A small modification to the input should produce a different digest.

Hashing is not encryption. A digest does not provide a mechanism for recovering the original message.

The project uses SHA-256 for artifact fingerprints and signature-related demonstrations.

## 4. Public-Key Infrastructure

### 4.1 Public-Key Infrastructure

Public-Key Infrastructure, or PKI, provides mechanisms for establishing and managing trust in public keys.

Its major components include:

| Component | Responsibility |
|---|---|
| Certificate Authority | Issues and signs digital certificates |
| Registration Authority | Performs identity-registration functions |
| Digital certificate | Associates an identity with a public key |
| Certificate repository | Distributes certificates |
| Certificate revocation mechanism | Communicates certificate invalidation |
| Certificate validation | Checks trust, validity, and policy requirements |

A public key alone does not establish the identity of its owner.

A trusted certificate or another authenticated key-distribution mechanism provides the necessary association.

### 4.2 Digital Certificates

A digital certificate commonly follows the X.509 format.

It can contain:

- Subject identity
- Public key
- Issuer identity
- Serial number
- Validity period
- Signature algorithm
- Certificate extensions
- Issuer signature

Certificate validation requires checking the certificate chain, validity period, key usage, applicable constraints, and revocation status.

The project uses public-key metadata and fingerprints rather than implementing a complete certificate authority.

### 4.3 Key Fingerprints

A public-key fingerprint is a digest calculated over a canonical representation of a public key.

The JavaScript and Java implementations calculate SHA-256 fingerprints.

Fingerprints help compare public-key identities and detect unexpected key substitution.

A fingerprint must be obtained through an authenticated channel before it can be used as a trustworthy identity check.

## 5. Key Management and Lifecycle

Cryptographic security depends on more than the strength of the mathematical algorithm.

Keys must be managed throughout their operational lifecycle.

### 5.1 Key Lifecycle

The project models these states:

| State | Meaning |
|---|---|
| ACTIVE | Key is permitted for authorized operations |
| SUSPENDED | Key is temporarily unavailable |
| EXPIRED | Key has passed its validity period |
| REVOKED | Key has been invalidated |

The Python implementation models active and revoked states and defines an expired state.

The JavaScript implementation supports registration, rotation, and revocation.

The Java implementation provides enterprise lifecycle management with explicit state metadata.

The PostgreSQL model stores the lifecycle and associated audit information.

### 5.2 Key Rotation

Key rotation replaces an existing cryptographic key with a newly generated key.

A controlled rotation process should:

1. Generate a replacement key.
2. Validate its algorithm and security parameters.
3. Register the replacement.
4. Update dependent applications.
5. Transition the old key according to the applicable policy.
6. Retain necessary historical public-key information.
7. Record the operation in the audit system.

Revoking an encryption key can make previously encrypted data inaccessible if no valid recovery mechanism exists.

Revoking a signing key does not automatically invalidate every signature previously produced using that key. Historical signature validation requires appropriate evidence of the signing time, certificate validity, and revocation context.

### 5.3 Private-Key Protection

Private keys require stronger protection than public keys.

Appropriate controls include:

- Hardware Security Modules
- Key Management Services
- Encrypted key storage
- Strict access control
- Multi-person authorization for sensitive operations
- Secure backups
- Key rotation
- Audit logging
- Separation of administrative and cryptographic privileges

The private key should not be stored in ordinary database tables or application logs.

The PostgreSQL implementation intentionally stores only public-key metadata and references to cryptographic operations.

## 6. Python Implementation

### 6.1 Mathematical RSA Model

The Python implementation provides an educational mathematical model.

Its functions include:

| Function | Purpose |
|---|---|
| `extended_gcd()` | Calculates Bézout coefficients |
| `modular_inverse()` | Calculates a modular inverse |
| `is_probable_prime()` | Performs Miller-Rabin testing |
| `generate_prime()` | Generates educational prime candidates |
| `generate_rsa_keypair()` | Constructs RSA public and private keys |
| `encrypt_integer()` | Performs modular RSA encryption |
| `decrypt_integer()` | Performs modular RSA decryption |
| `sign_integer()` | Demonstrates textbook RSA signing |
| `verify_signature()` | Checks the corresponding mathematical relationship |

The implementation uses Python's arbitrary-precision integers.

The built-in modular exponentiation operation, `pow(base, exponent, modulus)`, performs efficient modular exponentiation.

### 6.2 Key Registry

The `KeyRegistry` class stores public-key records.

It supports:

- Key registration
- Duplicate identifier rejection
- Active-key retrieval
- Key revocation
- Public-directory export

The `KeyStatus` enumeration provides explicit lifecycle states.

The `dataclass` structures separate public-key information, private-key information, key pairs, and registry records.

### 6.3 Security Limitations

The Python implementation uses textbook RSA and very small primes.

Its signature demonstration reduces a SHA-256 digest modulo the small RSA modulus. This is not a secure digital signature scheme.

The implementation does not provide:

- RSA-OAEP encryption
- RSA-PSS signatures
- Constant-time private-key operations
- Secure private-key storage
- Certificate validation
- Production-grade key generation

Its purpose is to demonstrate RSA mathematics and lifecycle behavior.

## 7. JavaScript Implementation

### 7.1 Node.js Cryptographic Architecture

The JavaScript implementation uses the built-in Node.js cryptographic library.

The asynchronous key-generation workflow uses:

- `crypto.generateKeyPair`
- Promises
- `async`
- `await`

The implementation uses PEM-encoded public and private key material internally.

The public key uses SubjectPublicKeyInfo encoding.

The private key uses PKCS#8 encoding.

### 7.2 Identity Management

The `RSAIdentity` class represents an individual cryptographic identity.

Its operations include:

- Public-key encryption
- Private-key decryption
- Digital signing
- Signature verification
- Fingerprint calculation
- Lifecycle validation
- Revocation

The `IdentityRegistry` uses a JavaScript `Map` to maintain identities.

This avoids repeated linear searches when retrieving a key by its identifier.

The registry also provides public-directory information without exposing private-key material.

### 7.3 Asynchronous Operations

Key generation is asynchronous because cryptographic key generation is computationally expensive.

The main workflow awaits key generation before performing dependent operations.

Errors are propagated through Promise rejection and handled by the main execution boundary.

### 7.4 Failure Handling

The implementation checks:

- Empty input
- Invalid buffers
- Message-size restrictions
- Missing identities
- Duplicate identifiers
- Revoked identities
- Invalid signatures
- Decryption failures

The registry demonstrates replacement-key registration before revocation of the previous identity.

For production use, the replacement process must also account for concurrent updates, persistent storage, rollback, and distributed application dependencies.

## 8. C++17 Implementation

### 8.1 Modular Arithmetic Engine

The C++ implementation provides an integer-based RSA engine using standard-library facilities.

Its central mathematical functions are:

- Modular addition
- Modular multiplication
- Modular exponentiation
- Miller-Rabin primality testing
- Extended Euclidean algorithm

### 8.2 Overflow-Safe Multiplication

Ordinary integer multiplication can overflow before a modulo operation is applied.

The implementation avoids this problem through repeated doubling.

For multiplication:

\[
a\times b\bmod n
\]

the algorithm repeatedly adds the current value of \(a\) modulo \(n\) when the corresponding bit of \(b\) is set.

It then doubles \(a\) modulo \(n\) and shifts \(b\).

This avoids relying on non-standard wide-integer types.

### 8.3 Deterministic Primality Testing

The C++ implementation uses a deterministic Miller-Rabin base set suitable for unsigned 64-bit integers.

This differs from the Python implementation, which uses random bases and probabilistic testing.

### 8.4 Domain Modeling

The program separates:

- `PublicKey`
- `PrivateKey`
- `RSAKeyPair`
- `KeyRecord`
- `KeyStatus`
- `RSAEngine`
- `KeyRegistry`

The registry enforces unique identifiers and prevents access to revoked keys.

### 8.5 Performance Considerations

For modular exponentiation, the repeated-squaring algorithm performs logarithmically many exponentiation iterations.

Its iteration count is:

\[
O(\log e)
\]

The modular multiplication routine uses repeated doubling, giving a worst-case complexity of:

\[
O(\log n)
\]

per multiplication.

These algorithms are appropriate for a small mathematical demonstration but not for production RSA cryptography.

## 9. Java 17 Implementation

### 9.1 Enterprise Domain Model

The Java implementation models cryptographic operations as enterprise services.

Its principal domain types are:

| Type | Responsibility |
|---|---|
| `KeyMetadata` | Immutable key identity and lifecycle metadata |
| `KeyMaterial` | Public and private key references |
| `SignatureResult` | Artifact signature information |
| `KeyStatus` | Key lifecycle state |
| `Operation` | Authorized cryptographic operation |
| `CryptographicPolicy` | Policy validation interface |
| `EnterprisePolicy` | Concrete key-usage and lifecycle rules |
| `KeyService` | Cryptographic service and identity management |

Java records provide immutable metadata structures.

The service class separates domain validation from cryptographic API execution.

### 9.2 Cryptographic Policy

The enterprise policy evaluates:

- Key availability
- Algorithm compatibility
- Key size
- Lifecycle status
- Private-key availability

An operation is rejected when the key does not meet the configured policy.

This separates cryptographic functionality from operational authorization.

### 9.3 Java Cryptography Architecture

The implementation uses Java's standard cryptographic interfaces.

| API | Responsibility |
|---|---|
| `KeyPairGenerator` | Generates RSA key pairs |
| `Cipher` | Encrypts and decrypts information |
| `Signature` | Generates and verifies signatures |
| `MessageDigest` | Calculates cryptographic digests |
| `SecureRandom` | Supplies cryptographically secure randomness |
| `OAEPParameterSpec` | Configures RSA-OAEP |
| `PSSParameterSpec` | Configures RSA-PSS |

The program uses a 3072-bit RSA key and SHA-256.

### 9.4 Concurrency

The identity registry uses `ConcurrentHashMap`.

This supports concurrent access to registered identities.

The rotation operation uses conditional replacement to detect some concurrent state changes.

A production implementation would require a stronger transactional lifecycle mechanism to coordinate rotation across multiple application instances and persistent storage.

## 10. PostgreSQL Implementation

### 10.1 Relational Architecture

The PostgreSQL implementation models cryptographic governance independently from cryptographic computation.

The relational structure is:

`Organizations`

→ `Users`

→ `Cryptographic Keys`

→ `Key Permissions`

→ `Encryption Operations`

`Artifacts`

→ `Digital Signatures`

→ `Verification Records`

`Audit Events`

### 10.2 Organizations and Users

The `organizations` table represents organizational ownership.

The `users` table stores organizational identities and roles.

Supported roles include:

- ADMIN
- CRYPTO_OPERATOR
- DEVELOPER
- AUDITOR

Foreign keys enforce valid organizational relationships.

### 10.3 Cryptographic Keys

The `cryptographic_keys` table stores:

- Key identifier
- Organization
- Owner
- Algorithm
- Key usage
- Public-key representation
- SHA-256 fingerprint
- Modulus size
- Public exponent
- Creation time
- Expiration time
- Revocation status

Private-key material is excluded.

The uniqueness constraints prevent duplicate key identifiers and fingerprints within an organization.

Check constraints restrict supported algorithms, usage types, lifecycle states, and RSA parameters.

### 10.4 Key Permissions

The `key_permissions` table defines which users can perform particular operations.

Permissions include:

| Permission | Meaning |
|---|---|
| ENCRYPT | Encrypt information using an authorized key |
| DECRYPT | Request authorized decryption |
| SIGN | Sign an artifact |
| VERIFY | Verify a signature |
| MANAGE | Manage key-related operations |

The permission trigger checks organizational ownership and the role of the granting operator.

These database controls are governance checks, not substitutes for application authentication or cryptographic authorization.

### 10.5 Artifact and Signature Management

The `artifacts` table stores artifact metadata and SHA-256 digests.

The `digital_signatures` table records:

- Artifact reference
- Signing key
- Signer
- Signature algorithm
- Signature representation
- Signed digest
- Signing timestamp
- Signature state

The `verification_records` table stores verification outcomes.

A signature marked valid in this demonstration represents a recorded result. PostgreSQL does not independently perform RSA-PSS verification.

The cryptographic service must perform the actual signature verification before the result is recorded.

### 10.6 Eligibility Function

The `is_key_eligible()` function evaluates whether a user may perform an operation using a particular key.

It considers:

- Key lifecycle status
- Expiration
- User activity
- Organization membership
- Granted permission
- Intended key usage

The function provides a reusable eligibility decision for database workflows.

### 10.7 Triggers and Constraints

The implementation includes two important triggers.

`protect_key_identity()` prevents modification of registered public-key identity fields and prevents reactivation of revoked keys.

`validate_key_permission()` checks organizational ownership and the authorization of the granting operator.

These controls reduce accidental or unauthorized changes to the metadata model.

### 10.8 Audit Events

The `audit_events` table records important administrative and operational events.

JSONB stores structured event details.

The GIN index supports searches over structured audit metadata.

Audit records should be protected from unauthorized modification and deletion in a production environment.

### 10.9 Reporting and Performance

The SQL script includes:

- Active public-key directory
- Organization-level activity report
- Signature verification report
- Failed-operation report
- Key-expiration report
- User eligibility query

Indexes support frequent retrieval by organization, key status, permissions, artifact, user, and timestamp.

The activity report uses aggregate filtering to distinguish successful and unsuccessful operations.

## 11. Distinctions Between Cryptographic Mechanisms

| Mechanism | Primary purpose | Key involved |
|---|---|---|
| Public-key encryption | Confidentiality | Public key |
| Private-key decryption | Recovery of encrypted information | Private key |
| Digital signing | Integrity and signer authentication evidence | Private key |
| Signature verification | Validate signature against a message | Public key |
| Hashing | Produce a fixed-length digest | No cryptographic key |
| Key fingerprinting | Identify a public-key representation | No cryptographic key |
| Certificate validation | Establish trust in a public-key identity | Certificate and issuer trust keys |
| Key revocation | Invalidate a key for future authorized operations | Key lifecycle metadata |
| Key rotation | Replace an existing key | Old and replacement key pairs |

Encryption and digital signatures solve different security problems.

A signature does not encrypt a message.

Encryption does not automatically establish the identity of the sender.

Both mechanisms may be combined when confidentiality and authenticity are required.

## 12. Security Considerations

### 12.1 Weak RSA Parameters

The educational Python and C++ implementations use small prime numbers.

Their RSA moduli can be factored relatively easily.

They must not be used for confidential data or real authentication.

### 12.2 Textbook RSA

Unpadded RSA is deterministic and vulnerable to several attacks.

The Python and C++ programs deliberately expose the underlying mathematics rather than implementing a secure encryption protocol.

Secure application encryption should use RSA-OAEP or an appropriate modern alternative.

Secure RSA signatures should use RSA-PSS or another approved signature scheme.

### 12.3 Random Number Generation

Cryptographic key generation requires a cryptographically secure random-number generator.

The implementations use:

- Python `secrets`
- Node.js `crypto`
- Java `SecureRandom`
- C++ `std::random_device` only for educational prime generation

The C++ implementation is not suitable for production key generation because its randomness and arithmetic are not designed as a complete hardened cryptographic implementation.

### 12.4 Timing and Side-Channel Attacks

Cryptographic operations can reveal information through:

- Execution-time differences
- Cache behavior
- Memory access patterns
- Power consumption
- Error responses

Private-key operations should use established cryptographic libraries designed to mitigate applicable side-channel risks.

### 12.5 Key Storage

Private keys should not be exposed through:

- Source-control repositories
- Application logs
- Public database columns
- Unencrypted backups
- Configuration files committed to repositories

A production environment should use a dedicated key-management service or hardware-backed storage.

### 12.6 Algorithm Agility

Cryptographic systems should support controlled changes to algorithms and parameters.

The project stores algorithm identifiers and key sizes so that policy and reporting can distinguish cryptographic configurations.

A production system must also validate algorithm parameters and prevent downgrade to weaker configurations.

## 13. Testing and Failure Scenarios

The source files include executable validation and failure-handling examples.

| Test scenario | Expected behavior |
|---|---|
| Valid RSA integer encryption | Original integer is recovered |
| Message greater than RSA modulus | Operation is rejected |
| Invalid modular inverse | Key construction fails |
| Composite primality candidate | Candidate is rejected |
| Valid digital signature | Verification succeeds |
| Modified signed artifact | Verification fails |
| Unknown key identifier | Lookup fails |
| Revoked key | Protected operations are rejected |
| Duplicate identity | Registration fails |
| Empty message | Input validation fails |
| Unauthorized database permission | Permission validation fails |
| Cross-organization permission | Database trigger rejects the operation |
| Expired key | Eligibility function returns false |
| Invalid cryptographic parameters | Policy or cryptographic API rejects the operation |

The mathematical implementations validate RSA relationships directly.

The Node.js and Java implementations exercise cryptographic library operations.

The PostgreSQL implementation validates metadata, permissions, lifecycle states, and recorded workflow outcomes.

## 14. Execution Requirements

| File | Runtime | Execution |
|---|---|---|
| Python | Python 3.10+ | `python public_key_practice.py` |
| JavaScript | Node.js 18+ | `node public_key_practice.js` |
| C++17 | C++17 compiler | `g++ -std=c++17 -O2 public_key_practice.cpp -o public_key_practice` followed by `./public_key_practice` |
| Java | Java 17 | `javac PublicKeyPractice.java` followed by `java PublicKeyPractice` |
| PostgreSQL | PostgreSQL 15+ | Execute the SQL script using `psql` |

Python, JavaScript, C++, and Java require no third-party packages.

The JavaScript implementation requires a Node.js version supporting the built-in cryptographic APIs used by the program.

The PostgreSQL script creates its own schema and sample records. It should be executed against a database in which the executing role has schema, table, function, procedure, and trigger creation privileges.

The SQL script is intended for an isolated practice database.

## 15. Implementation Limitations

The five implementations have different security and operational boundaries.

| Area | Implementation boundary |
|---|---|
| Python | Educational RSA mathematics, not secure RSA encryption |
| JavaScript | Real RSA-OAEP and RSA-PSS library operations with in-memory identity management |
| C++17 | Educational 64-bit RSA arithmetic, not production cryptography |
| Java 17 | Library-backed cryptographic operations with enterprise-oriented policy modeling |
| PostgreSQL | Cryptographic metadata and governance, not cryptographic execution |

None of the implementations constitutes a complete production PKI.

Production deployment would require authenticated key distribution, certificate validation, secure private-key storage, controlled key recovery, authorization enforcement, durable audit retention, and operational incident handling.

The project deliberately separates mathematical learning, secure library usage, application-level identity management, and database-level governance.
