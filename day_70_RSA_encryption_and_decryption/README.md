# RSA Encryption and Decryption

## 1. Technical Scope

RSA (Rivest–Shamir–Adleman) is an asymmetric cryptographic algorithm that uses a mathematically related public key and private key.

The public key supports encryption and signature verification. The private key supports decryption and signature creation.

This project implements RSA concepts through five different engineering perspectives:

| Implementation | Primary responsibility |
|---|---|
| Python | RSA mathematics, key generation, OAEP encoding, encryption, decryption and PSS signatures |
| JavaScript | Event-driven RSA service, key registry, asynchronous key generation and operation monitoring |
| C++17 | Modular arithmetic, RSA mathematics, key lifecycle and access-control simulation |
| Java 17 | Enterprise cryptographic services, policy evaluation, immutable domain types and audit management |
| PostgreSQL | Key registry, authorization, operation records, lifecycle events and reporting |

The implementations are independent programs. They do not share runtime keys or depend on one another.

## 2. Mathematical Foundation of RSA

RSA security is based on the computational difficulty of factoring a sufficiently large integer into its prime factors.

### 2.1 Key generation

Two distinct large prime numbers are selected:

- `p`: First prime.
- `q`: Second prime.

The RSA modulus is calculated as:

\[
n=pq
\]

Euler's totient for distinct primes is:

\[
\phi(n)=(p-1)(q-1)
\]

A public exponent `e` is selected such that:

\[
1<e<\phi(n)
\]

and:

\[
\gcd(e,\phi(n))=1
\]

The private exponent `d` is the modular multiplicative inverse of `e`:

\[
d\equiv e^{-1}\pmod{\phi(n)}
\]

The resulting keys are:

| Key | Parameters |
|---|---|
| Public key | \((n,e)\) |
| Private key | \((n,d)\) |

The prime factors must remain confidential. Knowledge of `p` and `q` makes it possible to derive the private exponent.

### 2.2 Encryption

For a mathematical plaintext representative \(m\), RSA encryption is:

\[
c=m^e\bmod n
\]

Where:

- \(m\) is the encoded plaintext integer.
- \(e\) is the public exponent.
- \(n\) is the modulus.
- \(c\) is the ciphertext integer.

Anyone possessing the corresponding public key can perform encryption.

### 2.3 Decryption

The private-key operation is:

\[
m=c^d\bmod n
\]

The decrypted representative is decoded into the original message.

RSA encryption and decryption use modular exponentiation. Efficient implementations employ square-and-multiply techniques rather than calculating extremely large ordinary powers.

### 2.4 Small mathematical example

The C++17 implementation uses small primes to demonstrate the mathematical process.

Given:

\[
p=61,\quad q=53
\]

The modulus is:

\[
n=61\times53=3233
\]

The totient is:

\[
\phi(n)=60\times52=3120
\]

Choose:

\[
e=17
\]

The corresponding private exponent is:

\[
d=2753
\]

For plaintext:

\[
m=65
\]

Encryption produces:

\[
c=65^{17}\bmod3233=2790
\]

Decryption produces:

\[
2790^{2753}\bmod3233=65
\]

This example demonstrates RSA mathematics, not secure encryption. Its small modulus can be factored easily.

## 3. RSA Padding and Encoding

Raw mathematical RSA must not be used directly to encrypt application messages.

A secure implementation requires standardized padding and encoding mechanisms.

### 3.1 RSA-OAEP

RSA-OAEP stands for Optimal Asymmetric Encryption Padding.

It provides randomized encoding before the RSA public-key operation.

Its principal components include:

- A message hash.
- A label hash.
- A randomly generated seed.
- A Mask Generation Function.
- A masked data block.

The Mask Generation Function used in the Python implementation is MGF1 with SHA-256.

The general process is:

Plaintext + Label  
→ Hash processing  
→ Random seed  
→ MGF1 masking  
→ Encoded message  
→ RSA public-key operation  
→ Ciphertext

Decryption reverses these operations and validates the encoded structure.

OAEP prevents identical plaintext messages encrypted with the same key from producing identical ciphertexts, assuming independently generated random seeds.

### 3.2 Maximum plaintext size

For RSA-OAEP with SHA-256:

\[
mLen\leq k-2hLen-2
\]

Where:

- `mLen` is the plaintext length in bytes.
- `k` is the RSA modulus length in bytes.
- `hLen` is the SHA-256 digest length, 32 bytes.

For a 2048-bit RSA modulus:

\[
k=256
\]

Therefore:

\[
mLen\leq256-64-2
\]

\[
mLen\leq190\text{ bytes}
\]

The implementations validate this restriction before encryption.

RSA is consequently unsuitable for encrypting large files directly.

### 3.3 Hybrid encryption

Practical systems generally use hybrid encryption.

A symmetric algorithm encrypts the actual data. RSA protects the randomly generated symmetric key.

The workflow is:

Plaintext  
→ Generate random AES key  
→ Encrypt plaintext using AES-GCM  
→ Encrypt AES key using RSA-OAEP  
→ Store encrypted data and encrypted AES key

Decryption reverses this process.

This design combines the performance of symmetric encryption with asymmetric key distribution.

The five programs concentrate on RSA operations and their governance. They do not implement a complete AES-GCM hybrid file-encryption application.

## 4. RSA Digital Signatures

Encryption and digital signatures address different security requirements.

Encryption provides confidentiality. Digital signatures provide authenticity and integrity verification.

RSA signatures use the private key to produce a signature and the public key to verify it.

### 4.1 RSA-PSS

RSA-PSS stands for Probabilistic Signature Scheme.

It uses a message digest, a random salt and a mask generation function.

The signing workflow is:

Message  
→ SHA-256  
→ PSS encoding  
→ Private-key RSA operation  
→ Digital signature

Verification is:

Message + Signature  
→ SHA-256  
→ Public-key RSA operation  
→ PSS validation  
→ Valid or invalid

The implementations use RSA-PSS with SHA-256 and a 32-byte salt.

### 4.2 Encryption versus signatures

| Property | RSA-OAEP | RSA-PSS |
|---|---|---|
| Primary purpose | Confidentiality | Authenticity and integrity |
| Key used for primary operation | Public key | Private key |
| Reverse operation | Private key | Public key |
| Randomized processing | Yes | Yes |
| Produces ciphertext | Yes | No |
| Produces signature | No | Yes |

A valid signature does not mean that a message is confidential.

An encrypted message does not automatically prove who created it.

## 5. Python Implementation

The Python program provides an implementation-oriented examination of RSA.

### 5.1 Number-theory functions

The following functions implement the mathematical foundation:

| Function | Responsibility |
|---|---|
| `gcd()` | Calculates the greatest common divisor |
| `extended_gcd()` | Calculates Bezout coefficients |
| `modular_inverse()` | Finds the private exponent |
| `is_probable_prime()` | Implements Miller-Rabin primality testing |
| `generate_prime()` | Generates probable prime candidates |

Miller-Rabin repeatedly tests randomly selected bases against the candidate number.

The implementation uses 64 rounds to reduce the probability of accepting a composite candidate.

### 5.2 Key generation

`generate_key_pair()` constructs the public and private keys.

The implementation:

- Generates two distinct primes.
- Calculates the RSA modulus.
- Calculates Euler's totient.
- Checks the public exponent.
- Calculates the private exponent.
- Validates the resulting key relationships.

The implementation uses 2048-bit RSA keys by default.

### 5.3 OAEP encoding

`mgf1()` implements the SHA-256-based mask generation function.

`oaep_encode()` creates the padded message representation.

`oaep_decode()` validates the decoded representation and extracts the original message.

`rsa_encrypt()` and `rsa_decrypt()` perform the modular exponentiation operations.

### 5.4 Digital signatures

`rsa_sign()` implements RSA-PSS encoding and the private-key operation.

`rsa_verify()` performs signature verification and checks the encoded message structure.

The implementation also tests modified messages and rejects invalid signatures.

### 5.5 Validation and testing

The automated tests cover:

- Successful encryption and decryption.
- Empty messages.
- Randomized ciphertext generation.
- Oversized messages.
- Incorrect OAEP labels.
- Signature creation.
- Signature verification.
- Modified messages.
- Invalid ciphertext lengths.

### 5.6 Important implementation limitation

This Python implementation is an educational cryptographic implementation, not a production cryptographic library.

Python's arbitrary-precision modular exponentiation is convenient for demonstrating RSA, but its private-key operation does not provide a complete constant-time, side-channel-resistant cryptographic implementation.

The program also does not implement RSA blinding, protected private-key storage, hardware-backed operations or a complete standardized key-management system.

Production deployments should use an established cryptographic library.

## 6. JavaScript Implementation

The JavaScript implementation adopts an event-driven service architecture.

It uses Node.js native cryptographic functionality instead of independently implementing large-integer RSA mathematics.

### 6.1 Key generation

`generateKeyPair()` uses Node.js `crypto.generateKeyPair()`.

The generated keys use:

- RSA.
- A 2048-bit modulus.
- Public exponent 65537.
- SPKI public-key encoding.
- PKCS#8 private-key encoding.

The function returns a Promise because key generation is performed asynchronously.

### 6.2 Key registry

`KeyRegistry` manages registered keys through a JavaScript Map.

Each record includes:

- Key identifier.
- Public key.
- Private key.
- SHA-256 fingerprint.
- Creation timestamp.
- Lifecycle status.

The registry supports registration, retrieval, counting and revocation.

Private class fields prevent ordinary external access to the registry's internal Map.

### 6.3 Event-driven operations

The service extends `EventEmitter`.

Important events include:

| Event | Meaning |
|---|---|
| `key:registered` | A key has entered the registry |
| `key:revoked` | A key has been revoked |
| `encryption:completed` | Encryption succeeded |
| `decryption:completed` | Decryption succeeded |
| `signature:created` | A signature was generated |
| `signature:verified` | A signature was evaluated |
| `service:stopped` | The service was stopped |

This separates cryptographic processing from monitoring and operational reporting.

### 6.4 Cryptographic operations

The service implements:

- `encrypt()`
- `decrypt()`
- `sign()`
- `verify()`

Encryption and decryption use RSA-OAEP with SHA-256.

Digital signatures use RSA-PSS with SHA-256.

The OAEP label is supplied explicitly and must match during decryption.

### 6.5 Failure handling

The implementation distinguishes key errors, encryption errors, decryption errors and revoked-key errors.

It also includes:

- Input validation.
- Ciphertext-length validation.
- Key revocation.
- Operation counters.
- Failure counters.
- Event monitoring.
- Service lifecycle management.

The public-key file-writing operation uses exclusive file creation to prevent accidental replacement of an existing file.

The demonstration keeps private keys in memory. Production deployment requires protected private-key storage and access controls.

## 7. C++17 Implementation

The C++17 implementation concentrates on RSA mathematical operations and repository-style security governance.

It deliberately uses small integer values to make modular arithmetic transparent.

### 7.1 Modular multiplication

The `modularMultiply()` function uses the GCC and Clang `__uint128_t` extension to prevent intermediate multiplication overflow for the demonstration's 64-bit values.

This extension is not part of the ISO C++17 standard, although it is available in common GCC and Clang environments.

### 7.2 Modular exponentiation

`modularPower()` implements square-and-multiply.

Its time complexity is:

\[
O(\log e)
\]

where `e` is the exponent.

It avoids constructing the full mathematical power.

### 7.3 Key management

`RSAKeyManager` manages RSA key pairs using an unordered Map.

It validates:

- Prime factors.
- Distinct prime requirements.
- Modulus overflow.
- Public exponent compatibility.
- Duplicate identifiers.
- Key status.

It supports active and revoked keys.

### 7.4 Encryption engine

`RSAEngine` provides separate encryption and decryption operations.

It rejects:

- Unknown keys.
- Revoked keys.
- Negative values are impossible in the unsigned input representation.
- Plaintext values greater than or equal to the modulus.
- Ciphertext values greater than or equal to the modulus.

The audit log records the actor, operation, result and processed value.

### 7.5 Engineering tradeoff

The C++ program prioritizes mathematical transparency over cryptographic strength.

It does not implement OAEP, PSS, SHA-256, cryptographically secure random key generation, constant-time private-key operations or secure key storage.

Its small-prime example must never be used to protect actual information.

## 8. Java 17 Enterprise Implementation

The Java implementation uses the Java Cryptography Architecture (JCA) and Java Cryptography Extension (JCE).

It emphasizes separation of responsibilities, immutable domain objects and enterprise service design.

### 8.1 Domain model

The implementation uses records and enumerations to represent security information.

Important types include:

| Type | Responsibility |
|---|---|
| `RSAConfiguration` | Cryptographic configuration |
| `ManagedRSAKey` | Key identity and lifecycle |
| `KeyStatus` | Key lifecycle states |
| `OperationType` | Cryptographic operation categories |
| `SecurityLevel` | Configuration classification |
| `AuditEvent` | Operation history |

Records provide immutable data structures for configuration, key metadata and audit events.

### 8.2 Key-generation service

`RSAKeyService` generates RSA key pairs using `KeyPairGenerator`.

The public key is represented by the X.509 SubjectPublicKeyInfo encoding.

The private key uses PKCS#8 encoding.

The implementation computes a SHA-256 fingerprint from the encoded public key.

The fingerprint identifies public-key material without exposing private-key material.

### 8.3 Key repository

`RSAKeyRepository` uses a ConcurrentHashMap.

Its responsibilities include:

- Registering keys.
- Preventing duplicate identifiers.
- Retrieving keys.
- Checking active status.
- Revoking keys.
- Counting active keys.

The concurrent collection supports concurrent access to repository metadata.

The key registry does not replace a hardware-backed key-management system.

### 8.4 Cryptographic policy

`CryptographicPolicy` defines encryption and decryption validation.

`StandardRSAPolicy` enforces:

- Minimum RSA key strength.
- Active-key requirements.
- Ciphertext-length validation.
- OAEP plaintext-size restrictions.

This separates policy decisions from cryptographic execution.

### 8.5 Cryptographic service

`RSACryptoService` provides four operations:

- Encryption.
- Decryption.
- Digital signing.
- Signature verification.

The OAEP configuration explicitly specifies SHA-256 for both the primary digest and MGF1.

This avoids relying on provider-specific defaults for the mask-generation digest.

The signing service explicitly configures RSA-PSS with SHA-256 and MGF1-SHA256.

### 8.6 Audit service

`AuditService` records operation events using a synchronized collection and an atomic sequence counter.

It provides immutable snapshots and operation counts.

This creates a separation between cryptographic processing and operational accountability.

The audit data in this demonstration is held in memory rather than persisted in a database.

## 9. PostgreSQL Relational Model

The PostgreSQL implementation models cryptographic governance rather than performing RSA calculations.

PostgreSQL does not provide a native RSA-OAEP or RSA-PSS encryption interface through ordinary SQL statements.

The actual cryptographic operations must occur in an approved application or cryptographic service.

### 9.1 Entity relationships

The relational structure is:

Application Users  
→ Cryptographic Policies  
→ RSA Key Registry  
→ Key Permissions  
→ Cryptographic Operations  
→ Security Audit

Key lifecycle changes are recorded separately.

### 9.2 Main tables

| Table | Purpose |
|---|---|
| `application_users` | Users and assigned security roles |
| `cryptographic_policies` | Approved algorithms and key requirements |
| `rsa_keys` | Public-key metadata and lifecycle status |
| `key_permissions` | User-specific cryptographic permissions |
| `cryptographic_operations` | Encryption, decryption, signing and verification records |
| `key_lifecycle_events` | Key status changes |
| `security_audit` | Security-related operational events |

### 9.3 Database constraints

The schema uses:

- Primary keys for entity identity.
- Foreign keys for relationships.
- Unique constraints for usernames, key identifiers and fingerprints.
- Check constraints for key sizes and public exponents.
- Enum types for operation and lifecycle states.
- Partial indexes for active permissions.
- JSONB for structured audit information.

These mechanisms enforce relational integrity and reduce invalid metadata.

### 9.4 Authorization

`has_key_permission()` determines whether a user possesses a specific permission for a key.

`is_key_eligible()` checks whether the key satisfies its assigned policy.

`authorize_rsa_operation()` combines:

1. User activation.
2. Key eligibility.
3. Permission assignment.
4. Message-size restrictions.

The operation-validation trigger calls these functions before an operation record is inserted.

Database authorization is a governance control. It does not independently guarantee that an external cryptographic application will use the correct key or algorithm.

### 9.5 Lifecycle auditing

`audit_key_status_change()` records transitions in key status.

For example:

ACTIVE → REVOKED

The trigger records:

- Previous status.
- New status.
- Responsible user.
- Timestamp.
- Reason.

Revocation is an operational lifecycle event, not mathematical destruction of the private key.

An external key-management system must also prevent further use of revoked private-key material.

### 9.6 Transactional processing

The SQL script demonstrates a transactional workflow:

1. Find the registered key.
2. Identify the authorized user.
3. Insert a pending encryption operation.
4. Complete the operation.
5. Record the result.
6. Create a corresponding decryption operation.
7. Complete the decryption record.

`complete_rsa_operation()` prevents already-completed operations from being modified through the normal completion workflow.

The database transaction ensures that related metadata changes can be committed or rolled back together.

The sample ciphertext and key data are illustrative metadata. They are not the result of a real RSA encryption operation.

## 10. Key Management and Security Governance

RSA security depends on correct mathematical operations and the protection of key material throughout its lifecycle.

### 10.1 Public-key management

Public keys may be distributed to authorized users and applications.

Their authenticity must still be established.

A public-key fingerprint can help identify a particular public key, but a fingerprint alone does not establish trust.

A certificate authority, authenticated key-distribution mechanism or another trusted verification process is required.

### 10.2 Private-key management

Private keys must remain confidential.

Important controls include:

- Restricted access.
- Encrypted storage.
- Hardware security modules where appropriate.
- Secure key backup.
- Rotation policies.
- Revocation procedures.
- Separation of administrative responsibilities.
- Access logging.
- Secure deletion where applicable.

Private-key material should not be placed in ordinary application logs, database audit records or source-code repositories.

### 10.3 Key rotation

Key rotation replaces an existing key with a new key pair.

A controlled rotation process includes:

Old key  
→ Generate replacement key  
→ Register replacement public key  
→ Update dependent applications  
→ Verify successful transition  
→ Restrict old-key operations  
→ Retain necessary historical decryption capability  
→ Retire old key according to policy

Revoking a key immediately can make previously encrypted information inaccessible if no authorized recovery mechanism exists.

Key retirement must therefore consider data recovery requirements.

### 10.4 RSA blinding and side-channel protection

Private-key operations may expose information through timing, power consumption or other side channels.

RSA blinding reduces certain timing-based risks by randomizing intermediate values during private-key operations.

A production cryptographic implementation should also address:

- Constant-time processing.
- Fault attacks.
- Memory protection.
- Secure randomness.
- Padding-oracle vulnerabilities.
- Error-message leakage.
- Key extraction attacks.

The Python and C++ educational implementations do not provide these protections.

## 11. Edge Cases and Failure Conditions

| Condition | Expected behavior |
|---|---|
| Invalid prime factors | Reject key generation |
| Equal RSA prime factors | Reject key generation |
| Public exponent not coprime to totient | Reject key generation |
| Plaintext exceeds OAEP limit | Reject encryption |
| Ciphertext length is incorrect | Reject decryption |
| Ciphertext exceeds modulus | Reject operation |
| Incorrect OAEP label | Reject decryption |
| Wrong private key | Reject decryption |
| Tampered signature | Signature verification returns false |
| Revoked key | Reject new protected operations |
| Expired key | Reject operations under the applicable policy |
| Unauthorized user | Reject the operation |
| Duplicate key identifier | Reject registration |
| Invalid algorithm configuration | Reject the configuration |

Cryptographic failures should not reveal whether an individual OAEP padding component was valid.

Production applications should use consistent external error handling and avoid exposing sensitive internal diagnostic information.

## 12. Performance Considerations

RSA operations are substantially more computationally expensive than symmetric encryption.

The main performance considerations are:

| Operation | Main computational characteristic |
|---|---|
| Key generation | Expensive prime generation |
| Public-key encryption | Modular exponentiation using public exponent |
| Private-key decryption | More expensive private-key modular exponentiation |
| Signing | Private-key modular exponentiation |
| Verification | Public-key modular exponentiation |
| Key fingerprinting | Linear in encoded public-key size |

The public exponent 65537 is commonly used because its binary representation permits efficient exponentiation.

Private-key operations can be accelerated using the Chinese Remainder Theorem (CRT).

CRT performs separate calculations modulo `p` and `q`, then recombines the results.

The Python implementation does not use CRT optimization during decryption.

The C++ implementation uses square-and-multiply, while the JavaScript and Java implementations delegate optimized cryptographic operations to their respective runtime providers.

For large data, hybrid encryption avoids the performance and message-size limitations of direct RSA encryption.

## 13. Implementation Comparison

| Engineering concern | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Key generation | Custom mathematics | Native crypto API | Demonstration mathematics | JCA | Metadata only |
| OAEP | Implemented | Native crypto API | Not implemented | JCE | Policy metadata |
| PSS | Implemented | Native crypto API | Not implemented | JCA | Operation metadata |
| Key registry | Dataclasses | Map | Unordered Map | ConcurrentHashMap | Relational table |
| Access control | Basic validation | Key lifecycle checks | Governance simulation | Policy service | Database authorization |
| Audit | Console and tests | EventEmitter | In-memory records | Audit service | Persistent records |
| Production cryptography | Not recommended | Runtime provider | Not suitable | JCA/JCE with protected keys | Not applicable |

## 14. Execution Requirements

| File | Runtime | Execution |
|---|---|---|
| Python | Python 3.10+ | Run the Python script |
| JavaScript | Node.js 20+ | Run the JavaScript file |
| C++17 | GCC or Clang | Compile with C++17 support |
| Java | Java 17 | Compile and execute `RSAEnterpriseApplication` |
| PostgreSQL | PostgreSQL 15+ | Execute the SQL script |

The Python implementation requires no external packages.

The JavaScript implementation uses only Node.js built-in modules.

The C++ implementation uses the standard library and the commonly available `__uint128_t` compiler extension.

The Java implementation uses JCA and JCE without third-party dependencies.

The PostgreSQL implementation creates its own schema and database objects.

## 15. Security Boundaries and Practical Limitations

The five implementations have deliberately different responsibilities.

The Python program exposes RSA mathematics and encoding mechanisms.

The JavaScript program demonstrates asynchronous cryptographic services and event-driven monitoring.

The C++ program demonstrates modular arithmetic and a simplified key-governance engine.

The Java program demonstrates enterprise cryptographic architecture using standard security providers.

The PostgreSQL script demonstrates relational integrity, operation authorization, lifecycle governance and audit reporting.

These implementations are educational artifacts, not a unified production key-management platform.

In particular:

- The C++ implementation uses insecure toy-sized RSA parameters.
- The Python implementation does not provide complete side-channel protection.
- The JavaScript example retains private keys in process memory.
- The Java example requires protected private-key storage in a real deployment.
- The PostgreSQL database does not execute RSA encryption or decryption.
- The SQL sample public-key values are illustrative and are not valid operational key material.
- The implementations do not establish a complete certificate-validation or public-key trust infrastructure.

A production RSA deployment requires standardized cryptographic implementations, authenticated public-key distribution, protected private-key storage, controlled key rotation and independently reviewed security policies.
