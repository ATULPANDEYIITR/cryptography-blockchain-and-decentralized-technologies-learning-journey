# RSA Security and Limitations

## 1. Technical Scope

RSA (Rivest-Shamir-Adleman) is an asymmetric public-key cryptographic algorithm based on modular arithmetic and the computational difficulty of factoring sufficiently large composite integers.

RSA uses two mathematically related keys:

- **Public key:** Used for encryption or signature verification.
- **Private key:** Used for decryption or digital signature generation.

The security of RSA depends on the protection of the private key, suitable modulus sizes, secure padding schemes, reliable random-number generation, correct implementation, and appropriate operational controls.

The implementations in this project examine RSA from five engineering perspectives:

| Implementation | Primary responsibility |
|---|---|
| Python | RSA mathematics, security demonstrations, and key-policy simulation |
| JavaScript | Actual encryption, decryption, signatures, and event-driven key management |
| C++17 | RSA governance and operation-eligibility evaluation |
| Java 17 | Enterprise cryptographic services and approval workflows |
| PostgreSQL | Relational key inventory, policy enforcement, and audit management |

The project distinguishes mathematical RSA, secure cryptographic schemes, key lifecycle management, and organizational security governance.

## 2. RSA Mathematical Foundations

### 2.1 Key generation

RSA key generation involves the following operations:

1. Select two distinct large probable primes, `p` and `q`.
2. Calculate the modulus:

   `n = p × q`

3. Calculate Euler's totient:

   `φ(n) = (p - 1)(q - 1)`

4. Select a public exponent `e` satisfying:

   `1 < e < φ(n)`

   `gcd(e, φ(n)) = 1`

5. Calculate the private exponent `d`:

   `d × e ≡ 1 (mod φ(n))`

6. Publish `(n, e)` as the public key.
7. Protect `(n, d)` and associated private-key parameters as private material.

The commonly used public exponent is `65537`.

The private exponent is calculated using the modular multiplicative inverse.

### 2.2 Encryption and decryption

The mathematical textbook RSA operations are:

Encryption:

`c = m^e mod n`

Decryption:

`m = c^d mod n`

Where:

- `m` represents the message integer.
- `c` represents the ciphertext integer.
- `e` represents the public exponent.
- `d` represents the private exponent.
- `n` represents the modulus.

These equations describe RSA mathematics, not a complete secure encryption scheme.

Raw RSA must not be used directly for real-world encryption.

### 2.3 Digital signatures

RSA signatures use the private key to produce a signature and the public key to verify it.

A conceptual signature operation is:

`signature = Sign(private_key, message)`

Verification is:

`Verify(public_key, message, signature)`

Secure RSA signatures require a defined encoding and padding construction. RSA-PSS is the preferred signature scheme in this project.

A valid signature demonstrates that the signed message verifies under the corresponding public key. It does not independently establish the identity, authorization, or trustworthiness of the signer.

## 3. Secure RSA Schemes

Encryption and digital signatures have different security requirements.

| Property | RSA-OAEP | RSA-PSS |
|---|---|---|
| Primary purpose | Encryption | Digital signatures |
| Main operation | Public-key encryption | Private-key signing |
| Verification or recovery | Private-key decryption | Public-key verification |
| Hashing | SHA-256 in this project | SHA-256 in this project |
| Randomness | Required | Required |
| Security objective | Confidentiality | Authenticity and integrity |

### 3.1 RSA-OAEP

Optimal Asymmetric Encryption Padding introduces randomized encoding before RSA encryption.

OAEP prevents the deterministic behavior associated with textbook RSA and provides a standardized encryption construction.

The project uses:

- RSA as the asymmetric primitive.
- OAEP padding.
- SHA-256.
- An appropriately configured mask generation function.

For a modulus of `k` bytes and a hash output of `hLen` bytes, the maximum OAEP plaintext length is:

`Maximum plaintext length = k - 2(hLen) - 2`

For SHA-256, `hLen = 32`.

Therefore:

| RSA modulus | Maximum OAEP plaintext |
|---|---:|
| 2048 bits | 190 bytes |
| 3072 bits | 318 bytes |
| 4096 bits | 446 bytes |

RSA is unsuitable for directly encrypting large files or arbitrary application payloads.

### 3.2 RSA-PSS

Probabilistic Signature Scheme provides randomized encoding for RSA signatures.

PSS uses a hash function, a mask generation function, and a salt.

The JavaScript and Java implementations use SHA-256 and a 32-byte salt.

RSA-PSS is preferred over older deterministic RSA signature constructions for new applications.

### 3.3 Hybrid encryption

Practical applications use hybrid encryption rather than encrypting entire documents with RSA.

The workflow is:

Client data  
→ Generate a random symmetric key  
→ Encrypt the data using authenticated symmetric encryption  
→ Encrypt or wrap the symmetric key using RSA-OAEP  
→ Transmit the encrypted data and wrapped key  
→ Recover the symmetric key using the RSA private key  
→ Authenticate and decrypt the data

Suitable symmetric algorithms include AES-256-GCM and ChaCha20-Poly1305.

The authenticated encryption scheme protects the actual payload. RSA protects the symmetric key.

Hybrid encryption must also correctly manage nonces, authentication tags, associated data, key identifiers, and key rotation.

## 4. RSA Security Limitations

### 4.1 Integer factorization

RSA security relies on the difficulty of factoring the modulus into its prime factors.

If an attacker obtains `p` and `q`, the attacker can calculate the private exponent.

Weak prime generation, insufficient modulus sizes, and defective key-generation procedures can compromise the system.

### 4.2 Small modulus sizes

RSA security decreases when the modulus is insufficiently large.

| Modulus | Security assessment |
|---|---|
| 512 bits | Insecure |
| 1024 bits | Insecure |
| 2048 bits | Current commonly accepted minimum |
| 3072 bits | Higher security margin |
| 4096 bits | Higher computational and storage cost |

A 2048-bit modulus is not a guarantee of indefinite security.

The project applies a minimum modulus policy of 2048 bits and demonstrates stronger configurations using 3072-bit keys.

Actual deployment decisions should follow current organizational cryptographic standards and applicable regulatory requirements.

### 4.3 Deterministic textbook RSA

Raw RSA encryption is deterministic.

For the same public key and plaintext:

`RSA(m) = RSA(m)`

The Python and C++ programs demonstrate this behavior.

Deterministic encryption can expose repeated plaintext patterns and facilitate attacks when message structure or a limited plaintext space is known.

### 4.4 Multiplicative malleability

Textbook RSA has a multiplicative property:

`E(m1) × E(m2) mod n = E(m1 × m2 mod n)`

This property allows ciphertext manipulation without knowledge of the private key.

The Python and C++ programs demonstrate this mathematical property.

Secure encoding schemes such as OAEP are necessary to prevent the direct application of textbook RSA's algebraic structure to practical encryption.

### 4.5 Padding oracle attacks

Improperly implemented RSA padding can expose information through different error responses.

An attacker may exploit differences in:

- Padding-validation errors.
- Decryption responses.
- Response timing.
- Network behavior.
- Application exceptions.

Historical padding-oracle attacks demonstrate why RSA decryption must use carefully implemented standardized schemes.

Applications should avoid exposing detailed decryption errors to untrusted callers.

### 4.6 Timing and side-channel attacks

RSA operations may leak information through implementation behavior.

Potential attack surfaces include:

- Execution time.
- Cache activity.
- Memory access patterns.
- Power consumption.
- Electromagnetic emissions.
- Fault injection.

Private-key operations should use vetted cryptographic implementations with appropriate side-channel protections.

Hardware security modules can reduce private-key exposure and provide controlled cryptographic operations.

### 4.7 Private-key compromise

RSA does not protect a private key after compromise.

Private-key exposure may result from:

- Insecure filesystem permissions.
- Application memory disclosure.
- Accidental source-control commits.
- Unencrypted backups.
- Excessive administrator access.
- Malware.
- Inadequate key-storage practices.

The project models exportability, storage location, revocation, and compromise status as separate security properties.

### 4.8 Quantum computing

A sufficiently capable, fault-tolerant quantum computer running Shor's algorithm could factor RSA moduli efficiently relative to known classical factoring approaches.

This creates a long-term risk for RSA-based public-key infrastructure.

An attacker may collect encrypted communications today and attempt decryption later when sufficiently capable quantum hardware becomes available.

This is known as the harvest-now-decrypt-later threat.

RSA is not post-quantum cryptography.

Organizations with long-lived confidentiality requirements must plan migration toward standardized post-quantum cryptographic algorithms.

## 5. Python Implementation

The Python program provides a mathematical and policy-oriented perspective.

### Implemented mechanisms

**Probable prime generation**

The `is_probable_prime()` function uses the Miller-Rabin primality test.

The implementation rejects small composite numbers and performs repeated randomized primality rounds.

`generate_prime()` produces probable primes using the operating system-backed `secrets` random generator.

**Educational RSA key generation**

`generate_educational_key()` calculates:

- Prime candidates.
- The RSA modulus.
- Euler's totient.
- The modular inverse.
- The public and private exponents.

The demonstration deliberately uses small keys.

It is not suitable for production cryptography.

**Security assessment**

`RSASecurityPolicy` evaluates:

- RSA modulus size.
- Public exponent.
- Key lifecycle status.
- Private-key exportability.
- Encryption padding.
- Signature padding.
- Legacy algorithm usage.

**Key registry**

`KeyRegistry` manages key metadata, evaluates operations, changes lifecycle status, and exports audit events.

Private key material is not included in exported audit records.

### Important limitation

Python's educational implementation does not implement OAEP or PSS.

Its modular arithmetic is intended to demonstrate RSA properties rather than replace a cryptographic library.

The Miller-Rabin implementation also does not provide the full validation and prime-generation assurances required by a production RSA implementation.

## 6. JavaScript Implementation

The JavaScript implementation uses Node.js built-in cryptographic functionality.

It provides actual RSA encryption, decryption, signature creation, and verification.

### Cryptographic operations

The implementation uses:

- `crypto.generateKeyPairSync()` for RSA key generation.
- `crypto.publicEncrypt()` for OAEP encryption.
- `crypto.privateDecrypt()` for OAEP decryption.
- `crypto.sign()` for PSS signature creation.
- `crypto.verify()` for signature verification.

The implementation explicitly selects SHA-256 and PSS salt length.

### Event-driven architecture

`RSAService` extends `EventEmitter`.

Important events include:

- `KEY_GENERATED`
- `POLICY_EVALUATED`
- `ENCRYPTION_COMPLETED`
- `DECRYPTION_COMPLETED`
- `DECRYPTION_FAILED`
- `SIGNATURE_CREATED`
- `KEY_REVOKED`

The event mechanism separates cryptographic operations from audit consumers.

The service maintains key metadata and cryptographic material in separate maps.

### Asynchronous policy evaluation

`RSAPolicy.evaluate()` returns a Promise.

This allows policy evaluation to participate in asynchronous application workflows.

Concurrent requests can be evaluated without introducing a database dependency.

### Input validation

The implementation validates:

- Key identifiers.
- Modulus sizes.
- Public exponents.
- Key lifecycle states.
- Ciphertext representation.
- Ciphertext length.
- OAEP message capacity.

It also returns a generic decryption failure instead of exposing detailed padding-related errors.

### Operational limitation

The example retains private key material in application memory.

The generated private key is marked exportable in metadata because it exists as PEM material.

A production system should use a managed key service or HSM when appropriate, with explicit access policies and secure key lifecycle procedures.

Revocation in this demonstration removes locally retained material. It does not automatically revoke copies or previously issued public certificates elsewhere.

## 7. C++17 Implementation

The C++ implementation focuses on security governance and operation eligibility.

It models cryptographic policy as a set of explicit rules.

### Domain model

The main structures are:

- `RSAKey`
- `Finding`
- `PolicyResult`
- `BranchProtection`
- `OperationRequest`

The enumerations distinguish key lifecycle states, operation types, padding schemes, and finding severity.

### Policy evaluation

`RSAPolicyEngine` evaluates whether an RSA configuration satisfies the required security conditions.

It rejects:

- Inactive keys.
- Weak moduli.
- Nonstandard exponents.
- Exportable private keys.
- Raw RSA.
- Incorrect padding for the requested operation.
- Prohibited legacy padding.

### Governance evaluation

`GovernanceEngine` applies additional organizational controls.

These include:

- Minimum approval count.
- Independent reviewer requirements.
- Required security checks.
- Failed-check rejection.
- Key lifecycle restrictions.

This distinguishes cryptographic correctness from organizational authorization.

A mathematically valid RSA key may still be rejected because it violates repository or enterprise policy.

### Modular exponentiation

`modularPower()` uses repeated squaring.

Its time complexity is:

`O(log exponent)`

The implementation uses the GCC/Clang `__uint128_t` extension to avoid intermediate multiplication overflow for the demonstrated 64-bit operands.

This arithmetic is educational and is not a constant-time cryptographic implementation.

No production private-key operation should rely on this implementation.

## 8. Java 17 Implementation

The Java implementation models RSA as an enterprise cryptographic service.

It uses Java Cryptography Architecture rather than implementing RSA arithmetic manually.

### Domain types

Java records represent immutable security information.

Important records include:

- `RSAKeyMetadata`
- `SecurityFinding`
- `PolicyResult`
- `Review`
- `Approval`
- `ApprovalPolicy`
- `EnterpriseRequest`

The model separates security decisions from cryptographic material.

### RSAKeyStore

`RSAKeyStore` maintains:

- Key metadata.
- Generated key pairs.
- Lifecycle status.
- Audit events.

Concurrent maps support access from multiple application threads.

The implementation does not persist private keys.

### RSAService

The cryptographic service performs four distinct operations.

| Method | Responsibility |
|---|---|
| `encrypt()` | RSA-OAEP encryption |
| `decrypt()` | RSA-OAEP decryption |
| `sign()` | RSA-PSS signature creation |
| `verify()` | RSA-PSS verification |

The implementation explicitly configures the OAEP parameters, including the SHA-256 mask generation function.

It also configures PSS with SHA-256 and a 32-byte salt.

This avoids relying on potentially provider-dependent defaults.

### ApprovalService

The approval service checks whether reviewers are eligible and whether the required number of independent approvals exists.

It rejects:

- Ineligible reviewers.
- Duplicate approvals.
- Insufficient independent approvals.
- Approval-policy violations.

### GovernanceService

The governance service evaluates approval and status-check conditions before permitting the enterprise request to proceed.

The governance result is separate from the actual cryptographic operation.

A production authorization service must also bind approval decisions to the exact key version, operation, policy version, and request contents to prevent approval reuse or time-of-check/time-of-use problems.

## 9. PostgreSQL Data Model

The SQL implementation manages RSA security metadata and operational governance.

It intentionally does not store private keys.

### Entity relationships

The relational model follows this structure:

Repositories  
→ Security principals  
→ Repository memberships  
→ RSA keys  
→ Operation requests  
→ Reviews  
→ Approvals  
→ Security checks  
→ Branch-protection policies  
→ Eligibility evaluations  
→ Audit records

### Main tables

| Table | Responsibility |
|---|---|
| `repositories` | Organizational repository ownership |
| `security_principals` | Users and organizational roles |
| `repository_members` | Repository-level membership |
| `rsa_keys` | RSA key metadata and lifecycle |
| `operation_requests` | Requested cryptographic operations |
| `operation_reviews` | Reviewer eligibility and independence |
| `operation_approvals` | Recorded review decisions |
| `security_checks` | Automated security-check results |
| `branch_protection_policies` | Organizational RSA security requirements |
| `security_audit` | Security event history |

### Integrity constraints

The database enforces:

- Unique repository and key identifiers.
- Valid RSA algorithm identifiers.
- Minimum metadata ranges.
- Valid public exponent ranges.
- Valid key lifecycle states.
- Consistent expiration timestamps.
- Required revocation and compromise timestamps.
- Valid approval references.

Foreign keys maintain referential integrity.

### Triggers

The key lifecycle trigger prevents reactivation of revoked or compromised keys.

It also automatically assigns lifecycle timestamps.

The approval trigger prevents a request owner from approving their own request and rejects approvals from ineligible reviewers.

These triggers provide database-level integrity enforcement.

### Evaluation function

`evaluate_rsa_request()` applies the configured policy to an operation request.

Its checks include:

1. Key lifecycle state.
2. Key expiration.
3. RSA modulus size.
4. Public exponent.
5. Private-key exportability.
6. Storage location.
7. Padding selection.
8. Approval count.
9. Independent approval count.
10. Active rejection decisions.
11. Automated security checks.

The function returns an eligibility decision and a machine-readable reason.

### Workflow procedure

`process_rsa_request()` locks the requested operation record, evaluates the applicable policy, updates the request state, and writes an audit event.

The transaction ensures that workflow processing and its associated audit record are committed together.

The sample dataset contains:

- A 3072-bit RSA key stored in an HSM.
- A weak 1024-bit legacy key.
- An approved OAEP encryption request.
- A prohibited raw-RSA request.
- Independent reviewer decisions.
- Automated security checks.

The final queries demonstrate retrieval, aggregation, risk reporting, workflow processing, and eligibility determination.

### Database limitations

The database evaluates declared metadata and recorded decisions.

It cannot independently establish that an external cryptographic service actually used the declared padding scheme or private key.

The application or HSM must enforce the actual cryptographic operation.

Database permissions must also prevent unauthorized modification of policies, approvals, and audit records.

## 10. Key Lifecycle Management

RSA security requires continuous management after initial key generation.

A typical lifecycle is:

Key generation  
→ Registration  
→ Secure storage  
→ Activation  
→ Controlled usage  
→ Monitoring  
→ Rotation  
→ Retirement or revocation

### Key generation

Use a cryptographically secure random source and a vetted implementation.

Generate RSA keys with sufficient modulus size and validated prime-generation procedures.

### Key storage

Private keys should be protected using suitable controls:

- Hardware security modules.
- Managed key-management services.
- Restricted access.
- Encryption at rest.
- Separation of duties.
- Backup and recovery controls.

### Key rotation

Rotation replaces an existing key with a new key pair.

A rotation procedure should define:

- New-key generation.
- Public-key distribution.
- Application migration.
- Certificate updates.
- Old-key retirement.
- Historical signature verification.
- Encrypted-data migration where necessary.

Rotation does not automatically make ciphertext encrypted under an old key decryptable with the new key.

### Revocation

Revocation prevents future authorized use of a compromised or retired key.

Certificate-based systems must distribute revocation information through appropriate mechanisms.

Previously created signatures may require separate validation procedures and trusted timestamps.

## 11. RSA Versus Other Cryptographic Approaches

| Property | RSA | Elliptic-curve cryptography | Post-quantum cryptography |
|---|---|---|---|
| Mathematical basis | Integer factorization | Elliptic-curve discrete logarithm | Algorithm-dependent mathematical problems |
| Key representation | Relatively large | Generally smaller | Algorithm-dependent |
| Encryption | RSA-OAEP | Usually used through key agreement or hybrid schemes | Depends on standardized algorithm |
| Digital signatures | RSA-PSS | ECDSA and related schemes | ML-DSA and other standardized schemes |
| Quantum resistance | No | No | Designed for post-quantum threats |
| Main operational concern | Key size and padding | Curve and implementation selection | Algorithm maturity, interoperability, and migration |

RSA remains relevant to existing public-key infrastructure, certificate systems, and legacy enterprise applications.

Its continued use must be evaluated against the expected confidentiality lifetime, performance requirements, and migration strategy.

## 12. Security Requirements and Engineering Decisions

| Security area | Required control |
|---|---|
| Key generation | Cryptographically secure random generation |
| Modulus | At least 2048 bits under the demonstrated policy |
| Public exponent | 65537 |
| Encryption | RSA-OAEP with SHA-256 |
| Signatures | RSA-PSS with SHA-256 |
| Large payloads | Hybrid authenticated encryption |
| Private-key storage | HSM or managed key service where appropriate |
| Authorization | Role-based and operation-specific access |
| Monitoring | Key usage and security audit events |
| Rotation | Defined replacement and migration procedures |
| Revocation | Immediate rejection of inactive key states |
| Quantum risk | Post-quantum migration planning |

The modulus-size policy, exponent requirement, and padding requirements in the source files are educational governance defaults. Real deployments must account for applicable cryptographic standards and interoperability requirements.

## 13. Limitations of the Project

The five implementations deliberately address different engineering concerns.

| Component | Limitation |
|---|---|
| Python | Educational RSA mathematics is not production cryptography |
| JavaScript | Generated private material is retained in application memory |
| C++17 | Governance engine does not perform production RSA operations |
| Java 17 | Key material is held in memory rather than a persistent HSM |
| PostgreSQL | Evaluates declared security metadata, not actual cryptographic execution |

Other limitations include:

- No certificate-authority implementation.
- No complete public-key infrastructure.
- No certificate revocation distribution.
- No distributed key replication.
- No formal cryptographic verification.
- No production hardware security module integration.
- No implementation of post-quantum cryptographic algorithms.
- No complete multi-region key-recovery workflow.

The examples demonstrate policy and operational controls rather than claiming that a single RSA configuration provides complete system security.

## 14. Execution and Validation

| File | Runtime | Execution |
|---|---|---|
| Python | Python 3.10+ | `python rsa_security.py` |
| JavaScript | Node.js 18+ | `node rsa_security.js` |
| C++17 | C++17 compiler | `g++ -std=c++17 -O2 rsa_security.cpp -o rsa_security` |
| Java 17 | JDK 17 | `javac RSASecurityEnterprise.java` followed by `java RSASecurityEnterprise` |
| PostgreSQL | PostgreSQL 15+ | Execute the SQL script using `psql` |

The Python, JavaScript, C++, and Java programs include executable validation scenarios.

The SQL script creates its schema, domain types, tables, indexes, views, functions, procedures, triggers, and sample records.

The SQL workflow should be executed by a database role authorized to create the schema objects.

## 15. Practical Security Interpretation

RSA security is not determined by key length alone.

A secure deployment requires the correct relationship between mathematical parameters, encoding schemes, implementation quality, key custody, authorization, and lifecycle management.

The central distinctions are:

- RSA mathematics defines the underlying public-key operations.
- OAEP provides a secure encryption encoding.
- PSS provides a secure signature encoding.
- Key management protects the private-key lifecycle.
- Governance controls determine who can request and authorize operations.
- Audit mechanisms provide operational accountability.
- Post-quantum migration addresses a fundamental limitation of RSA against sufficiently capable quantum computers.

A system should therefore evaluate RSA as a complete cryptographic service rather than as an isolated mathematical algorithm.
