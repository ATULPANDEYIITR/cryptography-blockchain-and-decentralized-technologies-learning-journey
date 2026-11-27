# Digital Signatures for Authentication

## 1. Domain and Technical Scope

Digital signatures provide a cryptographic mechanism for establishing that a message was signed by an entity possessing a particular private key.

Digital signature-based authentication uses asymmetric cryptography to verify control of a registered private key without requiring the private key to be transmitted to the authentication server.

The implementations in this repository demonstrate an end-to-end authentication workflow using public-key registration, challenge issuance, digital signing, signature verification, replay prevention, key revocation, policy evaluation, and audit recording.

The primary cryptographic algorithm is Ed25519.

| Implementation | Engineering perspective | Cryptographic approach |
|---|---|---|
| Python | Repository-style authentication simulation | Ed25519 |
| JavaScript | Event-driven authentication and policy evaluation | Ed25519 |
| C++17 | Authentication governance and verification mechanics | Educational RSA arithmetic |
| Java 17 | Enterprise identity and authentication services | Ed25519 |
| PostgreSQL | Relational identity and authentication governance | Verification evidence from application service |

The C++ implementation deliberately uses small educational RSA parameters to demonstrate modular exponentiation and public-key verification. It is not suitable for security-sensitive deployments.

## 2. Digital Signature Fundamentals

### 2.1 Asymmetric cryptography

Asymmetric cryptography uses two mathematically related keys:

- Private key: retained by the identity owner and used to generate signatures.
- Public key: registered with the authentication service and used to verify signatures.

The keys have different responsibilities.

A private key must remain confidential. A public key can be distributed to systems that need to verify signatures.

The authentication server does not need access to the private key.

### 2.2 Signature generation

A signing operation processes a message using the private key.

Conceptually:

`Signature = Sign(PrivateKey, Message)`

For Ed25519, the signature is 64 bytes.

The resulting signature is associated with the exact message being signed.

Changing the message changes the verification outcome.

### 2.3 Signature verification

The authentication service retrieves the registered public key and verifies the signature.

`Verify(PublicKey, Message, Signature)`

Verification returns a Boolean decision:

| Result | Meaning |
|---|---|
| Valid | The signature corresponds to the supplied message and public key |
| Invalid | The signature does not verify against the supplied message and public key |

A successful verification establishes control of the corresponding signing key under the assumptions of the cryptographic system.

It does not independently establish a person's real-world identity, authorization to access a resource, or the security of the device holding the key.

### 2.4 Authentication versus encryption

Digital signatures and encryption serve different purposes.

| Property | Digital signatures | Encryption |
|---|---|---|
| Primary purpose | Authenticity and integrity | Confidentiality |
| Main operation | Signing and verification | Encryption and decryption |
| Private-key role | Signing | Decryption in conventional public-key encryption |
| Public-key role | Verification | Encryption |
| Message confidentiality | Not provided | Provided when correctly implemented |

A digitally signed message may be publicly readable.

Signing does not automatically encrypt the underlying information.

### 2.5 Authentication versus authorization

Authentication establishes whether a claimant can demonstrate control of an accepted credential.

Authorization determines what an authenticated identity may access.

For example:

- Authentication: Alice proves control of her registered private key.
- Authorization: The application determines whether Alice may approve a financial transaction.

These decisions belong to separate security layers.

## 3. Cryptographic Algorithms

### 3.1 Ed25519

Ed25519 is a digital signature algorithm based on Edwards-curve elliptic-curve cryptography.

Its characteristics include:

- Public-key verification.
- Private-key signing.
- Fixed-size 64-byte signatures.
- Compact public keys.
- Deterministic signature generation.
- Efficient signing and verification.
- No requirement for an external signing nonce supplied by the application.

Ed25519 is supported by the Python `cryptography` package and the standard cryptographic APIs in modern Node.js and Java.

The implementations use their respective platform cryptographic libraries rather than implementing elliptic-curve mathematics directly.

### 3.2 RSA signatures

RSA signatures use modular arithmetic and exponentiation.

The educational C++ implementation demonstrates:

`Verification = Signature^PublicExponent mod Modulus`

For valid signature data, the resulting representative matches the signed message representative.

Real RSA signatures require secure encoding and padding schemes.

RSA-PSS is a modern signature scheme that uses probabilistic padding and should be preferred over obsolete raw RSA or PKCS#1 v1.5 signing in new designs where interoperability requirements permit.

The small RSA parameters in the C++ implementation are intentionally insecure.

### 3.3 ECDSA

ECDSA is another asymmetric digital signature algorithm.

Its security depends on correct elliptic-curve operations and secure nonce handling.

Reusing or exposing an ECDSA signing nonce can reveal the private key.

The SQL model includes ECDSA as a supported algorithm identifier for a broader authentication architecture, although the executable application implementations focus on Ed25519.

### 3.4 Algorithm selection

| Algorithm | Category | Implementation consideration |
|---|---|---|
| Ed25519 | Edwards-curve signature | Preferred demonstration algorithm |
| RSA-PSS | RSA signature | Requires appropriate padding and parameter configuration |
| ECDSA P-256 | Elliptic-curve signature | Requires correct nonce and signature encoding management |

Algorithm selection must account for interoperability, cryptographic library support, organizational requirements, key lifecycle management, and security policy.

## 4. Challenge-Response Authentication

### 4.1 Why challenge-response is necessary

Signing a fixed message is insufficient for authentication.

An attacker who captures an old valid signature may attempt to submit it again.

Challenge-response authentication addresses this problem by requiring the claimant to sign a fresh, unpredictable challenge.

The authentication server generates a random nonce and associates it with:

- A unique challenge identifier.
- A user identifier.
- A registered public-key identifier.
- An intended service audience.
- An expiration time.
- A one-time-use state.

The claimant signs the complete authentication message.

### 4.2 Authentication workflow

The complete workflow is:

`Identity Registration`
          |
          v
`Public Key Registration`
          |
          v
`Challenge Generation`
          |
          v
`Nonce Delivery`
          |
          v
`Private-Key Signing`
          |
          v
`Signature Submission`
          |
          v
`Public-Key Verification`
          |
          v
`Policy Evaluation`
          |
          v
`Atomic Challenge Consumption`
          |
          v
`Authentication Decision`
          |
          v
`Audit Recording`

### 4.3 Nonce generation

A nonce is a value intended for one-time use.

The implementations use cryptographically secure random-number generators.

Python uses `secrets.token_bytes()`.

JavaScript uses `crypto.randomBytes()`.

Java uses `SecureRandom`.

PostgreSQL uses `gen_random_bytes()` from `pgcrypto`.

The C++ implementation uses fixed demonstration values and does not provide production-grade random challenge generation.

A production implementation must never use predictable timestamps, sequential counters without appropriate safeguards, or ordinary pseudorandom generators for authentication nonces.

### 4.4 Canonical message construction

The signature must bind all relevant authentication parameters.

The message should contain:

- Protocol version.
- Authentication purpose.
- Challenge identifier.
- User identifier.
- Nonce.
- Intended audience.
- Registered key identifier where applicable.

Canonical serialization prevents different systems from interpreting the same logical message differently.

The Python and JavaScript implementations use deterministic JSON serialization for their defined message structures.

The Java implementation uses length-prefixed fields to prevent ambiguous concatenation.

A production protocol should define one exact serialization format and byte representation for every participant.

### 4.5 Audience binding

Audience binding identifies the intended receiving service.

For example:

- `identity-api`
- `payments-api`
- `enterprise-access-api`

A signature generated for one service must not automatically be accepted by another.

This prevents cross-service signature reuse.

The audience is included in the signed challenge message and checked against the authentication policy.

### 4.6 Expiration

Challenges must have a limited lifetime.

An expired challenge must not produce a successful authentication decision.

The examples use a default lifetime of 120 seconds, with configurable policy values.

Expiration reduces the usefulness of captured authentication messages and limits the lifetime of outstanding challenges.

Clock synchronization and consistent server-side time handling are important in distributed deployments.

## 5. Public-Key Registration and Identity Management

### 5.1 Registration

The authentication server associates a public key with a registered user.

A registration operation records:

- User identifier.
- Key identifier.
- Public key.
- Cryptographic algorithm.
- Key fingerprint.
- Registration timestamp.
- Key status.

The fingerprint is calculated using SHA-256 over a defined public-key representation.

It provides a compact identifier for comparing public-key records.

A fingerprint is not a replacement for public-key validation.

### 5.2 Key ownership

A registered key must be associated with the correct identity.

The authentication service must check that:

- The key exists.
- The key belongs to the requested user.
- The key is active.
- The challenge belongs to the same user.
- The challenge references the same key.
- The signature algorithm matches the registered key.

These checks prevent an attacker from combining another user's key with a legitimate challenge.

### 5.3 Key revocation

A public key may become untrusted because of:

- Suspected private-key compromise.
- Device loss.
- Employee departure.
- Credential replacement.
- Administrative security action.
- Cryptographic policy changes.

Revocation prevents subsequent authentication using the affected key.

The Python, JavaScript, and Java implementations model active and revoked states.

The PostgreSQL trigger prevents a revoked key from being reactivated through an ordinary status update.

A replacement key should be registered as a new credential rather than silently restoring the compromised key.

### 5.4 Private-key protection

Private-key security is a fundamental requirement.

Private keys should not be transmitted to authentication servers or stored in ordinary database tables.

Appropriate storage mechanisms include:

- Hardware Security Modules.
- Trusted Platform Modules.
- Secure Enclaves.
- Operating-system key stores.
- Dedicated hardware security tokens.
- Approved encrypted key containers.

The Java example retains a private key in memory only to demonstrate local signing. It explicitly separates this demonstration behavior from enterprise key custody.

## 6. Replay Protection and Challenge State Management

### 6.1 Replay attacks

A replay attack occurs when an attacker captures a previously valid authentication request and submits it again.

For example:

1. Alice authenticates successfully.
2. An attacker captures the signed authentication message.
3. The attacker resubmits the same message.
4. The authentication service receives a previously used challenge.

Without replay protection, a system might incorrectly accept the old signature.

### 6.2 One-time challenge states

The implementations use three challenge states.

| State | Meaning | Authentication eligibility |
|---|---|---|
| ISSUED | Challenge has been created | Potentially eligible |
| CONSUMED | Challenge has been successfully used | Rejected |
| EXPIRED | Challenge lifetime has ended | Rejected |

The primary valid transition is:

`ISSUED → CONSUMED`

Another valid transition is:

`ISSUED → EXPIRED`

A consumed or expired challenge cannot be reopened.

### 6.3 Atomic consumption

Replay prevention must be enforced atomically.

Checking a challenge and consuming it in separate, unprotected operations creates a race condition.

Two concurrent requests could both observe the challenge as unused.

A production database implementation should use a transaction with row locking or a conditional update.

For example, a conditional update can require the challenge to remain in the ISSUED state.

Only the transaction that successfully changes the state may complete authentication.

The PostgreSQL implementation uses `SELECT ... FOR UPDATE` and a conditional state transition.

The Java implementation uses synchronized authentication operations and concurrent collections.

The JavaScript implementation explains why its local single-process state transition is insufficient for a distributed deployment.

## 7. Authentication Policies

### 7.1 Policy evaluation

Cryptographic verification is necessary but does not represent the complete authentication decision.

The service must evaluate operational and security requirements.

The policy layer evaluates:

- Whether the user is enabled.
- Whether the public key is active.
- Whether the challenge belongs to the user.
- Whether the challenge is still valid.
- Whether the signature format is correct.
- Whether the cryptographic algorithm is permitted.
- Whether the intended audience matches.
- Whether the challenge has already been consumed.

The JavaScript implementation separates policy evaluation from the cryptographic verification service.

The Java implementation uses an `AuthenticationPolicy` interface and a `DefaultAuthenticationPolicy` implementation.

This design allows policy rules to evolve independently of cryptographic operations.

### 7.2 Authentication eligibility

A useful conceptual expression is:

`Eligible = UserActive AND KeyActive AND ChallengeValid AND PolicySatisfied`

The final decision additionally requires:

`ValidSignature AND ChallengeNotPreviouslyConsumed`

An identity should not be authenticated merely because a valid signature exists.

The signature must correspond to the correct user, key, challenge, purpose, and audience.

### 7.3 Pending challenge limits

The examples impose limits on outstanding challenges.

This reduces unnecessary challenge accumulation and provides a basic control against excessive request generation.

Production deployments should also implement:

- Per-user rate limits.
- Per-IP rate limits.
- Account lockout or risk-based restrictions where appropriate.
- Request quotas.
- Abuse detection.
- Distributed rate limiting.

A failed signature should be recorded without treating it as a successful authentication.

## 8. Codebase Architecture

### 8.1 Python implementation

The Python program uses a domain-oriented design.

| Component | Responsibility |
|---|---|
| `DigitalIdentity` | Generates and signs with an Ed25519 key pair |
| `RegisteredKey` | Stores public-key registration state |
| `Challenge` | Represents a one-time authentication request |
| `AuthenticationServer` | Manages registration, challenges, verification, and revocation |
| `AuthenticationError` | Represents authentication failures |
| `AuditEvent` | Records security-relevant events |

Python-specific mechanisms include dataclasses, dictionaries, enums, type annotations, exception handling, cryptographic library integration, and assertions.

The demonstration covers successful authentication, replay rejection, signature tampering, and revocation.

The implementation uses in-memory storage and is intended for a single-process learning environment.

### 8.2 JavaScript implementation

The JavaScript program emphasizes asynchronous processing and policy separation.

| Component | Responsibility |
|---|---|
| `Identity` | Generates an Ed25519 key pair |
| `AuthenticationPolicy` | Evaluates authentication conditions |
| `AuthenticationService` | Coordinates the authentication workflow |
| `AuthenticationError` | Provides structured failure information |
| `Map` | Stores registered identities and challenges |
| `Set` | Tracks consumed challenges |
| `Promise` | Supports asynchronous random-byte generation |

Node.js provides the cryptographic operations through its built-in `crypto` module.

The implementation uses event-independent asynchronous operations while maintaining explicit state transitions.

A production multi-instance deployment requires shared persistent storage and atomic challenge consumption.

### 8.3 C++17 implementation

The C++ program emphasizes governance logic and mathematical verification mechanics.

| Component | Responsibility |
|---|---|
| `RSAKey` | Represents a public-key modulus and exponent |
| `EducationalRSA` | Implements modular exponentiation and signature verification |
| `Identity` | Represents an identity and its key status |
| `Challenge` | Models one-time challenge state |
| `StatusCheck` | Represents a policy or operational condition |
| `AuthenticationGovernance` | Controls registration, revocation, and authentication |
| `AuditRecord` | Records authentication outcomes |

The modular exponentiation function uses repeated squaring.

Its time complexity is logarithmic in the exponent.

The implementation uses STL containers, enumerations, exceptions, and domain-specific structures.

The RSA parameters are deliberately small. The implementation does not provide secure hashing, RSA-PSS encoding, secure random generation, or production-grade cryptographic protection.

Its purpose is to demonstrate the relationship between signature verification and authentication governance.

### 8.4 Java 17 implementation

The Java implementation uses enterprise-oriented domain modeling.

| Component | Responsibility |
|---|---|
| `RegisteredIdentity` | Immutable public-key registration |
| `Challenge` | Immutable challenge representation |
| `AuthenticationRequest` | Validated authentication request |
| `AuthenticationResult` | Authentication outcome |
| `SignatureVerifier` | Cryptographic verification abstraction |
| `Ed25519Verifier` | Ed25519 verification implementation |
| `AuthenticationPolicy` | Authentication policy contract |
| `DefaultAuthenticationPolicy` | Challenge and key validation |
| `IdentityService` | Enterprise identity management |

Java records provide immutable domain structures.

Interfaces separate cryptographic verification from policy evaluation.

Concurrent collections support shared state management.

The synchronized authentication operation prevents duplicate challenge consumption inside the example service instance.

Private-key handling remains demonstration-oriented and should be replaced with client-side signing or protected key-service integration in an enterprise environment.

### 8.5 PostgreSQL implementation

The SQL script models persistent identity and authentication governance.

| Table | Responsibility |
|---|---|
| `auth_users` | User identity and account state |
| `public_keys` | Registered public keys and revocation |
| `authentication_challenges` | Nonces and challenge lifecycle |
| `signature_verifications` | Cryptographic verification evidence |
| `authentication_policies` | Algorithm and challenge requirements |
| `user_policy_assignments` | User-to-policy relationships |
| `authentication_attempts` | Authentication outcomes |
| `security_audit` | Security event history |

The schema includes primary keys, foreign keys, unique constraints, checks, indexes, functions, procedures, triggers, views, transactions, and reporting queries.

The database does not independently verify Ed25519 signatures.

A trusted application service performs cryptographic verification and submits the result as verification evidence.

This separation prevents database workflow logic from being confused with cryptographic verification itself.

## 9. PostgreSQL Workflow and Integrity Controls

### 9.1 Relational relationships

The principal relational structure is:

`auth_users`
    |
    +---- `public_keys`
    |         |
    |         +---- `authentication_challenges`
    |         |             |
    |         |             +---- `signature_verifications`
    |         |
    |         +---- `authentication_attempts`
    |
    +---- `user_policy_assignments`
    |                 |
    |                 +---- `authentication_policies`
    |
    +---- `security_audit`

The relationships enforce ownership and referential integrity.

### 9.2 Constraints

The database uses constraints to prevent invalid states.

Examples include:

- Public keys cannot be empty.
- SHA-256 fingerprints must contain 32 bytes.
- Nonces must meet the minimum length.
- Challenge expiration must follow issuance.
- Successful challenges require a consumption timestamp.
- Successful verification records cannot contain failure reasons.
- Failed verification records require a failure reason.
- Authentication policies require positive expiration limits.

These constraints protect the database against malformed or inconsistent records.

### 9.3 Triggers

The key revocation trigger prevents a revoked credential from being reactivated through a normal update.

The challenge transition trigger prevents consumed or expired challenges from being reopened.

These controls enforce state consistency at the database level.

### 9.4 Functions and procedures

`issue_authentication_challenge()` validates the user, registered key, assigned policy, challenge lifetime, and pending challenge count before creating a challenge.

`complete_authentication()` records verification evidence and manages the corresponding authentication transaction.

`expire_old_challenges()` processes expired challenges.

`is_authentication_eligible()` determines whether a user, key, challenge, and policy satisfy the recorded eligibility conditions.

The eligibility function does not replace signature verification.

### 9.5 Indexing strategy

The schema includes indexes for:

- User-to-key retrieval.
- Public-key fingerprint lookup.
- Outstanding challenge retrieval.
- Challenge ownership.
- Authentication history.
- Failed authentication analysis.
- Audit event retrieval.
- JSONB audit searches.

Partial indexes support queries targeting failed or blocked authentication attempts.

Index selection should be reviewed using actual query plans and production workload statistics.

## 10. Security Threats and Mitigations

| Threat | Description | Primary mitigation |
|---|---|---|
| Replay attack | Reuse of a previously valid signature | Fresh nonce and one-time challenge consumption |
| Private-key theft | Attacker obtains signing credentials | HSM, secure enclave, protected device storage |
| Signature tampering | Modification of signed message data | Cryptographic signature verification |
| Man-in-the-middle attack | Interception or modification of authentication traffic | TLS, audience binding, challenge integrity |
| Key substitution | Replacement of a registered public key | Authenticated registration and fingerprint validation |
| Cross-service reuse | Use of a signature at another service | Audience and purpose binding |
| Algorithm downgrade | Use of a weaker or disallowed algorithm | Explicit algorithm policy |
| Denial of service | Excessive challenge or authentication requests | Rate limiting and resource controls |
| Race condition | Concurrent consumption of one challenge | Atomic transactions and locking |
| Database compromise | Unauthorized alteration of authentication records | Least privilege, monitoring, immutable audit storage |

### 10.1 Man-in-the-middle protection

Digital signatures alone do not protect every part of the communication channel.

TLS should protect communication between clients and authentication services.

The authentication message should bind the challenge to its intended audience and purpose.

The application should also validate server identity and certificate chains.

### 10.2 Key compromise

When a private key is compromised, revocation must be performed promptly.

The identity provider should:

1. Mark the compromised key as revoked.
2. Reject new challenges for that key.
3. Prevent outstanding challenges from succeeding.
4. Record the revocation event.
5. Require registration of a replacement key.
6. Review historical authentication activity.

Revocation status must be checked during authentication, not only during initial registration.

### 10.3 Audit integrity

Authentication records should capture:

- User identifier.
- Key identifier.
- Challenge identifier.
- Authentication result.
- Failure category.
- Timestamp.
- Source network information where permitted.
- Verifier version.

Audit data should be protected against unauthorized modification.

For higher-assurance systems, logs can be exported to independently controlled, append-only storage.

Sensitive information, private keys, and reusable authentication secrets must not be written to logs.

## 11. Important Distinctions

### 11.1 Digital signature versus electronic signature

An electronic signature is a broad category of electronic methods used to indicate agreement, intent, or approval.

A digital signature is a cryptographic mechanism based on mathematical key relationships and signature verification.

Not every electronic signature is a digital signature.

Legal recognition depends on the applicable jurisdiction, technology, certificate arrangements, and statutory requirements.

### 11.2 Digital signature versus digital certificate

A digital signature is generated using a private key.

A digital certificate binds a public key to an identity through a certificate authority or another trusted certification arrangement.

A certificate can provide evidence about the identity associated with a public key.

Certificate validation may include:

- Issuer validation.
- Certificate validity period.
- Trust-chain verification.
- Key usage restrictions.
- Certificate revocation status.
- Subject identity validation.

The demonstration implementations register public keys directly rather than implementing a complete public-key infrastructure.

### 11.3 Signature validity versus identity assurance

A mathematically valid signature establishes that the signing operation corresponds to the registered public key and signed message.

It does not independently prove:

- The legal identity of the key owner.
- The security of the device.
- The absence of malware.
- The user's physical presence.
- The user's intent.
- The user's authorization for a particular operation.

These properties require additional identity-proofing, device-security, authorization, and transaction controls.

### 11.4 Signature verification versus non-repudiation

Digital signatures can provide evidence useful for accountability and dispute resolution.

They do not automatically guarantee non-repudiation in every legal or operational context.

Private-key custody, identity verification, certificate governance, audit integrity, and applicable legal rules affect the strength of such evidence.

## 12. Edge Cases and Failure Handling

The implementations cover several operational failure conditions.

| Scenario | Expected behavior |
|---|---|
| Unknown user or key | Reject authentication |
| User-key mismatch | Reject authentication |
| Unknown challenge | Reject authentication |
| Revoked key | Reject authentication |
| Expired challenge | Reject authentication |
| Previously consumed challenge | Reject replay |
| Invalid signature length | Reject request |
| Modified signed message | Reject verification |
| Unsupported algorithm | Reject policy evaluation |
| Excessive pending challenges | Reject challenge creation |
| Duplicate key registration | Reject duplicate registration |
| Missing policy assignment | Reject challenge issuance |
| Concurrent challenge consumption | Permit only one successful consumption |

Failure handling must avoid leaking sensitive information.

Externally visible responses should generally use consistent authentication failure messages, while protected internal logs can retain more detailed failure classifications.

## 13. Performance and Scalability

### 13.1 Cryptographic performance

Ed25519 provides compact signatures and public keys, making it suitable for many authentication applications.

Cryptographic operations consume CPU resources and should be measured under realistic concurrent workloads.

Public-key verification is typically less expensive than many large-scale RSA verification workloads, although actual performance depends on hardware and implementation.

### 13.2 Database performance

Authentication systems can generate large numbers of short-lived challenges and audit events.

Important database considerations include:

- Indexing challenge ownership and expiration.
- Efficient key lookup.
- Limiting outstanding challenges.
- Partitioning large audit tables.
- Archiving old authentication attempts.
- Avoiding unnecessary full-table scans.
- Monitoring lock contention.
- Keeping challenge-consumption transactions short.

### 13.3 Distributed deployment

An in-memory authentication service is not sufficient for a horizontally scaled production system.

Multiple service instances need shared state for:

- Public-key registration.
- Key revocation.
- Challenge creation.
- Challenge consumption.
- Rate limiting.
- Authentication audit records.

A central transactional database or another appropriately designed distributed state service should coordinate one-time challenge use.

### 13.4 Availability and recovery

The authentication service should handle:

- Database outages.
- Cryptographic provider failures.
- Key-service unavailability.
- Network interruptions.
- Expired credentials.
- Policy configuration errors.
- Recovery after service restarts.

A security-sensitive authentication service should fail closed when it cannot establish the required verification or credential status.

## 14. Execution Requirements

| Deliverable | Runtime | Requirement |
|---|---|---|
| Python | Python 3.10+ | `cryptography` package |
| JavaScript | Node.js 20+ | Built-in `crypto` module |
| C++17 | C++17 compiler | Standard library only |
| Java | Java 17 | Standard Java cryptography APIs |
| PostgreSQL | PostgreSQL 14+ | `pgcrypto` extension |

Python requires the `cryptography` package because the standard library does not provide a complete Ed25519 implementation.

JavaScript and Java use their built-in cryptographic facilities.

The C++ implementation is self-contained but intentionally non-production-grade.

The PostgreSQL script requires permission to install or use `pgcrypto`.

## 15. Testing and Verification Scenarios

The source files demonstrate the following test cases.

| Test | Expected result |
|---|---|
| Generate an Ed25519 key pair | Public and private keys created |
| Register public key | Registration succeeds |
| Issue challenge | Unique nonce generated |
| Sign canonical challenge | Signature generated |
| Verify valid signature | Authentication succeeds |
| Reuse consumed challenge | Authentication rejected |
| Modify signed message | Verification fails |
| Modify signature bytes | Verification fails |
| Revoke public key | Future authentication rejected |
| Use expired challenge | Authentication rejected |
| Submit mismatched identity | Authentication rejected |
| Exceed pending challenge limit | New challenge rejected |
| Query authentication reports | Operational statistics returned |
| Attempt invalid database state transition | Database rejects the update |

For production validation, additional testing should cover concurrent requests, key rotation, distributed replay protection, cryptographic provider failures, clock discrepancies, database transaction failures, and security logging.

## 16. Practical Applications

Digital signature-based authentication is applicable to:

- Enterprise employee identity systems.
- Passwordless authentication.
- API client authentication.
- Hardware security tokens.
- Secure software deployment.
- Device identity management.
- Financial transaction authorization.
- Secure service-to-service communication.
- Machine identity and workload authentication.
- High-assurance access-control systems.

The mechanism is particularly useful when a system needs proof of private-key possession without transmitting reusable passwords or private credentials to the authentication service.

The final authentication decision must combine cryptographic verification, identity binding, credential status, challenge freshness, replay protection, and applicable security policies.
