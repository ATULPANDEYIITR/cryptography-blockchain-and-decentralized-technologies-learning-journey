# Rainbow Tables and Password Attacks

## 1. Domain Overview

Password attacks exploit weaknesses in password selection, password storage, authentication workflows, or user behavior. Rainbow tables represent one specific category of offline password-hash attack. They use precomputed hash chains to reduce repeated computation when searching for password candidates.

The security implications depend on how passwords are stored and how authentication is protected.

This project examines password attacks through five complementary implementations:

- Python: password hashing, synthetic dictionary attacks, rainbow-table construction, and authentication simulation.
- JavaScript: event-driven authentication and asynchronous credential verification.
- C++17: password-security governance and authentication-state evaluation.
- Java 17: enterprise credential management and explicit authentication workflows.
- PostgreSQL: relational storage, credential metadata, authentication history, and security reporting.

All attack demonstrations use synthetic data. The implementations do not access external credential databases.

## 2. Password Hashing Fundamentals

A password hashing system converts a password into a fixed-length verifier.

A simplified representation is:

Password → Hash Function → Password Verifier

A cryptographic hash function has several important properties:

- Deterministic output for identical inputs.
- Fixed-length digest.
- Computational difficulty of recovering the original input.
- Sensitivity to small changes in input.
- Resistance to finding two different inputs with the same digest.

SHA-256 is a general-purpose cryptographic hash function. It is designed for fast computation, which makes it unsuitable as the sole password-storage mechanism.

Password verification requires a different design because attackers can perform large numbers of candidate computations when password hashes are exposed.

### 2.1 General-purpose hashes

SHA-256 produces a 256-bit digest.

Its speed is useful for file integrity, digital signatures, and other cryptographic applications. The same speed becomes a disadvantage for password storage because an attacker can evaluate many password candidates quickly.

### 2.2 Password hashing algorithms

Password-storage algorithms introduce configurable computational costs.

| Algorithm | Main characteristic | Security consideration |
|---|---|---|
| SHA-256 | Fast digest computation | Not suitable alone for password storage |
| PBKDF2 | Iterative key derivation | Work factor must be appropriately configured |
| bcrypt | Adaptive password hashing | Cost factor controls computation |
| Argon2id | Memory-hard password hashing | Uses memory and computation to increase attack cost |

Argon2id is particularly relevant when resistance to large-scale password guessing is required.

PBKDF2 is included in the executable Python, JavaScript, and Java implementations because it is available through their standard cryptographic libraries.

Production configurations should be benchmarked against the actual deployment environment. Work factors should be periodically reviewed as computing capabilities change.

## 3. Rainbow Tables

A rainbow table is a precomputed structure designed to reduce the cost of repeated password-hash searches.

It uses two principal operations:

1. A hash function converts a password candidate into a digest.
2. A reduction function converts a digest into another candidate password.

The reduction function is not a cryptographic inverse. It maps a digest into a defined candidate space.

### 3.1 Hash chains

A simplified chain is:

Password P0
    |
    v
Hash(P0)
    |
    v
Reduction 0
    |
    v
Password P1
    |
    v
Hash(P1)
    |
    v
Reduction 1
    |
    v
Password P2

A rainbow table stores chain starting points and endpoints rather than every intermediate password and hash.

During lookup, possible chain positions are reconstructed. If an endpoint matches a stored chain, the chain can be regenerated to check whether the target hash occurs within it.

### 3.2 Rainbow-table components

| Component | Purpose |
|---|---|
| Candidate space | Defines possible password values |
| Hash function | Produces cryptographic digests |
| Reduction function | Maps digests into candidate values |
| Chain position | Determines which reduction function is applied |
| Starting point | Initial candidate of a chain |
| Endpoint | Final candidate used as the lookup index |
| Chain length | Number of transformations in a chain |
| Lookup | Attempts to identify a chain containing the target hash |

### 3.3 Why multiple reduction functions matter

Rainbow tables use position-dependent reduction functions.

Using the same reduction function at every position increases undesirable chain merging. Position-dependent functions reduce this problem and improve the organization of the precomputed structure.

### 3.4 Time and storage trade-offs

Rainbow tables exchange storage for computation.

- Longer chains can reduce the number of stored starting points.
- Longer chains increase reconstruction work.
- Shorter chains require more stored entries for comparable candidate coverage.
- Chain collisions can reduce effective coverage.
- Larger password spaces require substantially greater storage and computation.

A rainbow table does not guarantee recovery of every password in a candidate space.

### 3.5 Rainbow tables versus direct guessing

| Characteristic | Direct guessing | Rainbow tables |
|---|---|---|
| Main operation | Repeated candidate hashing | Precomputed chain lookup |
| Precomputation | Usually not required | Required |
| Storage | Small working state | Potentially substantial |
| Reuse | Candidate work is repeated | Tables can be reused for compatible hashes |
| Salt sensitivity | Depends on verification scheme | Unique salts invalidate reusable unsalted tables |
| Main limitation | Computational cost | Storage, coverage, and chain collisions |

## 4. Password Attack Categories

The different attack categories exploit different weaknesses. They should not be treated as interchangeable.

### 4.1 Dictionary attacks

Dictionary attacks use likely password candidates rather than exhaustively enumerating every possible combination.

Common password patterns, predictable substitutions, and frequently used passwords increase exposure.

The Python implementation demonstrates dictionary lookup against a small synthetic dataset.

Defensive controls:

- Screen passwords against common-password lists.
- Reject known compromised passwords.
- Use adaptive password hashing.
- Encourage password managers and unique passwords.

### 4.2 Brute-force attacks

Brute-force attacks systematically explore a candidate space.

The candidate space depends on:

- Password length.
- Character set.
- Character distribution.
- Search strategy.
- Available computing resources.

For an alphabet containing \(A\) possible characters and a fixed password length \(L\), the candidate space is:

\[
N=A^L
\]

The number of candidates grows exponentially with password length.

Defensive controls include authentication rate limiting, progressive delays, monitoring, and strong password-storage algorithms.

### 4.3 Rainbow-table attacks

Rainbow-table attacks exploit reusable precomputation against compatible password hashes.

The central weakness is the absence of unique per-password salts in password storage.

A unique salt changes the input to the password hashing operation:

\[
H=\operatorname{Hash}(S\parallel P)
\]

Where:

- \(H\) is the resulting digest.
- \(S\) is the random salt.
- \(P\) is the password.

Two accounts using the same password but different salts produce different stored verifiers.

A rainbow table generated for unsalted passwords cannot be directly reused against independently salted password records.

Salting does not make weak passwords strong. It prevents direct reuse of precomputed tables and makes large-scale guessing more expensive.

### 4.4 Credential stuffing

Credential stuffing uses previously compromised username-password combinations against other services.

Its principal weakness is password reuse rather than hash-storage configuration.

Defensive controls:

- Multi-factor authentication.
- Unique passwords across services.
- Compromised-credential screening.
- Suspicious login detection.
- Account-aware authentication monitoring.

### 4.5 Password spraying

Password spraying involves testing a limited number of likely passwords across many accounts.

It differs from brute-force attacks that concentrate on repeatedly guessing one account's password.

Defensive controls should include monitoring across multiple accounts and identifying distributed failure patterns.

### 4.6 Phishing

Phishing targets users rather than password hashing algorithms.

A user may disclose valid credentials through a deceptive website or communication.

Defensive controls include passkeys, phishing-resistant authentication, and appropriate user verification procedures.

## 5. Password Salting and Secure Storage

A salt is a random value generated independently for each password credential.

A secure password-storage record generally contains:

- Password hashing algorithm.
- Password verifier.
- Unique random salt.
- Work factor.
- Memory cost where applicable.
- Parallelism parameters where applicable.
- Credential version.

A salt is not a secret key. It can be stored alongside the password verifier.

### 5.1 Salt versus pepper

| Property | Salt | Pepper |
|---|---|---|
| Uniqueness | Unique per credential | Usually shared across a defined application boundary |
| Storage | Stored with the verifier | Stored separately |
| Main purpose | Prevent reusable precomputation and identical verifier values | Add protection against database-only compromise |
| Confidentiality | Not required | Must remain secret |

A pepper requires independent secret management. Storing it in the same compromised database removes much of its security benefit.

### 5.2 Adaptive password hashing

PBKDF2 applies repeated pseudorandom-function operations to password material and a salt.

Argon2id introduces memory-hard computation, increasing the resources required for large-scale password guessing.

The appropriate algorithm and work factor depend on security requirements, hardware, concurrency, and response-time constraints.

### 5.3 Constant-time verification

Password-verifier comparison should avoid leaking information through data-dependent comparison timing.

Python uses `hmac.compare_digest`, Java uses `MessageDigest.isEqual`, and JavaScript uses `crypto.timingSafeEqual`.

The C++ implementation models authentication governance rather than implementing a cryptographic verifier.

## 6. Python Implementation

The Python script models the complete educational workflow.

### 6.1 Synthetic password dataset

The implementation defines a small candidate space containing four synthetic passwords.

This provides a controlled environment for comparing direct dictionary lookup with rainbow-table lookup.

### 6.2 Rainbow-table construction

The `RainbowTable` dataclass maintains:

- Chain length.
- Starting passwords.
- Stored chain endpoints.

Its chain-generation method applies SHA-256 and position-dependent reduction functions.

The lookup method reconstructs possible chain suffixes and verifies candidate hashes.

### 6.3 Salt demonstration

The script generates independent random salts for the same synthetic password.

The resulting salted hashes differ, demonstrating why unsalted precomputed tables are not directly reusable against independently salted records.

### 6.4 Secure credential storage

`PasswordHasher` uses PBKDF2-HMAC-SHA256 with a unique random salt.

The credential record contains the salt, verifier, iteration count, and algorithm identifier.

Verification uses constant-time digest comparison.

### 6.5 Authentication state

`AuthenticationService` manages:

- Account registration.
- Credential storage.
- Authentication verification.
- Failed-attempt counters.
- Temporary account lockout.
- Successful login recovery.

The implementation also includes a password-policy validator and attack-classification dictionary.

### 6.6 Testing

Assertions validate:

- SHA-256 digest behavior.
- Synthetic dictionary lookup.
- Correct password verification.
- Incorrect password rejection.
- Salt uniqueness.
- Password-policy validation.

The small rainbow-table dataset is educational rather than representative of a production password search space.

## 7. JavaScript Implementation

The JavaScript implementation focuses on asynchronous authentication and event-driven security monitoring.

### 7.1 Node.js cryptographic functionality

The script uses:

- `node:crypto` for SHA-256.
- `randomBytes` for random salt generation.
- `pbkdf2` for password derivation.
- `timingSafeEqual` for verifier comparison.
- `node:events` for authentication events.

It uses only Node.js built-in modules.

### 7.2 RainbowTable class

The `RainbowTable` class uses `Map` to store chain endpoints and their corresponding starting values.

BigInt is used for reduction calculations to avoid losing precision when handling large hexadecimal values.

### 7.3 CredentialRepository

The repository separates credential persistence from authentication behavior.

It creates a new salt for each registered account and stores an immutable credential record.

Password verification is asynchronous because PBKDF2 is computationally expensive.

### 7.4 Event-driven authentication

`AuthenticationEngine` extends `EventEmitter`.

It publishes events for:

- Successful authentication.
- Failed authentication.
- Account lockout.

The active-login set prevents overlapping attempts against the same account from racing the failure counter within a single process.

A production distributed authentication service must use shared atomic state, such as a database or centralized rate-limiting service. An in-memory map cannot enforce account lockout consistently across multiple application instances.

### 7.5 Failure handling

The implementation uses `try/finally` to release active-login state even when credential verification fails.

The executable test workflow checks successful authentication, invalid credentials, and account lockout.

## 8. C++17 Implementation

The C++ program uses a domain-oriented security governance architecture.

It deliberately separates cryptographic implementation from security policy evaluation.

### 8.1 Domain types

The program defines enumerations for:

- Attack classification.
- Authentication status.
- Hash algorithms.
- Risk levels.

These types prevent arbitrary string values from being used throughout the policy engine.

### 8.2 AttackCatalog

The attack catalog stores descriptions and defensive controls in a map.

Each attack type has a distinct classification and corresponding mitigation strategy.

### 8.3 StoragePolicyEvaluator

The evaluator considers:

- Hash algorithm.
- Unique salt requirement.
- Minimum work factor.
- Memory-hard behavior.

It produces a risk classification for the configured password-storage approach.

### 8.4 AuthenticationService

The authentication service manages account records using an `unordered_map`.

Its responsibilities include:

- Account registration.
- Authentication-state tracking.
- Failed-attempt counting.
- Temporary lockout.
- Security event collection.

The state transitions are explicit and independent of the attack-classification component.

### 8.5 Architectural trade-off

The C++ implementation uses a synthetic password verifier to test the authentication state machine.

It does not implement password hashing or claim cryptographic security.

A real deployment should integrate a maintained cryptographic library, use constant-time password verification, and protect account state against concurrent access.

## 9. Java 17 Implementation

The Java program provides an enterprise-oriented password security model.

Its primary design emphasis is domain modeling, encapsulation, immutable credential data, and explicit service responsibilities.

### 9.1 Domain records and enumerations

Java records represent immutable data structures such as:

- `AttackProfile`
- `PasswordCredential`
- `SecurityEvent`
- `StoragePolicy`

Enumerations represent attack categories, hashing algorithms, authentication states, and risk levels.

The password credential record defensively copies its byte arrays to prevent callers from modifying the stored salt or verifier.

### 9.2 PasswordHashingService

The hashing service uses Java's `SecretKeyFactory` with `PBKDF2WithHmacSHA256`.

A `PBEKeySpec` contains the password, salt, iteration count, and requested derived-key length.

The password specification is cleared in a `finally` block.

### 9.3 Account aggregate

The `Account` class manages its own authentication state.

Its responsibilities include:

- Failure recording.
- Lockout evaluation.
- Successful-login recovery.
- Account disabling.

Synchronization protects account-level state transitions within the running process.

### 9.4 SecurityAuditService

The audit service maintains timestamped security events.

Events distinguish account registration, authentication failures, successful logins, and lockout operations.

Production audit systems should use durable storage, restricted access, retention policies, and appropriate protection of sensitive metadata.

### 9.5 AuthenticationService

The authentication service combines:

- Account retrieval.
- Password-policy validation.
- Credential creation.
- Password verification.
- Account-state evaluation.
- Audit recording.

`ConcurrentHashMap` supports concurrent account lookup, while account-level synchronization protects changes to an individual account's authentication state.

## 10. PostgreSQL Relational Model

The PostgreSQL script models password security as a relational system rather than an isolated authentication function.

### 10.1 Entity relationships

The principal relationships are:

Organization
    |
    +-- Accounts
    |     |
    |     +-- Password Credentials
    |     |
    |     +-- Authentication Attempts
    |
    +-- Password Policies
    |
    +-- Security Assessments
    |
    +-- Security Incidents

Additional reference entities:

Hashing Algorithms
Attack Types

### 10.2 Main tables

| Table | Responsibility |
|---|---|
| `organizations` | Organizational ownership |
| `hashing_algorithms` | Supported password-storage algorithms |
| `accounts` | Account identity and authentication state |
| `password_credentials` | Salt, verifier, and work parameters |
| `password_policies` | Password-storage and authentication requirements |
| `attack_types` | Attack classification |
| `security_assessments` | Password-storage risk evaluations |
| `authentication_attempts` | Login history |
| `security_incidents` | Security incident tracking |

### 10.3 Database constraints

The database enforces:

- Primary-key uniqueness.
- Foreign-key relationships.
- Unique account identities within an organization.
- Valid account states.
- Nonnegative failed-attempt counters.
- Positive work factors.
- Minimum salt size.
- Valid security risk categories.
- Valid incident states.

The credential-validation trigger rejects general-purpose fast hashes as password-storage algorithms and checks configured work factors.

This is a metadata-level safeguard. It does not independently verify that a supplied password verifier was generated correctly.

### 10.4 Authentication transaction

The `record_authentication_result` function implements account-level authentication state management.

It uses `SELECT ... FOR UPDATE` to lock the relevant account row during an authentication-state update.

This prevents concurrent database transactions from independently updating the same account's failure counter without serialization.

The function handles:

- Successful login.
- Invalid credentials.
- Maximum failed attempts.
- Temporary account lockout.
- Recovery after lockout expiry.

The actual password comparison must occur in the trusted application layer before the function is called.

### 10.5 Views and reporting

The database provides three principal reporting views.

`credential_security_report` examines stored credential metadata and classifies storage risks.

`authentication_failure_report` identifies accounts with failed authentication attempts or locked status.

`attack_incident_report` combines incident records with attack classifications and organizational ownership.

Additional queries aggregate incidents, examine recent authentication activity, and evaluate rainbow-table exposure.

## 11. Four Important Security Distinctions

Password attacks involve different security mechanisms. Four particularly important distinctions are summarized below.

| Security mechanism | What it addresses | What it does not replace |
|---|---|---|
| Unique salts | Reusable rainbow-table attacks and identical stored hashes | Strong password selection and adaptive hashing |
| Adaptive password hashing | High-volume offline password guessing | MFA and authentication monitoring |
| Authentication rate limiting | Online repeated login attempts | Secure password storage |
| MFA and passkeys | Compromised or stolen passwords | Secure credential storage |

### 11.1 Salting does not encrypt passwords

Salting is part of password hashing.

Encryption is reversible when the appropriate decryption key is available. Password hashing is designed for verification without recovering the original password.

### 11.2 Hashing does not prevent phishing

Even a well-designed password-storage system cannot prevent a user from voluntarily submitting credentials to a deceptive website.

Phishing-resistant authentication addresses a different attack surface.

### 11.3 Rate limiting does not protect exposed hashes

An attacker possessing a copy of a password database can perform offline guessing without contacting the authentication server.

Adaptive password hashing, salts, and appropriate credential protection are essential for this threat.

### 11.4 MFA does not repair insecure password storage

MFA reduces the impact of compromised passwords, but an organization must still protect stored credentials.

The controls work together rather than replacing one another.

## 12. Security Limitations and Production Considerations

The implementations are educational security models, not complete production identity-management platforms.

Important deployment considerations include:

- Use Argon2id or an appropriately configured PBKDF2 or bcrypt implementation.
- Generate cryptographically secure random salts independently for every credential.
- Store algorithm identifiers and work parameters with credential records.
- Support credential rehashing when security parameters change.
- Check passwords against appropriately maintained compromised-password data.
- Apply account-aware and network-aware rate limits.
- Use MFA and phishing-resistant authentication where appropriate.
- Protect credential databases with encryption at rest and strict access controls.
- Prevent authentication logs from recording passwords, tokens, or password verifiers.
- Use generic login failure responses to reduce account enumeration.
- Monitor distributed authentication failures.
- Protect lockout mechanisms against denial-of-service abuse.
- Use durable, centralized security event storage.
- Establish backup, recovery, and credential rotation procedures.
- Benchmark password-hashing parameters under realistic concurrent workloads.

The in-memory authentication implementations are single-process examples. Distributed deployments require shared state and atomic updates.

The SQL model stores synthetic verifier values for demonstration. A real application must generate and verify password credentials through a trusted cryptographic service.

## 13. Performance and Complexity

| Operation | Approximate computational characteristic |
|---|---|
| SHA-256 | Linear in input size |
| Dictionary lookup | Number of candidates multiplied by hash cost |
| Rainbow-table construction | Number of chains multiplied by chain length |
| Rainbow-table lookup | Chain reconstruction plus candidate verification |
| PBKDF2 | Configured iteration count multiplied by underlying PRF cost |
| Argon2id | Configured memory and computation cost |
| Authentication reporting | Depends on indexes, filtering, and matching record volume |

Database indexes on account status, authentication timestamps, and account identifiers support the principal reporting and operational queries.

Password hashing should be performed outside ordinary database reporting queries. This separates cryptographic computation from relational storage and reduces the impact of expensive authentication operations on analytical workloads.

## 14. Execution Requirements

| Implementation | Runtime | Dependencies |
|---|---|---|
| Python | Python 3.10+ | Standard library |
| JavaScript | Node.js 18+ | Node.js standard library |
| C++17 | C++17 compiler | Standard library |
| Java | Java 17+ | Java standard library |
| PostgreSQL | PostgreSQL 15+ | PostgreSQL built-in functionality |

The scripts use synthetic accounts and test credentials. Their demonstration work factors are intentionally lower in some test configurations to reduce execution time. Production work factors must be benchmarked and configured independently.

## 15. Technical Learning Outcomes

The implementations distinguish six related but separate concerns:

1. Password candidate generation and hash verification.
2. Precomputed rainbow-table construction and lookup.
3. Salted and adaptive password storage.
4. Online authentication protection and account-state management.
5. Attack classification and security-policy evaluation.
6. Relational persistence, transactional integrity, and security reporting.

The central architectural principle is that password security requires multiple independent controls. Unique salts reduce the effectiveness of reusable precomputation, adaptive password hashing increases offline guessing costs, and authentication controls reduce the impact of online credential attacks. 
