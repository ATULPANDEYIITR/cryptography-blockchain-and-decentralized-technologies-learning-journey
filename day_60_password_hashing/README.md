# Password Hashing and Secure Authentication

## 1. Technical Scope

Password hashing is the process of transforming a submitted password into a derived value that can be stored and subsequently used for authentication without retaining the original password.

A password verifier should remain computationally expensive to reproduce, even when an attacker obtains the credential database.

The implementations in this project use PBKDF2-HMAC-SHA256 as a portable adaptive password-hashing mechanism. They demonstrate credential generation, verification, parameter validation, authentication workflows, account throttling, and migration from historical hashing configurations.

Password hashing is distinct from encryption.

| Property | Password hashing | Encryption |
|---|---|---|
| Operation | One-way key derivation | Reversible transformation |
| Original value | Not recovered during verification | Recovered with appropriate key |
| Main purpose | Password authentication | Confidentiality |
| Secret key requirement | Not normally required | Required |
| Salt | Unique random salt | Not the equivalent of a password salt |
| Verification | Recompute and compare | Decrypt and inspect |

Passwords must never be stored as plaintext or protected using ordinary fast hashes such as MD5, SHA-1, or an unkeyed SHA-256 operation.

## 2. Password Hashing Architecture

The implementation follows a consistent authentication architecture.

Repository or account identifier

→ Password policy validation

→ Unicode normalization

→ Cryptographically secure salt generation

→ Adaptive password derivation

→ Credential serialization

→ Credential storage

→ Authentication request

→ Stored credential parsing

→ Password derivation using stored parameters

→ Constant-time comparison

→ Authentication decision

→ Optional credential upgrade

The password is processed by the application. The database stores the resulting verifier and its parameters.

### Main components

| Component | Responsibility |
|---|---|
| Password policy | Validates password length, encoding and blocked values |
| Password normalizer | Produces a consistent Unicode representation |
| Password hasher | Derives the password verifier |
| Salt generator | Produces a unique random salt |
| Credential serializer | Stores algorithm and work-factor metadata |
| Credential verifier | Checks a submitted password |
| Account repository | Maintains account and credential information |
| Authentication service | Coordinates authentication and account state |
| Throttling mechanism | Limits repeated authentication failures |
| Credential migration service | Upgrades outdated hashing parameters |
| Audit mechanism | Records security-relevant authentication events |

## 3. PBKDF2-HMAC-SHA256

PBKDF2 is a password-based key derivation function defined for deriving cryptographic material from passwords.

Its inputs include:

- Password.
- Random salt.
- Iteration count.
- Pseudorandom function.
- Required output length.

The implemented pseudorandom function is HMAC-SHA256.

The main parameters are:

| Parameter | Implementation |
|---|---:|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Current iteration count | 600,000 |
| Minimum accepted historical count | 100,000 |
| Maximum accepted count | 2,000,000 |
| Salt length | 16 bytes |
| Derived-key length | 32 bytes |
| Password encoding | UTF-8 in Python, JavaScript and the C++ implementation |
| Unicode handling | NFC normalization where implemented |

The derived value depends on both the password and the random salt.

Two accounts using the same password should therefore have different stored verifiers.

Increasing the iteration count increases the computational work required for each password guess. The implementation also limits accepted stored parameters to prevent malicious credential records from requesting excessive computational work.

### Algorithm selection

PBKDF2 is a useful interoperable option, particularly in environments with FIPS-oriented requirements and widely available cryptographic libraries.

For general new deployments, Argon2id is normally the preferred option because its memory-hard design increases the cost of large-scale password guessing. Scrypt is another memory-hard alternative.

The PBKDF2 configuration used here is an implementation choice, not a claim that PBKDF2 offers the same memory-hard properties as Argon2id.

Any production parameter selection should be benchmarked under expected authentication concurrency and resource limits.

## 4. Salt, Pepper and Derived Credentials

### Salt

A salt is a randomly generated value associated with an individual password credential.

Its purposes include:

- Preventing identical passwords from automatically producing identical verifiers.
- Preventing effective reuse of precomputed rainbow tables.
- Making each password-guessing computation specific to a credential.

A salt is not a password and does not have to be confidential.

Each password-hashing operation in the source implementations creates a new salt using an appropriate cryptographic random-number generator.

| Language | Random salt mechanism |
|---|---|
| Python | `secrets.token_bytes()` |
| JavaScript | `crypto.randomBytes()` |
| C++17 | OpenSSL `RAND_bytes()` |
| Java 17 | `SecureRandom` |
| PostgreSQL | Supplied by the application |

### Pepper

A pepper is an additional secret maintained separately from the credential database.

Unlike a salt, it is intended to remain confidential.

A pepper can provide another security boundary when an attacker obtains database records without obtaining the separately managed application secret.

The implementations do not introduce a pepper because doing so requires a clearly defined secret-management, key-versioning and rotation architecture.

A production pepper must not be embedded in source code or stored beside the password verifiers.

### Credential serialization

The implementations use a versioned representation:

`pbkdf2-sha256$iterations$salt$derived_key`

The components identify:

1. Algorithm.
2. Iteration count.
3. Salt.
4. Derived verifier.

This allows a credential verifier to select parameters from the stored record rather than relying exclusively on the application's current configuration.

Stored parameters are validated before expensive cryptographic operations.

## 5. Password Creation and Verification

### Password creation

A registration workflow performs the following operations:

1. Receive the submitted password.
2. Normalize its Unicode representation where supported.
3. Validate its length and encoding.
4. Compare the complete password against a blocked-password list.
5. Generate a random salt.
6. Derive the verifier using the selected PBKDF2 parameters.
7. Serialize the credential.
8. Store the verifier and metadata.

The original password must not be written to databases, audit logs, exception messages, analytics events or application diagnostics.

### Password verification

Authentication does not decrypt the stored verifier.

Instead, the application:

1. Retrieves the account's stored credential.
2. Parses the algorithm and work factor.
3. Validates all stored parameters.
4. Derives a new verifier using the submitted password and stored salt.
5. Compares the derived value with the stored verifier.
6. Updates account authentication state.

A failed comparison must never result in successful authentication.

The Python implementation uses `hmac.compare_digest()`, JavaScript uses `crypto.timingSafeEqual()`, Java uses `MessageDigest.isEqual()`, and C++ uses OpenSSL's `CRYPTO_memcmp()`.

Constant-time comparison reduces timing differences associated with comparison operations. It does not make the entire authentication workflow automatically constant-time.

## 6. Password Policy and Validation

Password quality and password hashing are related but separate security controls.

The implementations validate several important conditions.

| Condition | Policy |
|---|---|
| Minimum length | 15 characters |
| Maximum length | 256 characters |
| Maximum encoded size | 1,024 bytes |
| Unicode | NFC normalization where supported |
| Null character | Rejected |
| Known blocked values | Rejected |
| Username equality | Rejected |
| Empty password | Rejected by length validation |

The minimum of 15 characters reflects the NIST recommendation for passwords used as single-factor authentication.

A verifier should also permit sufficiently long passwords, apply an appropriate blocklist, and use rate limiting.

The sample blocklist is intentionally small. It is not a substitute for a maintained database of commonly used, expected and compromised passwords.

The implementations do not impose arbitrary uppercase, lowercase, digit and special-character combinations. Such composition requirements are not a substitute for password length, blocklisting and effective throttling.

## 7. Credential Migration and Work-Factor Upgrades

Password-hashing configurations should evolve as computing capabilities and security requirements change.

An authentication system may therefore contain credentials with different historical iteration counts.

The important distinction is between verifying an old credential and creating a new credential.

An old credential must be verified using its original stored parameters.

It must not be interpreted using the current iteration count.

### Migration workflow

Existing credential

→ Read stored algorithm and parameters

→ Derive verifier using historical parameters

→ Compare submitted password

→ Reject incorrect password

→ Generate a new salt after successful verification

→ Derive using the current parameters

→ Replace the credential atomically

→ Preserve the previous credential in history when appropriate

The Python, JavaScript, C++17 and Java 17 programs implement this migration approach.

Their demonstrations create a historical 120,000-iteration credential and upgrade it following successful authentication with the original password.

The PostgreSQL script demonstrates the corresponding database update. Its trigger automatically archives the previous credential before recording the replacement.

Migration must never occur merely because a user submits a password. Successful verification is required first.

## 8. Account Authentication and Throttling

Password hashing primarily increases the cost of offline password guessing.

It does not independently prevent online guessing attacks.

An attacker may repeatedly submit password guesses through an authentication endpoint, making account-level throttling necessary.

The implementations demonstrate:

- Tracking consecutive unsuccessful attempts.
- Allowing successful authentication to reset the failure count.
- Locking an account after repeated failures.
- Rejecting authentication while the lock remains active.
- Avoiding account-existence timing differences through dummy verification where implemented.

The demonstration uses five unsuccessful attempts and a 60-second lock period.

These are example operational parameters, not universal security requirements.

A permanent or easily triggered account lock can itself create a denial-of-service vulnerability. Production systems should combine graduated delays, distributed rate limits, account-level and network-level signals, monitoring, and suitable account recovery mechanisms.

An in-memory counter is insufficient for a distributed authentication service because requests can reach different application instances. Distributed state should be maintained using an appropriate shared store or another atomic rate-limiting service.

## 9. Python Implementation

The Python program uses standard-library cryptographic and application features.

| Mechanism | Implementation |
|---|---|
| Password derivation | `hashlib.pbkdf2_hmac()` |
| Salt generation | `secrets.token_bytes()` |
| Secure comparison | `hmac.compare_digest()` |
| Credential encoding | `base64.urlsafe_b64encode()` |
| Unicode normalization | `unicodedata.normalize()` |
| Domain models | `dataclasses` |
| Authentication results | `Enum` |
| Account repository | Dictionary |
| Account synchronization | `threading.RLock` |
| Failure tracking | Account-level counters |

`PasswordHasher` separates password derivation, parsing, verification and rehash evaluation.

`PasswordPolicy` handles validation independently of cryptographic operations.

`Account` stores account-specific authentication state.

`PasswordAuthenticationService` coordinates registration, authentication, account disabling and credential upgrades.

The use of a per-account lock prevents competing authentication operations from updating the same account's failure state inconsistently.

The demonstration includes incorrect-password handling, random-salt uniqueness, malformed credential rejection, weak-password rejection, credential migration and account throttling.

## 10. JavaScript Implementation

The Node.js program provides an asynchronous event-driven authentication model.

| Mechanism | Implementation |
|---|---|
| Password derivation | `crypto.pbkdf2()` |
| Secure random salt | `crypto.randomBytes()` |
| Constant-time comparison | `crypto.timingSafeEqual()` |
| Asynchronous operations | Promises and `async/await` |
| Security events | `EventEmitter` |
| Account repository | `Map` |
| Concurrent operation management | `KeyedMutex` |
| Unicode normalization | `String.prototype.normalize()` |

Password derivation is asynchronous so expensive authentication operations do not block the JavaScript event loop through synchronous PBKDF2 calls.

`KeyedMutex` serializes operations for the same account while permitting unrelated accounts to be processed independently.

The event-driven design distinguishes account creation, successful authentication, failed authentication, credential upgrades, throttling and account disabling.

Event payloads contain account and operational metadata, not submitted passwords.

The sample account repository is in memory. A production application would implement persistent storage and distributed throttling.

## 11. C++17 Implementation

The C++ program approaches password hashing as a security-sensitive repository authentication engine.

It uses OpenSSL for operations that should not be implemented using ordinary C++ standard-library facilities.

| Mechanism | Implementation |
|---|---|
| PBKDF2 | `PKCS5_PBKDF2_HMAC()` |
| SHA-256 | `EVP_sha256()` |
| Salt generation | `RAND_bytes()` |
| Constant-time comparison | `CRYPTO_memcmp()` |
| Sensitive temporary cleanup | `OPENSSL_cleanse()` |
| Account storage | `std::unordered_map` |
| Account ownership | `std::shared_ptr` |
| Synchronization | `std::mutex` |
| Credential parsing | Structured string processing |
| Input validation | UTF-8 validation and code-point counting |

The implementation explicitly checks UTF-8 byte sequences, including invalid continuation bytes, overlong encodings and invalid Unicode scalar values.

C++17 does not provide standard Unicode NFC normalization. The calling application must perform NFC normalization before supplying Unicode passwords. This differs from the Python, JavaScript and Java implementations.

The account registry has its own mutex, while individual accounts have separate mutexes.

This design prevents registry operations from requiring one global lock throughout the expensive password-derivation process.

OpenSSL is necessary for the cryptographic operations. Replacing these operations with homemade random-number generation or a custom cryptographic hash implementation would introduce unnecessary security risk.

## 12. Java 17 Implementation

The Java implementation uses an enterprise-oriented domain model.

| Mechanism | Implementation |
|---|---|
| Key derivation | `SecretKeyFactory` |
| PBKDF2 algorithm | `PBKDF2WithHmacSHA256` |
| Password specification | `PBEKeySpec` |
| Random salt | `SecureRandom` |
| Constant-time comparison | `MessageDigest.isEqual()` |
| Immutable credential | Java record |
| Authentication events | Java records |
| Repository abstraction | `AccountRepository` interface |
| Account persistence example | `ConcurrentHashMap` |
| Explicit account state | `AccountState` enum |
| Application workflow | `AuthenticationService` |

`PasswordCredential` represents an encoded immutable credential.

`Account` owns authentication state, including failure counters and lock expiration.

`AccountRepository` separates account retrieval and storage from authentication policy.

`PasswordHasher` manages the cryptographic operations.

`AuthenticationService` coordinates registration, verification, account status, migration and audit events.

The implementation synchronizes changes to individual accounts, preventing competing login attempts from creating inconsistent failure counters or simultaneous credential upgrades.

The Java program also demonstrates cleanup of temporary mutable password arrays and `PBEKeySpec` password data.

Java `String` objects themselves are immutable and cannot be reliably erased from memory. Systems requiring stronger memory-lifetime controls should design their credential-handling interfaces around mutable character arrays and minimize their lifetime.

## 13. PostgreSQL Database Architecture

The SQL implementation models the persistent authentication system rather than independently implementing password derivation.

### Relational entities

| Table | Purpose |
|---|---|
| `accounts` | Account identity and account status |
| `password_credentials` | Current password-hashing parameters and verifier |
| `password_history` | Previously replaced credentials |
| `authentication_attempts` | Authentication audit records |
| `auth_throttle_state` | Current failure and lockout state |

The principal relationship is:

`accounts`

→ `password_credentials`

→ `password_history`

`accounts`

→ `authentication_attempts`

→ `auth_throttle_state`

An account has one current password credential and can have multiple historical credentials and authentication events.

### Integrity controls

The schema enforces:

- Primary keys.
- Foreign keys.
- Unique account identifiers.
- Supported password algorithm.
- Minimum and maximum historical iteration counts.
- Salt length constraints.
- Derived-verifier length constraints.
- Valid account states.
- Valid authentication failure categories.

The unique index on `lower(username)` prevents differently capitalized identifiers from creating duplicate accounts.

The credential-history trigger archives the previous credential before a change becomes current.

### Authentication throttling

The `update_authentication_throttle()` trigger processes authentication events transactionally.

It maintains account failure counters, a rolling failure window and temporary lock expiration.

Successful authentication resets the failure state.

Repeated failures activate an increasing lock period with a maximum duration of 15 minutes.

The `authentication_allowed()` function evaluates both account status and current throttling state.

This database evaluation is an eligibility check, not cryptographic password verification.

### Database reporting

The SQL script includes queries for:

- Current credential configurations.
- Salt and verifier length validation.
- Historical credentials requiring upgrades.
- Account authentication eligibility.
- Successful and failed authentication aggregation.
- Recent security events.
- Credential migration history.
- Currently locked accounts.
- Authentication configuration distributions.

The credential update transaction replaces all relevant cryptographic components together.

This avoids a partially updated password credential.

## 14. Error Handling and Failure Scenarios

| Failure condition | Expected behavior |
|---|---|
| Incorrect password | Authentication rejected |
| Unknown username | Generic authentication failure |
| Invalid credential encoding | Verification rejected |
| Unsupported algorithm | Credential rejected |
| Excessive iteration count | Credential rejected before derivation |
| Invalid salt length | Credential rejected |
| Incorrect verifier length | Credential rejected |
| Duplicate username | Account creation rejected |
| Blocklisted password | Registration rejected |
| Excessively long password | Request rejected |
| Invalid UTF-8 in C++ | Password rejected |
| Repeated authentication failures | Temporary throttling |
| Disabled account | Authentication rejected |
| Historical work factor | Upgrade after successful verification |
| Database update failure | Transaction rolled back |

A corrupted credential must not be interpreted as an automatically valid password or silently replaced with a new credential.

Operational diagnostics should distinguish infrastructure failures from incorrect credentials without disclosing password material.

## 15. Security Considerations

### Offline attacks

An attacker who obtains a database containing password verifiers can perform offline guessing without interacting with the authentication service.

Adaptive work factors increase the cost of each guess.

Unique salts prevent attackers from efficiently reusing a single precomputed password-verification table across accounts.

Memory-hard algorithms, particularly Argon2id, offer stronger resistance to certain GPU-oriented guessing strategies than PBKDF2.

### Online attacks

Authentication endpoints require throttling, abuse monitoring and appropriate network-level controls.

Password hashing does not replace these controls.

### Timing attacks

The implementations use constant-time comparison functions for derived-key comparisons.

Malformed credential data is rejected before comparison.

### Database compromise

A database compromise may expose:

- Account identifiers.
- Password-hashing algorithms.
- Iteration counts.
- Salts.
- Derived verifiers.
- Historical credentials.
- Authentication audit records.

The confidentiality of the original password is protected by the one-way derivation mechanism, not by keeping the algorithm name or salt secret.

### Credential history

Credential history can help enforce password-reuse policies.

A candidate password must be checked against historical verifiers by the authentication application because the database cannot determine password equality by comparing salted verifier bytes.

### Secret handling

Additional operational controls include:

- Encrypted network connections.
- Restricted database roles.
- Secure backup handling.
- Minimal retention of sensitive input.
- Redacted application logging.
- Separate pepper management.
- Secure password-reset workflows.
- MFA for sensitive accounts.
- Monitoring of repeated authentication failures.

## 16. Performance and Operational Trade-offs

PBKDF2 is deliberately more expensive than ordinary hashing.

Increasing iteration counts increases CPU consumption during registration and authentication.

The cost must be measured under realistic concurrency rather than selected only from a standalone benchmark.

| Operation | Main cost |
|---|---|
| Password normalization | Linear in password length |
| Random salt creation | Small |
| PBKDF2 derivation | Proportional to iteration count |
| Verifier comparison | Constant for fixed key length |
| Credential lookup | Depends on storage indexing |
| Account throttling | Small state update |
| Credential upgrade | One historical verification plus one new derivation |
| Audit insertion | Database write and indexing |

The dominant operation is PBKDF2 derivation.

Authentication workloads should therefore include concurrency limits and resource protection to prevent expensive password derivation from becoming a denial-of-service vector.

For large deployments, account records and authentication throttle state must be shared consistently across application instances.

## 17. Execution Requirements

| File | Runtime or dependency | Execution |
|---|---|---|
| Python | Python 3.10+ | `python password_hashing.py` |
| JavaScript | Node.js 18+ | `node password_hashing.js` |
| C++17 | C++17 compiler and OpenSSL development library | `g++ -std=c++17 password_hashing.cpp -O2 -Wall -Wextra -lcrypto -o password_hashing` |
| Java 17 | JDK 17+ | `javac PasswordHashing.java` followed by `java PasswordHashing` |
| PostgreSQL | PostgreSQL 14+ | Execute the SQL script using `psql` |

The four application implementations use standard language facilities or the necessary OpenSSL cryptographic library.

The database implementation does not require an additional cryptographic extension because hashing and verification are deliberately performed by the application.

## 18. Implementation Comparison

| Capability | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Password derivation | Yes | Yes | Yes | Yes | Application-owned |
| Random salt | Yes | Yes | Yes | Yes | Supplied |
| Constant-time comparison | Yes | Yes | Yes | Yes | Application-owned |
| Password normalization | NFC | NFC | Caller responsibility | NFC | Application-owned |
| Credential validation | Yes | Yes | Yes | Yes | Constraints |
| Account throttling | Yes | Yes | Yes | Yes | Trigger and function |
| Credential upgrades | Yes | Yes | Yes | Yes | Transactional storage |
| Credential history | In-memory example omitted | In-memory example omitted | In-memory example omitted | In-memory example omitted | Yes |
| Authentication auditing | Demonstration output | EventEmitter | Console | Audit events | Persistent records |
| Persistent storage | No | No | No | No | Yes |

The application examples use in-memory account repositories to concentrate on password derivation and authentication behavior. PostgreSQL supplies the persistent account, credential, history and audit model.

The database schema and application programs are complementary architectural examples. They are not presented as a fully integrated production identity-management deployment.

## 19. Design Limitations

The implementations establish the principal password-hashing mechanisms but do not constitute a complete identity platform.

Specific limitations include:

- PBKDF2 is not memory-hard.
- The sample blocked-password lists are not comprehensive.
- Demonstration throttling is not a distributed rate-limiting system.
- Password-reset and email-verification workflows are not implemented.
- Multi-factor authentication is outside the implementation scope.
- Pepper storage and rotation are not implemented.
- The sample PostgreSQL credentials are test data.
- Application repositories are not connected directly to PostgreSQL.
- The database schema does not perform cryptographic password verification.
- C++17 requires an upstream Unicode-normalization mechanism.
- Operational lockout parameters require deployment-specific security testing.

The central architectural principle remains unchanged: password verification should use a validated adaptive password hash, unique random salt and secure comparison, while account controls and database integrity provide additional layers of authentication security.
