# Password Salts: Credential Storage and Verification

## Scope

This project models password salts as part of a complete credential-management workflow.

The central distinction is:

- A password is secret user input.
- A salt is public, random, per-credential input to password derivation.
- A password hash or derived key is stored verification material.
- Authentication compares derived values rather than storing plaintext passwords.
- Password rotation generates a new salt rather than reusing the previous one.
- Account lockout is an authentication-control decision and is separate from salting.

The four source implementations use different cryptographic mechanisms while preserving the same security model.

## Domain Model

The implemented relationship is:

`User Account`
→ `Password Credential`
→ `Unique Salt`
→ `Password Derivation`
→ `Stored Derived Value`
→ `Authentication`
→ `Failure Tracking`
→ `Account Lockout`
→ `Password Rotation`

A salt does not need to be secret. Its security value comes from being unpredictable, sufficiently large, and independently generated for each password.

Two users can select the same password and still receive different stored derived values because their salts differ.

## Why Password Salts Exist

Without a per-password salt, identical passwords can produce identical stored hashes.

For example:

`password + same fixed input → same stored hash`

A unique salt changes the calculation:

`password + random salt A → derived value A`

`password + random salt B → derived value B`

This prevents a database observer from immediately identifying accounts that share the same password.

Salts also make precomputed password-hash lookup tables much less useful because an attacker must work against each individual salt.

A salt does not make a weak password strong. A password such as `password123` remains vulnerable to guessing even when it has a unique salt. The password derivation function must also be deliberately expensive or memory-intensive.

## Salt Requirements

The implementations apply these principles:

| Property | Implementation |
|---|---|
| Per-credential | Every new credential receives a new salt |
| Random | Python uses `secrets`; Java uses `SecureRandom`; JavaScript uses `crypto.randomBytes`; PostgreSQL uses `gen_salt` |
| Size | Python, Java, JavaScript and the policy models use at least 16 bytes |
| Replaced on password change | Yes |
| Stored with verification material | Yes |
| Treated as a secret | No |
| Plaintext password stored | No |
| Hash comparison | Constant-time or cryptographically appropriate comparison |

The salt is normally stored beside the password-derived value because the verifier needs the same salt when recalculating the candidate value.

## Python Implementation

The Python program models credentials with `dataclass` records and separates password policy from authentication state.

`PasswordPolicy` controls:

- minimum password length
- PBKDF2 iteration count
- salt size
- derived-key size

`PasswordManager` owns the credential store and implements:

- account registration
- password validation
- salt generation
- PBKDF2-HMAC-SHA256 derivation
- authentication
- failed-attempt tracking
- account locking
- account unlocking
- password rotation
- metadata export

The salt is generated with `secrets.token_bytes`, which is appropriate for security-sensitive random values.

The derived value is produced with `hashlib.pbkdf2_hmac`.

Verification uses `hmac.compare_digest` rather than ordinary string comparison. This avoids the common mistake of allowing an early-exit comparison to become a timing signal.

Password rotation deliberately creates a new salt. Reusing the previous salt would remove an important property of independent password records.

The Python example also verifies that two users with the same password receive different salts and different derived values.

## JavaScript Implementation

The JavaScript implementation uses Node.js cryptographic primitives and an event-driven credential store.

The primary password derivation mechanism is `crypto.scrypt`.

`scrypt` is memory-hard, which makes large-scale password guessing more expensive than a simple general-purpose hash.

The implementation uses:

- `crypto.randomBytes` for salts
- `crypto.scrypt` for password derivation
- `crypto.timingSafeEqual` for comparison
- `Map` for credential storage
- `EventEmitter` for authentication and credential lifecycle events
- Promises for asynchronous password derivation

The event model distinguishes successful authentication, failed authentication, credential creation, and password rotation.

This makes security events observable without mixing event handling with credential-storage logic.

The authentication workflow is:

`username`
→ `credential lookup`
→ `account-state check`
→ `salt decoding`
→ `scrypt`
→ `timing-safe comparison`
→ `success or failure`
→ `failure counter`
→ `optional lock`

The implementation deliberately does not put the plaintext password into the credential record.

## C++17 Implementation

The C++ program is a repository-style credential governance case study rather than a direct translation of the other programs.

It contains:

- a `PasswordPolicy`
- a `Credential` structure
- explicit account states
- a credential engine
- secure-salt generation
- password derivation
- constant-time comparison
- account locking
- password rotation
- invariant checks

The program uses a self-contained SHA-256 implementation so it can compile using only C++17 facilities.

The derivation routine repeatedly hashes salt- and password-dependent material. This is included to keep the case study self-contained and executable without a third-party dependency.

This construction should not replace a vetted password KDF in a production system. A production C++ implementation should use a maintained implementation of Argon2id, scrypt, or PBKDF2-HMAC-SHA256.

The C++ example therefore demonstrates an important engineering distinction: implementing cryptographic primitives yourself is different from deploying a reviewed password-hashing construction.

The account collection uses `std::map`, giving logarithmic account lookup.

The program also performs a constant-time comparison of the resulting 32-byte values.

## Java 17 Implementation

The Java implementation models the credential service as an enterprise-style domain.

The main domain types are:

- `AccountState`
- `PasswordPolicy`
- `PasswordRecord`
- `CredentialException`
- `PasswordDeriver`
- `Pbkdf2Deriver`
- `PasswordPolicyService`
- `AuthenticationService`

The `PasswordDeriver` interface isolates the derivation mechanism from account management.

The Java runtime provides `PBKDF2WithHmacSHA256` through `SecretKeyFactory`.

The service explicitly manages:

- account creation
- password policy validation
- random salt creation
- password derivation
- authentication
- failed-attempt state
- account locking
- unlocking
- password rotation
- password-version tracking

`PasswordRecord` returns defensive copies of byte arrays. This prevents callers from modifying internal salt or derived-key state through a returned array.

Password character arrays are cleared after credential operations where practical. Java strings cannot be explicitly cleared, so the service uses `char[]` for password input.

`MessageDigest.isEqual` is used for the derived-value comparison.

## PostgreSQL Implementation

The PostgreSQL implementation treats credential storage as a relational security subsystem.

The schema contains:

- `app_user`
- `password_credential`
- `password_rotation`
- `authentication_event`

The relationship is:

`app_user`
→ `password_credential`

and independently:

`app_user`
→ `password_rotation`

`app_user`
→ `authentication_event`

The credential table has a unique constraint on `user_id`, preventing multiple active credential records from being accidentally attached to one user.

It also validates:

- bcrypt algorithm selection
- cost-factor range
- password-version positivity
- failure-counter validity
- bcrypt hash structure
- bcrypt salt-setting structure

The PostgreSQL `pgcrypto` extension provides `gen_salt` and `crypt`.

The credential creation function generates a new bcrypt salt and derives the stored password value from that salt.

The database therefore does not need to implement the bcrypt algorithm itself.

## PostgreSQL Password Verification

The verification function accepts a username and password and evaluates the stored bcrypt credential.

The important operation is conceptually:

`crypt(candidate_password, stored_hash) = stored_hash`

The stored bcrypt value contains the parameters required to repeat the derivation, including the salt and cost factor.

The function also records authentication outcomes.

Possible outcomes include:

- `success`
- `invalid_password`
- `unknown_user`
- `locked`
- `disabled`

The database records events without storing the submitted password.

## Password Rotation

Password rotation is different from authentication.

Authentication asks:

`Does this supplied password match the existing credential?`

Rotation asks:

`Has the existing credential been successfully authenticated, and should a completely new credential replace it?`

The PostgreSQL rotation workflow:

`current password`
→ `authentication`
→ `new password validation`
→ `new random salt`
→ `new bcrypt value`
→ `version increment`
→ `rotation audit record`

The rotation operation is transactional.

A failed transaction does not leave half-updated credential state.

## Failure Handling

The implementations distinguish several failure conditions.

### Unknown Account

A lookup can fail because the username does not exist.

The application should avoid unnecessarily revealing account existence to remote callers.

### Invalid Password

The supplied password fails verification.

The credential remains valid, but the failure counter increases.

### Locked Account

Repeated failures can move the account into a locked state.

A correct password should not automatically bypass a policy that requires administrative or explicit unlocking.

### Invalid Credential Record

Malformed salt or derived-value data should be treated as a credential-store integrity problem rather than silently accepted.

### Password Policy Failure

Passwords below the configured minimum are rejected before credential creation or rotation.

## Salt Versus Hash

A salt and a password hash serve different purposes.

| Component | Purpose | Secret? |
|---|---|---|
| Password | User authentication secret | Yes |
| Salt | Unique derivation input | No |
| Password-derived value | Verification material | Sensitive |
| KDF parameters | Control derivation cost | No |
| Username | Account identifier | Usually no |
| Authentication event | Operational audit data | Sensitive |

The salt should not be treated as an encryption key.

It also does not need to be encrypted merely because it is a salt. Access to the complete credential record remains sensitive because an attacker who obtains it can perform offline password guessing.

## Salt Generation and Reuse

A new salt is required when a password credential is created.

A new salt is also generated when the password changes.

This means:

`old password + old salt`

and

`new password + new salt`

are independent credential calculations.

The implementation does not reuse a user's previous salt during password rotation.

The programs also check the important invariant that two users with the same password do not receive identical derived values when their salts differ.

## Workflows

### Credential Creation

`User`
→ `password policy validation`
→ `secure random salt`
→ `password KDF`
→ `stored credential`

### Authentication

`Username`
→ `credential lookup`
→ `account state`
→ `stored salt`
→ `password KDF`
→ `constant-time comparison`
→ `authentication result`

### Failed Authentication

`Failed comparison`
→ `failure counter`
→ `lock threshold`
→ `account lock`
→ `security event`

### Password Change

`Current password`
→ `successful authentication`
→ `new password validation`
→ `new random salt`
→ `new derived value`
→ `credential replacement`
→ `version increment`

## Security Design Decisions

### Unique Salts

Each credential receives independent random salt material.

A global salt shared by every account would not provide the same protection against identifying identical passwords.

### Password-Specific KDF

A password should not normally be processed with a fast general-purpose hash such as a single SHA-256 operation.

The Python implementation uses PBKDF2-HMAC-SHA256.

The Java implementation also uses PBKDF2-HMAC-SHA256.

The JavaScript implementation uses scrypt.

The PostgreSQL implementation uses bcrypt through `pgcrypto`.

The C++ program contains an explicitly documented standalone construction for educational compilation, with a production warning to use a vetted password KDF.

### Constant-Time Comparison

The comparison stage should not reveal whether a password matched a prefix of the stored derived value.

Python uses `hmac.compare_digest`.

JavaScript uses `crypto.timingSafeEqual`.

Java uses `MessageDigest.isEqual`.

C++ implements a fixed-length comparison that accumulates byte differences instead of returning at the first mismatch.

### No Plaintext Storage

None of the credential stores contain a plaintext password field.

Password input is used only to calculate the verification value.

### Failure Tracking

Salting does not prevent online authentication attacks.

The examples therefore include failed-attempt tracking and account-locking behavior.

Rate limiting, distributed abuse detection, multi-factor authentication, credential-stuffing detection, and recovery controls would normally exist at the broader authentication-service layer.

## Database Integrity

The PostgreSQL model moves important rules into the database.

Constraints protect:

- unique usernames
- unique email addresses
- one credential per user
- valid credential algorithms
- acceptable cost factors
- valid password versions
- nonnegative failure counts

Triggers maintain timestamps and lock-state consistency.

Functions centralize credential creation, verification, and rotation.

This reduces the chance that a separate application path accidentally creates an invalid credential record.

## Performance

Password derivation is intentionally more expensive than ordinary hashing.

For normal application data, faster hashing is usually desirable.

For passwords, excessive speed helps attackers test large numbers of guesses.

The cost therefore represents a security-performance trade-off.

| Implementation | Derivation | Primary Cost |
|---|---|---|
| Python | PBKDF2-HMAC-SHA256 | Configured iteration count |
| JavaScript | scrypt | Memory and CPU parameters |
| C++17 | Repeated SHA-256 case-study construction | Configured rounds |
| Java 17 | PBKDF2-HMAC-SHA256 | Configured iteration count |
| PostgreSQL | bcrypt | bcrypt cost factor |

The appropriate work factor depends on deployment hardware and should be benchmarked under realistic authentication load.

A password KDF should not be so expensive that ordinary authentication becomes a denial-of-service vector.

## Storage and Operational Considerations

A credential database deserves stronger protection than ordinary application data.

Important controls include:

- strict database permissions
- encryption at rest
- encrypted database connections
- restricted administrative access
- credential-table access auditing
- secure backups
- secret-management controls for database credentials
- authentication-event monitoring
- controlled password-reset workflows

A salt being non-secret does not make the credential table safe to expose.

The password-derived value remains useful to an attacker attempting offline password guesses.

## Edge Cases Covered

The implementations explicitly address:

- empty usernames
- malformed usernames
- duplicate accounts
- passwords below the minimum length
- whitespace-only passwords
- unknown accounts
- incorrect passwords
- repeated authentication failures
- account lockout
- account unlocking
- password rotation
- salt replacement during rotation
- equal passwords across different accounts
- malformed stored credential material
- database transaction rollback
- credential-version changes

## Conceptual Distinction

The key security relationship is:

`Password`
is the secret supplied by the user.

`Salt`
is unique random input associated with that credential.

`KDF`
turns the password and salt into a deliberately expensive derived value.

`Stored Credential`
contains the salt, KDF parameters, and derived verification material.

`Authentication`
repeats the derivation and compares the resulting value.

`Account Policy`
controls failures, lockout, rotation, and operational state.

These mechanisms solve different problems and should not be collapsed into one concept.

## Cross-Language Comparison

| Area | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Random salt | `secrets` | `crypto.randomBytes` | `std::random_device` seeded engine | `SecureRandom` | `gen_salt` |
| KDF | PBKDF2-HMAC-SHA256 | scrypt | Standalone case-study construction | PBKDF2-HMAC-SHA256 | bcrypt |
| Constant-time comparison | `hmac.compare_digest` | `timingSafeEqual` | fixed-length byte comparison | `MessageDigest.isEqual` | `crypt` equality |
| State model | dataclass | object + Map | structs/classes/enums | records/classes/enums | relational tables |
| Failure state | locked flag | locked flag | enum state | enum state | user status + lock timestamp |
| Rotation | new salt | new salt | new salt | new salt | new bcrypt salt |
| Audit | logging | events | program output | explicit service behavior | authentication events |

## Practical Limitations

A salt protects against reuse of precomputed password-hash results and makes equal-password records distinguishable.

It does not:

- make weak passwords strong
- stop online guessing by itself
- replace rate limiting
- replace multi-factor authentication
- encrypt the password database
- protect an application from credential theft before hashing
- make password recovery safe automatically

The strength of the complete authentication design depends on the password KDF, password policy, account controls, database protection, monitoring, and recovery process.

## Verification Invariants

The implementations enforce or demonstrate these core invariants:

1. Every new credential receives fresh salt material.
2. Plaintext passwords are not persisted.
3. Equal passwords can produce different stored values.
4. Password verification uses the stored salt and KDF parameters.
5. Password rotation creates a new salt.
6. Failed authentication can transition an account into a locked state.
7. Password versions increase after successful rotation.
8. Credential records are not treated as ordinary application data.
9. Password-derived values are compared using timing-resistant mechanisms where the runtime exposes them.
10. A password salt is distinct from an encryption key and should not be managed as though it were one.

## File Mapping

| File | Implemented focus |
|---|---|
| Python | PBKDF2 credential manager, validation, lockout, rotation, metadata handling |
| JavaScript | scrypt credential store, asynchronous derivation, event-driven security events |
| C++17 | standalone credential governance engine, explicit hashing implementation, state management |
| Java 17 | enterprise domain model, PBKDF2 service abstraction, immutable policy records, state transitions |
| PostgreSQL | relational credential model, bcrypt, constraints, triggers, transactional rotation, authentication reporting |

The five implementations use the same security principle while deliberately exposing different engineering decisions, runtime facilities, data structures, state models, and persistence boundaries.
