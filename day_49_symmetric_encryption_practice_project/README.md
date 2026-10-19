# Symmetric Encryption Practice Project

## Scope

This project studies symmetric encryption as a complete security workflow rather than as a single encryption function.

The central model is:

`plaintext + secret key + encryption parameters -> ciphertext + authentication data`

For modern applications, confidentiality alone is not sufficient. An encrypted record also needs protection against unauthorized modification. The implementations therefore emphasize authenticated encryption, especially AES-256-GCM, together with nonce management, key derivation, key rotation, authenticated metadata, validation, and failure handling.

The five implementations deliberately use different technical perspectives:

| Implementation | Primary perspective |
|---|---|
| Python | Cryptographic mechanics and a complete educational AES-256-GCM implementation |
| JavaScript | Node.js authenticated-encryption APIs and asynchronous file processing |
| C++ | Repository-style document protection and cryptographic lifecycle management |
| Java | Enterprise domain modeling, state transitions, JCA/JCE, and policy enforcement |
| PostgreSQL | Relational modeling of encrypted records, key versions, constraints, and rotation |

The project distinguishes encryption from the surrounding key-management and integrity responsibilities. A cipher transforms data under a secret key. A usable system must also decide how keys are generated, identified, stored, rotated, retired, and associated with encrypted data.

## Symmetric Encryption Fundamentals

Symmetric encryption uses the same secret key, or equivalent secret key material, for the encryption and decryption operation.

A conceptual transformation can be represented as:

`C = E(K, P)`

where `P` is plaintext, `K` is the secret key, and `C` is ciphertext.

Decryption reverses the transformation:

`P = D(K, C)`

The important property is that both communicating or processing parties must have access to the required secret key material. This differs from public-key cryptography, where separate public and private keys provide asymmetric operations.

The Python implementation begins with XOR because XOR exposes the basic reversibility property directly. Applying the same XOR key twice restores the original data. The implementation also explicitly states why this is not secure encryption when a key is predictable, short, or reused.

Real symmetric encryption requires a cryptographically designed construction with well-defined security properties. The primary construction used by the remaining implementations is AES with a 256-bit key and GCM mode.

## AES-256

AES is a block cipher operating on 128-bit blocks. AES-256 uses a 256-bit key and performs a sequence of substitution, permutation, mixing, and key-addition operations.

The Python implementation exposes these internal mechanisms directly:

- The S-box performs nonlinear byte substitution.
- `ShiftRows` rearranges state bytes between rows.
- `MixColumns` provides diffusion using arithmetic in a finite field.
- `AddRoundKey` combines the state with round-key material.
- AES-256 key expansion derives the round keys from the original 256-bit key.
- Block decryption applies the inverse transformations in reverse order.

This implementation includes an AES-256 block test vector, making the internal implementation testable rather than merely illustrative.

The JavaScript, Java, and C++ programs intentionally do not reproduce these AES internals. They demonstrate the more appropriate application-level design of using maintained cryptographic implementations.

## Authenticated Encryption

Encryption without authentication creates a dangerous gap.

A system might successfully decrypt modified ciphertext and return corrupted or attacker-controlled plaintext. The receiver needs evidence that the ciphertext and protected metadata were not modified.

AES-GCM combines encryption and authentication.

Its output consists conceptually of:

`nonce + ciphertext + authentication tag`

The tag is derived from the ciphertext and associated authenticated data under the secret key. During decryption, the tag is checked before the application accepts the plaintext.

The Python implementation implements the AES-GCM construction directly, including GHASH. The JavaScript implementation uses Node.js's `aes-256-gcm` interface. The Java implementation uses `AES/GCM/NoPadding` through JCA/JCE.

The C++ case study uses a compact authenticated-encryption model to make application architecture visible. It explicitly identifies that model as educational and does not present it as a replacement for a reviewed cryptographic library.

## Associated Authenticated Data

Some information must remain readable but must still be protected against modification.

Examples include:

- document identifiers
- record classifications
- protocol versions
- message types
- tenant identifiers
- encryption metadata

GCM supports this through authenticated associated data, commonly called AAD.

AAD is not encrypted, but it participates in authentication.

For example:

`AAD = document=FIN-001;classification=CONFIDENTIAL`

The receiver must supply the same AAD during decryption. Changing the document identifier or classification causes authentication to fail even though the metadata itself was never encrypted.

The Python implementation constructs JSON metadata as AAD. Node.js calls `setAAD()`. Java uses `updateAAD()`. The C++ case study explicitly authenticates document metadata along with ciphertext.

## Nonce Management

A nonce is an input to many symmetric encryption modes. With GCM, nonce management is particularly important.

The implementations use a 12-byte nonce, which is the standard nonce size for typical GCM usage.

A nonce is not normally a secret. Its critical property is uniqueness under the same key.

Reusing a GCM nonce with the same key can seriously undermine confidentiality and authentication. Therefore, the encryption service should generate nonces using a cryptographically secure random source or use a carefully designed deterministic construction that guarantees uniqueness.

The Python implementation generates a new nonce for each encryption operation.

The JavaScript implementation obtains the nonce from `crypto.randomBytes()`.

The Java implementation uses `SecureRandom`.

The C++ case study adds a `NonceRegistry` that records the combination of key version and nonce. A repeated pair is rejected.

The SQL model enforces uniqueness with:

`UNIQUE (key_id, nonce)`

This does not replace correct cryptographic nonce generation, but it provides an additional database-level guard against accidental reuse in the stored data.

## Key Generation

Encryption security depends on the secrecy and unpredictability of the key.

The project uses 32-byte keys for AES-256.

Python uses `secrets.token_bytes()`.

Node.js uses `crypto.randomBytes()`.

Java uses `SecureRandom`.

The C++ case study provides a random byte generator only as part of its educational model and does not claim that the compact case-study primitive is suitable for production cryptography.

Keys should not be generated from predictable application values such as:

- usernames
- timestamps
- database identifiers
- filenames
- ordinary hashes of public information

The key itself should be treated as high-value secret material.

## Password-Based Key Derivation

Passwords generally have much less entropy than randomly generated encryption keys.

Using a password directly as an AES key is therefore inappropriate.

The Python, JavaScript, and Java implementations demonstrate PBKDF2-HMAC-SHA256. PBKDF2 applies repeated password-based computation so that password guessing becomes more expensive.

A password-derived key requires a random salt.

The relationship is:

`derived_key = PBKDF2(password, salt, work_factor)`

The salt does not have to be secret. Its purpose is to make identical passwords produce different derived keys and to prevent precomputed tables from being reused across different salts.

The Python implementation requires a minimum salt size and validates the iteration count.

Node.js calls `pbkdf2Sync()`.

Java uses `PBKDF2WithHmacSHA256` through `SecretKeyFactory`.

The practice implementations use a high iteration count for demonstration. Production systems should choose parameters appropriate for the current hardware and security requirements and should support parameter migration over time.

## Encrypted Envelope Design

Raw ciphertext is not enough to reconstruct a modern authenticated-encryption operation.

An encrypted message needs information such as:

| Field | Purpose |
|---|---|
| Version | Allows the envelope format to evolve |
| Algorithm | Identifies the cryptographic construction |
| Key ID | Identifies which key version is required |
| Nonce | Required for the encryption operation |
| Ciphertext | Confidential protected content |
| Authentication tag | Verifies integrity and authenticity |
| AAD | Reconstructs authenticated metadata |

The Python `EncryptedEnvelope` models these fields explicitly.

The Node.js implementation serializes the same conceptual information into JSON.

Java represents it as an immutable record.

The C++ case study uses a typed `EncryptedRecord`.

The SQL schema separates document identity, key version, nonce, ciphertext, tag, and associated data into relational columns.

This separation matters because cryptographic parameters are part of the data needed to interpret the ciphertext.

## Python Implementation

The Python program has the deepest cryptographic implementation.

It begins with XOR to demonstrate reversible symmetric transformation. It then implements AES-256 at block level, including key expansion, substitution, row shifting, column mixing, inverse operations, and round-key processing.

The program builds on those primitives to implement GCM.

The GCM implementation includes:

- a 96-bit nonce
- counter construction
- AES-generated keystream blocks
- ciphertext generation
- GHASH processing
- authentication of AAD
- authentication of ciphertext
- authentication of length information
- final tag generation
- constant-time tag comparison

The program then wraps these operations in `SecureMessageService`.

That service adds a key store and key identifiers so that encrypted data can refer to a specific key version rather than depending on an implicit global key.

The file workflow demonstrates the practical relationship between plaintext files and encrypted envelopes. A file is read, encrypted, serialized, and then restored only after successful authentication.

Key rotation is represented by decrypting data under the existing key and encrypting it under a replacement key.

The Python program also deliberately tests tampering. A modified ciphertext causes authentication failure, and modified AAD also causes authentication failure.

### Python Security Boundary

The handwritten AES-GCM implementation is educational. Production applications should use established cryptographic libraries that have undergone extensive review, testing, platform integration, and maintenance.

The implementation is valuable for understanding how AES and GCM fit together, but understanding cryptographic mechanics does not make handwritten cryptography suitable for production deployment.

## JavaScript Implementation

The JavaScript program focuses on Node.js cryptographic APIs rather than reimplementing AES.

`crypto.createCipheriv("aes-256-gcm", ...)` establishes the AES-GCM operation.

`cipher.setAAD()` authenticates metadata.

`cipher.getAuthTag()` obtains the authentication tag.

During decryption, `decipher.setAuthTag()` supplies the expected tag, and `decipher.final()` performs the authentication check.

This makes an important JavaScript-specific behavior visible: successful processing is not complete until `final()` succeeds.

The implementation wraps the Node.js primitive in `EncryptedMessageService`, which maps application metadata and key identifiers into an encrypted envelope.

The file workflow uses Node's promise-based filesystem API. This gives the example a practical application shape without adding an external npm dependency.

The JavaScript implementation also uses `structuredClone()` when constructing a tampering test. This avoids modifying the original encrypted envelope while deliberately changing a copy.

## C++ Case Study

The C++ implementation models a protected enterprise document repository.

The architecture contains distinct responsibilities:

`KeyManager -> EncryptionService -> DocumentRepository`

`KeyManager` owns key versions and their active or inactive status.

`NonceRegistry` tracks key-and-nonce combinations. This models a defense against accidental nonce reuse.

`EncryptionService` performs the protected transformation and verifies authentication before returning plaintext.

`DocumentRepository` stores encrypted records under application document identifiers.

The `EncryptedRecord` structure contains:

- key identifier
- nonce
- ciphertext
- authentication tag
- associated data

This makes the encryption envelope a first-class system object.

The case study also models key rotation. A document is decrypted using the old active key, encrypted under the replacement key, and then stored using the new key identifier. The old key can subsequently be retired.

Tampering tests demonstrate two distinct integrity boundaries. Changing ciphertext causes authentication failure, while changing associated data also causes failure.

The C++ source explicitly warns that its compact transformation is a system-design model rather than a production cryptographic primitive. The correct production boundary is a reviewed cryptographic library.

## Java Enterprise Model

The Java program models encrypted documents as domain objects rather than treating encryption as a standalone utility function.

`KeyVersion` represents versioned cryptographic material.

`EncryptedEnvelope` represents the authenticated encryption result.

`ProtectedDocument` represents document lifecycle state.

`KeyRing` manages active and retired key versions.

`NonceRegistry` prevents repeated key-and-nonce combinations within the service.

`EncryptionService` owns AES-GCM operations.

`DocumentService` manages application-level document behavior.

The `DocumentState` enum provides explicit lifecycle states:

`ACTIVE`

`ROTATED`

`REVOKED`

This makes invalid application behavior easier to detect than a collection of unrelated Boolean fields.

The Java implementation also demonstrates immutable records. A state transition produces a new `ProtectedDocument` rather than silently changing unrelated fields.

Revoked documents cannot be read through the document service even when their cryptographic key remains technically available.

This illustrates an important distinction between cryptographic capability and business authorization. Possessing a key does not necessarily mean an application operation should be permitted.

### Java Authentication Failure

The JCA/JCE GCM implementation produces an authentication failure when the supplied tag does not validate.

The service catches `AEADBadTagException` and converts it into a security-level failure.

The caller therefore does not receive corrupted plaintext as if it were valid data.

## PostgreSQL Data Model

The SQL implementation represents the cryptographic metadata and lifecycle without storing raw encryption keys.

The central tables are:

`encryption_keys`

Stores key identifiers, algorithm names, key versions, lifecycle status, and timestamps. It intentionally does not contain actual secret key material.

`protected_documents`

Stores document identity, classification, lifecycle state, and the currently assigned key version.

`encrypted_document_versions`

Stores the encrypted representations of documents. It contains nonce, ciphertext, authentication tag, associated data, and the key identifier used to produce the encrypted version.

`encryption_key_events`

Records key lifecycle events such as creation, rotation, retirement, and revocation.

`encryption_audit_log`

Records encryption-related application events and whether an operation succeeded.

## Database Integrity Rules

Several cryptographic metadata constraints belong naturally at the database layer.

The nonce constraint requires exactly 12 bytes:

`CHECK (octet_length(nonce) = 12)`

The authentication tag constraint requires 16 bytes:

`CHECK (octet_length(authentication_tag) = 16)`

The key version must be positive.

The algorithm is constrained to the expected authenticated-encryption algorithm.

Most importantly, the database requires:

`UNIQUE (key_id, nonce)`

This prevents the same nonce from being stored twice under the same key version.

A trigger also prevents a new encrypted document version from being associated with a retired or revoked key.

These constraints do not implement AES. They protect the integrity of the data model surrounding the encryption operation.

## Transactional Key Rotation

Key rotation is not merely generating a new key.

Existing ciphertext remains encrypted under the old key, so the application must establish a controlled migration path.

The workflow demonstrated by the SQL transaction is:

`old encrypted version -> decrypt under old key -> encrypt under new key -> insert new version -> update current key reference -> retire old key`

The database transaction makes the metadata transition atomic.

The new encrypted representation is inserted before the document's current key reference is updated. The old key is retired only within the same transactional workflow.

The actual decryption and encryption operations remain outside SQL.

This separation is intentional. PostgreSQL maintains relational integrity while a cryptographic service handles secret key operations.

## Key Rotation and Key Retirement

Key rotation limits the amount of data protected by a single key over its operational lifetime and provides a mechanism for responding to cryptographic policy changes.

The implementations identify keys by version rather than assuming a single permanent encryption key.

A rotated document can therefore indicate:

`key-v1`

or

`key-v2`

without changing the identity of the document itself.

Retirement should not automatically mean destruction. A system may need an old key temporarily to decrypt historical data during controlled migration or archival recovery.

Key destruction is a stronger lifecycle operation and requires a separate retention decision.

## Confidentiality Versus Integrity

A common mistake is to treat encryption as equivalent to complete message security.

Encryption addresses confidentiality.

Authentication addresses integrity and authenticity.

Authenticated encryption combines these requirements into one construction.

For example, suppose a ciphertext contains a financial amount. If encryption alone is used without integrity protection, a system may receive modified ciphertext and attempt to process the resulting plaintext.

With authenticated encryption, the receiver checks the authentication tag before accepting the data.

This is why the examples treat authentication failure as a hard failure.

## Common Failure Modes

### Reusing a GCM nonce

The same nonce must not be reused with the same GCM key.

The C++ nonce registry and PostgreSQL uniqueness constraint illustrate two different layers of protection.

The application should still generate nonces correctly because a database constraint is not a substitute for sound cryptographic design.

### Using a password directly as an AES key

A human password generally does not have the entropy expected of a cryptographic key.

PBKDF2 with a unique salt and a deliberately expensive work factor is demonstrated instead.

### Storing encryption keys beside ciphertext

A database containing ciphertext and the corresponding raw encryption key defeats much of the intended confidentiality boundary.

The SQL schema therefore stores key identifiers and lifecycle metadata, not raw key material.

A real deployment would place key material under a dedicated key-management boundary.

### Releasing plaintext after authentication failure

An authentication failure indicates that the ciphertext or authenticated metadata cannot be trusted.

The Python implementation checks the tag before decrypting the ciphertext.

Java's GCM implementation validates the tag during `doFinal()`.

The JavaScript implementation depends on `decipher.final()` succeeding.

### Treating metadata as automatically trustworthy

Document identifiers, classifications, and other metadata can affect authorization and business behavior.

AAD provides a way to authenticate such metadata without encrypting it.

## Security Considerations

Encryption keys should be generated using a cryptographically secure random source.

Encryption keys should not be logged.

Passwords should not be used directly as symmetric keys.

Salt values for password derivation should be unique and sufficiently large.

GCM nonces must not be reused with the same key.

Authentication tags must be verified before accepting plaintext.

Key identifiers should be included in the encrypted envelope so that the correct key version can be selected.

Old keys should have explicit lifecycle states rather than being silently deleted.

Encrypted files should carry the cryptographic parameters required for decryption, but secret key material should remain outside the file.

Sensitive exceptions and logs should not expose keys, plaintext, or authentication secrets.

Production cryptographic implementations should use maintained, reviewed libraries rather than custom cryptographic primitives.

## Performance Considerations

AES is designed for efficient processing of large data volumes and benefits from hardware acceleration on many modern processors.

Authenticated encryption adds authentication work to encryption, but the combined construction is generally preferable to independently designing encryption and integrity mechanisms.

PBKDF2 is intentionally expensive. Its computational cost should be tuned differently from ordinary application hashing because password guessing resistance is the goal.

File encryption should avoid loading extremely large files entirely into memory. The practice implementations use complete buffers for clarity, while a production implementation should normally process large files using a secure streaming construction or an appropriate chunked authenticated-encryption design.

Database indexes should support the actual operational access pattern. The PostgreSQL model indexes document history and current key references because those relationships are important during inspection and rotation.

## Testing Strategy

The project contains several categories of tests and demonstrations.

AES block processing is checked against a known AES-256 test vector in Python.

Authenticated encryption is tested through encryption and decryption round trips.

Ciphertext tampering is tested by changing a ciphertext byte and expecting authentication failure.

AAD tampering is tested by changing authenticated metadata without changing the ciphertext.

Wrong-key behavior is tested in the JavaScript implementation.

Password derivation is checked for deterministic output with the same password and salt and different output with a different salt.

Nonce reuse is explicitly rejected in the C++ model and structurally constrained in PostgreSQL.

Key rotation is tested by decrypting under the old key and re-encrypting under a replacement key.

Document revocation is tested independently from cryptographic decryption in the Java enterprise model.

## Practical Design Distinctions

The project keeps several responsibilities separate because they solve different problems.

| Concern | Responsibility |
|---|---|
| AES | Symmetric block-cipher mechanism |
| GCM | Authenticated-encryption mode |
| Nonce | Unique per-key encryption parameter |
| Authentication tag | Detects modification and invalid authentication |
| AAD | Authenticated but unencrypted metadata |
| PBKDF2 | Password-to-key derivation |
| Key ID | Selects cryptographic key version |
| Key rotation | Moves encrypted data to replacement key material |
| Key retirement | Stops normal use of an older key |
| Document authorization | Controls whether an application may access data |
| Database constraints | Prevent invalid cryptographic metadata states |

This separation prevents the encryption primitive from becoming responsible for application policy.

## Production Boundaries

The practice project intentionally demonstrates cryptographic mechanics, application architecture, and relational enforcement separately.

For production use, the strongest design boundary is normally:

`Application -> Cryptographic Library -> Key Management System`

The application should request encryption or decryption using an identified key.

The cryptographic library should implement established algorithms and modes.

The key-management system should protect, rotate, audit, and control access to encryption keys.

The database should store ciphertext and the metadata necessary to interpret it, while enforcing relationships and invariants that belong to the data layer.

The result is a system in which symmetric encryption is one controlled component of a broader confidentiality and integrity architecture.
