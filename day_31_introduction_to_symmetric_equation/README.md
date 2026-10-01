# Introduction to Symmetric Encryption

## Scope

Symmetric encryption uses a secret key shared by the parties or components that need to encrypt and decrypt data. The same underlying secret is used for both directions, although a production construction may derive separate internal encryption and authentication keys from one master key.

This project focuses on the mechanics and engineering decisions behind symmetric encryption rather than treating encryption as a single opaque operation. The implementations examine plaintext, ciphertext, keys, nonces, authentication, associated data, password-derived keys, encrypted envelopes, file protection, key rotation, and failure handling.

The three implementations deliberately use different perspectives:

- The Python program develops an educational authenticated-encryption model, password protection, file encryption, serialization, key rotation, and self-tests.
- The JavaScript program uses Node.js `crypto` and demonstrates AES-256-GCM, password-based key derivation, JSON envelopes, asynchronous event-driven processing, file workflows, and key rotation.
- The C++ program models a repository secret vault in which encrypted application secrets are associated with key identifiers, authenticated metadata, nonces, ciphertext, and authentication tags.

The custom cryptographic constructions in the Python and C++ programs are instructional models. They should not replace established cryptographic libraries.

## Plaintext, Ciphertext, and Keys

Plaintext is the original information that an application wants to protect. Examples in this project include deployment configuration, database credentials, API tokens, and backup metadata.

Ciphertext is the transformed representation produced by encryption. A correctly designed encryption scheme should make the ciphertext computationally infeasible to use for recovering the plaintext without the required secret key.

The key is the secret input controlling the transformation. Security should depend on the secrecy and strength of the key rather than on hiding the algorithm.

A typical symmetric-encryption data flow is:

`plaintext + secret key + nonce -> ciphertext`

For authenticated encryption, the operation also produces an authentication tag:

`plaintext + key + nonce + associated data -> ciphertext + authentication tag`

Decryption verifies the authentication information before accepting the recovered plaintext:

`ciphertext + key + nonce + associated data + tag -> authenticated plaintext`

## Why XOR Is Useful for Learning

XOR has an important property:

`A XOR B XOR B = A`

That means the same XOR operation can reverse an XOR transformation when the same byte sequence is used again.

The Python and JavaScript programs use small XOR examples to expose this property. They also deliberately demonstrate why repeating-key XOR is unsuitable for modern encryption.

If the same keystream is reused for two plaintexts:

`C1 = P1 XOR K`

`C2 = P2 XOR K`

then:

`C1 XOR C2 = P1 XOR P2`

The key itself does not appear directly in the result, but the relationship between the two plaintexts is exposed. This is one reason modern stream constructions require careful nonce and keystream management.

XOR is therefore an important building operation, but XOR by itself is not a secure encryption algorithm.

## Modern Symmetric Encryption

A practical symmetric-encryption system normally uses a standardized construction that has undergone extensive cryptographic analysis.

Common authenticated-encryption choices include:

- AES-GCM, which combines the AES block cipher with Galois/Counter Mode authentication.
- ChaCha20-Poly1305, which combines the ChaCha20 stream cipher with Poly1305 authentication.

Authenticated encryption is generally preferred over encryption that provides confidentiality without integrity. Confidentiality prevents unauthorized parties from learning plaintext, while authentication and integrity prevent an attacker from silently modifying encrypted data.

The JavaScript implementation uses Node.js AES-256-GCM directly through the built-in `crypto` module. This provides a concrete production-oriented example without requiring an external npm dependency.

## Nonces

A nonce is a value associated with an encryption operation. In many symmetric constructions, the nonce does not need to be secret, but its uniqueness requirements are security-critical.

The JavaScript AES-GCM implementation generates a fresh 12-byte nonce for each encryption operation.

The Python educational construction generates a 16-byte nonce.

The C++ case study models a 12-byte nonce.

These values are not interchangeable across algorithms. A production application must follow the exact nonce requirements of the selected cryptographic construction.

Nonce reuse can be catastrophic for constructions that derive a reusable keystream from the key and nonce. The examples deliberately demonstrate this relationship so that nonce handling is treated as a security requirement rather than merely another message field.

A nonce should not be treated as a password, encryption key, or authentication secret.

## Authentication and Integrity

Encryption without authentication can allow an attacker to modify ciphertext without necessarily knowing the original plaintext.

Authenticated encryption addresses this by producing an authentication tag over relevant encrypted-message components.

The Python implementation uses an HMAC-based educational construction. Its authentication input includes the protocol version, associated data, nonce, and ciphertext.

The JavaScript implementation relies on AES-GCM's authentication tag. During decryption, `decipher.final()` performs the authentication check. If the ciphertext, tag, nonce, or authenticated associated data has been modified, decryption fails.

The C++ repository-vault model explicitly stores an authentication tag and verifies it before converting ciphertext back into a secret value.

This ordering matters. Application code should not treat unauthenticated decrypted content as trustworthy input.

## Associated Data

Authenticated encryption can protect information that should remain visible while still preventing unauthorized modification.

This information is commonly called associated data or authenticated associated data.

For example, the C++ repository vault associates a secret with:

`repository=payments-api|secret=DATABASE_PASSWORD|environment=production`

The metadata itself is not encrypted. It can remain available to the database or routing layer. It is nevertheless included in authentication.

If an attacker changes `environment=production` to another environment, authentication fails.

The Python implementation demonstrates the same distinction with deployment metadata. The JavaScript implementation authenticates values such as tenant and record-version information without placing those values inside the ciphertext.

Associated data is therefore different from plaintext:

- Plaintext is encrypted and authenticated.
- Associated data is visible but authenticated.
- Neither should be modified without causing authentication failure.

## Python Implementation

The Python program develops the topic from fundamental byte operations into a complete educational encrypted-message workflow.

`xor_bytes()` establishes the reversible XOR operation. `repeating_xor_encrypt()` then demonstrates a weak repeating-key construction and explicitly shows the relationship leakage caused by keystream reuse.

The `AuthenticatedStreamCipher` class provides the next conceptual layer. It derives separate internal keys for encryption and authentication from a 32-byte master key. Its keystream is generated from the encryption key, nonce, and block counter. Ciphertext is produced by XORing plaintext with that keystream.

Authentication uses HMAC-SHA256. The tag covers the nonce, ciphertext, and associated data. `hmac.compare_digest()` is used for tag comparison rather than an ordinary early-exit equality test.

The `EncryptedMessage` dataclass models an encrypted envelope containing:

- protocol version
- nonce
- ciphertext
- authentication tag

It also serializes these binary values into Base64 so the complete envelope can be represented as JSON.

### Password-Based Encryption

A password is not normally an appropriate direct encryption key because human-selected passwords often have much lower entropy than randomly generated cryptographic keys.

The Python program uses PBKDF2-HMAC-SHA256 to derive a 256-bit key from a password and a random salt.

The envelope stores the salt and iteration count but never stores the password.

The salt does not need to be secret. Its purpose includes preventing identical passwords from automatically producing identical derived keys across different encrypted records.

The program validates the iteration count so an accidentally or maliciously malformed envelope cannot request an unreasonable KDF configuration.

### File Encryption

`encrypt_file()` protects a complete file using the password-based encrypted-message format. It adds a format marker before the serialized envelope.

The program writes encrypted output through a temporary file before replacing the destination. This reduces the chance that an interrupted write leaves the destination containing a partial encrypted file.

Decryption verifies the encrypted message before writing recovered plaintext to the destination.

The example intentionally reads the complete file into memory. This keeps the educational implementation simple, but large production files should use a properly designed streaming authenticated-encryption mechanism.

### Key Rotation

The Python `KeyRing` separates key identity from the encrypted message.

A record can identify which key protected it while the key itself remains in a separate key-management structure.

The example allows an old key to become inactive for new operations while existing encrypted data can still be decrypted during a controlled migration.

This distinction is important because key rotation and immediate key destruction are different operations.

## JavaScript Implementation

The JavaScript program provides a complementary Node.js perspective.

Rather than implementing a custom modern cipher, it uses the built-in `crypto` module and AES-256-GCM. This is a better representation of how application code should normally interact with symmetric encryption: the application selects an established primitive and correctly manages its inputs, outputs, and lifecycle.

`encryptAesGcm()` generates a 32-byte key-compatible AES key and a fresh 12-byte nonce. It returns the algorithm identifier, nonce, ciphertext, and authentication tag as an object.

`decryptAesGcm()` reconstructs the AES-GCM operation and supplies the authentication tag before finalization. A modified message causes the decryption operation to throw.

This directly demonstrates the distinction between encryption and authentication while using a standard library implementation.

### JavaScript Envelope Handling

Binary values do not naturally belong in ordinary JSON strings. The JavaScript implementation converts the nonce, ciphertext, and authentication tag to Base64 for serialization.

`serializeEnvelope()` produces a JSON representation, while `deserializeEnvelope()` validates the algorithm and expected nonce and tag lengths before returning binary buffers.

This pattern is useful when encrypted records need to travel through JSON APIs or be stored in systems where binary fields are inconvenient.

The envelope itself is not a secret. Its ciphertext and metadata can be stored in a database, while the encryption key remains outside the record.

### Event-Driven Processing

The `EncryptionJob` class extends Node's `EventEmitter`.

The job emits state changes such as `encrypting` and `completed`, while the encrypted result is emitted through an `encrypted` event.

This models an application architecture in which cryptographic operations form part of a larger event-driven workflow. The cryptographic primitive remains synchronous for the small demonstration record, while the surrounding workflow uses asynchronous scheduling.

The important JavaScript-specific concept is that encryption can be integrated into event-driven application state without changing the security requirements of the cryptographic operation.

### File Workflow

The JavaScript file example uses asynchronous filesystem APIs from Node.js.

Encryption reads the source file, creates an authenticated envelope, and writes the result to a temporary path before renaming it into place.

Decryption verifies the password-derived key and AES-GCM authentication before writing the recovered file.

A wrong password therefore fails before a destination plaintext file is produced.

## C++ Repository Secret Vault Case Study

The C++ program models a deployment repository that stores application secrets without storing their plaintext values in repository records.

The central classes are:

- `RepositoryKeyRing`, which controls key identifiers and key lifecycle state.
- `RepositorySecretVault`, which creates and retrieves encrypted secret records.
- `EncryptedSecret`, which represents the persisted encrypted record.
- `EducationalCipher`, which models encryption and authentication operations.

A stored secret contains a key identifier, nonce, ciphertext, associated data, and authentication tag.

The plaintext secret itself is absent from the encrypted record.

### Repository Data Flow

A secret such as an application database password enters the vault.

The vault validates the repository, secret name, secret value, and environment.

It then obtains the currently active key and constructs associated data describing the repository context.

A fresh nonce is generated.

The plaintext is transformed into ciphertext.

An authentication tag is calculated over the ciphertext and associated metadata.

The resulting `EncryptedSecret` can be stored by another persistence layer.

During retrieval, the key identifier selects the key required for decryption. The authentication tag is checked before the ciphertext is transformed back into plaintext.

This creates a clear separation between application metadata, encrypted content, and key-management responsibilities.

### Key Rotation

The case study uses identifiers such as `repository-key-2026-10`.

When a new key becomes active, new writes use the new key identifier.

Existing records retain their original key identifier. This allows a migration process to decrypt old records with the appropriate historical key while new records use the current key.

`stopNewWrites()` models a key becoming ineligible for future encryption while remaining available for controlled decryption.

This is different from revoking decryption entirely. A production key-management system would define explicit lifecycle states and policies for generation, activation, rotation, archival, revocation, and destruction.

### Metadata Authentication

Repository and environment information is constructed as associated data.

The metadata remains visible to the vault but is covered by authentication.

This prevents an attacker from taking a valid production secret record and changing its repository or environment metadata without detection.

This property is particularly useful for systems where routing information or record classification needs to remain visible to infrastructure components but must not be silently altered.

## Encryption Versus Encoding

Encryption and encoding solve different problems.

Base64, hexadecimal, JSON, and similar formats represent data in another form. They do not provide secrecy.

For example, Base64 can turn binary ciphertext into text suitable for JSON transport, but anyone can decode the Base64 representation.

Encryption requires a secret key and a cryptographic algorithm.

The project uses Base64 only as an envelope-serialization mechanism. The secrecy comes from the encryption operation, not from Base64.

## Encryption Versus Hashing

Encryption is reversible with the correct key.

Hashing is designed as a one-way transformation and is normally used for integrity, indexing, fingerprints, and password-verification systems rather than recovering original data.

The project uses HMAC-SHA256 in the Python educational construction for message authentication. It does not use an ordinary hash as if it were an encryption algorithm.

A password-storage system also requires a different design from reversible application-data encryption. Password verification normally uses a password-hashing or password-KDF design rather than storing a decryptable password representation.

## Key Management

The security of symmetric encryption depends heavily on key management.

A strong algorithm cannot protect data if the key is embedded in public source code or stored beside ciphertext without appropriate access controls.

A production key lifecycle generally needs controls for:

- secure key generation
- access authorization
- key identification
- active-key selection
- rotation
- historical decryption
- revocation
- auditing
- backup and recovery
- controlled destruction

The key-ring models in the Python and C++ programs demonstrate the separation between key identifiers and encrypted records.

A key ID is metadata. The actual key is sensitive material.

## Password-Derived Keys

Passwords and randomly generated encryption keys have different security properties.

A 256-bit randomly generated key has substantially different entropy characteristics from a human-created password.

When a password must serve as the source of encryption material, a password KDF such as PBKDF2 can make large-scale guessing more expensive. A unique salt ensures that the same password does not automatically result in the same derived key for every record.

The KDF parameters must be treated as part of the encrypted format because the application needs them for future decryption.

The password itself must not be included in the encrypted envelope.

Production systems should select KDF parameters appropriate to the threat model and operational environment rather than blindly copying demonstration values.

## Edge Cases

The implementations explicitly handle several important boundary conditions.

Empty plaintext is valid. The JavaScript and Python programs authenticate and recover an empty message rather than introducing a special unauthenticated path.

Malformed serialized envelopes are rejected instead of being interpreted as partially valid encryption records.

Wrong passwords cause authentication failure.

Wrong keys cause authentication failure.

Modified ciphertext causes authentication failure.

Modified associated data causes authentication failure.

Invalid key sizes are rejected at API boundaries.

Invalid nonce sizes are rejected where the selected construction specifies an expected nonce size.

Source and destination file paths are checked so an encryption operation does not intentionally overwrite its own plaintext input.

Temporary file writes reduce the risk of leaving incomplete output after an I/O failure.

These checks are part of secure system design because cryptographic correctness alone does not address malformed inputs, file-system failures, or application-level misuse.

## Common Cryptographic Mistakes

### Treating Base64 as Encryption

Base64 is an encoding format. It provides no confidentiality.

### Using a Password Directly as an AES Key

A human password should not simply be padded or truncated into an AES key. A password KDF and unique salt should be used when password-based encryption is actually required.

### Reusing Nonces Incorrectly

Some algorithms permit random nonces while others require deterministic uniqueness. The exact rule depends on the algorithm. A nonce-management policy must therefore be designed together with the selected encryption construction.

### Encrypting Without Authentication

Ciphertext can be confidential while still being vulnerable to modification. Authenticated encryption is generally preferable for application data.

### Hard-Coding Keys

Keys embedded in source files can be exposed through repositories, backups, package artifacts, logs, or build systems.

### Logging Plaintext Secrets

Encryption does not help if the application prints decrypted credentials into logs.

### Destroying Historical Keys Without a Migration Plan

Rotating an encryption key can make historical data unrecoverable if old ciphertext depends on the previous key and no controlled migration or archival strategy exists.

### Writing Decrypted Data Before Verification

Authenticated decryption should verify the message before application code trusts or persists the recovered plaintext.

## Performance Considerations

Symmetric encryption is generally much cheaper computationally than public-key encryption and is therefore appropriate for protecting substantial data volumes after a suitable key has been established.

The relevant performance dimensions include:

- plaintext size
- cipher implementation
- CPU acceleration
- authentication cost
- memory allocation
- file I/O
- password-KDF work factor
- serialization overhead

The JavaScript implementation uses Node's optimized cryptographic implementation rather than manually implementing AES.

The Python implementation is intentionally educational and therefore should not be interpreted as a benchmark for optimized cryptographic software.

The C++ case study processes data in blocks in its educational keystream model. A production file-encryption API should support bounded-memory streaming where large files make full in-memory buffering inappropriate.

Password-based encryption has a different performance profile because the KDF is deliberately computationally expensive. That cost is intended to make password guessing more expensive, while encryption of the resulting data can remain efficient.

## Security Boundary of the Demonstrations

The Python and C++ custom cryptographic constructions exist to make internal mechanisms visible.

They are not substitutes for established cryptographic primitives.

The Python construction uses HMAC-SHA256 to create an educational keystream and authentication mechanism.

The C++ construction uses a deliberately simplified educational digest rather than a real cryptographic hash.

Neither construction should be used to protect production secrets.

The JavaScript AES-256-GCM example provides the production-oriented implementation pattern in this project because Node.js supplies an established cryptographic implementation through its built-in `crypto` module.

For production software, the correct engineering approach is to use a reviewed implementation of a standardized authenticated-encryption construction and follow its exact key, nonce, authentication, and error-handling requirements.

## Debugging Considerations

Encryption bugs can be difficult to diagnose because the expected output is intentionally not human-readable.

Useful debugging boundaries include:

- plaintext length
- ciphertext length
- key identifier rather than the secret key
- nonce length and uniqueness tracking
- authentication-tag length
- envelope version
- algorithm identifier
- KDF parameters
- associated-data consistency
- file format markers

Sensitive values should not be printed merely for debugging.

For a failed decryption, an application should generally distinguish operationally between malformed data, unavailable keys, and authentication failure while avoiding error messages that unnecessarily expose secrets or security-sensitive internal details.

The self-tests in the Python and JavaScript implementations verify round trips, serialization, wrong-key behavior, tampering, and associated-data changes.

## Practical Architecture

A production application can separate symmetric encryption into several boundaries:

`Application Data`

`        |`

`        v`

`Encryption Service`

`        |`

`        +----> Key Identifier`

`        |`

`        +----> Encryption Key`

`        |`

`        +----> Nonce`

`        |`

`        +----> Authenticated Associated Data`

`        v`

`Ciphertext + Authentication Tag`

`        |`

`        v`

`Encrypted Storage`

The encryption service should not require the persistence layer to know the plaintext secret.

The persistence layer can store the encrypted envelope and associated metadata.

A key-management boundary should control the actual encryption keys.

This separation reduces the chance that database access alone provides direct access to protected plaintext.

## Practical Applications

Symmetric encryption is suitable for protecting data such as:

- database backups
- configuration secrets
- application credentials
- API tokens
- private documents
- session-related confidential data
- encrypted files
- database fields containing sensitive application information
- internal service payloads

The appropriate construction depends on the application protocol, key lifecycle, nonce requirements, storage model, and threat model.

For example, encrypting a configuration file and encrypting a high-volume network stream may require different APIs even though both rely on symmetric cryptography.

## Implementation Relationship

The three implementations deliberately emphasize different layers.

The Python program concentrates on understanding the internal data transformations and message-envelope mechanics. It shows how a master key can be separated into encryption and authentication purposes, how a nonce influences a keystream, how HMAC authenticates the result, and how password-derived keys can feed the encryption layer.

The JavaScript program concentrates on using a standard authenticated-encryption primitive in a real application runtime. AES-256-GCM, Node.js `crypto`, Base64 envelope serialization, asynchronous filesystem operations, and event-driven processing make the implementation closer to an application integration pattern.

The C++ program concentrates on system architecture. The repository secret vault shows how encrypted records, key identifiers, associated metadata, authentication tags, and key rotation can interact in a realistic secret-storage service.

These perspectives are related but not interchangeable: understanding encryption mechanics, correctly invoking a standard cryptographic API, and designing a key-managed encrypted storage system are separate engineering responsibilities.

## Production Requirements

A production symmetric-encryption system should establish explicit rules for:

- the selected authenticated-encryption algorithm
- key size and generation source
- nonce generation and uniqueness
- associated-data format
- envelope versioning
- key identifiers
- authentication-failure behavior
- key rotation
- historical-key retention
- secret access controls
- audit requirements
- backup and recovery
- secure deletion where applicable
- large-file streaming
- memory handling
- logging restrictions
- dependency and cryptographic-library maintenance

The encryption algorithm is only one part of the security architecture. Key lifecycle, nonce management, authentication, storage, access control, and operational handling determine whether the cryptographic primitive is integrated safely.
