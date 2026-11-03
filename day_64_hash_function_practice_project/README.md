# Hash Functions Practice Project

## Project Scope

This project demonstrates cryptographic hash functions through practical operations involving software release artifacts, file integrity, message authentication, password derivation, and verification records.

The five implementations use different engineering approaches:

| Implementation | Main purpose |
|---|---|
| Python | Hashing utilities, password derivation, and directory integrity manifests |
| JavaScript | Asynchronous file processing, bounded concurrency, and manifest verification |
| C++17 | Educational SHA-256 and HMAC-SHA256 implementations |
| Java 17 | Enterprise artifact registry, hash policies, and verification audit trail |
| PostgreSQL | Persistent artifact records, digest history, and integrity reporting |

The project distinguishes unkeyed hashing, keyed authentication, and password derivation. These operations use related cryptographic mechanisms but address different security requirements.

## 1. Hash Function Fundamentals

A cryptographic hash function accepts an input of arbitrary practical length and produces a fixed-length digest.

The fundamental relationship is:

Input data → Hash function → Fixed-length digest

For a given algorithm, the same input produces the same digest. Changing even one bit of the input should produce a substantially different digest.

A cryptographic hash function is designed to provide the following properties:

| Property | Meaning |
|---|---|
| Determinism | Identical input produces identical output |
| Preimage resistance | Given a digest, finding an input that produces it should be computationally infeasible |
| Second-preimage resistance | Given an input, finding a different input with the same digest should be computationally infeasible |
| Collision resistance | Finding any two different inputs with the same digest should be computationally infeasible |
| Avalanche effect | A small input change should cause a substantial change in the output |

A digest is not encrypted content. Hashing does not provide a method for recovering the original message.

A digest also does not establish the identity of the person or system that created it. That distinction is important when verifying software downloads, release packages, configuration files, and deployment artifacts.

## 2. SHA-2 and SHA-3

The project uses two SHA families.

### SHA-2

SHA-2 is a family of cryptographic hash functions standardized around different digest lengths.

The implementations use:

| Algorithm | Digest size | Hexadecimal length |
|---|---:|---:|
| SHA-256 | 256 bits | 64 characters |
| SHA-512 | 512 bits | 128 characters |

SHA-256 and SHA-512 are used for artifact fingerprints, file integrity checks, and digest comparisons.

The C++ implementation implements SHA-256 directly to demonstrate the internal processing mechanism.

### SHA-3

SHA-3 is based on the Keccak sponge construction. Its internal construction differs from the Merkle-Damgård structure used by SHA-2.

The implementations use:

| Algorithm | Digest size | Hexadecimal length |
|---|---:|---:|
| SHA3-256 | 256 bits | 64 characters |
| SHA3-512 | 512 bits | 128 characters |

Python, JavaScript, and Java provide SHA-3 operations through their standard cryptographic libraries.

The PostgreSQL implementation uses SHA-256 and SHA-512 through `pgcrypto` to maintain compatibility across a broad range of PostgreSQL installations.

SHA-256 and SHA3-256 produce digests of equal length, but they are different algorithms. A digest must always be interpreted together with its algorithm identifier.

## 3. Digest Calculation and File Integrity

File hashing calculates a fingerprint of the file's binary content.

A typical release verification workflow is:

1. Calculate the digest of an approved release artifact.
2. Store the algorithm identifier and expected digest.
3. Transfer or retrieve the artifact.
4. Calculate the digest of the received artifact.
5. Compare the expected and observed digests.
6. Accept the artifact only when the comparison succeeds.

The project uses this workflow for software releases such as a payment service package and a production configuration file.

### Streaming

Reading an entire large file into memory is unnecessary for digest calculation.

A streaming implementation processes the content in chunks:

File → Chunk 1 → Chunk 2 → Chunk 3 → Digest

The hash context maintains its internal state between chunks. The final digest is equivalent to hashing the complete input as one sequence of bytes.

The Python implementation uses `hash_stream()` and `hash_file()`. The JavaScript implementation uses an asynchronous file stream. Java uses `MessageDigest` with buffered input. The C++ program processes binary file data through an 8 KB buffer.

The approximate time complexity is \(O(n)\), where \(n\) is the number of input bytes. Streaming keeps working memory approximately proportional to the configured buffer size rather than the total file size.

### File Integrity Manifests

A file manifest records the relative path, size, and digest of each file in a directory.

A manifest entry has three essential values:

| Field | Purpose |
|---|---|
| `path` | Identifies the relative file location |
| `size` | Records the number of bytes |
| `digest` | Records the calculated cryptographic digest |

The Python and JavaScript implementations create JSON manifests and later verify their entries.

The verification operation checks both the file size and the digest. The size check provides an explicit consistency test, while the digest comparison verifies the file content.

Manifest paths are treated as untrusted input during verification. Absolute paths, parent-directory traversal, duplicate entries, and symbolic-link escapes are rejected.

The manifest itself requires a separate trust mechanism. An attacker who can replace both an artifact and its unprotected manifest can calculate a new digest and replace the expected value. A manifest should therefore be authenticated or obtained through a separately trusted channel.

## 4. HMAC and Message Authentication

An ordinary hash function does not use a secret key.

Anyone who possesses the input can independently calculate its digest. Consequently, an attacker who can modify a message and its accompanying unkeyed digest can replace both values.

HMAC addresses this issue by using a secret key together with a hash function.

The project uses HMAC-SHA256.

The process is:

Message + Secret key → HMAC-SHA256 → Authentication tag

The recipient calculates a new tag using the same secret key and compares it with the supplied tag.

A successful verification indicates that the message is consistent with the secret key used to generate the tag, subject to the security of the key and HMAC construction.

HMAC is useful for authenticating release manifests, API messages, and internal service communications when the communicating parties share a securely managed secret.

The implementations use constant-time comparison facilities where available:

- Python uses `hmac.compare_digest()`.
- JavaScript uses `crypto.timingSafeEqual()`.
- Java uses `MessageDigest.isEqual()`.
- C++ provides a dedicated comparison routine for the educational implementation.

The C++ routine illustrates the comparison mechanism but should not replace a vetted cryptographic library's comparison functions in production.

An HMAC secret must not be committed to source control or embedded in deployed application code. Secret provisioning, rotation, access control, and revocation must be managed separately from the digest record.

## 5. Password Derivation Is Different from File Hashing

A general-purpose digest is designed to calculate results efficiently. This makes a fast hash such as SHA-256 unsuitable as the sole password-storage mechanism.

An attacker who obtains a database of ordinary password digests can test large numbers of password guesses quickly.

Password storage requires a dedicated password-based key derivation function. This project demonstrates PBKDF2-HMAC-SHA256.

PBKDF2 uses:

- A password
- A random salt
- An iteration count
- A pseudorandom function
- A derived-key length

The stored representation includes the algorithm identifier, iteration count, salt, and derived key.

The salt ensures that identical passwords do not normally produce identical stored representations. The iteration count increases the cost of each password guess.

Python, JavaScript, and Java implement password derivation using their respective standard cryptographic APIs. The generated records can be verified without storing the original password.

The implementations enforce minimum and maximum iteration counts when processing stored records. This prevents malformed records from requesting unexpectedly low work or excessive processing.

PBKDF2 is included as an executable standard-library example. A production password-storage system should select and configure a dedicated password hashing scheme according to its security requirements and deployment environment. Passwords must not be stored as ordinary SHA-256 or SHA-512 digests.

## 6. Python Implementation

The Python script is organized around `HashEngine`, which provides the main hashing operations.

### Digest operations

`HashAlgorithm` defines the permitted algorithms. `hash_bytes()` processes in-memory data, while `hash_stream()` supports incremental processing from a binary stream.

`hash_file()` validates a path and delegates the calculation to the streaming operation.

`DigestResult` is an immutable data structure containing the algorithm, hexadecimal digest, and number of bytes processed.

### HMAC and password derivation

`hmac_sha256()` produces an authentication tag. `verify_hmac_sha256()` validates a supplied tag using a constant-time comparison.

`hash_password()` creates a PBKDF2 password record using a random salt. `verify_password()` validates the encoded representation and derives a candidate key using the stored parameters.

The password verifier rejects malformed records, unsupported formats, invalid hexadecimal values, and iteration counts outside its configured bounds.

### Manifest operations

`build_manifest()` traverses a directory and calculates file digests.

`write_manifest()` writes the manifest using a temporary file and atomic replacement. This reduces the chance of leaving a partially written manifest if the process fails during output.

`verify_manifest()` checks each registered path and returns individual verification results.

### Commands

| Command | Operation |
|---|---|
| `python hash_functions.py` | Runs demonstrations and known-answer tests |
| `python hash_functions.py hash sha256 artifact.bin` | Calculates a file digest |
| `python hash_functions.py manifest ./releases ./manifest.json sha256` | Creates a directory manifest |
| `python hash_functions.py verify-manifest ./releases ./manifest.json` | Verifies a directory manifest |

The script uses Python standard-library modules and requires no external package installation.

## 7. JavaScript Implementation

The JavaScript implementation uses the Node.js `crypto` and `fs` modules.

### Asynchronous file processing

`hashFile()` reads data through a file stream. The asynchronous iteration processes each chunk without loading the entire file into memory.

Manifest creation uses `mapWithConcurrency()` to limit the number of simultaneous file-hashing operations. This prevents the program from opening an excessive number of files in a large directory.

The default concurrency is four workers.

### Integrity verification

`createManifest()` records each file's relative path, size, and digest. `writeManifest()` writes the completed JSON representation using a temporary file and rename operation.

`verifyManifest()` validates the manifest structure, checks paths, verifies file types, and recalculates each digest.

A failed file check does not automatically stop verification of the remaining entries. The caller receives individual results and a final count of successful and failed checks.

### Authentication and password operations

`hmacSha256()` uses Node.js `createHmac()`. Verification uses `timingSafeEqual()` after checking the supplied tag's format and length.

`hashPassword()` and `verifyPassword()` use asynchronous PBKDF2 operations. The asynchronous API avoids blocking the JavaScript event loop while the derivation function performs its computational work.

### Commands

| Command | Operation |
|---|---|
| `node hash_functions.js` | Runs demonstrations and tests |
| `node hash_functions.js hash sha256 ./artifact.bin` | Calculates a file digest |
| `node hash_functions.js manifest ./releases ./manifest.json sha256` | Creates a manifest |
| `node hash_functions.js verify ./releases ./manifest.json` | Verifies a manifest |

The implementation uses Node.js built-in modules without external npm dependencies.

## 8. C++17 Implementation

The C++ program provides an educational implementation of SHA-256 rather than relying on an external cryptographic library.

### SHA-256 processing

SHA-256 processes input in 512-bit blocks. Each block contains 64 bytes.

The implementation maintains eight 32-bit state words and uses a 64-entry round-constant table.

For each block, it:

1. Reads sixteen initial 32-bit words in big-endian order.
2. Expands the message schedule to 64 words.
3. Executes 64 compression rounds.
4. Updates the eight working state values.
5. Retains the resulting state for the next block.

The finalization operation appends padding and the original message length before processing the final block.

The implementation tracks the total input byte count and rejects inputs beyond the length supported by the SHA-256 length field.

### HMAC-SHA256

The HMAC implementation uses the SHA-256 block size of 64 bytes.

It normalizes the key, derives the inner and outer padded keys, calculates the inner digest, and calculates the final outer digest.

This demonstrates that HMAC is a construction built around a hash function rather than a separate unkeyed digest operation.

### Known-answer tests

The program validates:

- SHA-256 of an empty input.
- SHA-256 of `abc`.
- An HMAC-SHA256 test vector.
- Release artifact comparison.
- Changed-message authentication.

### Commands

| Command | Operation |
|---|---|
| `./hash_lab_cpp` | Runs the demonstration and tests |
| `./hash_lab_cpp --file artifact.bin` | Calculates a file SHA-256 digest |
| `./hash_lab_cpp --hmac key "release manifest"` | Calculates an HMAC-SHA256 tag |

Compile with a C++17 compiler:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o hash_lab_cpp hash_lab.cpp`

The C++ implementation is intended for learning the compression function, padding, streaming state, and HMAC construction. It is not a production cryptographic library. Production software should rely on maintained implementations that receive independent security review and appropriate platform optimizations.

## 9. Java 17 Implementation

The Java implementation models an enterprise release-integrity service.

### Java Cryptography Architecture

`HashService` uses Java Cryptography Architecture providers for:

- SHA-256
- SHA-512
- SHA3-256
- SHA3-512
- HMAC-SHA256
- PBKDF2-HMAC-SHA256

The service creates a fresh `MessageDigest` or `Mac` instance for each operation. These objects maintain mutable processing state and should not be shared concurrently without appropriate synchronization.

File hashing uses buffered input and incremental digest updates.

### Hash policy

`HashPolicy` defines which algorithms may be used.

The enterprise default policy permits all four digest algorithms. A registration request using an algorithm outside the policy is rejected.

This separates algorithm selection from the individual artifact operation.

### Artifact registry

`ArtifactRecord` captures the artifact identifier, name, release version, expected digest, algorithm, registered size, and timestamp.

`ArtifactRegistry` stores these records in concurrent collections.

The registration workflow calculates a digest and stores the expected value. Verification accepts a candidate payload, recalculates its digest using the registered algorithm, and compares both the digest and byte count.

### Verification states

An artifact has one of three current verification states:

| State | Meaning |
|---|---|
| `NOT_CHECKED` | No candidate has been evaluated |
| `VERIFIED` | The most recent candidate matched |
| `INTEGRITY_FAILED` | The most recent candidate did not match |

Each verification also creates an `AuditEvent`. This retains the verifier identity, observed digest, result, and verification timestamp.

The state represents the latest result, while the audit list preserves the history of individual checks.

The example uses in-memory concurrent collections. A persistent enterprise service would normally store these records in a transactional database and define retention, access-control, and audit policies.

### Compile and run

Compile with Java 17:

`javac HashFunctions.java`

Run:

`java HashFunctions`

No third-party dependencies are required.

## 10. PostgreSQL Implementation

The SQL implementation uses the `hash_lab` schema and the PostgreSQL `pgcrypto` extension.

The schema separates artifact content, digest calculations, approved algorithms, and verification events.

### Relational model

The primary relationships are:

- An artifact can have multiple digest records.
- Each digest record belongs to one artifact.
- Each digest record identifies one approved algorithm.
- A digest record can have multiple verification events.
- Verification events retain the observed digest and result of an individual check.

The structure preserves historical calculations rather than replacing an earlier digest whenever a new calculation is performed.

### Integrity constraints

The database enforces:

- Unique artifact keys.
- Approved algorithm names.
- Valid digest lengths.
- Non-negative byte counts.
- Required artifact and verifier identities.
- Valid verification result and failure-reason combinations.
- Foreign-key relationships between artifacts, digest records, and verification events.

A trigger rejects updates and deletes on digest records. New calculations create new records, preserving the expected digest history.

### Database functions and procedures

`register_digest()` calculates a digest using `pgcrypto.digest()` and stores the result.

`verify_artifact()` recalculates the digest for the current artifact content, compares it with the selected digest record, and inserts a verification event.

`register_all_digests()` applies an approved algorithm to every registered artifact.

The functions use row-level locks when reading artifact content for calculations, helping keep each digest calculation consistent with the content observed within its transaction.

### Views and reports

`latest_digest_records` selects the newest digest record for each artifact and algorithm.

`artifact_integrity_report` combines artifact metadata, the latest digest, and its latest verification result.

The reporting queries cover:

- Artifact and digest retrieval.
- Digest history.
- Algorithm usage and processing volume.
- Successful and failed verification counts.
- Failed integrity events.
- Current eligibility for integrity acceptance.
- Artifacts requiring recalculation and review.

The sample workflow registers three release artifacts, creates SHA-256 records, creates an additional SHA-512 record, deliberately modifies one artifact, and runs verification.

The modified artifact produces a failed integrity result. The original digest record remains available for audit.

### HMAC in PostgreSQL

`pgcrypto` also provides `hmac()`.

The SQL example calculates a demonstration HMAC using an explicitly non-production key. Real keys should be supplied through a secure application or secret-management mechanism rather than stored in database tables or SQL source files.

The database example uses unkeyed digests for persistent artifact-integrity records. It does not treat an unkeyed digest as proof of a trusted publisher's identity.

### Database execution

Execute the SQL file using a PostgreSQL client with permission to create the `pgcrypto` extension.

For example, the script can be executed from `psql` with a command such as:

`psql -d your_database -f hash_functions.sql`

The script creates its own schema and uses transactions for sample artifact registration and modification.

## 11. Important Edge Cases

| Condition | Expected behavior |
|---|---|
| Empty input | Produces a valid digest |
| Binary file | Processes raw bytes without text conversion |
| Large file | Uses streaming or chunked reads |
| Modified content | Produces a digest mismatch |
| Incorrect HMAC | Authentication verification fails |
| Empty HMAC key | Rejected |
| Unsupported digest algorithm | Rejected |
| Invalid password record | Verification fails |
| Insufficient PBKDF2 iterations | Rejected |
| Malformed manifest | Rejected |
| Duplicate manifest path | Rejected |
| Missing manifest file entry | Verification fails for that entry |
| Symbolic-link input | Rejected by the file-processing workflows |
| Digest record modification | Rejected by the PostgreSQL trigger |
| Unknown artifact | Verification operation fails |

An empty file is not an invalid hash input. Cryptographic hash algorithms define valid outputs for empty messages.

Hashing binary data is also important. Files may contain arbitrary byte values that do not represent valid text. Converting such content to text before hashing can change the bytes and produce an incorrect digest.

## 12. Security and Operational Boundaries

### Unkeyed digest versus authentication

An ordinary digest can detect changes when the expected digest is trusted. It cannot independently establish who created the digest.

HMAC adds a secret key and provides message authentication between parties that possess that key.

### Hashing versus encryption

Hashing is a one-way digest operation. Encryption is designed to protect data confidentiality and normally supports decryption with the appropriate key.

The project does not implement encryption or claim that a digest hides the original content.

### Hashing versus digital signatures

HMAC requires a shared secret. Digital signatures use asymmetric cryptography, with a private signing key and a corresponding public verification key.

The project demonstrates HMAC but does not implement a digital-signature workflow or publisher certificate validation.

### Password storage

General-purpose SHA-256 and SHA-512 are fast digest algorithms, not password-storage functions.

The password examples use PBKDF2 with a random salt and configurable iteration count. The derived-key record is stored instead of the original password.

### Manifest authenticity

A JSON manifest can be modified by anyone with write access to it. File verification is meaningful only when the expected digest data is protected by an appropriate trust mechanism.

### C++ implementation limitations

The C++ SHA-256 and HMAC code is educational. Its purpose is to explain the algorithm's internal state, block processing, padding, and keyed construction.

The implementation has not been subjected to the review, side-channel analysis, fuzzing, or platform testing expected of a production cryptographic library.

### PostgreSQL limitations

The SQL schema stores artifact content as `BYTEA` for an executable practice workflow. Very large production artifacts may be better represented through external object storage with database metadata and verification records.

The database digest calculation verifies byte consistency but does not establish publisher identity. Database permissions, application authorization, backup integrity, audit retention, and secret management remain separate responsibilities.

## 13. Complexity and Performance

For a file containing \(n\) bytes, the digest calculation requires time proportional to the input size.

| Operation | Approximate time complexity | Working memory |
|---|---|---|
| In-memory digest | \(O(n)\) | \(O(n)\) for the supplied input |
| Streaming digest | \(O(n)\) | \(O(c)\), where \(c\) is the chunk size |
| HMAC | \(O(n)\) | Bounded by implementation buffers |
| PBKDF2 | Depends on iteration count and key length | Bounded by derivation implementation |
| Manifest generation | Proportional to total file content and file count | Proportional to manifest entries plus bounded processing buffers |
| Manifest verification | Proportional to total verified file content | Proportional to manifest entries plus bounded processing buffers |

Streaming reduces memory requirements for large artifacts but does not reduce the total amount of data that must be processed.

PBKDF2 deliberately performs repeated computation. Its processing cost is separate from ordinary file hashing and must be configured according to the intended authentication workload.

The JavaScript implementation bounds concurrent file operations to avoid unrestrained resource consumption.

The SQL implementation uses indexes on artifact-to-digest and digest-to-verification relationships to support retrieval of recent calculations and verification events.

## 14. Learning Outcomes Demonstrated in the Implementations

The project provides working examples of:

- SHA-2 and SHA-3 digest calculation.
- The internal SHA-256 compression process.
- Incremental and streaming digest processing.
- HMAC message authentication.
- Password derivation using PBKDF2.
- Constant-time digest or authentication-tag comparison through available platform mechanisms.
- File integrity manifest creation and verification.
- Algorithm allowlists and input validation.
- Artifact registration and verification state.
- Immutable digest history.
- Audit event creation.
- Relational constraints and database reporting.
- Error handling for malformed records, changed artifacts, and unsupported algorithms.

Each implementation uses the cryptographic facilities appropriate to its language while preserving the same fundamental distinction between digest calculation, message authentication, password derivation, and integrity verification.
