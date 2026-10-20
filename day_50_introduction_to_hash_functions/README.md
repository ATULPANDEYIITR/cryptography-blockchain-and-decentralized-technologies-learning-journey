# Introduction to Hash Functions

This project develops a practical foundation for understanding cryptographic hash functions and their use in software systems.

The implementations use the same subject from different engineering perspectives:

| File | Perspective | Main implementation |
|---|---|---|
| Python | Algorithm and systems simulation | Hashing, hash tables, file integrity, HMAC, password derivation, Merkle trees |
| JavaScript | Event-driven application processing | Node.js cryptography, streaming files, asynchronous password derivation, event emission |
| C++17 | Low-level algorithmic case study | SHA-256 compression, message padding, digest indexing, integrity checks, Merkle trees |
| Java 17 | Enterprise domain model | Immutable records, concurrent repositories, password policies, asynchronous hashing, Merkle trees |
| PostgreSQL | Relational integrity workflow | Digest triggers, artifact verification, credential records, HMAC, analytical queries, transactions |

## Hash Functions

A hash function maps input data of arbitrary practical length to a fixed-size output.

For a cryptographic hash function:

`message -> fixed-length digest`

For SHA-256, the output is 256 bits, represented by 64 hexadecimal characters.

A small input modification should normally produce a substantially different digest. This property is commonly called the avalanche effect.

A cryptographic hash should also provide strong resistance to:

- Finding an input that produces a specified digest, called preimage resistance.
- Finding another input with the same digest as a specified input, called second-preimage resistance.
- Finding any two distinct inputs with the same digest, called collision resistance.

These properties are different from the properties required by an ordinary hash table.

## Cryptographic Hashing vs Hash Tables

A programming-language hash table uses a hash function to map keys into storage locations.

Its primary objective is efficient lookup.

A cryptographic hash function is designed to provide security properties such as collision resistance and preimage resistance.

Therefore:

| Property | Hash table | Cryptographic hash |
|---|---|---|
| Primary purpose | Efficient lookup | Integrity and security |
| Collision handling | Required explicitly | Collisions should be computationally difficult |
| Secret key | Usually unnecessary | Unkeyed hash does not use one |
| Security guarantee | Not inherently security-oriented | Designed for defined security properties |
| Example | `dict`, `Map`, `unordered_map` | SHA-256, SHA3-256 |

The Python implementation deliberately separates these concepts. Its chained hash table demonstrates ordinary collision handling while SHA-256 is used for cryptographic integrity.

## Determinism and Fixed-Length Output

The same input must produce the same digest when processed with the same algorithm.

The Python, JavaScript, C++, Java, and PostgreSQL implementations all calculate deterministic SHA-256 values.

For example:

`hash("repository artifact")`

always produces the same SHA-256 digest.

The digest size does not grow with the input. A small message and a multi-gigabyte file can both produce a 256-bit SHA-256 result.

This makes a digest useful as a compact integrity identifier, but the digest itself does not contain enough information to reconstruct the original input.

## Avalanche Behavior

The implementations compare:

`hash-function`

with:

`hash-functions`

Only one character changes, but many digest positions normally change.

The avalanche property is important because predictable local changes in the input should not produce predictable local changes in the digest.

The demonstration counts differing hexadecimal characters. This is useful for observation but is not itself a formal statistical test of a cryptographic hash function.

## SHA-256 and SHA3-256

The examples use both SHA-256 and SHA3-256.

SHA-256 belongs to the SHA-2 family and uses a Merkle-Damgård-style construction.

SHA3-256 belongs to the SHA-3 family and is based on the Keccak sponge construction.

Both produce 256-bit digests, but they use substantially different internal constructions.

A system should specify the exact algorithm rather than simply storing a field named `hash`. The PostgreSQL schema therefore records the algorithm alongside the digest.

## Python Implementation

The Python program uses the standard `hashlib` module for cryptographic algorithms.

It demonstrates:

- Text-to-byte conversion using UTF-8.
- SHA-256 and SHA3-256.
- Deterministic digest calculation.
- Avalanche observation.
- A separate-chaining educational hash table.
- Incremental file hashing.
- Constant-time digest comparison through `hmac.compare_digest`.
- HMAC-SHA256.
- PBKDF2-HMAC-SHA256 for password-derived credentials.
- Merkle-tree construction.

The file hashing implementation processes the file in chunks rather than loading the entire file into memory. This makes the technique appropriate for large artifacts.

The hash table intentionally uses Python's ordinary `hash()` only for indexing. Python's `hash()` is not presented as a cryptographic primitive.

## JavaScript Implementation

The JavaScript implementation targets Node.js and uses the built-in `crypto` module.

It complements the Python implementation by emphasizing event-driven and asynchronous processing.

The `HashWorkflow` class extends `EventEmitter` and emits events when artifact hashing starts, succeeds, or fails.

Large files are processed through `fs.createReadStream()`. Chunks are supplied asynchronously to the SHA-256 digest object.

Password derivation uses Node.js `scrypt`, which is designed to make password guessing substantially more expensive than ordinary fast hashing.

The implementation also uses `crypto.timingSafeEqual()` for security-sensitive byte comparisons.

## C++ Implementation

The C++17 program provides a lower-level view of SHA-256.

Unlike the other implementations, it implements the SHA-256 compression algorithm directly.

The implementation shows the relationship between:

`message -> padding -> 512-bit blocks -> message schedule -> 64 compression rounds -> 256-bit digest`

The message is padded by:

- Appending the `1` bit represented at byte level by `0x80`.
- Adding zero bytes until the block has 56 bytes.
- Appending the original message length as a 64-bit big-endian value.

Each 512-bit block is expanded into a 64-word message schedule.

The compression function then uses SHA-256's logical functions, rotations, round constants, and working variables.

This implementation is intentionally educational. Production systems should normally use a reviewed cryptographic library rather than maintaining application-specific cryptographic primitives.

## Java Enterprise Model

The Java program models hashing as part of an enterprise artifact-management workflow.

`HashAlgorithm` explicitly defines supported algorithms.

`Artifact` is an immutable record containing:

- artifact identifier
- repository
- branch
- author
- digest

`ArtifactRepository` uses `ConcurrentHashMap` so artifact lookups can safely support concurrent application workloads.

The repository treats the digest as an artifact identifier. This demonstrates content-oriented addressing while keeping the digest separate from authentication secrets.

The Java implementation also uses `CompletableFuture` for asynchronous digest processing.

## Password Hashing

A general cryptographic hash such as SHA-256 is fast.

That is useful for integrity checks but undesirable for password storage because an attacker can test very large numbers of candidate passwords quickly.

Password storage therefore uses a password-specific key derivation function.

The Python implementation uses PBKDF2-HMAC-SHA256.

The JavaScript implementation uses scrypt.

The Java implementation uses PBKDF2-HMAC-SHA256.

These mechanisms use a random salt and computational cost parameters.

The important model is:

`password + unique salt + expensive derivation -> stored derived value`

The salt does not need to be secret.

A password verifier recomputes the derived value using the stored salt and parameters and compares the result with the stored derived value.

A production password system should select a current password-specific algorithm and parameters based on its security requirements and deployment environment. A plain SHA-256 digest should not be substituted for password-specific derivation.

The PostgreSQL demonstration contains a deliberately simplified credential derivation example to show database-level concepts. It should not be interpreted as a production password-storage implementation because its derivation construction is not a complete PBKDF2 implementation.

## File and Artifact Integrity

A digest can detect accidental or unauthorized modification when a trusted reference digest is available.

The workflow is:

`artifact -> hash -> expected digest`

Later:

`artifact -> hash -> actual digest`

Then:

`expected digest == actual digest`

A changed artifact normally produces a different digest.

This is useful for:

- Release artifacts
- Configuration files
- Data exports
- Backups
- Software packages
- Content-addressed storage

A digest alone does not prove who created the artifact. An attacker who can modify both an artifact and its trusted digest can replace both values. Authenticity requires a trusted distribution mechanism, digital signature, HMAC, or another appropriate authentication mechanism.

## HMAC

HMAC is a keyed message-authentication construction based on a cryptographic hash.

Conceptually:

`secret key + message -> authentication tag`

A recipient possessing the secret key can recompute the tag.

The Python and JavaScript implementations demonstrate HMAC-SHA256.

HMAC is appropriate when two parties share a secret and need to detect modification and authenticate messages.

A plain expression such as:

`SHA256(secret || message)`

should not be treated as a general replacement for HMAC.

## Constant-Time Comparison

Security-sensitive digest and authentication-tag comparisons should avoid simple comparisons that return immediately at the first mismatch when timing differences could expose information.

The implementations use:

- Python `hmac.compare_digest`
- Node.js `crypto.timingSafeEqual`
- Explicit constant-time-style comparison in C++ and Java

The C++ and Java implementations also account for different input lengths before comparing the corresponding bytes.

Constant-time comparison is one part of a broader side-channel defense strategy. It does not make an otherwise insecure authentication protocol secure.

## Merkle Trees

A Merkle tree organizes hashes hierarchically.

For four transactions:

`TX1    TX2    TX3    TX4`

their leaf hashes are calculated first:

`H(TX1)  H(TX2)  H(TX3)  H(TX4)`

Parent nodes are then calculated:

`H(H(TX1) || H(TX2))`

and:

`H(H(TX3) || H(TX4))`

The root is calculated from those parent hashes.

The structure becomes:

`                 Root`
`                /    \`
`              H12    H34`
`             /  \    /  \`
`           H1   H2  H3   H4`

The implementations duplicate the final node when a level contains an odd number of nodes.

Merkle structures are useful when a system needs compact commitments to collections of data and efficient proofs about individual members.

## PostgreSQL Model

The SQL implementation represents hashing as a database workflow.

The `repositories` table identifies logical repositories.

The `artifacts` table stores:

- repository relationship
- artifact name
- content
- selected hash algorithm
- calculated digest
- creation timestamp

A trigger calculates the digest whenever an artifact is inserted or its content or algorithm changes.

This ensures that application code does not have to be trusted to remember to recalculate the digest.

The `verify_artifact()` function independently calculates the digest from stored content and compares it with the recorded digest.

The resulting `hash_integrity_report` view makes integrity status queryable.

## Database Constraints

The PostgreSQL schema uses constraints to prevent invalid state.

Examples include:

- Repository names cannot be empty.
- Artifact names cannot be empty.
- Only explicitly supported digest algorithms are accepted.
- SHA-256 and SHA3-256 digests must have the expected 64-character hexadecimal representation.
- Password salts have a minimum length.
- Derived keys have an expected size.
- PBKDF2 iteration counts must meet the configured minimum.
- Foreign keys maintain repository-to-artifact relationships.

Database constraints provide a second line of defense when multiple application processes write to the same data store.

## Transactions

The SQL script includes a transaction with a savepoint.

The workflow creates an artifact, establishes a savepoint, modifies the artifact, and rolls back to the savepoint before committing.

This demonstrates that hashing-related database state should participate in ordinary transactional integrity rather than being treated as an unrelated side effect.

The trigger recalculates the digest when the content changes.

## Performance

For an input of `n` bytes, cryptographic hash computation is generally linear in input size:

`O(n)`

Memory consumption can remain close to constant when data is processed incrementally.

This is why the Python and JavaScript file examples use streaming or chunked processing.

Hash-table lookup has an expected average complexity close to:

`O(1)`

but its actual behavior depends on the table implementation, load factor, hash distribution, and collision handling.

Merkle-tree construction over `n` leaves requires hashing a number of nodes proportional to `n`, giving approximately:

`O(n)`

construction time.

Password derivation deliberately trades performance for resistance to large-scale guessing attempts. Its cost must therefore be evaluated differently from ordinary data hashing.

## Collision Considerations

A hash function maps a potentially enormous input space into a finite output space.

Collisions must therefore exist mathematically.

The security objective of a cryptographic hash is not to make collisions impossible. It is to make finding useful collisions computationally infeasible under the algorithm's security assumptions.

This is different from a hash-table collision.

A hash table must explicitly handle collisions during normal operation. The Python example uses separate chaining for this purpose.

A cryptographic hash should instead provide strong resistance to adversarial collision construction.

## Security Boundaries

A digest does not automatically provide:

- Confidentiality
- User authentication
- Authorization
- Non-repudiation
- Proof of authorship

Different security goals require different mechanisms.

| Requirement | Appropriate mechanism |
|---|---|
| Detect accidental modification | Cryptographic hash |
| Authenticate data with a shared secret | HMAC |
| Authenticate a signer publicly | Digital signature |
| Store passwords | Password-specific KDF |
| Efficient membership commitment | Merkle tree |
| Fast application lookup | Hash table |

The mechanism must match the security property being requested.

## Edge Cases

The implementations explicitly handle several failure conditions:

- Empty input where a meaningful value is required.
- Unsupported hash algorithms.
- Missing files.
- Invalid digest formats.
- Invalid password parameters.
- Empty Merkle trees.
- Missing repository artifacts.
- Invalid credential records.
- Tampered artifact content.
- Changed authentication messages.
- Odd numbers of Merkle-tree leaves.

These cases matter because cryptographic code is part of a larger application boundary. Invalid input should not silently become a valid security state.

## Practical Workflow

The relationship between the implemented concepts can be viewed as:

`Data`
`  |`
`  v`
`Cryptographic Hash`
`  |`
`  +--> Integrity Digest`
`  |`
`  +--> Content Identifier`
`  |`
`  +--> Merkle Tree Node`
`  |`
`  +--> HMAC input`
`  |`
`  +--> Password KDF input`

The important distinction is that each use case adds different requirements around the basic hash primitive.

A plain digest is suitable for integrity identification when the expected digest is trusted.

A secret key is required when the objective is message authentication through HMAC.

A salt and deliberately expensive password derivation process are required for password credential storage.

A hierarchy of hashes is useful when large collections need compact integrity commitments.

## Limitations

The C++ SHA-256 implementation is intended to expose the algorithm's internal mechanics and should not replace a professionally maintained cryptographic library.

The database password demonstration is intentionally simplified and does not implement a complete production-grade PBKDF2 verification construction.

Digest algorithms should not be selected solely because they are available. Algorithm lifecycle, interoperability, threat model, regulatory requirements, and existing system compatibility should be considered.

Hash functions also cannot provide confidentiality. If sensitive information must remain secret, encryption is required rather than hashing.
