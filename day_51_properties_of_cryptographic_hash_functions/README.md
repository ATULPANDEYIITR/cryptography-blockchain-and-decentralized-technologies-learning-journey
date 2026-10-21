# Properties of Cryptographic Hash Functions

## Scope

A cryptographic hash function maps an input of arbitrary practical length to a fixed-size digest. The digest is designed to expose changes in the input while making several important attack goals computationally difficult.

This artifact studies the properties through five different implementation perspectives:

| File | Technical perspective |
|---|---|
| Python | Executable property experiments, file integrity, domain separation, brute-force demonstrations, and hash chaining |
| JavaScript | Node.js event-driven hashing, streaming file processing, digest comparison, hash chains, and Merkle-style aggregation |
| C++17 | A self-contained SHA-256 implementation used as a repository-artifact integrity case study |
| Java 17 | Enterprise-style domain modeling with JCA, immutable records, integrity services, evidence chains, and Merkle aggregation |
| PostgreSQL | Relational storage of algorithms, repository artifacts, integrity checks, and append-only hash-chain evidence |

The implementations intentionally distinguish mathematical properties of a hash from security mechanisms built using hashes.

## Core Hash Function Model

A hash function can be represented as:

`H : {0,1}* -> {0,1}^n`

The input may have variable length, while the output has a fixed size of `n` bits.

For SHA-256, `n = 256`.

A secure cryptographic hash is expected to provide several properties.

### Determinism

The same input always produces the same digest:

`H(x) = H(x)`

This makes hashes suitable for integrity fingerprints, content addressing, cache keys, and database verification records.

Determinism alone is not a security property. A simple checksum can also be deterministic.

### Fixed-Length Output

Different input sizes still produce the same digest size.

For SHA-256:

| Input | Digest |
|---|---:|
| Empty input | 256 bits |
| One byte | 256 bits |
| 1 KB | 256 bits |
| 1 GB | 256 bits |

The compression of arbitrary-length input into a fixed-length value is fundamental to hashing. It also means collisions must exist mathematically because the input space is much larger than the output space.

### Avalanche Effect

A small input modification should cause a substantial and apparently unpredictable change in the digest.

For example:

`amount=1000;account=42`

and

`amount=1001;account=42`

differ by only one character, yet their SHA-256 digests should differ across many output bits.

The implementations calculate the Hamming distance between two digest values to make this property observable.

The avalanche effect is not equivalent to collision resistance. A hash can show strong diffusion while still being unsuitable for cryptographic use if other structural weaknesses exist.

## Preimage Resistance

Given a digest `y`, preimage resistance means that finding an input `x` such that:

`H(x) = y`

should be computationally infeasible for a secure hash.

The Python implementation deliberately truncates a digest to 16 bits and performs a small brute-force search. The JavaScript and C++ implementations use similarly small truncated digest spaces for collision experiments.

This is intentionally not an attack against the full SHA-256 space.

A full 256-bit preimage search has an idealized work factor on the order of:

`2^256`

for generic brute force.

Real-world security analysis depends on the construction, attack model, available structure, and the exact security property being considered.

## Second-Preimage Resistance

Second-preimage resistance is different from ordinary collision resistance.

Given a specific existing message `m1`, an attacker should find it difficult to construct a different message `m2` such that:

`H(m1) = H(m2)`

The attacker does not freely choose both messages.

This distinction matters for systems that hash an already established artifact such as a signed release, repository commit, audit record, or legal document.

## Collision Resistance

Collision resistance means finding any two distinct inputs:

`m1 != m2`

such that:

`H(m1) = H(m2)`

is computationally infeasible.

For an ideal `n`-bit hash, generic collision search has a birthday-bound scale around:

`2^(n/2)`

For SHA-256 this gives an idealized generic collision-security level of approximately 128 bits.

The PostgreSQL model stores both `digest_bits` and `collision_security_bits` so that these two quantities are not confused.

## Why the Collision Experiments Use Truncated Hashes

The demonstrations intentionally retain only a small digest prefix.

A 16-bit digest has only:

`2^16 = 65,536`

possible values.

A collision therefore becomes practical in a short experiment.

This does not demonstrate a weakness in SHA-256 itself. It demonstrates the relationship between digest size and collision probability.

Reducing a cryptographic digest from 256 bits to 16 bits destroys the security margin that makes the full construction useful.

## Integrity Is Not Confidentiality

A hash is not encryption.

If an attacker can see the original data, hashing does not hide it. The digest is an integrity fingerprint rather than a confidentiality mechanism.

For example:

`SHA-256("approved")`

does not prevent someone from learning that the original message was `"approved"` if the message is already known or can be guessed.

This distinction is especially important when hashes are used for passwords, tokens, or sensitive database fields.

## Integrity Verification

The implementations use hashes to detect accidental or unauthorized modification.

A stored artifact is associated with a digest:

`expected = H(artifact)`

When the artifact is later received:

`actual = H(received_artifact)`

The artifact is unchanged when the expected and actual digests match.

This is useful for:

- build artifacts
- release packages
- repository objects
- configuration snapshots
- audit records
- downloaded files
- archival data

A plain hash does not prove who produced the artifact. An attacker who can replace both the artifact and its stored digest can defeat a naive comparison.

Authentication therefore requires a keyed MAC such as HMAC or a digital signature.

## Domain Separation

The Python and JavaScript implementations use explicit context prefixes.

For example:

`registration:user=42`

and:

`audit:user=42`

are intentionally different hash inputs.

Domain separation prevents different logical protocols from accidentally treating the same raw byte sequence as equivalent cryptographic input.

The prefix must be part of the canonical input definition rather than an informal convention.

## Hash Chaining

A hash chain links each record to the digest of its predecessor.

The conceptual relationship is:

`Block[i].hash = H(index || previous_hash || payload)`

The resulting structure is:

`Block 0 -> Block 1 -> Block 2 -> Block 3`

Changing an earlier payload changes its digest and invalidates the subsequent link.

The implementations use this technique for repository-oriented evidence such as:

- commit events
- review decisions
- merge events
- release events

A hash chain provides tamper evidence. It does not automatically provide an independently trusted source of truth or prove the identity of the party that created a record.

## Merkle-Style Aggregation

The JavaScript and Java implementations also construct a Merkle-style root.

Individual values are first hashed:

`h1 = H(x1)`

`h2 = H(x2)`

The values are then combined:

`parent = H(h1 || h2)`

This process continues until one root remains.

The root provides a compact commitment to a collection of values.

Merkle structures are useful when systems need efficient proofs that a particular item belongs to a committed collection. A complete production Merkle implementation must define ordering, duplicate handling, odd-node behavior, serialization, domain separation, and proof verification precisely.

The examples duplicate the final node when a level has an odd number of entries. That rule is part of the implementation and must be consistent between tree construction and verification.

## Python Implementation

The Python program uses the standard `hashlib` module rather than external cryptographic packages.

It demonstrates:

- deterministic hashing
- fixed digest length
- avalanche measurement
- domain separation
- integrity verification
- truncated preimage search
- truncated collision search
- hash-chain validation
- streaming file hashing
- SHA-256, SHA3-256, and BLAKE2b digest sizes

The file hashing implementation reads the file incrementally rather than loading the complete file into memory. This makes the approach suitable for large artifacts.

`hmac.compare_digest()` is used when comparing already computed digest values because direct string comparison is not the preferred primitive for security-sensitive equality checks.

The program also explicitly distinguishes general-purpose hashing from password hashing.

## JavaScript Implementation

The JavaScript implementation uses Node.js's built-in `crypto` module.

The program emphasizes event-driven and streaming behavior.

The `hashFile()` function uses `fs.createReadStream()` so a large artifact can be processed without loading the entire file into memory.

The implementation also uses:

- `Buffer` for binary data
- `crypto.createHash()` for digest construction
- `crypto.timingSafeEqual()` for equal-length digest comparisons
- asynchronous filesystem operations
- structured cloning for a tampering experiment
- Merkle-style aggregation

The program validates algorithm names before constructing a digest. This prevents a caller from silently using an unintended algorithm.

## C++17 Implementation

The C++ implementation deliberately takes a different approach.

It contains a complete SHA-256 compression implementation and uses it as the primitive for a repository artifact integrity model.

The implementation exposes the major SHA-256 components:

- message padding
- 512-bit message blocks
- message schedule
- choice function
- majority function
- rotation operations
- compression rounds
- 256-bit final state

This makes the internal mechanics visible without requiring an external cryptographic library.

The implementation is suitable for studying the algorithm but is not recommended as a production cryptographic implementation. Production systems should use mature, independently reviewed cryptographic libraries.

The repository case study builds hash-linked records for commits, reviews, and merges. Tampering with a review payload causes chain validation to fail.

## Java 17 Implementation

The Java implementation uses the Java Cryptography Architecture rather than implementing SHA-256 manually.

`HashAlgorithm` represents supported JCA algorithms as explicit domain values.

`RepositoryArtifact` is a record representing an immutable repository artifact.

`IntegrityService` defines the canonical representation of an artifact and verifies the resulting digest.

`ReviewEvidenceChain` models append-only evidence and explicitly validates predecessor links.

`MerkleService` models collection-level digest aggregation.

This separation is important in enterprise systems because the cryptographic primitive, domain representation, integrity policy, and workflow state should not be mixed into one general-purpose utility.

The use of `MessageDigest.isEqual()` provides a security-conscious comparison operation for digest values.

## PostgreSQL Model

The SQL implementation treats hashes as part of a persistent integrity workflow.

### Hash Algorithm Registry

`hash_algorithms` stores:

- algorithm name
- digest size
- estimated generic collision-security level
- approval state

This prevents algorithm properties from being scattered through application code.

### Repository Artifacts

`repository_artifacts` stores:

- repository
- branch
- commit identifier
- binary content
- selected hash algorithm
- computed digest
- creation timestamp

A trigger computes the SHA-256 digest from a canonical representation.

This provides a database-level integrity mechanism rather than relying exclusively on application code.

### Integrity Checks

`integrity_checks` records observed digests and whether they match the stored artifact digest.

A check constraint requires failed checks to include a failure reason and successful checks to omit one.

This converts an informal application rule into a database integrity rule.

### Hash-Chain Evidence

`hash_chain_events` stores chained repository evidence.

The table is deliberately protected by a trigger that rejects updates and deletes. The model therefore treats evidence as append-only.

A recursive CTE follows the sequence of events and checks that each event's `previous_digest` equals the preceding event's `current_digest`.

## Database Transaction Boundary

The SQL script wraps schema creation and initial data operations in a transaction.

A savepoint is also used around a later artifact-and-integrity operation.

This matters because cryptographic integrity metadata is useful only when it remains consistent with the associated artifact record.

An application that inserts an artifact but fails before recording the corresponding integrity state can create an incomplete audit trail. Transactions reduce this class of inconsistency.

## Canonicalization

Hashing structured information requires a deterministic representation.

The implementations therefore construct explicit canonical strings before hashing repository artifacts or chain records.

For example, an artifact is represented using:

`repository + branch + commit + content`

The exact delimiter and encoding are part of the protocol.

Different systems must not independently serialize the same logical object in incompatible ways and expect identical digests.

For binary data, encoding choices must also be explicit. The PostgreSQL implementation uses hexadecimal representation for content when constructing its canonical digest input.

## Hashing Versus Authentication

| Mechanism | Main purpose | Secret required |
|---|---|---|
| Cryptographic hash | Integrity fingerprint | No |
| HMAC | Message authentication and integrity | Yes |
| Digital signature | Authentication, integrity, non-repudiation properties | Private key |
| Encryption | Confidentiality | Encryption key |
| Password KDF | Slow password-derived verification value | Salt; KDF parameters |

A hash by itself does not establish authenticity.

If an attacker can modify a message and its associated untrusted digest, both values can simply be replaced.

## Passwords Require Special Treatment

Fast general-purpose hashes are intentionally efficient.

That property is useful for file integrity and content addressing but undesirable for password storage because attackers can attempt enormous numbers of guesses.

Password storage should use a password-specific key derivation function such as Argon2id, scrypt, or bcrypt with appropriate parameters and a unique salt.

A plain SHA-256 password table is therefore not an adequate password-storage design.

## Edge Cases

The implementations account for several relevant failure conditions:

- empty inputs
- very large file inputs
- unsupported algorithms
- mismatched digest lengths
- empty hash chains
- invalid chain predecessors
- modified chain payloads
- empty Merkle inputs
- odd Merkle-tree levels
- truncated digest collisions
- tampered repository artifacts
- missing integrity failure reasons
- attempts to modify append-only evidence

These cases are not interchangeable. A failed integrity check is different from an unsupported algorithm, which is different from a collision experiment, and different again from a broken hash-chain link.

## Performance Considerations

For a message of length `n`, conventional Merkle-Damgård-style hash processing is approximately linear in `n`.

Memory consumption can remain small when input is processed incrementally.

The Python and JavaScript file-hashing implementations therefore use streaming or chunked processing.

Hash-chain validation is linear in the number of chain records.

Merkle-tree construction is approximately linear in the number of leaves, with logarithmic tree depth.

The collision experiments are intentionally inefficient because their purpose is to demonstrate security scaling. A real 256-bit collision search is not practical through generic brute force.

## Security Limitations

A digest match is meaningful only when the expected digest comes from a trusted source.

If an attacker controls both:

`artifact`

and:

`expected_digest`

then ordinary hash comparison provides no authenticity.

For authenticated integrity, use HMAC when the communicating parties share a secret key, or digital signatures when public verification is required.

Hash algorithm selection also matters. Legacy algorithms such as MD5 and SHA-1 should not be selected for new cryptographic collision-resistance requirements.

SHA-256 and SHA3-256 provide 256-bit digest outputs, but their internal constructions differ. A system should select an algorithm according to its security requirements, interoperability requirements, protocol standards, and implementation support.

## Practical Relationship of the Properties

The properties studied here form a security model rather than independent features:

`Variable-length input`
`        |`
`        v`
`Deterministic transformation`
`        |`
`        v`
`Fixed-size digest`
`        |`
`        +--> Avalanche behavior`
`        |`
`        +--> Preimage resistance`
`        |`
`        +--> Second-preimage resistance`
`        |`
`        +--> Collision resistance`
`        |`
`        v`
`Integrity constructions`
`        |`
`        +--> Hash chains`
`        +--> Merkle structures`
`        +--> HMAC`
`        +--> Digital signatures`

The important distinction is that a cryptographic hash is a primitive. Security properties of larger systems depend on how that primitive is constructed, authenticated, serialized, stored, and verified.
