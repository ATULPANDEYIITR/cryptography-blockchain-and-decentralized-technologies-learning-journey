# SHA Family

## Scope

The SHA family consists of cryptographic hash constructions designed to map arbitrary-length input to fixed-size digest values. The implementations in this project focus on the practical distinction between SHA-1, SHA-2, and SHA-3, while also showing incremental processing, file integrity verification, keyed authentication, and password-derived verification.

The five source files use different technical perspectives:

| File | Perspective | Main implementation |
|---|---|---|
| Python | Practical cryptographic operations | `hashlib`, streaming files, HMAC, PBKDF2 |
| JavaScript | Event-driven application processing | Node.js `crypto`, streams, asynchronous PBKDF2 |
| C++17 | Cryptographic mechanism and state transformation | Direct SHA-256 compression implementation |
| Java 17 | Enterprise integrity service | JDK cryptographic providers, domain records, policy services |
| PostgreSQL | Persistent integrity model | `pgcrypto`, relational constraints, functions, views |

The implementations deliberately do not treat every SHA algorithm as interchangeable.

## SHA Family Structure

The major families represented here are:

| Family | Representative algorithms | Digest sizes | Core construction |
|---|---|---:|---|
| SHA-1 | SHA-1 | 160 bits | Merkle-Damgård |
| SHA-2 | SHA-224, SHA-256, SHA-384, SHA-512 | 224–512 bits | Merkle-Damgård |
| SHA-3 | SHA3-224, SHA3-256, SHA3-384, SHA3-512 | 224–512 bits | Keccak sponge |

SHA-1 is retained in the examples only to demonstrate compatibility and algorithm-policy decisions. It should not be selected for new collision-resistant security designs.

SHA-2 remains widely deployed. SHA-256 is especially common in software distribution, digital signatures, certificates, Git object identifiers in SHA-1 repositories, artifact verification, and integrity records.

SHA-3 uses a substantially different internal construction. SHA-256 processes 512-bit blocks through a compression function, while SHA-3 is based on the Keccak sponge construction.

## Digest Semantics

A cryptographic hash has a deterministic mapping:

`message → fixed-length digest`

A one-bit or one-byte modification normally produces a substantially different digest. This avalanche behavior makes a digest useful as an integrity fingerprint.

A digest does not prove the identity of the party that generated it.

If an attacker can modify both a file and its publicly available SHA-256 digest, ordinary hashing does not prevent the attack. Authentication requires an additional trust mechanism, such as HMAC with a secret key or a digital signature.

The project therefore separates three cases:

| Mechanism | Secret required | Primary purpose |
|---|---:|---|
| SHA-256 | No | Integrity fingerprint |
| HMAC-SHA-256 | Yes | Message authentication |
| Password KDF | Yes, password-derived | Password verification |

## Python Implementation

The Python implementation uses the standard-library `hashlib` module to expose several SHA-family algorithms without external dependencies.

It demonstrates:

- SHA-1 and SHA-2 digest calculation.
- SHA-3 digest calculation.
- SHAKE variable-length output.
- Incremental hashing through repeated `update()` operations.
- Streaming file hashing with fixed-size chunks.
- Constant-time digest comparison through `hmac.compare_digest`.
- HMAC creation and verification.
- PBKDF2-HMAC password-derived values.
- Salt generation using `secrets`.
- Runtime validation of supported algorithms.
- A small performance comparison across modern algorithms.

Incremental hashing is important when input is too large to load into memory. The file hashing function reads one MiB at a time and feeds each chunk into the digest state.

The SHAKE algorithms are treated differently from fixed-length SHA algorithms because their output length is selected when the digest is requested.

The password example uses PBKDF2-HMAC-SHA-256 with a randomly generated salt and a deliberately high iteration count. A password should never be stored as a plain SHA digest. Password hashing needs a construction designed to make large-scale guessing expensive.

## JavaScript Implementation

The JavaScript implementation targets Node.js and uses the platform `crypto` module.

The file hashing workflow is event-driven:

`ReadStream → data events → hash.update() → end event → digest`

This avoids reading an entire large artifact into application memory.

The HMAC implementation uses `createHmac()`. Verification converts hexadecimal values to buffers and uses `timingSafeEqual()` after validating that the values have equal lengths.

PBKDF2 is executed through Node's asynchronous `crypto.pbkdf2()` API. This is significant for a server application because password derivation is intentionally expensive and should not unnecessarily block the main event loop.

The implementation also checks algorithm availability through `crypto.getHashes()`. Cryptographic algorithm availability can depend on the underlying Node.js and OpenSSL build, so applications should not silently assume that every algorithm is exposed on every deployment.

## C++17 Implementation

The C++ program takes a lower-level approach.

Instead of calling a cryptographic library for the central demonstration, it implements the SHA-256 compression mechanism directly. The implementation exposes the major components of the SHA-256 design:

- Eight 32-bit initial state words.
- Sixty-four round constants.
- 512-bit message blocks.
- A 64-word message schedule.
- Choice and majority functions.
- Large and small sigma functions.
- Right rotations.
- Sixty-four compression rounds.
- Feed-forward accumulation.
- Merkle-Damgård padding.
- A 256-bit final digest.

The message-processing relationship is:

`input → padding → 512-bit blocks → message schedule → 64 rounds → state accumulation → 256-bit digest`

The `Sha256` class also supports incremental input. Data can therefore be processed in separate calls rather than as one contiguous string.

The program includes a repository-style artifact integrity model. An artifact contains an identifier, payload, and expected digest. The integrity engine calculates the current digest and compares it against the stored value.

The C++ example is primarily educational. Production systems should use a vetted cryptographic library rather than maintaining a custom cryptographic primitive. Cryptographic correctness depends not only on the algorithm but also on implementation quality, side-channel behavior, memory handling, testing, compiler behavior, and maintenance.

## Java 17 Implementation

The Java implementation models an enterprise integrity service.

The main domain types are:

- `Artifact`
- `VerificationResult`
- `PasswordRecord`
- `IntegrityPolicy`
- `DigestService`
- `IntegrityWorkflow`
- `PasswordService`

The `Artifact` record provides immutable domain data. An expected digest is associated with the artifact after the reference value has been calculated.

`IntegrityPolicy` separates algorithms approved for new data from compatibility-only algorithms. SHA-1 can therefore exist as a recognized legacy algorithm without being accepted for new integrity records.

`DigestService` delegates cryptographic primitives to the JDK provider. This is the appropriate production-oriented boundary for a Java application because the application should not maintain its own SHA implementation when a platform cryptographic provider is available.

`IntegrityWorkflow` converts verification failures into explicit `VerificationResult` values instead of exposing cryptographic implementation exceptions directly to higher application layers.

The password service demonstrates PBKDF2 with HMAC-SHA-256. A random salt is stored with the derived key, while the password itself is never persisted.

## PostgreSQL Model

The SQL implementation treats SHA-family operations as persistent application data.

The schema contains:

- `hash_algorithms`
- `artifacts`
- `artifact_digests`
- `hmac_records`
- `password_verification_records`

The `hash_algorithms` table provides a central algorithm policy. It records digest size, family, security status, and whether an algorithm is approved for new records.

The relational structure is:

`artifacts → artifact_digests → hash_algorithms`

This allows one artifact to have multiple digest representations, such as SHA-256 and SHA3-256, without duplicating artifact content.

Foreign keys preserve referential integrity. Unique constraints prevent multiple digest records for the same artifact and algorithm. Check constraints prevent invalid empty values and enforce minimum password-KDF iteration counts.

The `calculate_digest()` PostgreSQL function validates the algorithm against the database policy before invoking `pgcrypto.digest()`.

The `verify_artifact_digest()` function calculates the current digest and compares it with the stored digest. The `artifact_integrity_report` view exposes both recorded and recalculated values, making it suitable for operational integrity checks.

## SHA-256 Processing Model

SHA-256 works with 512-bit blocks and maintains eight 32-bit working state words.

For each block, the first 16 words are extracted directly from the message. The remaining 48 words are derived from earlier schedule entries.

The round transformation uses:

`T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]`

`T2 = Σ0(a) + Maj(a,b,c)`

The working variables are rotated through the state and the resulting state is added back into the hash state after all 64 rounds.

Padding appends a single `1` bit, followed by zero bits, and finally the original message length encoded as a 64-bit value.

This processing explains why incremental hashing works. The digest state after one block is sufficient to process the next block without retaining the complete original message.

## SHA-2 and SHA-3 Distinction

SHA-2 and SHA-3 should not be described as different names for the same internal algorithm.

SHA-2 uses the traditional compression-function structure. SHA-3 uses a sponge construction based on Keccak.

For SHA-3, the input is absorbed into an internal state. Permutation rounds transform that state, and output is then squeezed from it.

This structural difference matters when selecting algorithms for interoperability, implementation diversity, standards compliance, or migration planning.

A system may support both SHA-256 and SHA3-256 without treating them as interchangeable byte-level implementations.

## Integrity Verification

A typical artifact verification workflow is:

`Artifact`
`  ↓`
`Reference SHA-256 digest`
`  ↓`
`Retrieve artifact`
`  ↓`
`Recalculate SHA-256`
`  ↓`
`Constant-time comparison`
`  ↓`
`Match / mismatch`

The reference digest must come from a trusted source. Otherwise an attacker who can replace both the artifact and its digest can defeat simple fingerprint comparison.

For software distribution, stronger authenticity normally comes from a digital signature or another authenticated trust mechanism.

## HMAC

HMAC combines a cryptographic hash with a secret key.

Conceptually:

`HMAC(K, M)`

where `K` is the secret key and `M` is the message.

Unlike a plain digest, an attacker who does not possess the secret key cannot simply calculate a valid authentication tag for modified content.

The Python and JavaScript implementations explicitly demonstrate this distinction.

A secret HMAC key should not be embedded permanently in source code or committed to a repository. Production deployments should obtain it through an appropriate secret-management boundary.

## Password Verification

Password storage is a separate problem from ordinary file integrity.

A simple operation such as:

`SHA-256(password)`

is unsuitable for password storage because modern hardware can perform enormous numbers of fast guesses.

The Python and Java implementations use PBKDF2-HMAC-SHA-256 with a random salt and a high iteration count.

The conceptual workflow is:

`password + random salt + cost parameter`
`                ↓`
`           PBKDF2-HMAC`
`                ↓`
`          derived value`

During authentication, the supplied password is processed with the stored salt and cost parameters, and the derived values are compared.

Modern deployments should select password-hashing parameters based on current platform capabilities and applicable security requirements. Memory-hard password hashing schemes such as Argon2id can be preferable when the deployment environment supports them.

## Digest Comparison

Digest verification should avoid unsafe comparison patterns when an attacker can observe timing behavior.

The examples use:

- Python `hmac.compare_digest`
- Node.js `crypto.timingSafeEqual`
- Java `MessageDigest.isEqual`
- A constant-time comparison loop in the C++ educational implementation

Length validation remains necessary before a byte-oriented constant-time comparison in APIs that require equal-length inputs.

Constant-time comparison does not make an unauthenticated digest trustworthy. It only addresses the comparison operation itself.

## Edge Cases and Failure Conditions

The implementations explicitly address several operational failures:

| Condition | Handling |
|---|---|
| Unsupported algorithm | Reject |
| Empty artifact identifier | Reject |
| Missing reference digest | Verification failure |
| Modified artifact | Digest mismatch |
| Invalid digest length | Reject |
| Malformed hexadecimal digest | Reject or return false |
| Large file | Stream incrementally |
| Incorrect password | Verification failure |
| Weak KDF iteration policy | Reject |
| Deprecated SHA-1 for new data | Policy rejection |
| Missing JDK/Node cryptographic algorithm | Runtime failure |
| Database integrity violation | Constraint enforcement |

A digest mismatch is not itself proof of malicious activity. It can result from a legitimate rebuild, serialization change, encoding difference, corrupted storage, or an unauthorized modification.

## Performance Considerations

Hashing is approximately linear in input size:

`Time = O(n)`

where `n` is the number of input bytes.

Fixed-size digest algorithms use bounded internal state, so incremental hashing requires memory independent of the total message size, apart from the input buffer and implementation overhead.

File streaming provides a practical memory bound:

`memory ≈ hashing state + read buffer`

PBKDF2 intentionally behaves differently. Its computational cost increases with the configured iteration count. This is desirable for password verification because the objective is to make guessing expensive.

SHA-1, SHA-256, SHA-512, and SHA-3 should not be compared only by raw benchmark speed. Algorithm choice also depends on required security properties, platform acceleration, interoperability, protocol requirements, digest size, and existing ecosystem support.

## Security Boundaries

A SHA digest provides collision resistance and related properties appropriate to its algorithm and security level. It does not provide confidentiality.

Hashing is therefore not encryption.

A digest also does not provide authorization, identity, or non-repudiation.

The practical security hierarchy is:

`Plain SHA digest → integrity fingerprint`

`HMAC-SHA → integrity + shared-secret authentication`

`Digital signature → integrity + public-key authenticity`

The correct mechanism depends on the trust model rather than simply selecting the strongest-looking hash function.

## Practical Design Distinctions

The project keeps several concepts separate:

| Concept | Meaning |
|---|---|
| Hash algorithm | Defines the cryptographic transformation |
| Digest | Fixed-size output of a hash |
| Hashing | Transformation of input into a digest |
| Incremental hashing | Feeding input into the same hash state over multiple operations |
| HMAC | Keyed authentication construction using a hash |
| Salt | Public random value used with password derivation |
| KDF | Function that derives a cryptographic value from secret material |
| Integrity | Ability to detect unexpected modification |
| Authentication | Ability to establish that a message came from a holder of a secret or key |

This separation prevents a common design error: assuming that replacing SHA-1 with SHA-256 automatically turns an unauthenticated integrity fingerprint into an authenticated security mechanism.

## Production Considerations

Production systems should:

- Prefer SHA-256, SHA-384, SHA-512, or SHA-3 variants according to protocol and policy requirements.
- Avoid SHA-1 for new collision-resistant security applications.
- Use platform or audited cryptographic libraries instead of maintaining custom cryptographic primitives.
- Stream large files rather than loading them entirely into memory.
- Store algorithm identifiers alongside digest values.
- Version cryptographic policies so migrations can be performed deliberately.
- Keep HMAC keys outside application source code and database rows that are intended to hold public metadata.
- Use dedicated password-hashing mechanisms for credentials rather than ordinary file-integrity hashing.
- Record enough metadata to reproduce verification decisions, including algorithm and relevant KDF parameters.
- Treat digest mismatches as investigation signals rather than automatically assuming compromise.
- Test algorithm availability during deployment when portability across operating systems or runtime builds matters.

The source files provide complementary implementations of these boundaries rather than five translations of the same program.```
