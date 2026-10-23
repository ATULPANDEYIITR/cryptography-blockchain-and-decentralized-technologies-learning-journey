# SHA-256

SHA-256 is a member of the SHA-2 family of cryptographic hash functions. It maps an arbitrary-length byte sequence to a fixed 256-bit digest, normally represented as 64 hexadecimal characters.

The five implementations in this artifact approach SHA-256 from different engineering perspectives:

| File | Primary perspective | Main implementation |
|---|---|---|
| Python | Algorithm and verification workflow | Full SHA-256 compression implementation plus file hashing |
| JavaScript | Event-driven application processing | Full SHA-256 implementation plus asynchronous file hashing |
| C++17 | Systems-level streaming | Stateful SHA-256 engine with incremental updates |
| Java 17 | Enterprise integrity service | Domain model, validation, verification states, and service abstraction |
| PostgreSQL | Database integrity workflow | SHA-256 calculation, artifact records, constraints, verification functions, and audit history |

The implementations are deliberately independent. The Python, JavaScript, and C++ programs implement the SHA-256 compression algorithm directly, while the Java implementation uses the standard Java cryptographic provider for an enterprise-oriented service design. PostgreSQL uses `pgcrypto` for database-side SHA-256 calculation.

## Cryptographic purpose

A cryptographic hash function provides deterministic transformation from data to a fixed-size digest:

`message → SHA-256 → 256-bit digest`

The same byte sequence always produces the same digest. A one-byte change normally produces a substantially different digest.

SHA-256 is useful for:

- file integrity verification
- artifact identification
- content-addressed storage
- software distribution integrity
- audit records
- duplicate detection
- digital-signature workflows as a hash component
- tamper detection when the trusted digest is protected separately

SHA-256 is not encryption. It does not provide confidentiality, and a digest cannot be reversed into the original message.

It is also not a password-storage solution by itself. Password systems require password-specific, deliberately expensive functions such as Argon2, scrypt, or bcrypt together with appropriate salting and operational controls.

## SHA-256 processing model

SHA-256 processes data as 512-bit blocks.

```text
Input bytes
    |
    v
Padding
    |
    v
512-bit message blocks
    |
    v
Message schedule W[0..63]
    |
    v
64 compression rounds
    |
    v
Updated eight-word state
    |
    v
256-bit digest
```

Each internal state consists of eight 32-bit words:

`H0 H1 H2 H3 H4 H5 H6 H7`

Together they contain 256 bits.

Each 512-bit block is initially interpreted as sixteen 32-bit big-endian words. The compression process expands these into a 64-word message schedule.

## Padding

SHA-256 appends a `1` bit, followed by enough zero bits to make room for a 64-bit representation of the original message length.

The final padded message has a length divisible by 512 bits.

For byte-oriented implementations, the important structure is:

`message || 0x80 || zero bytes || 64-bit big-endian bit length`

The Python implementation explicitly constructs this representation. The JavaScript implementation uses a `BigInt` for the 64-bit length field. The C++ implementation performs the final padding incrementally inside its stateful hashing object.

The length field is measured in bits rather than bytes.

## Compression function

The SHA-256 compression function uses:

- 32-bit modular addition
- right rotations
- right shifts
- XOR
- AND
- NOT
- the choice function
- the majority function
- message-schedule expansion
- 64 round constants

The two Boolean functions used by the implementations are:

`Ch(x,y,z) = (x AND y) XOR (NOT x AND z)`

`Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)`

The large and small sigma functions provide diffusion through bit rotations and shifts.

The Python implementation makes these mechanisms explicit as separate functions. The JavaScript implementation uses unsigned 32-bit operations because JavaScript's ordinary numeric type is floating-point. The C++ implementation uses `std::uint32_t`, which naturally models SHA-256's 32-bit arithmetic.

## Python implementation

The Python file contains a complete SHA-256 compression implementation rather than delegating the algorithm to `hashlib`.

`pad_message()` constructs the padded representation. `compress_block()` creates the 64-word schedule and executes the 64 compression rounds. `sha256_bytes()` processes all blocks and serializes the eight final state words into the 32-byte digest.

The implementation also uses `hashlib.sha256()` independently when validating its results. This is important when implementing cryptographic primitives: the reference implementation should not be the same code path as the implementation being tested.

The file includes:

- empty-message verification
- short-message verification
- the standard `"abc"` test vector
- `"hello world"`
- the million-`a` test vector
- file hashing
- constant-time digest comparison
- invalid file handling
- digest-format validation

The file hashing workflow deliberately uses `hashlib` in streaming mode. Loading a very large file into memory merely to calculate its digest is unnecessary.

## JavaScript implementation

JavaScript requires particular care because all ordinary numeric values are IEEE-754 double-precision numbers. Bitwise operations convert values to signed 32-bit representations.

The implementation therefore uses:

- `Uint32Array` for the SHA-256 state and schedule
- unsigned shifts
- `>>> 0` after modular arithmetic
- `Buffer` for binary input
- `BigInt` for the 64-bit message-length field

The built-in `crypto` module provides an independent reference implementation.

The asynchronous file workflow uses `fs.createReadStream()`. Each received chunk is fed into a Node.js SHA-256 hash object without requiring the complete file to reside in memory.

This demonstrates an important distinction between algorithm implementation and application integration. The custom implementation establishes understanding of the compression algorithm, while the runtime's cryptographic implementation is preferable for production file hashing.

## C++17 implementation

The C++ implementation is structured as a stateful `SHA256` class.

The `update()` method accepts arbitrary chunks. It fills a 64-byte internal buffer and processes a block whenever the buffer becomes full. This models how hashing APIs are commonly used for streams.

The design supports:

- multiple `update()` calls
- final padding
- 64-bit message-length accounting
- digest serialization
- hexadecimal encoding
- constant-time verification
- explicit finalized-state protection

The separation between `update()` and `finalize()` is useful for large inputs because callers do not need to construct one giant input buffer.

The C++ implementation also illustrates a low-level implementation concern: unsigned integer overflow is intentional in SHA-256 because additions operate modulo `2^32`. Using unsigned 32-bit types makes this behavior explicit.

## Java enterprise model

The Java implementation treats hashing as an application service rather than reimplementing a cryptographic primitive.

`DigestService` defines the application-level contract. `Sha256DigestService` implements it with Java's standard `MessageDigest` API.

The `Artifact` record models immutable input data and its trusted expected digest. Validation rejects:

- missing artifact identifiers
- blank identifiers
- missing content
- malformed SHA-256 strings
- digests with a length other than 64 hexadecimal characters

`ArtifactVerifier` converts the digest comparison into an explicit domain result:

`RECEIVED → VERIFIED`

or

`RECEIVED → REJECTED`

The result retains the calculated digest and an explanation of the verification decision.

This separation allows repository or release systems to treat hashing as a reusable service. The cryptographic provider can be replaced without changing the artifact verification workflow.

The content is copied when entering and leaving the immutable record so external callers cannot mutate the byte array after validation.

## PostgreSQL model

The PostgreSQL implementation treats SHA-256 as part of an artifact-integrity workflow.

The relational model contains:

- repositories
- artifacts
- verification events

An artifact stores its content, expected digest, actual digest, and verification state.

The database enforces digest structure with `CHECK` constraints. A SHA-256 hexadecimal digest must contain exactly 64 lowercase hexadecimal characters.

The relationship is:

```
repositories
     |
     | 1-to-many
     v
artifacts
     |
     | 1-to-many
     v
verification_events
```

The `calculate_artifact_sha256()` function wraps PostgreSQL's `digest()` function and converts the binary result into hexadecimal using `encode()`.

`verify_artifact()` locks the artifact row during verification, calculates its digest, records an audit event, and updates the artifact state.

The transaction therefore treats verification and its resulting state transition as one database operation.

## Integrity states

The database uses an explicit state model:

| State      | Meaning                                                             |
| ---------- | ------------------------------------------------------------------- |
| `RECEIVED` | Content exists but successful verification has not been established |
| `VERIFIED` | Calculated digest matches the trusted expected digest               |
| `REJECTED` | Verification failed or the expected digest was unavailable          |

A successful verification records the calculated digest and verification timestamp.

A rejected artifact retains its calculated digest so an operator can determine what value was actually observed.

## Digest comparison

A digest comparison should not unnecessarily leak the location of the first mismatch when the digest itself is security-sensitive.

The Python implementation uses `hmac.compare_digest()`. The Java implementation compares digest bytes without returning on the first mismatch. The C++ implementation accumulates byte differences rather than stopping at the first differing character.

This is particularly relevant when a digest is used in an authentication-related protocol. For ordinary file-integrity checks, timing concerns are usually less significant than in password or authentication comparisons, but constant-time comparison is still a sound implementation practice when comparing security-sensitive values.

## Verification workflow

A practical artifact-integrity workflow can be represented as:

```
Artifact received
      |
      v
Calculate SHA-256
      |
      v
Compare with trusted digest
      |
   +--+--+
   |     |
 match  mismatch
   |     |
   v     v
VERIFIED REJECTED
```

The trusted digest must itself come from a trustworthy channel. Hashing a file and storing its digest beside the same potentially compromised file does not establish meaningful integrity.

For software distribution, stronger designs can protect the expected digest through a signed manifest, authenticated transport, a trusted package repository, or another independently protected mechanism.

## Test vectors

The implementations validate well-known SHA-256 values.

| Input         | SHA-256                                                            |
| ------------- | ------------------------------------------------------------------ |
| empty string  | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `abc`         | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `hello world` | `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9` |

The Python implementation also tests the standard one-million-`a` vector. This exercises many compression blocks and is useful for detecting errors that short examples may not expose.

## Edge cases

Important boundary conditions include:

- empty input
- input exactly near a 512-bit block boundary
- input requiring an additional padding block
- multi-block input
- large files
- missing expected digests
- malformed hexadecimal digests
- digest length errors
- repeated streaming updates
- attempts to modify a finalized C++ hash object
- tampered artifact content
- unavailable files

A particularly important boundary occurs when the original message leaves fewer than nine bytes available in its final 64-byte block. The `0x80` marker and 64-bit length cannot both fit, so SHA-256 must allocate another 512-bit block.

## Complexity

For an input of `n` bytes, SHA-256 requires time proportional to `n`.

The compression function performs a fixed 64 rounds for each 64-byte message block.

The streaming implementations use constant-size working memory apart from application buffers:

- state: 256 bits
- message schedule: 64 × 32 bits
- one 512-bit input block
- implementation-specific buffering

The Python and JavaScript direct implementations allocate padded message data for their educational one-shot processing paths. Their file-oriented workflows should use streaming APIs for large files.

## Security considerations

SHA-256 is designed to provide strong collision resistance, preimage resistance, and second-preimage resistance within its intended security model.

A hash does not authenticate its source. An attacker who can modify both a file and its expected digest can simply generate a new digest.

For this reason:

`hash + trusted reference`

is materially different from:

`hash + untrusted reference`

For password storage, raw SHA-256 is inappropriate because it is intentionally fast. Password hashing should use a dedicated password KDF with a unique salt and suitable work factor.

For message authentication, a bare SHA-256 digest is also not a replacement for an authenticated construction such as HMAC-SHA-256.

For digital signatures, SHA-256 can be used as the hash component of a signature scheme, but the signature mechanism provides the authentication property that the bare digest does not.

## Production considerations

The direct implementations are useful for understanding the algorithm, validating educational exercises, and building test vectors. Production systems should normally rely on a mature, audited cryptographic library supplied by the platform or a well-maintained cryptographic library.

Operational implementations should also consider:

- streaming large files
- protecting trusted digest values
- authenticated transport
- audit logging
- key management when HMAC or signatures are used
- secure random generation for salts and keys
- dependency and cryptographic-provider maintenance
- algorithm-agility requirements
- verification failures as explicit operational events

The PostgreSQL implementation is suitable for demonstrating database-side integrity workflows. Large binary artifact storage should be evaluated separately against storage architecture, backup requirements, database size, and retrieval patterns.

## Relationship between the five implementations

The implementations solve the same cryptographic problem at different abstraction levels.

```
                 SHA-256
                    |
       +------------+------------+
       |            |            |
   Algorithm     Runtime      Database
       |            |            |
    Python       JavaScript   PostgreSQL
    C++17          Java
       |
   compression,
   padding,
   state,
   rounds
```

Python exposes the algorithm directly and pairs it with a trusted reference implementation.

JavaScript emphasizes binary processing, JavaScript's 32-bit bitwise semantics, and asynchronous file streams.

C++ emphasizes explicit memory and state management through an incremental hashing class.

Java emphasizes domain modeling and separation between a cryptographic service and an enterprise artifact-verification workflow.

PostgreSQL treats the digest as part of persistent integrity state and an auditable verification process.

These distinctions are intentional: SHA-256 is the common mechanism, while the engineering concerns surrounding its use differ by runtime and system boundary.
