# SHA-3 and Keccak: Cryptographic Hashing and Integrity Verification

## 1. Technical Scope

SHA-3 is a family of cryptographic hash functions standardized by NIST and based on the Keccak sponge construction. Keccak is the underlying permutation-based design, but the standardized SHA-3 functions and the original Keccak submissions do not use identical domain-separation padding.

This distinction is essential for interoperability. **SHA3-256 and legacy Keccak-256 produce different digests for the same message.** They must not be treated as interchangeable algorithms.

The implementations examine five connected concerns:

- Fixed-output SHA-3 hashing.
- Extendable-output functions, or XOFs, through SHAKE.
- The Keccak-f[1600] permutation and sponge construction.
- Artifact integrity verification and binary Merkle trees.
- Persistent verification records, validation, and operational reporting.

## 2. SHA-3, Keccak, and SHAKE

### 2.1 The sponge construction

A sponge function maintains an internal state divided conceptually into a rate and a capacity.

For Keccak-f[1600], the state contains 1,600 bits, represented as 25 lanes of 64 bits each.

The sponge processes an input in blocks:

1. Apply the algorithm-specific padding and domain-separation suffix.
2. XOR each rate-sized input block into the state.
3. Apply the Keccak-f[1600] permutation after each absorbed block.
4. Extract output bytes from the rate portion of the state.
5. Apply additional permutations when a longer output is required.

For SHA3-256, the rate is 1,088 bits, or 136 bytes, and the capacity is 512 bits. The capacity contributes to the security properties of the construction.

SHA3-224, SHA3-256, SHA3-384, and SHA3-512 use different rate and capacity settings appropriate to their output sizes.

### 2.2 The Keccak-f[1600] permutation

The permutation consists of 24 rounds. Each round applies five transformations:

| Transformation | Mechanism |
|---|---|
| Theta | Mixes the parity of state columns. |
| Rho | Rotates individual 64-bit lanes. |
| Pi | Moves lanes to new positions. |
| Chi | Applies a nonlinear operation to each row. |
| Iota | XORs a round constant into the state. |

The C++17 implementation uses a 25-element array of 64-bit integers. It implements these transformations directly, absorbs data in little-endian lane order, and extracts the first 32 output bytes for SHA3-256.

The implementation is useful for studying the algorithm's structure. A production cryptographic implementation should normally use a maintained, independently tested cryptographic library with suitable security review and platform-specific optimizations.

### 2.3 Domain separation and padding

SHA-3 and legacy Keccak use different domain-separation suffixes.

For SHA3-256, the suffix begins with `0x06`, and the final byte of the padded rate block has its most significant bit set. Legacy Keccak-256 uses different padding.

The difference is not cosmetic. Changing the suffix changes the input to the permutation and therefore changes the resulting digest.

A system that calculates SHA3-256 must not verify a digest produced by a legacy Keccak-256 implementation unless it explicitly uses the same algorithm and padding convention.

### 2.4 Fixed-output functions and SHAKE

| Function | Output behavior |
|---|---|
| SHA3-224 | Always produces 28 bytes. |
| SHA3-256 | Always produces 32 bytes. |
| SHA3-384 | Always produces 48 bytes. |
| SHA3-512 | Always produces 64 bytes. |
| SHAKE128 | Produces a requested number of output bytes. |
| SHAKE256 | Produces a requested number of output bytes. |

SHAKE functions are extendable-output functions. Their output length is selected by the caller rather than fixed by the function name.

The Python implementation supports SHAKE128 and SHAKE256 with bounded output lengths. The JavaScript implementation uses Node.js's configurable `outputLength` option. The PostgreSQL model focuses on fixed-output SHA-3 digests.

A SHAKE output should be identified by its algorithm, parameters, and output length wherever those details affect protocol interoperability.

## 3. Implementation Architecture

### 3.1 Python: workflow simulation and utility functions

The Python script uses `hashlib` for the standardized digest functions.

Its main components are:

- `HashAlgorithm`: identifies supported SHA-3 and SHAKE variants.
- `HashResult`: stores the algorithm, input size, digest encoding, and output size.
- `sha3_hash`: calculates fixed-size digests or a 32-byte SHAKE result.
- `shake_hash`: generates a caller-selected number of output bytes.
- `hash_file`: processes a file incrementally in 64 KiB chunks.
- `verify_digest`: validates a supplied digest and compares it with a calculated SHA3-256 digest.
- `merkle_root_sha3`: constructs a binary Merkle tree with explicit domain separation.
- `Sha3Tests`: checks known-answer vectors, verification behavior, invalid inputs, and tree properties.

The file hashing function avoids loading an entire file into memory. Its working memory remains approximately proportional to the chunk size, rather than the size of the file.

The `keccak_vs_sha3` function optionally uses PyCryptodome to calculate legacy Keccak-256. If that optional package is unavailable, the script reports that the comparison cannot be calculated rather than substituting SHA3-256.

The core SHA-3 and SHAKE operations require only the Python standard library.

### 3.2 JavaScript: asynchronous processing and queue management

The JavaScript implementation uses Node.js cryptographic primitives and the standard library.

Its main components are:

- `hashMessage`: validates a message and calculates a supported digest.
- `shakeMessage`: configures SHAKE strength and output length.
- `verifySha3`: validates the expected hexadecimal format and uses `crypto.timingSafeEqual` for equal-length digest comparison.
- `hashFile`: streams file data through a hashing pipeline.
- `merkleRoot`: constructs a domain-separated Merkle tree.
- `DigestJobQueue`: limits active jobs and bounds the number of queued and executing requests.

The queue provides a simple event-driven processing model. Each submitted job returns a promise. A job either produces a digest or rejects with an error, and the queue schedules more work as capacity becomes available.

The queue's concurrency setting controls how many jobs it manages simultaneously. It does not guarantee parallel CPU execution: Node.js hashing and event-loop scheduling have their own runtime behavior.

Input-size limits and queue-capacity limits reduce the risk of uncontrolled memory consumption. Applications processing untrusted requests should also enforce request timeouts, authentication, and rate limits.

### 3.3 C++17: direct permutation implementation

The C++ program implements SHA3-256 without external libraries.

Its architecture separates the cryptographic primitive from the application workflow:

- `keccak_f1600` implements the 24-round permutation.
- `Sha3_256` applies padding, absorbs message blocks, runs the permutation, and extracts the digest.
- `Artifact` stores a release artifact's name, content, expected digest, and verification state.
- `RepositoryVerifier` validates artifact registration and reports whether each digest matches.

The example registers a source file with a valid expected digest and a manifest with an intentionally incorrect digest. The resulting report distinguishes verified content from rejected content.

The implementation also checks the known SHA3-256 digest for `abc`.

The digest comparison in this educational program is not constant-time. The expected digest is public, so that choice is acceptable for the demonstration, but the code should not be reused unchanged in a security-sensitive authentication protocol. The program also constructs a padded copy of the input, so its memory use is proportional to message length.

### 3.4 Java 17: enterprise verification service

The Java implementation uses `MessageDigest` for SHA-3 operations provided by the installed runtime.

The domain model includes:

- `Artifact`: validates names, content size, and expected digest format.
- `Digest`: represents a calculated digest and its metadata.
- `DigestProvider`: defines the hashing boundary.
- `JdkDigestProvider`: validates supported algorithms and calculates fixed-output digests.
- `ArtifactVerificationService`: registers artifacts, performs checks, tracks states, and produces reports.
- `VerificationPolicy`: distinguishes strict processing from report-only behavior.
- `VerificationResult`: records the verification outcome and its explanation.

The service rejects duplicate artifact names and returns an immutable status map. It clones artifact bytes at construction and when returning content, preventing callers from modifying the stored artifact through a shared array reference.

`MessageDigest.isEqual` is used to compare the binary digest values. The strict policy throws an exception if any artifact fails verification; report-only mode preserves the individual results so an operator can investigate failures.

The synchronized service methods serialize access to the registry. This favors simple state consistency over maximum throughput. A high-volume deployment could use finer-grained locking or immutable request-scoped data, depending on its concurrency requirements.

Java 17 does not provide a standard SHAKE API through `MessageDigest`. The Java implementation therefore focuses on fixed-output SHA-3 algorithms.

### 3.5 PostgreSQL: integrity registry and audit history

The SQL script creates an `integrity` schema containing three principal tables.

| Table | Responsibility |
|---|---|
| `repositories` | Identifies repositories and their owners. |
| `artifacts` | Records artifact paths, byte lengths, algorithms, and expected digests. |
| `verification_runs` | Records individual digest checks and their outcomes. |

The schema uses primary keys, foreign keys, uniqueness rules, check constraints, and indexes to enforce data integrity and support common queries.

The `validate_artifact_digest` trigger checks the digest length and hexadecimal representation. `calculate_sha3` calculates a digest from binary input. `record_verification` compares registered content metadata with supplied bytes and stores a verification result.

The `latest_artifact_verification` view exposes the most recent result for each artifact. Reporting queries show verification counts and release eligibility.

The database stores verification history instead of overwriting a single status field. This makes it possible to inspect previous successful checks, mismatches, and errors.

PostgreSQL does not automatically have access to arbitrary files on a client's computer. The caller must supply artifact bytes or use an external ingestion service.

The SQL script requires `pgcrypto` and a build whose underlying cryptographic provider supports the requested SHA-3 algorithms. It checks SHA3-256 availability before inserting sample records. Some installations will not provide that capability. In such environments, use a verified external SHA-3 implementation and persist its results through an appropriately controlled interface. Do not silently replace SHA-3 with legacy Keccak.

## 4. Artifact Integrity Workflow

The implementations use artifact verification as a concrete application of cryptographic hashing.

Plain-text diagram:

Repository  
  → Artifact registration  
  → Expected digest supplied by a trusted release process  
  → Content bytes received  
  → SHA-3 digest calculated  
  → Actual digest compared with expected digest  
  → Verification result recorded  
  → Release eligibility evaluated

The expected digest must originate from a trustworthy source. If an attacker can replace both an artifact and its expected digest, a matching hash does not establish authenticity.

A cryptographic digest establishes a content fingerprint. It does not, by itself, establish who produced the content or whether the content is authorized.

For authenticity, systems can use digital signatures, authenticated release metadata, or a suitably protected distribution channel.

## 5. Digest Verification and Failure States

The examples distinguish several conditions that should not be collapsed into a single success or failure message.

| Condition | Interpretation |
|---|---|
| Valid digest matches | The supplied bytes match the registered digest. |
| Valid digest differs | The supplied bytes do not match the expected digest. |
| Malformed digest | The expected value does not have the required encoding or length. |
| Unknown artifact | The requested artifact has not been registered. |
| Length mismatch | The content size differs from registered metadata. |
| Unsupported algorithm | The selected implementation cannot calculate the requested function. |
| Cryptographic provider failure | The required algorithm is unavailable or a provider operation fails. |

A successful comparison is evidence of integrity relative to the expected digest. It does not prove that the original artifact was safe, correctly built, or authorized.

For release pipelines, a mismatch should normally block publication until the discrepancy has been investigated.

## 6. Merkle Trees and Domain Separation

A Merkle tree combines leaf digests into a single root digest.

The Python and JavaScript implementations use SHA3-256 with different prefixes for leaf and internal nodes:

- Leaf: `SHA3-256(0x00 || data)`
- Internal node: `SHA3-256(0x01 || left || right)`
- Empty tree: `SHA3-256(0x02)`

Here, `||` means byte concatenation.

When a level contains an odd number of nodes, the final node is duplicated before the next level is calculated. This rule makes the tree construction deterministic.

The prefixes separate leaf inputs from internal-node inputs. Without a clear encoding and domain-separation rule, different structural interpretations of byte strings can create ambiguity.

A Merkle root can summarize a collection of artifacts, but a root alone does not prove membership. A verification system must also provide the appropriate sibling hashes and tree-position information for an inclusion proof.

## 7. Validation and Operational Security

The implementations apply input checks at different boundaries:

- Python validates byte-oriented messages and bounds SHAKE output lengths.
- JavaScript validates message types, digest encoding, output lengths, and queue capacity.
- C++ validates artifact names, digest lengths, hexadecimal characters, and input size.
- Java validates artifact metadata and separates calculation from verification policy.
- PostgreSQL enforces relational constraints and stores verification outcomes transactionally.

These checks prevent common application errors, but they do not replace cryptographic review.

Important operational requirements include:

- Use SHA-3 or another suitable modern cryptographic hash rather than a deprecated hash for new security-sensitive designs.
- Do not confuse a hash with encryption. Hashing does not provide confidentiality or reversible recovery.
- Do not use an unkeyed hash alone as a password-storage scheme.
- Use a keyed construction such as HMAC when a shared secret must authenticate messages, or a suitable signature scheme when public verification is required.
- Keep trusted digest manifests separate from the artifacts they authenticate.
- Apply size limits and rate limits to externally supplied content.
- Avoid logging secrets or sensitive input bytes.
- Use independent test vectors and reviewed cryptographic libraries for production systems.
- Avoid relying on implementation-specific algorithm names without checking their exact padding and output semantics.

## 8. Performance and Complexity

Let \(n\) represent the input length in bytes.

For a fixed-output SHA-3 digest, processing time is linear in the input length, with a constant cost for each absorbed block. SHAKE has the same linear input-processing behavior, plus work proportional to the requested output length.

| Operation | Approximate time | Additional memory |
|---|---|---|
| Fixed-output SHA-3 | \(O(n)\) | \(O(1)\) for a streaming implementation |
| SHAKE generation | \(O(n + m)\) | \(O(m)\) when the output is retained |
| Streaming file hash | \(O(n)\) | \(O(c)\), where \(c\) is the chunk size |
| Merkle tree construction | \(O(n + k)\) for total leaf data \(n\) and \(k\) leaves | \(O(k)\) in the provided implementations |
| Latest-result query | Depends on row counts and index selectivity | Database execution-plan dependent |

The Python file-hashing implementation uses a fixed-size chunk buffer. The JavaScript stream implementation avoids reading the entire file into memory. The C++ example prioritizes clarity and allocates the padded message. The Java implementation retains artifact bytes in the service registry, making it appropriate for bounded demonstrations rather than an unrestricted artifact repository.

The SQL indexes support repository lookups and retrieval of recent verification records. Their value should be confirmed against actual workloads and query plans.

## 9. Testing and Expected Behavior

The Python script checks the standardized SHA3-256 outputs for the empty message and `abc`. It also tests digest verification, SHAKE output sizes, Merkle-tree behavior, and invalid parameters.

The JavaScript script validates the SHA3-256 result for `abc`, processes multiple artifacts through a bounded queue, and prints digest and Merkle-root results.

The C++ program validates the same `abc` vector, verifies one correct artifact, and rejects another with an intentionally incorrect expected digest.

The Java program validates the empty-message and `abc` vectors and demonstrates report-only verification with one matching artifact and one mismatching manifest.

The PostgreSQL script inserts sample artifact metadata, calculates digests from sample content, records verification runs, and queries the latest results.

Known-answer tests are essential because a plausible-looking hexadecimal result does not prove that an implementation follows the correct padding, byte ordering, or output convention.

## 10. Execution Requirements

| Deliverable | Runtime | External dependency |
|---|---|---|
| Python | Python 3.10 or later | Standard library; PyCryptodome is optional for legacy Keccak comparison. |
| JavaScript | Node.js with SHA-3 and SHAKE support | Node.js standard library. |
| C++17 | C++17-compatible compiler | Standard library. |
| Java | Java 17 or later | JDK cryptographic provider supporting SHA-3. |
| PostgreSQL | PostgreSQL with `pgcrypto` | Underlying cryptographic provider must support the requested SHA-3 algorithms. |

The Python, JavaScript, C++, and Java programs run independently. The SQL script represents a persistent database workflow and must be executed against a compatible PostgreSQL instance.

The implementations intentionally expose different engineering concerns: direct permutation mechanics, application-level hashing, asynchronous processing, enterprise policy boundaries, and database-backed auditability. All depend on using the correct algorithm definition and maintaining a trustworthy relationship between an artifact and its expected digest.
