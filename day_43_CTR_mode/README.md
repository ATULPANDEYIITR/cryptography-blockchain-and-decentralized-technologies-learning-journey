# CTR Mode: Counter-Based Stream Encryption

## Technical scope

Counter mode (CTR) converts a block cipher such as AES into a stream-like encryption mechanism. It encrypts successive counter blocks to generate a keystream, then XORs that keystream with the message. The same operation transforms ciphertext back into plaintext.

CTR is useful when a system needs encryption without padding, independent processing of blocks, or access to a specific byte range. Its main security limitation is that it provides confidentiality without built-in integrity or authenticity.

The accompanying implementations examine the counter mechanism from different perspectives:

- **Python:** explicit keystream generation, counter validation, chunk alignment, random-access transformation, file processing, tests, and authenticated-encryption comparisons.
- **JavaScript:** Node.js cryptographic APIs, asynchronous transfer events, input validation, nonce tracking, and authenticated record processing.
- **C++:** a repository-independent case study of an inspection-record transport service, with a deliberately nonsecure block-cipher substitute to make counter mechanics and exhaustion visible.
- **Java:** a service-oriented transfer model using Java Cryptography Architecture, immutable key and counter wrappers, transfer-state validation, and AES-GCM authentication.
- **PostgreSQL:** a relational ledger for key identities, counter allocations, transfer states, and audit events. The database coordinates metadata but does not perform AES encryption.

## CTR construction

Let \(E_K\) denote encryption under block-cipher key \(K\), and let \(T_i\) denote the counter block for position \(i\).

The keystream block is

\[
S_i = E_K(T_i)
\]

Encryption produces

\[
C_i = P_i \oplus S_i
\]

Decryption produces

\[
P_i = C_i \oplus S_i
\]

The identity \(x \oplus y \oplus y = x\) explains why encryption and decryption use the same transformation. The block cipher itself is still an encryption primitive; CTR does not require the block cipher's decryption operation.

A counter block must never repeat under the same key. If two messages reuse the same key and counter sequence, they reuse their keystream. For corresponding ciphertext bytes,

\[
C^{(1)} \oplus C^{(2)}
=
P^{(1)} \oplus P^{(2)}
\]

The key cancels out of the expression, exposing a relationship between the plaintexts. Predictable or partially known plaintext can make this failure particularly damaging.

## Counter layout and allocation

A counter block is commonly 128 bits when used with AES. A protocol must define its layout, byte order, initial value, and increment rule.

The Python example treats the entire 128-bit block as a big-endian integer. The JavaScript example delegates the counter sequence to Node.js's AES-CTR implementation. The Java example passes a complete initial counter block to the JCA provider. These implementations are compatible only when their initial counter values and counter-increment conventions match.

Some protocols divide the block into a nonce prefix and a counter field. In that design, only the counter field increments. Other implementations increment a complete block. These conventions must not be mixed.

For an \(n\)-bit counter field, the number of distinct values is \(2^n\). Once the counter space is exhausted, a system must reject further processing or allocate a fresh, nonoverlapping sequence under a suitable key-management policy. Wrapping to zero is not a safe recovery mechanism.

A counter allocator must account for the complete range used by each message, not only its initial counter. If a message begins at counter \(a\) and consumes \(m\) blocks, its allocation covers the counter values from \(a\) through \(a+m-1\).

## Handling partial blocks

CTR does not require PKCS padding. A message containing 23 bytes consumes two 16-byte keystream blocks, using only the first seven bytes of the second block.

This property makes CTR convenient for arbitrary-length records. It also creates a streaming implementation requirement: processing must preserve the byte position within a partially consumed keystream block.

The Python implementation's `transform_at` method calculates the counter block and intra-block offset for a requested byte range. Its streaming interface maintains a cumulative byte offset across chunks. Independently starting a new CTR cipher for each chunk with the same initial counter would restart the keystream and is incorrect.

The JavaScript implementation uses Node.js's streaming cipher interface for a complete message. Its chunk-splitting example focuses on message boundaries and event processing, rather than pretending each chunk can independently restart the counter.

## Random access and parallel processing

CTR blocks can be generated independently when their counter values are known. This allows parallel processing of distinct counter blocks and supports random access.

For a byte offset \(o\), the first required block index is

\[
b = \left\lfloor \frac{o}{16} \right\rfloor
\]

The byte position within that block is

\[
r = o \bmod 16
\]

The processor begins with the counter corresponding to block \(b\), skips the first \(r\) keystream bytes, and transforms the requested data.

The Python code demonstrates this behavior directly. Such an interface is useful for large encrypted objects and indexed data, provided the application records the correct initial counter and prevents overlapping counter reuse.

Parallel implementations must assign distinct counter ranges to concurrent workers. A worker must not receive a range already assigned to another message under the same key.

## Why CTR does not authenticate data

CTR is malleable. If an attacker changes a ciphertext bit, the corresponding plaintext bit changes when the receiver decrypts it. CTR has no built-in mechanism to detect this modification.

A successful decryption operation therefore does not prove that the ciphertext is authentic, complete, or unmodified. Applications must not treat valid-looking plaintext as proof of integrity.

Authentication can be supplied by a correctly designed authenticated-encryption construction. AES-GCM is included in the Python, JavaScript, and Java implementations to demonstrate this distinction.

AES-GCM combines encryption with an authentication tag. It also supports associated authenticated data (AAD), which authenticates metadata without encrypting it. For example, a record identifier, schema version, or message type can be authenticated alongside the ciphertext.

A receiver must verify the tag before trusting the recovered plaintext. Authentication failure must result in rejection, not partial acceptance of unverified data.

Nonce requirements depend on the mode. CTR requires nonrepeating counter blocks under a given key. AES-GCM has strict nonce-uniqueness requirements and commonly uses a 96-bit nonce. Nonce generation and allocation must be designed for the deployment's concurrency, restart, and recovery behavior.

## Python implementation

The Python program implements the CTR mechanics using the `cryptography` package's AES primitive. It deliberately encrypts counter blocks using the AES block-encryption operation, then performs the XOR in application code.

The `encode_counter` and `decode_counter` functions make byte order explicit. `CTRParameters` validates key length and the initial counter range. `AESCTR.transform_at` checks counter exhaustion before processing the requested range.

`iter_transform` illustrates how chunked processing preserves stream alignment. `encrypt_file` and `decrypt_file` read files in bounded-size chunks instead of loading the complete file into memory. The example is educational: the file format does not store the key or counter and provides no authentication or crash-safe publication.

The unit tests exercise empty messages, partial blocks, multi-block data, random-access offsets, invalid keys, negative offsets, counter overflow, chunk boundaries, and nonce reuse.

The `NonceRegistry` is an in-memory safety demonstration. It does not provide durable protection across restarts or coordinate separate application instances. A real allocator needs durable state, concurrency control, key lifecycle management, and recovery procedures.

## JavaScript implementation

The JavaScript file uses Node.js's built-in `crypto` module. `createCipheriv` and `createDecipheriv` supply the AES-CTR primitive, while Buffer objects represent binary keys, counters, nonces, ciphertext, and plaintext.

The `incrementCounter` function illustrates fixed-width counter arithmetic and detects overflow. The `CTRJob` class models a transfer as an event-driven operation with explicit `created`, `running`, `completed`, and `failed` states. It emits lifecycle events so an application can connect encryption to monitoring and transfer orchestration.

`NonceLedger` demonstrates per-key duplicate detection. Its memory-only storage is not a production allocation service. The AES-GCM functions show how authenticated data is supplied and how a modified tag or associated-data value causes verification to fail.

Asynchronous orchestration does not itself make cryptography safer. The critical controls remain unique counter allocation, correct key handling, error propagation, and authenticated processing where integrity is required.

## C++ case study

The C++ program models an inspection-record transport system. An inspection service protects a record containing a record identifier, classification, and binary payload before sending it to a central records service.

The `EducationalCTR` class calculates block indexes, preserves partial-block offsets, validates the available counter range, and transforms arbitrary-length data. `NonceAllocationService` tracks allocated nonce labels by key identifier, while `RecordTransport` connects the transformation to the record-transfer workflow.

The program intentionally uses `EducationalBlockCipher`, which is a deterministic demonstration mapping and not a secure block cipher. It allows the program to compile with C++17 and the standard library alone. Its output is not suitable for protecting real records.

This limitation is important: CTR is only as secure as the underlying block cipher and the correctness of counter allocation. Replacing the demonstration primitive with an ad hoc algorithm would not create a secure AES implementation.

The restricted eight-bit counter field makes exhaustion easy to reproduce. The program rejects a request that would consume more counter blocks than remain available. A real AES-based implementation would use a vetted cryptographic library and a protocol-specific counter layout.

## Java implementation

The Java program represents key material, counter blocks, cryptographic operations, and transfer state as separate classes.

`KeyMaterial` validates supported AES key lengths and returns defensive copies of key bytes. `CounterBlock` makes the initial counter immutable and exposes checked counter advancement. `CTRService` uses the JCA transformation `AES/CTR/NoPadding`, ensuring arbitrary-length messages do not require padding.

`InspectionTransfer` restricts encryption to a new transfer and verifies the recovered payload before moving to its verified state. The `NonceRegistry` uses synchronized allocation to prevent duplicate entries within one running process.

These abstractions clarify ownership and state transitions, but they do not replace secure key storage, distributed nonce allocation, or authenticated encryption. The sample registry loses its state when the process exits, and the transfer verification operation compares recovered bytes with the original payload rather than authenticating a received message independently.

The AES-GCM methods provide the authenticated alternative. They use a 128-bit authentication tag and reject modified associated data or ciphertext during final verification.

## PostgreSQL data model

The SQL script records cryptographic operations without attempting to implement AES in the database.

| Table | Responsibility |
|---|---|
| `crypto_keys` | Identifies algorithms, key versions, and lifecycle status without storing raw key material. |
| `counter_allocations` | Records initial counter values, nonce prefixes, block counts, and allocation ownership. |
| `encrypted_transfers` | Tracks transfer metadata, byte lengths, key references, authentication mode, and processing state. |
| `transfer_events` | Stores an audit trail of state changes. |

Foreign keys ensure that transfers reference known keys and allocations. Unique constraints prevent repeated allocation identifiers and duplicate starting values for the same key and nonce prefix. Check constraints enforce supported states, nonnegative lengths, and equal plaintext and ciphertext lengths for CTR.

The `enforce_transfer_transition` trigger rejects invalid state changes and prevents the key and allocation references from changing after a transfer has been created. The audit trigger records transfer creation and state transitions. Indexes support queries by transfer state, key, allocation time, and event history.

These constraints do not establish that counter ranges never overlap. The unique allocation constraint only prevents duplicate starting values; two allocations with different starting values could still overlap. A production implementation must enforce range exclusion or allocate ranges through a serialized, transactional service. PostgreSQL range types and exclusion constraints can be useful when a range representation fits the counter layout.

The database records whether an application claims external authentication, but it cannot infer that a cryptographic tag was correctly verified merely from a state label. Verification evidence must come from trusted application logic, and access to audit tables must be controlled.

## Operational failure modes

**Counter reuse:** Reusing a counter block under the same key repeats the keystream. Allocation must be coordinated across concurrent workers, restarts, replicas, and retries.

**Counter overflow:** A request that exceeds the remaining counter space must fail before any partial result is accepted. The initial value alone does not determine safety; message length determines the number of required blocks.

**Chunk misalignment:** Restarting the stream at the beginning of each chunk produces incorrect results and may repeat keystream. Stream offsets must account for bytes already processed.

**Ciphertext modification:** CTR decryption will generally return modified plaintext instead of reporting an integrity failure. Authenticate data before accepting it.

**Key confusion:** Counter allocation must be associated with an unambiguous key identity and version. Reusing a counter under a genuinely different key is not the same failure as reusing it under the same key, but unreliable key identifiers can undermine the allocation service.

**Incomplete file publication:** Streaming output can leave a partially written destination after a crash. Production file workflows should use authenticated records, temporary output files, atomic publication where available, and recovery procedures.

**Misleading tests:** A round-trip test can pass even when the counter scheme is insecure. Tests must also cover nonce allocation, tampering, overflow, metadata validation, and cross-process behavior.

## Performance and deployment considerations

CTR permits block-level parallelism because each counter block can be encrypted independently. Actual throughput depends on the cryptographic provider, hardware acceleration, buffer sizes, and application architecture.

Streaming reduces memory use for large files, while random access avoids processing unrelated preceding bytes. These benefits introduce requirements for offset calculation, counter-range management, and reliable metadata storage.

Key material should be managed separately from encrypted payloads. Counter or nonce values are not generally secret, but they are security-critical metadata. Logs should record key identifiers and allocation decisions without exposing raw keys or sensitive plaintext.

For network protocols, a vetted authenticated-encryption construction is generally preferable to standalone CTR. If a legacy protocol requires CTR, its integrity mechanism, counter layout, allocation strategy, failure handling, and compatibility rules must be explicitly defined and independently reviewed.

The examples are designed to expose the mechanics and failure modes of counter mode. The Python, JavaScript, and Java implementations use standard cryptographic providers for AES operations. The C++ example is deliberately nonsecure, and the PostgreSQL schema is an operational ledger rather than a cryptographic implementation.
