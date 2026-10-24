The central transformation is:

`arbitrary-length message -> padded 512-bit blocks -> compression rounds -> 256-bit digest`

The five implementations approach the mechanism from different engineering perspectives:

| Implementation | Primary perspective | Main focus |
|---|---|---|
| Python | Algorithm model | Padding, schedule expansion, compression, testing |
| JavaScript | Event-oriented systems programming | 32-bit arithmetic, buffers, runtime verification |
| C++17 | Low-level implementation | Explicit state, memory layout, streaming interface |
| Java 17 | Enterprise-oriented domain model | Type safety, validation, standard cryptographic verification |
| PostgreSQL | Data-integrity workflow | Digest storage, validation, transactions, reporting |

The implementations intentionally expose the SHA-256 compression process rather than treating the algorithm as a single library call.

## What SHA-256 Does

A cryptographic hash function maps an input of arbitrary length to a fixed-size output.

For SHA-256:

- Input: arbitrary byte sequence subject to the algorithm's length encoding
- Block size: 512 bits, or 64 bytes
- Word size: 32 bits
- Digest size: 256 bits, or 32 bytes
- Number of compression rounds per block: 64
- Number of initial state words: 8
- Final representation: eight 32-bit words

A digest is not an encrypted version of the original message.

For example:

`abc`

produces:

`ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

The fixed-size output is one of the defining properties of a cryptographic hash.

## Core Processing Pipeline

The algorithm can be viewed as six connected stages.

```text
Input bytes
    |
    v
Append 1 bit and zero padding
    |
    v
Append original length as 64-bit big-endian value
    |
    v
Split into 512-bit blocks
    |
    v
Expand each block into 64 words
    |
    v
Run 64 compression rounds
    |
    v
Add compressed state back into chaining state
    |
    v
256-bit digest

The digest depends on every processed block because the state produced by one block becomes the starting state for the next block.

## Message Padding

SHA-256 does not process arbitrary-length input directly.

The message is extended so that its final length is a multiple of 512 bits.

The padding procedure is:

1. Append a single `1` bit.
2. Append zero bits until 64 bits remain in the current 512-bit block.
3. Append the original message length as a 64-bit big-endian integer.

In byte-oriented implementations, the first step is represented by appending `0x80`.

For a message whose byte length is `L`, the padded message satisfies:

`(L + 1 + zero_padding + 8) mod 64 = 0`

The final eight bytes contain the original bit length.

The Python, JavaScript, and Java implementations explicitly construct this representation. The C++ implementation performs the same transformation in its finalization stage. PostgreSQL makes the UTF-8 byte representation explicit before passing it to `pgcrypto`.

## Why the Length Is Included

Without the encoded original length, the final block would not have a complete description of where the original message ended.

The length field also forms part of the domain separation created by the standardized padding construction.

For SHA-256, the length is encoded as an unsigned 64-bit value in big-endian order.

## 512-Bit Blocks

After padding, the message is divided into blocks of 64 bytes.

Each block contains sixteen 32-bit words:

    512-bit block
    |
    +-- W0
    +-- W1
    +-- W2
    ...
    +-- W15

Those sixteen words are expanded into a 64-word message schedule:

    W0 ... W15
         |
         v
    W16 ... W63

The expanded schedule ensures that later rounds depend on information distributed across the entire original block.

## Message Schedule

For positions `0` through `15`, the schedule contains the original block words.

For `t >= 16`:

`W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]`

The additions operate modulo `2^32`.

The small sigma functions are:

`σ0(x) = ROTR7(x) XOR ROTR18(x) XOR SHR3(x)`

`σ1(x) = ROTR17(x) XOR ROTR19(x) XOR SHR10(x)`

Here:

- `ROTR` means rotate right
- `SHR` means logical shift right
- `XOR` means exclusive OR

The Python implementation represents the schedule as a list of 64 integers. JavaScript uses `Uint32Array`. C++ uses `std::array<std::uint32_t, 64>`. Java uses an `int[64]`, where Java's defined 32-bit integer overflow supplies the required modulo-`2^32` behavior.

## Initial Hash State

SHA-256 starts with eight predefined 32-bit words:

| State word | Initial value |
|---|---|
| H0 | `6A09E667` |
| H1 | `BB67AE85` |
| H2 | `3C6EF372` |
| H3 | `A54FF53F` |
| H4 | `510E527F` |
| H5 | `9B05688C` |
| H6 | `1F83D9AB` |
| H7 | `5BE0CD19` |

The eight words form a 256-bit chaining state.

For each message block, this state is copied into working variables:

`a, b, c, d, e, f, g, h`

The compression function transforms these variables for 64 rounds.

## The Choice Function

SHA-256 uses:

`Ch(x,y,z) = (x AND y) XOR ((NOT x) AND z)`

The function selects bits from `y` or `z` depending on the corresponding bits of `x`.

It creates a data-dependent selection operation that contributes to the nonlinear behavior of the compression function.

## The Majority Function

The second Boolean primitive is:

`Maj(x,y,z) = (x AND y) XOR (x AND z) XOR (y AND z)`

For every bit position, the result corresponds to the value held by at least two of the three inputs.

`Ch` primarily appears in the `e` side of the round transformation, while `Maj` appears in the `a` side.

## Big Sigma Functions

The compression rounds use:

`Σ0(x) = ROTR2(x) XOR ROTR13(x) XOR ROTR22(x)`

`Σ1(x) = ROTR6(x) XOR ROTR11(x) XOR ROTR25(x)`

These operations combine rotations with XOR to distribute bit influence across positions.

The algorithm intentionally uses 32-bit words. Implementations must therefore preserve unsigned 32-bit semantics even when the host language represents integers differently.

## Compression Round

For round `t`, SHA-256 calculates:

`T1 = h + Σ1(e) + Ch(e,f,g) + K[t] + W[t]`

`T2 = Σ0(a) + Maj(a,b,c)`

Then the working variables shift:

    h <- g
    g <- f
    f <- e
    e <- d + T1
    d <- c
    c <- b
    b <- a
    a <- T1 + T2

All additions are modulo `2^32`.

The 64 constants `K[t]` are fixed parts of the SHA-256 specification.

## State Update

After all 64 rounds for a block, the resulting working variables are added to the previous chaining state:

    H0 <- H0 + a
    H1 <- H1 + b
    H2 <- H2 + c
    H3 <- H3 + d
    H4 <- H4 + e
    H5 <- H5 + f
    H6 <- H6 + g
    H7 <- H7 + h

The resulting state becomes the input state for the next 512-bit block.

This chaining mechanism is why the final digest depends on the sequence of all processed blocks.

## Python Implementation

The Python implementation presents the algorithm as a direct functional model.

Important components include:

| Component | Implementation |
|---|---|
| 32-bit rotation | `rotr32()` |
| Boolean primitives | `ch()` and `maj()` |
| Sigma functions | Four dedicated functions |
| Padding | `pad_message()` |
| Schedule | `build_schedule()` |
| Compression | `compress()` |
| Full hash | `sha256_bytes()` |
| Text interface | `sha256_hex()` |
| Verification | `hashlib` comparison |
| Avalanche experiment | `avalanche_experiment()` |

The implementation intentionally does not call `hashlib.sha256()` to calculate its primary result. `hashlib` is used separately as an independent verification mechanism.

The randomized tests compare many randomly generated messages against the standard-library implementation. This is useful because a SHA-256 implementation can produce correct results for short examples while still containing an error in padding, word ordering, rotation, or multi-block processing.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library facilities and emphasizes explicit 32-bit operations.

JavaScript's ordinary numeric type is IEEE-754 double precision, so the implementation uses operations such as:

- `>>>`
- `Uint32Array`
- `Buffer`
- explicit `>>> 0`
- modular addition through `add32()`

The `Buffer` type is particularly appropriate for SHA-256 because the algorithm operates on bytes rather than abstract characters.

Node's `crypto` module is used only for independent verification and randomized testing.

The implementation also exposes an avalanche experiment by modifying a single input bit and comparing the two 256-bit outputs.

## C++17 Implementation

The C++ implementation models SHA-256 as a reusable streaming class.

The `SHA256` class maintains:

- eight-word internal state
- an incomplete input buffer
- total processed byte count

The `update()` method accepts data incrementally. A full 64-byte block is immediately compressed.

This creates a realistic distinction between:

`update(data)`

and:

`final()`

The finalization operation handles the remaining bytes, padding, length encoding, and final compression blocks.

C++ is particularly suitable for exposing the low-level characteristics of SHA-256 because `std::uint32_t` gives an explicit 32-bit unsigned representation.

The implementation also avoids external cryptographic libraries so that the compression logic remains visible.

## Java 17 Implementation

The Java implementation models the algorithm with explicit methods while using Java's standard library for byte encoding and independent verification.

Java `int` is exactly 32 bits, which is convenient for SHA-256. Java integer overflow wraps around in two's-complement arithmetic, corresponding to modulo `2^32` for the unsigned word operations used by SHA-256.

Important components include:

- `pad()`
- `compress()`
- `hash(byte[])`
- `hash(String)`
- `hammingDistance()`
- known-answer tests
- JDK `MessageDigest` verification

`MessageDigest` is not used to replace the educational compression implementation. It acts as a reference implementation for detecting mistakes.

## PostgreSQL Implementation

The PostgreSQL implementation treats SHA-256 as a database integrity mechanism rather than reproducing the compression algorithm in procedural SQL.

The `pgcrypto` extension supplies the database's cryptographic digest operation.

The relational model contains:

    hash_messages
          |
          +---- verification_runs
          |
          +---- avalanche_experiments

`hash_messages` stores:

- original text
- UTF-8 byte representation
- algorithm
- raw 32-byte digest
- generated hexadecimal digest
- byte length
- creation timestamp

The database constraint:

`message_bytes = convert_to(message_text, 'UTF8')`

makes the relationship between the logical text and the actual hashed bytes explicit.

## Raw Digest Versus Hexadecimal Digest

A SHA-256 digest contains 32 bytes.

Hexadecimal encoding represents those 32 bytes using 64 characters.

For example:

`32 bytes -> 64 hexadecimal characters`

The PostgreSQL model stores the raw digest in `BYTEA` because it is the compact representation.

A generated `TEXT` column provides hexadecimal output for reporting and interoperability.

This distinction matters when comparing storage formats and designing indexes.

## Database-Level Integrity

The PostgreSQL trigger verifies that a stored digest actually corresponds to the stored message.

The trigger calls:

`calculate_sha256(NEW.message_text)`

and rejects the row when the supplied digest does not match.

This protects against an application that accidentally writes:

    message = A
    digest = hash(B)

Database constraints and triggers are valuable here because application-level validation alone can be bypassed by another writer or an incorrect integration.

## Verification Workflow

The database models verification as a separate event.

    Stored message
          |
          v
    Recalculate SHA-256
          |
          v
    Compare with supplied digest
          |
          +---- match ----> verified
          |
          +---- mismatch -> mismatch

This separates the immutable content record from individual verification attempts.

A mismatch record is retained instead of silently discarded. That creates an audit trail for integrity failures.

## Avalanche Effect

A cryptographic hash should exhibit a strong avalanche effect.

A small change in the input should produce a substantially different output.

The implementations change one input bit and calculate the Hamming distance between the two 256-bit digests.

The distance is:

`number of different output bits`

For two unrelated-looking 256-bit outputs, a value near half the output width is expected statistically.

The experiment does not prove cryptographic security. It provides an observable demonstration of diffusion.

## Multi-Block Messages

The algorithm is not limited to messages shorter than one block.

For a larger message:

    Message
      |
      +-- Block 0 -> State 0
      |
      +-- Block 1 -> State 1
      |
      +-- Block 2 -> State 2
      |
      +-- ...
      |
      +-- Final block -> Final state

Each block modifies the chaining state.

The C++ implementation exposes this behavior naturally through its streaming `update()` method. The Python, JavaScript, and Java implementations process the padded representation block by block.

## UTF-8 and Byte-Level Hashing

SHA-256 hashes bytes, not programming-language strings.

The text:

`SHA-256`

must first be converted to a byte sequence.

The implementations use UTF-8 for text inputs.

This matters for non-ASCII characters because different encodings produce different byte sequences and therefore different digests.

The PostgreSQL implementation makes the conversion explicit with:

`convert_to(text, 'UTF8')`

The JavaScript implementation uses `Buffer.from(text, 'utf8')`.

The Java implementation uses `StandardCharsets.UTF_8`.

## Hashing Is Not Encryption

Encryption is designed to be reversible when the appropriate key is available.

Hashing is designed to produce a fixed-size output from which recovering the original message is computationally infeasible under the intended security assumptions.

| Property | Encryption | SHA-256 |
|---|---|---|
| Primary purpose | Confidentiality | Integrity and fingerprinting |
| Reversible with key | Yes | No |
| Fixed-size output | Usually no | Yes |
| Secret key required | Usually | No |
| Suitable for file integrity | Indirectly | Yes |
| Suitable for password storage alone | No | No |

A SHA-256 digest does not hide information in the same sense as encryption.

## Collision Resistance

A collision occurs when two distinct inputs produce the same digest.

Because SHA-256 has 256 output bits, there are only `2^256` possible digest values even though the input space is much larger.

Therefore collisions must exist mathematically.

Cryptographic collision resistance means finding a practical collision should be computationally infeasible under the algorithm's intended security assumptions.

This distinction is important:

`collisions exist` does not imply `collisions are practically discoverable`.

## Preimage Resistance

Given a digest:

`h`

a preimage attack attempts to find an input:

`m`

such that:

`SHA-256(m) = h`

The intended security property is that recovering such an input should require computational work that is infeasible for properly selected targets.

This does not mean every input is secret. If an attacker knows the input is one of a small set of possibilities, they can hash each candidate.

For example, hashing a short public word does not make the word confidential.

## Password Security

Raw SHA-256 is not a suitable password-storage mechanism.

The algorithm is intentionally fast. That is valuable for file integrity and general hashing, but dangerous for password storage because attackers can test large numbers of guesses quickly.

Password systems should use a dedicated password-hashing design with:

- unique salts
- memory or computation cost
- configurable work factors
- resistance to high-rate guessing

The source files deliberately use SHA-256 for hashing demonstrations rather than presenting it as a password-storage scheme.

## Integrity Versus Authentication

A SHA-256 digest can detect accidental modification when the expected digest is trusted.

It does not prove who created the digest.

An attacker who can modify both:

`file`

and:

`file.sha256`

can recompute the digest.

Authentication requires a secret-key MAC such as HMAC or a digital signature when public verification is required.

This gives a useful distinction:

    SHA-256
      -> "Does this data produce this digest?"

    HMAC-SHA-256
      -> "Was this data authenticated with the shared secret?"

    Digital signature
      -> "Can this signature be verified against the public key?"

## Performance

For a message containing `n` bytes, the compression work is proportional to the number of 64-byte blocks.

The asymptotic processing cost is:

`O(n)`

The final digest size remains constant:

`O(1)` output size

The working memory required for a streaming implementation is also effectively constant with respect to message size, excluding the caller's input storage.

The C++ implementation demonstrates this explicitly by processing complete blocks during `update()` instead of retaining the entire message.

## Space Characteristics

The core compression operation requires:

- eight 32-bit state words
- a 64-word message schedule in the direct implementations
- one 64-byte block

A memory-optimized implementation can avoid storing the entire 64-word schedule at once by using a circular schedule buffer.

The provided implementations favor clarity over that optimization.

## Error Conditions

The implementations validate several classes of incorrect input:

| Failure | Handling |
|---|---|
| Wrong Python input type | `TypeError` |
| Invalid JavaScript input type | `TypeError` |
| Invalid block size | Explicit exception |
| Invalid avalanche input | Validation error |
| Null Java input | `IllegalArgumentException` |
| Incorrect stored PostgreSQL digest | Trigger rejection |
| Invalid digest length | Database constraint |
| Invalid hexadecimal digest | Verification function error |

Cryptographic implementations benefit from explicit validation because a silent byte-order or length error can produce consistently incorrect results that look superficially valid.

## Testing Strategy

The source files use three important forms of verification.

### Known-Answer Tests

Known values such as the SHA-256 digest of:

`abc`

are compared against expected standardized results.

This detects basic algorithm errors.

### Independent Reference Tests

The custom implementations are compared against:

- Python `hashlib`
- Node.js `crypto`
- Java `MessageDigest`

The reference implementation is intentionally separated from the custom compression logic.

### Randomized Tests

The Python and JavaScript programs generate random inputs and compare custom results with trusted implementations.

Randomized testing is especially useful for:

- empty inputs
- short inputs
- block boundaries
- multi-block inputs
- unusual byte patterns

## Important Boundary Cases

The padding logic has important boundaries around message lengths close to a block boundary.

For example, an input whose length leaves exactly eight bytes available after appending `0x80` cannot fit the eight-byte length field in the same block.

That causes an additional 64-byte block.

This is why padding code should not simply append a fixed number of zero bytes.

The implementations calculate the required padding dynamically.

## Endianness

SHA-256 interprets block words and length fields in big-endian order.

For example, four bytes:

`01 02 03 04`

represent:

`0x01020304`

The implementations explicitly read and write 32-bit words in big-endian form.

This is important because host processors may use little-endian memory layouts.

## Security Design Considerations

A production system should generally use a well-tested cryptographic library rather than maintaining a custom SHA-256 implementation.

The custom implementations are useful for understanding:

- message padding
- word expansion
- Boolean functions
- rotations
- modular arithmetic
- state transitions
- compression

Production cryptography should favor reviewed and maintained implementations.

The source programs therefore use standard library implementations as independent verification references.

## Practical Uses

SHA-256 is commonly useful for:

- file integrity checks
- content addressing
- artifact identification
- software release verification
- digital-signature inputs
- Merkle-tree construction
- blockchain data structures
- deduplication identifiers
- integrity metadata

The digest alone does not automatically provide confidentiality or sender authentication.

## Conceptual Data Flow

    SHA-256

    Input bytes
         |
         v
    UTF-8 / raw bytes
         |
         v
    SHA-256 pad
         |
         v
    +-----------------------+
    | 512-bit message block |
    +-----------------------+
         |
         v
    16 initial 32-bit
    words
         |
         v
    64-word schedule
         |
         v
    +----------------------+
    | 64 compression rounds|
    +----------------------+
         |
         v
    Updated 256-bit
    state
         |
    more blocks?
      /       \
    yes        no
     |          |
     +----<-----+
                |
                v
          256-bit digest

## Relationship Between the Five Implementations

The implementations are deliberately complementary.

Python exposes the mathematical structure directly.

JavaScript emphasizes byte buffers and explicit 32-bit runtime behavior.

C++ demonstrates a streaming, low-level implementation where state and memory handling are explicit.

Java models the algorithm with strong typing and uses the JDK cryptographic provider as an independent verification mechanism.

PostgreSQL moves the focus from algorithm internals to operational data integrity, including storage, constraints, triggers, verification records, indexes, and transactions.

The same underlying SHA-256 mechanism therefore appears in five different engineering contexts without requiring each implementation to be a mechanical translation of another.

## What the Implementations Demonstrate

The complete workflow is:

    Message
      |
      v
    Encoding
      |
      v
    Padding
      |
      v
    512-bit block
      |
      v
    16 words
      |
      v
    64-word schedule
      |
      v
    64 rounds
      |
      v
    State update
      |
      v
    Next block
      |
      v
    Final 256-bit digest

The accompanying tests then establish:

    Custom implementation
            |
            +---- known-answer tests
            |
            +---- standard-library comparison
            |
            +---- randomized testing
            |
            +---- avalanche experiment
            |
            +---- database integrity validation

This separation between algorithm mechanics, independent verification, and operational integrity is the central design principle of the five artifacts.
