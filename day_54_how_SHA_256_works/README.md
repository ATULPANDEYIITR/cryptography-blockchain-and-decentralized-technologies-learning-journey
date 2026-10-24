# 🔐 SHA-256 Cryptographic Hashing
### A Multi-Language Engineering Study: Python, JavaScript, C++17, Java 17, and PostgreSQL

---

## 📌 1. Project Overview

SHA-256 is a cryptographic hash function belonging to the SHA-2 family. It transforms an arbitrary-length input byte sequence into a fixed-length, 256-bit digest.

The central transformation is:

```text
╔══════════════════════════════════════════════════════╗
║                 SHA-256 PIPELINE                     ║
╚══════════════════════════════════════════════════════╝

 Arbitrary-Length Message
           │
           ▼
     Message Padding
           │
           ▼
   512-Bit Message Blocks
           │
           ▼
   16 Initial 32-Bit Words
           │
           ▼
   64-Word Message Schedule
           │
           ▼
    64 Compression Rounds
           │
           ▼
   Chaining State Update
           │
           ▼
     256-Bit Digest
```

The five implementations approach the mechanism from different engineering perspectives.

| Implementation | Primary perspective | Main focus |
|---|---|---|
| Python | Algorithm modeling | Padding, schedule expansion, compression, and testing |
| JavaScript | Runtime-oriented programming | 32-bit arithmetic, buffers, and verification |
| C++17 | Low-level implementation | Explicit state, memory layout, and streaming |
| Java 17 | Strongly typed application design | Validation, domain modeling, and cryptographic verification |
| PostgreSQL | Data-integrity engineering | Digest storage, validation, transactions, and reporting |

The implementations intentionally expose the SHA-256 compression process rather than treating the algorithm as a single library call. PostgreSQL is the exception: it uses the `pgcrypto` extension to provide the cryptographic digest operation and concentrates on database integrity.

---

## 🎯 2. Project Objectives

This project demonstrates how SHA-256 works internally and how the same cryptographic mechanism can be applied across different programming environments.

The main objectives are to:

- Understand the complete SHA-256 processing pipeline.
- Implement message padding and 64-bit length encoding.
- Expand 512-bit blocks into 64-word message schedules.
- Implement the Boolean functions and bitwise rotation operations.
- Perform 64 compression rounds per block.
- Preserve 32-bit modular arithmetic across programming languages.
- Process multi-block messages correctly.
- Convert text into UTF-8 bytes before hashing.
- Verify custom implementations against trusted cryptographic libraries.
- Demonstrate the avalanche effect through Hamming-distance measurements.
- Store and verify digests using PostgreSQL.
- Distinguish integrity checking from encryption and authentication.
- Identify the limitations of educational cryptographic implementations.

---

## 📐 3. SHA-256 at a Glance

| Property | Value |
|---|---|
| Algorithm family | SHA-2 |
| Standardized output | 256 bits |
| Digest size | 32 bytes |
| Hexadecimal digest length | 64 characters |
| Block size | 512 bits |
| Block size in bytes | 64 bytes |
| Word size | 32 bits |
| Initial state | Eight 32-bit words |
| Compression rounds | 64 per block |
| Initial message words | 16 |
| Expanded message words | 64 |
| Length field | 64-bit big-endian integer |
| Arithmetic | Modulo \(2^{32}\) |
| Input | Arbitrary byte sequence within the specification's length limit |
| Output | Fixed-length digest |

A digest is not an encrypted representation of the original message. SHA-256 is a one-way cryptographic hash function designed to provide properties such as preimage resistance and collision resistance.

### Example

Input:

```text
abc
```

Expected SHA-256 digest:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

The same input bytes always produce the same SHA-256 digest.

---

## ⚙️ 4. Core Processing Pipeline

SHA-256 processes the input through six connected stages.

### Stage 1: Input Encoding

Text is converted into bytes before hashing.

For example, the string `SHA-256` can be encoded using UTF-8.

The algorithm operates on bytes, not on abstract characters.

### Stage 2: Message Padding

The input is extended until its length is a multiple of 512 bits.

The original message length is encoded in the final 64 bits.

### Stage 3: Block Division

The padded message is divided into blocks of 64 bytes.

Each block is processed independently by the compression function, while the chaining state connects successive blocks.

### Stage 4: Message Schedule Expansion

Each 512-bit block initially contains 16 words of 32 bits each.

These words are expanded into a schedule of 64 words.

### Stage 5: Compression

The algorithm initializes eight working variables from the current state and performs 64 rounds of bitwise operations, modular additions, and state transitions.

### Stage 6: State Update and Digest Generation

After each block, the working variables are added to the previous state.

Once all blocks have been processed, the eight state words form the final 256-bit digest.

---

## 🧩 5. Message Padding

SHA-256 cannot directly process an arbitrary-length message as a single compression input. It first applies a standardized padding procedure.

The steps are:

1. Append a single `1` bit.
2. Append zero bits until the message length is 64 bits short of a multiple of 512 bits.
3. Append the original message length as a 64-bit big-endian integer.

In byte-oriented implementations, the first step is represented by appending the byte `0x80`.

Let \(L\) be the original message length in bytes. The number of zero-padding bytes \(k\) satisfies:

\[
(L+1+k+8)\bmod 64=0
\]

Equivalently:

\[
k=(56-(L+1)\bmod 64)\bmod 64
\]

The padded message length is therefore a multiple of 64 bytes.

### Padding Structure

```text
┌───────────────────────────────┬───────────────────────┐
│ Original Message              │ Padding and Length    │
├───────────────────────────────┼───────────────────────┤
│ Original bytes                │ 0x80                  │
│                               │ Zero padding          │
│                               │ 64-bit original length│
└───────────────────────────────┴───────────────────────┘

                 Total length: multiple of 64 bytes
```

### Why Padding Matters

Padding ensures that every compression input has exactly 512 bits.

It also incorporates the original message length into the standardized processing format.

The Python, JavaScript, and Java implementations explicitly construct the padded representation. The C++ implementation performs the same operation during finalization. PostgreSQL converts the input to UTF-8 bytes before invoking `pgcrypto`.

### Important Boundary Case

Suppose an input leaves exactly eight bytes available in a block after the `0x80` byte has been appended.

Those eight bytes are needed for the original length field, so the padding cannot fit in that block. A second block must be created.

This is why padding must be calculated dynamically instead of appending a fixed number of zero bytes.

---

## 🔢 6. Processing 512-Bit Blocks

After padding, the message is divided into 64-byte blocks.

Each block contains 512 bits:

\[
512=16\times32
\]

The block is interpreted as sixteen 32-bit words.

```text
512-BIT MESSAGE BLOCK
         │
         ▼
┌────┬────┬────┬────┬────┬────┬────┬────┐
│ W0 │ W1 │ W2 │ W3 │ W4 │ W5 │ W6 │ W7 │
├────┼────┼────┼────┼────┼────┼────┼────┤
│ W8 │ W9 │ W10│ W11│ W12│ W13│ W14│ W15│
└────┴────┴────┴────┴────┴────┴────┴────┘
                     │
                     ▼
           Message Schedule Expansion
                     │
                     ▼
           W0, W1, ... W63
```

The expanded schedule allows later compression rounds to depend on information distributed throughout the original block.

### Big-Endian Interpretation

SHA-256 interprets each four-byte word in big-endian order.

For example:

```text
Bytes: 01 02 03 04
Word:  0x01020304
```

This interpretation must be implemented explicitly because the host processor may use a different native byte order.

---

## 🧮 7. Message Schedule Expansion

The message schedule contains 64 words:

\[
W_0,W_1,\ldots,W_{63}
\]

The first sixteen words come directly from the input block.

For \(t\geq16\), the remaining words are calculated using:

\[
W_t =
\sigma_1(W_{t-2})+
W_{t-7}+
\sigma_0(W_{t-15})+
W_{t-16}
\pmod {2^{32}}
\]

The small sigma functions are:

\[
\sigma_0(x)=
\operatorname{ROTR}^{7}(x)
\oplus
\operatorname{ROTR}^{18}(x)
\oplus
\operatorname{SHR}^{3}(x)
\]

\[
\sigma_1(x)=
\operatorname{ROTR}^{17}(x)
\oplus
\operatorname{ROTR}^{19}(x)
\oplus
\operatorname{SHR}^{10}(x)
\]

Where:

- `ROTR` means rotate right.
- `SHR` means logical shift right.
- \(\oplus\) means exclusive OR.
- All schedule additions are performed modulo \(2^{32}\).

### Implementation Differences

| Language | Representation |
|---|---|
| Python | List of 64 integers with explicit 32-bit masking |
| JavaScript | `Uint32Array` with explicit unsigned conversion |
| C++17 | `std::array<std::uint32_t, 64>` |
| Java 17 | `int[64]` with defined 32-bit integer overflow |
| PostgreSQL | Schedule expansion is handled internally by `pgcrypto` |

Java's signed `int` representation does not prevent it from implementing SHA-256. Bitwise operations work on the 32-bit representation, and integer overflow preserves the required low-order 32 bits.

---

## 🔐 8. Initial Hash State

SHA-256 begins with eight predefined 32-bit state words.

| State word | Initial hexadecimal value |
|---|---|
| H0 | `6A09E667` |
| H1 | `BB67AE85` |
| H2 | `3C6EF372` |
| H3 | `A54FF53F` |
| H4 | `510E527F` |
| H5 | `9B05688C` |
| H6 | `1F83D9AB` |
| H7 | `5BE0CD19` |

Together, these eight words form a 256-bit chaining state.

For each message block, the current state is copied into eight working variables:

\[
a,b,c,d,e,f,g,h
\]

The compression function updates these variables for 64 rounds.

The initial state is defined by the SHA-256 specification and must not be replaced with arbitrary values when implementing the standard algorithm.

---

## 🧠 9. Boolean Functions

SHA-256 uses two important Boolean functions: `Ch` and `Maj`.

### 9.1 Choice Function

\[
\operatorname{Ch}(x,y,z)=
(x\land y)\oplus(\neg x\land z)
\]

For each bit position, the function selects a bit from \(y\) or \(z\) according to the corresponding bit of \(x\).

It contributes to the nonlinear behavior of the compression function.

### 9.2 Majority Function

\[
\operatorname{Maj}(x,y,z)=
(x\land y)\oplus(x\land z)\oplus(y\land z)
\]

For each bit position, the result is the bit value held by at least two of the three inputs.

The choice function is used on the `e` side of the compression round, while the majority function is used on the `a` side.

---

## 🔄 10. Big Sigma Functions

The compression rounds use two additional functions:

\[
\Sigma_0(x)=
\operatorname{ROTR}^{2}(x)
\oplus
\operatorname{ROTR}^{13}(x)
\oplus
\operatorname{ROTR}^{22}(x)
\]

\[
\Sigma_1(x)=
\operatorname{ROTR}^{6}(x)
\oplus
\operatorname{ROTR}^{11}(x)
\oplus
\operatorname{ROTR}^{25}(x)
\]

These functions differ from the small sigma functions used during message schedule expansion.

| Function | Purpose |
|---|---|
| \(\sigma_0\) | Message schedule expansion |
| \(\sigma_1\) | Message schedule expansion |
| \(\Sigma_0\) | Compression round transformation |
| \(\Sigma_1\) | Compression round transformation |

The big sigma functions use rotations and XOR to redistribute bit influence across word positions.

Correct rotation counts and correct distinctions between the small and big sigma functions are essential to matching the standardized SHA-256 output.

---

## ⚡ 11. Compression Rounds

Each block undergoes 64 compression rounds.

For round \(t\), two temporary values are calculated:

\[
T_1=
h+\Sigma_1(e)+\operatorname{Ch}(e,f,g)+K_t+W_t
\pmod {2^{32}}
\]

\[
T_2=
\Sigma_0(a)+\operatorname{Maj}(a,b,c)
\pmod {2^{32}}
\]

Here:

- \(K_t\) is the fixed round constant.
- \(W_t\) is the corresponding message schedule word.
- \(T_1\) and \(T_2\) are temporary 32-bit values.

The working variables are then updated:

```text
h ← g
g ← f
f ← e
e ← d + T1
d ← c
c ← b
b ← a
a ← T1 + T2
```

Every addition is performed modulo \(2^{32}\).

### Round Structure

```text
             Current Working State
        a  b  c  d  e  f  g  h
                         │
             ┌───────────┴───────────┐
             │                       │
             ▼                       ▼
         Sigma 1(e)              Sigma 0(a)
             │                       │
             ▼                       ▼
       Choice(e,f,g)            Majority(a,b,c)
             │                       │
             ▼                       ▼
      Round Constant K[t]              │
             │                       │
      Schedule Word W[t]               │
             │                       │
             ▼                       ▼
             T1                      T2
              \                      /
               \                    /
                ▼                  ▼
                  State Transition
                         │
                         ▼
                  Next Round State
```

The 64 round constants are fixed values defined by the SHA-256 specification.

---

## 🔗 12. State Update

After all 64 rounds, the working variables are added to the previous chaining state.

```text
H0 ← H0 + a
H1 ← H1 + b
H2 ← H2 + c
H3 ← H3 + d
H4 ← H4 + e
H5 ← H5 + f
H6 ← H6 + g
H7 ← H7 + h
```

All additions are performed modulo \(2^{32}\).

The updated state becomes the starting state for the next message block.

For a message containing multiple blocks, each state update carries information from the preceding blocks into subsequent processing.

The final eight state words are concatenated in order to form the 256-bit digest.

---

## 🐍 13. Python Implementation

The Python implementation presents SHA-256 as a direct functional model.

### Main Components

| Component | Responsibility |
|---|---|
| `rotr32()` | Performs 32-bit rotation |
| `ch()` | Implements the choice function |
| `maj()` | Implements the majority function |
| Sigma functions | Implement the four rotation-based functions |
| `pad_message()` | Constructs the padded byte sequence |
| `build_schedule()` | Expands each block into 64 words |
| `compress()` | Executes the compression rounds |
| `sha256_bytes()` | Calculates the digest of bytes |
| `sha256_hex()` | Provides hexadecimal output |
| `hashlib` comparison | Independently verifies results |
| `avalanche_experiment()` | Measures output-bit changes |

### Engineering Perspective

Python makes the mathematical structure easy to follow.

The implementation can expose every stage of the algorithm without relying on a built-in hash operation for its primary calculation.

The standard-library `hashlib` implementation is used separately as a reference for verification.

### Testing

The implementation should include:

- Known-answer tests.
- Empty-message testing.
- UTF-8 text testing.
- Block-boundary tests.
- Multi-block tests.
- Randomized comparisons against `hashlib.sha256`.
- Avalanche-effect experiments.

Randomized testing helps detect errors in padding, byte ordering, rotation, modular arithmetic, and multi-block processing.

---

## 🟨 14. JavaScript Implementation

The JavaScript implementation uses Node.js and emphasizes explicit 32-bit operations.

JavaScript's ordinary `Number` type uses IEEE-754 double-precision floating-point representation. It is therefore important to control the behavior of arithmetic and bitwise operations when implementing SHA-256.

### Main Components

| Component | Responsibility |
|---|---|
| `Buffer` | Stores input bytes |
| `Uint32Array` | Stores the message schedule |
| `>>>` | Performs logical right shifts |
| `add32()` | Preserves unsigned 32-bit results |
| Padding function | Constructs the final block representation |
| Compression function | Executes the 64 rounds |
| `crypto` module | Provides independent verification |

### Engineering Perspective

The `Buffer` type is suitable for SHA-256 because the algorithm operates on bytes rather than language-level characters.

The implementation uses explicit unsigned conversions and controlled 32-bit operations to avoid JavaScript numeric-representation errors.

Node.js `crypto` is used as an independent verification mechanism rather than as a replacement for the custom compression implementation.

### Testing

The JavaScript program should verify:

- Known SHA-256 vectors.
- Empty input.
- ASCII and non-ASCII text.
- Inputs that cross block boundaries.
- Randomized byte arrays.
- Output consistency with Node.js `crypto`.
- Avalanche behavior after changing a single input bit.

---

## ⚙️ 15. C++17 Implementation

The C++ implementation models SHA-256 as a reusable streaming class.

### Internal State

The `SHA256` class maintains:

- Eight 32-bit state words.
- An incomplete input buffer.
- The number of input bytes received.
- The logic needed to finalize the hash.

### Streaming Interface

The primary operations are conceptually:

```cpp
update(data);
final();
```

`update()` accepts input incrementally and compresses each complete 64-byte block.

`final()` processes the remaining bytes, appends padding, encodes the original length, and performs the final compression operations.

This design allows large inputs to be processed without retaining the entire message in memory.

### Engineering Perspective

C++17 is well suited to demonstrating the low-level characteristics of SHA-256.

The type `std::uint32_t` explicitly represents a 32-bit unsigned integer, making the intended word size clear.

A streaming implementation also distinguishes the lifecycle of a hash operation from the mechanics of processing a single block.

### Important Implementation Requirements

- Use explicit big-endian word loading.
- Preserve the original input length.
- Apply padding only during finalization.
- Correctly handle incomplete blocks.
- Prevent unintended reuse of finalized state.
- Compare results against a trusted cryptographic implementation during testing.

The educational implementation avoids external cryptographic libraries in its compression logic so that the algorithm remains visible.

---

## ☕ 16. Java 17 Implementation

The Java implementation combines explicit SHA-256 compression logic with Java's standard byte-encoding and cryptographic facilities.

### Main Components

| Component | Responsibility |
|---|---|
| `pad()` | Constructs the padded message |
| `compress()` | Processes a 512-bit block |
| `hash(byte[])` | Hashes an arbitrary byte sequence |
| `hash(String)` | Hashes text encoded as UTF-8 |
| `hammingDistance()` | Counts differing output bits |
| `MessageDigest` | Independently verifies results |

### Engineering Perspective

Java's `int` type is exactly 32 bits, making it useful for implementing SHA-256 word operations.

Java integer overflow wraps around in two's-complement arithmetic. The low-order 32 bits therefore provide the modular results required by SHA-256 when arithmetic is performed consistently.

The `MessageDigest` API supplies a trusted comparison point without replacing the educational compression logic.

### Validation

The implementation should include:

- Null-input validation.
- Known-answer tests.
- UTF-8 text tests.
- Multi-block tests.
- Block-boundary tests.
- Comparison against JDK `MessageDigest`.
- Hamming-distance calculations.

---

## 🐘 17. PostgreSQL Implementation

The PostgreSQL implementation treats SHA-256 as a database-integrity mechanism rather than reproducing the compression algorithm in procedural SQL.

The `pgcrypto` extension provides the digest operation.

The database layer focuses on consistent byte representation, digest storage, integrity validation, audit records, and reporting.

### Conceptual Data Model

```text
                 ┌──────────────────────┐
                 │    hash_messages      │
                 ├──────────────────────┤
                 │ Message ID            │
                 │ Original text         │
                 │ UTF-8 bytes           │
                 │ Algorithm             │
                 │ Raw digest            │
                 │ Hexadecimal digest    │
                 │ Byte length           │
                 │ Creation timestamp    │
                 └──────────┬───────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
      ┌──────────────────┐    ┌────────────────────┐
      │ verification_runs│    │avalanche_experiments│
      ├──────────────────┤    ├────────────────────┤
      │ Verification ID  │    │ Experiment ID      │
      │ Message ID       │    │ Original digest    │
      │ Expected digest  │    │ Modified digest    │
      │ Actual digest    │    │ Hamming distance   │
      │ Verification     │    │ Experiment time    │
      │ Timestamp        │    │                    │
      └──────────────────┘    └────────────────────┘
```

### Message Storage

The `hash_messages` table can store:

- Original text.
- UTF-8 byte representation.
- Hash algorithm identifier.
- Raw 32-byte digest.
- Hexadecimal digest.
- Input byte length.
- Creation timestamp.

The relationship between the original text and its byte representation can be expressed using:

```sql
message_bytes = convert_to(message_text, 'UTF8')
```

This ensures that the database's byte representation matches the selected text encoding.

### Raw Digest Versus Hexadecimal Digest

A SHA-256 digest consists of 32 bytes.

Hexadecimal representation uses two characters for every byte, producing 64 hexadecimal characters.

```text
32 raw bytes
     │
     ▼
Hexadecimal encoding
     │
     ▼
64 hexadecimal characters
```

The raw digest can be stored in PostgreSQL's `BYTEA` type. Hexadecimal output can be generated for reporting and interoperability.

### Database-Level Integrity

A trigger or controlled database operation can recalculate the digest from the stored message and reject a row if the supplied digest does not match.

Conceptually:

```text
Incoming message and digest
             │
             ▼
Recalculate SHA-256
             │
             ▼
Compare calculated and supplied digests
             │
       ┌─────┴─────┐
       ▼           ▼
     Match       Mismatch
       │           │
       ▼           ▼
    Accept       Reject
```

This helps prevent a faulty application from storing a message and an unrelated digest.

A trigger that validates the digest on insert or update should be designed together with suitable constraints and permissions. Database validation is useful, but it does not replace appropriate access controls or a trusted method of authenticating data.

### Verification Records

Verification should be modeled separately from the stored message.

Each verification event can record:

- The message being checked.
- The expected digest.
- The calculated digest.
- Whether the digests match.
- The verification timestamp.

Retaining failed verification attempts can provide an audit trail for integrity failures.

### Transactions

PostgreSQL transactions help ensure that related database changes are committed or rolled back together.

For example, a workflow that inserts a message and creates its verification record can use a transaction so that a partial operation does not leave inconsistent records.

A transaction does not make SHA-256 more cryptographically secure. It protects the consistency of the database workflow.

---

## 🌊 18. Avalanche Effect

A cryptographic hash should exhibit a strong avalanche effect.

A small change in the input should produce a substantially different output.

The experiment modifies one input bit and calculates both digests.

The Hamming distance is the number of bit positions that differ between the two outputs.

\[
d_H(x,y)=\operatorname{popcount}(x\oplus y)
\]

For SHA-256, the output contains 256 bits.

For two outputs that behave like independent, uniformly distributed 256-bit values, the expected Hamming distance is:

\[
E[d_H]=256\times\frac12=128
\]

This is a statistical expectation, not a requirement that every experiment return exactly 128.

### Experiment Workflow

```text
Original Input
      │
      ├─────────────────┐
      ▼                 ▼
Original Digest     Modified Input
                        │
                        ▼
                  Modified Digest
      │                 │
      └────────┬────────┘
               ▼
        Compare 256 Bits
               │
               ▼
       Calculate Hamming
           Distance
```

### Interpretation

A distance near half the output width is consistent with strong bit diffusion in that experiment.

The experiment does not prove cryptographic security. It demonstrates an observable property of the hash function.

---

## 🔁 19. Multi-Block Messages

SHA-256 supports messages longer than one 64-byte block.

The chaining state connects the blocks:

```text
Message
   │
   ▼
Block 0 ──► Compression ──► State 0
                                  │
                                  ▼
Block 1 ──► Compression ──► State 1
                                  │
                                  ▼
Block 2 ──► Compression ──► State 2
                                  │
                                 ...
                                  │
                                  ▼
                           Final Block
                                  │
                                  ▼
                           Final Digest
```

Each block modifies the chaining state, and that state becomes the input state for the next block.

The Python, JavaScript, and Java implementations process the padded message block by block.

The C++ implementation exposes this naturally through its streaming `update()` interface.

The PostgreSQL implementation delegates block processing to `pgcrypto`.

---

## 🌍 20. UTF-8 and Byte-Level Hashing

SHA-256 hashes bytes, not programming-language strings.

The text `SHA-256` must first be encoded into a byte sequence.

The implementations use UTF-8 for text input.

| Environment | UTF-8 conversion |
|---|---|
| Python | `text.encode("utf-8")` |
| JavaScript | `Buffer.from(text, "utf8")` |
| C++17 | Explicit byte sequence supplied to the hash |
| Java 17 | `StandardCharsets.UTF_8` |
| PostgreSQL | `convert_to(text, 'UTF8')` |

### Why This Matters

Different encodings can produce different byte sequences for the same logical text.

Different byte sequences produce different SHA-256 digests.

When comparing hashes across programming languages or databases, the input encoding and byte sequence must match exactly.

For binary files, the safest approach is to hash the original bytes rather than convert the content to text.

---

## 🛡️ 21. Hashing Is Not Encryption

Encryption and hashing serve different purposes.

Encryption is designed to protect confidentiality and is generally reversible when the appropriate key is available.

SHA-256 produces a fixed-size digest and is not designed to be reversed.

| Property | Encryption | SHA-256 |
|---|---|---|
| Primary purpose | Confidentiality | Integrity and fingerprinting |
| Reversible with a key | Yes | No |
| Fixed-size output | Usually no | Yes |
| Secret key required | Usually | No |
| Useful for file integrity | Yes, in suitable systems | Yes |
| Suitable for password storage alone | No | No |

A SHA-256 digest does not conceal information in the same way as encryption.

A short or predictable input may be recovered through guessing, even when the hash function itself is operating correctly.

---

## 🔎 22. Collision Resistance

A collision occurs when two different inputs produce the same digest.

For SHA-256:

\[
|\text{Digest Space}|=2^{256}
\]

The input space is much larger than the digest space, so collisions must exist mathematically.

Collision resistance means that finding a collision should be computationally infeasible under the algorithm's intended security assumptions.

The distinction is important:

```text
Collisions must exist
         ≠
Collisions are practically discoverable
```

For an ideal 256-bit hash, generic collision searches have an approximate birthday-bound work factor of \(2^{128}\) hash operations.

This is a theoretical reference, not a guarantee about every real-world system or attack model.

---

## 🔐 23. Preimage Resistance

Given a digest \(h\), a preimage attack attempts to find a message \(m\) satisfying:

\[
\operatorname{SHA256}(m)=h
\]

SHA-256 is designed to make recovering such a message computationally infeasible for appropriately selected targets under the intended security assumptions.

This does not mean the original message is always secret.

If the input belongs to a small set of likely possibilities, an attacker can hash each candidate and compare the result.

For example, hashing a short, publicly known word does not make that word confidential.

---

## 🔑 24. Password Security

Raw SHA-256 is not suitable as a password-storage mechanism.

SHA-256 is intentionally fast, which is useful for integrity checks but allows attackers to test many password guesses quickly.

Password storage should use a dedicated password-hashing scheme, such as Argon2id, scrypt, or appropriately configured bcrypt or PBKDF2, depending on the system's requirements and available implementation.

A suitable password-storage design should include:

- A unique salt for each password.
- A configurable computational cost.
- Memory-hard processing where supported and appropriate.
- A maintained, reviewed implementation.
- A migration strategy for older password hashes.

The SHA-256 implementations in this project are intended for algorithm study and integrity demonstrations, not password storage.

---

## 🪪 25. Integrity Versus Authentication

A SHA-256 digest can detect modification when the expected digest comes from a trusted source.

It does not independently prove who created the digest.

An attacker who can modify both a file and its accompanying digest can calculate a new digest for the modified file.

The mechanisms serve different purposes:

```text
SHA-256
   │
   └── Checks whether data matches a known digest

HMAC-SHA-256
   │
   └── Authenticates data using a shared secret

Digital Signature
   │
   └── Supports verification using a public key
```

A MAC such as HMAC-SHA-256 is appropriate when communicating parties share a secret key.

A digital signature is appropriate when public-key verification is required.

The digest algorithm alone does not provide sender authentication.

---

## 🚀 26. Performance Characteristics

For an input containing \(n\) bytes, SHA-256 processes a number of blocks proportional to the input length.

Its time complexity is:

\[
O(n)
\]

The output size remains constant:

\[
O(1)
\]

A streaming implementation requires constant working memory with respect to the total input size, excluding any storage maintained by the caller.

### Streaming Versus Whole-Message Processing

| Characteristic | Whole-message approach | Streaming approach |
|---|---|---|
| Input handling | Entire message available | Input supplied incrementally |
| Working storage | May retain padded input | Can retain only state and a partial block |
| Large-file processing | May require extra memory | Suitable for bounded-memory processing |
| Finalization | Process padded message | Pad the remaining data and finalize |
| Example | Direct educational model | C++ `update()` and `final()` |

The direct implementations favor clarity. A production implementation may use optimized libraries and hardware acceleration where available.

---

## 💾 27. Space Characteristics

The compression function uses:

- Eight 32-bit chaining-state words.
- Eight working variables.
- A 64-word message schedule in straightforward implementations.
- A 64-byte message block.

A memory-optimized implementation can calculate the message schedule using a circular buffer rather than storing all 64 words simultaneously.

The full schedule is easier to understand in an educational implementation, so the project favors clarity over this optimization.

---

## ⚠️ 28. Error Conditions and Validation

Cryptographic code should reject invalid inputs explicitly.

| Failure | Expected handling |
|---|---|
| Incorrect Python input type | `TypeError` |
| Invalid JavaScript input type | `TypeError` |
| Invalid block or buffer operation | Explicit exception |
| Invalid avalanche input | Validation error |
| Null Java input | `IllegalArgumentException` or documented validation error |
| Incorrect stored PostgreSQL digest | Trigger rejection |
| Invalid digest length | Database constraint |
| Invalid hexadecimal digest | Verification error |
| Incomplete streaming input | Correct finalization, not silent data loss |
| Length overflow beyond supported limits | Reject input or use a documented supported range |

A cryptographic implementation can produce a plausible-looking digest even when its internal logic is wrong. Known-answer tests and independent verification are therefore essential.

---

## 🧪 29. Testing Strategy

The source programs use three principal forms of verification.

### 29.1 Known-Answer Tests

Known-answer tests compare calculated digests against standardized expected values.

Example input:

```text
abc
```

Expected output:

```text
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

These tests detect many basic implementation errors.

### 29.2 Independent Reference Tests

The custom implementations can be compared against:

| Language | Reference implementation |
|---|---|
| Python | `hashlib.sha256` |
| JavaScript | Node.js `crypto` |
| C++17 | A trusted external cryptographic implementation in the test harness |
| Java 17 | JDK `MessageDigest` |
| PostgreSQL | `pgcrypto` digest operation |

The reference implementation should be separate from the custom compression logic.

For C++, an independent library can be used in the test harness without replacing the educational implementation itself.

### 29.3 Randomized Tests

Randomized tests generate many input byte sequences and compare custom outputs against trusted implementations.

They are particularly useful for discovering errors involving:

- Empty inputs.
- Short messages.
- Messages near 64-byte boundaries.
- Multi-block messages.
- Random binary values.
- Non-ASCII text.
- Padding and length encoding.

Randomized testing complements known-answer tests but does not replace them.

---

## 🧱 30. Important Boundary Cases

Padding and block processing should be tested at critical lengths.

| Input length | Purpose |
|---:|---|
| 0 bytes | Empty-message behavior |
| 1 byte | Minimum nonempty input |
| 3 bytes | Standard `abc` test vector |
| 55 bytes | Padding fits in one block |
| 56 bytes | Padding requires an additional block |
| 63 bytes | Nearly full original block |
| 64 bytes | Exactly one complete input block before padding |
| 65 bytes | First byte beyond one block |
| 119 bytes | Multi-block padding boundary |
| 120 bytes | Additional padding block required |
| Several kilobytes | Repeated compression and streaming behavior |

These values are useful because padding behavior changes around specific block boundaries.

The implementation must account for the original message length, the marker byte, the zero padding, and the final eight-byte length field.

---

## 🔀 31. Endianness and Integer Semantics

SHA-256 uses big-endian message-word and length-field encoding.

For example:

```text
Byte sequence: 01 02 03 04
Big-endian word: 0x01020304
```

The implementations must also preserve modulo-\(2^{32}\) arithmetic.

| Language | Important consideration |
|---|---|
| Python | Mask arithmetic results to 32 bits |
| JavaScript | Use deliberate 32-bit operations and unsigned conversions |
| C++17 | Use `std::uint32_t` |
| Java 17 | Use 32-bit `int` bit patterns consistently |
| PostgreSQL | Use the documented `pgcrypto` byte-input interface |

The byte order of the input words is part of the algorithm specification and must not depend on the host machine's native memory order.

---

## 🔒 32. Security Design Considerations

The educational implementations are useful for understanding SHA-256 internals, but production systems should generally use well-tested cryptographic libraries.

Custom implementations can introduce subtle errors involving:

- Padding.
- Integer overflow.
- Byte order.
- Length encoding.
- Buffer management.
- Streaming finalization.
- Incorrect digest comparisons.

The project separates three concerns:

1. **Algorithm mechanics:** Understand the compression process.
2. **Independent verification:** Compare the implementation against a trusted reference.
3. **Operational integrity:** Store and verify digests consistently in a database.

For production cryptographic systems, prefer reviewed, maintained implementations and follow the security requirements of the application.

---

## 🏭 33. Practical Applications

SHA-256 is useful in many engineering and security workflows.

| Application | Role of SHA-256 |
|---|---|
| File integrity | Detects changes when compared with a trusted digest |
| Software distribution | Supports release verification |
| Artifact identification | Produces a fixed-size content fingerprint |
| Content-addressed storage | Helps identify content by its digest |
| Digital signatures | Hashes data as part of signature workflows |
| Merkle trees | Provides hash values for tree construction |
| Blockchain data structures | Supports hash-linked structures and other protocol operations |
| Deduplication | Helps identify candidate duplicate content |
| Database integrity | Supports validation of stored content |
| Data pipelines | Helps compare content across processing stages |

A digest alone does not automatically provide confidentiality, authorization, or sender authentication.

---

## 🗺️ 34. Conceptual Data Flow

The full SHA-256 process can be summarized as follows:

```text
╔══════════════════════════════════════════════════╗
║                    SHA-256                       ║
╚══════════════════════════════════════════════════╝

             Input Text or Binary Data
                         │
                         ▼
                  UTF-8 / Raw Bytes
                         │
                         ▼
                   Message Padding
                         │
                         ▼
               ┌─────────────────────┐
               │ 512-Bit Block       │
               └─────────────────────┘
                         │
                         ▼
                 16 Initial Words
                         │
                         ▼
                 64-Word Schedule
                         │
                         ▼
               ┌─────────────────────┐
               │ 64 Compression      │
               │ Rounds              │
               └─────────────────────┘
                         │
                         ▼
                  State Update
                         │
                         ▼
                 More Blocks?
                    /       \
                  Yes        No
                   │          │
                   ▼          ▼
             Next Block   Final State
                              │
                              ▼
                        256-Bit Digest
                              │
                              ▼
                     64-Character Hex
                       Representation
```

The digest depends on the complete sequence of processed blocks because each block's output state becomes the next block's input state.

---

## 🔗 35. Relationship Between the Five Implementations

The five artifacts are deliberately complementary rather than mechanical translations of one another.

| Dimension | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Primary goal | Explain the algorithm | Manage byte buffers and runtime arithmetic | Demonstrate low-level processing | Combine explicit logic with typed APIs | Enforce data integrity |
| Custom compression | Yes | Yes | Yes | Yes | No |
| Explicit padding | Yes | Yes | Yes | Yes | Handled by `pgcrypto` |
| Message schedule | List | `Uint32Array` | `std::array` | `int[]` | Internal to extension |
| Streaming interface | Optional | Optional | Core design | Optional | Database operation |
| Reference verification | `hashlib` | `crypto` | External test reference | `MessageDigest` | `pgcrypto` |
| Database constraints | Not applicable | Not applicable | Not applicable | Not applicable | Central focus |
| Audit workflow | Test output | Test output | Test output | Test output | Verification records |

### Python

Makes the mathematical structure easy to inspect.

### JavaScript

Emphasizes byte buffers and deliberate handling of 32-bit runtime operations.

### C++17

Demonstrates explicit state, memory management, and incremental processing.

### Java 17

Shows how strongly typed application code can implement the algorithm while using the JDK for independent verification.

### PostgreSQL

Demonstrates how hashing can support a database-integrity workflow through storage, constraints, triggers, verification records, and transactions.

---

## 📋 36. What the Implementations Demonstrate

The complete workflow is:

```text
Message
   │
   ▼
Encoding
   │
   ▼
Padding
   │
   ▼
512-Bit Block
   │
   ▼
16 Initial Words
   │
   ▼
64-Word Schedule
   │
   ▼
64 Compression Rounds
   │
   ▼
State Update
   │
   ▼
Next Block, If Required
   │
   ▼
Final 256-Bit Digest
```

The verification workflow is separate:

```text
Custom Implementation
          │
          ├── Known-answer tests
          │
          ├── Independent reference comparison
          │
          ├── Randomized testing
          │
          ├── Boundary-case testing
          │
          ├── Avalanche experiment
          │
          └── Database integrity validation
```

This separation is important because a correct-looking digest is not sufficient evidence that an implementation is correct.

---

## 🏁 37. Conclusion

SHA-256 illustrates how a cryptographic hash function transforms arbitrary-length input into a fixed-size digest through padding, message scheduling, repeated compression rounds, and state updates.

The five implementations demonstrate different aspects of the same mechanism:

- **Python** presents the algorithm in a readable mathematical form.
- **JavaScript** emphasizes byte-oriented processing and explicit 32-bit operations.
- **C++17** demonstrates low-level control and streaming input.
- **Java 17** combines explicit algorithm logic with standard-library verification.
- **PostgreSQL** applies hashing to database integrity and operational auditing.

Together, they provide a practical study of cryptographic hashing across application development, systems programming, and database engineering.

The central engineering principle is to distinguish the mathematical algorithm from its implementation and from the system in which it is used. Understanding all three makes it easier to test correctness, identify implementation errors, and apply SHA-256 appropriately.

**Final takeaway:** SHA-256 provides a standardized 256-bit digest, while correct byte encoding, padding, modular arithmetic, independent verification, and trusted operational practices determine whether a real implementation uses it correctly.
