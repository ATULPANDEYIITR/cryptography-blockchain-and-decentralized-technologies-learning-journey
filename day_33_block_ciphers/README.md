# Block Ciphers

## Scope

This project studies block ciphers as cryptographic primitives and then places those primitives inside practical encryption modes and application-level workflows.

The three implementations deliberately use different perspectives:

- The Python program provides the broadest mathematical and algorithmic walkthrough, including a small Feistel construction, PKCS#7 padding, AES-128, ECB, CBC, CTR, known-answer testing, avalanche analysis, and validation.
- The JavaScript program focuses on byte-oriented APIs, `Uint8Array`, asynchronous processing, streaming-style CTR operation, nonce allocation policy, and the boundary between a hand-written educational primitive and the Web Crypto API.
- The C++ program models a telemetry archive in which structured records are serialized, encrypted with AES-128-CBC, validated during decryption, and governed by an explicit IV-reuse policy.

The implementations are educational cryptography rather than production cryptographic libraries.

## What a Block Cipher Is

A block cipher is a keyed transformation that maps a fixed-size plaintext block to a ciphertext block of the same size.

For a key `K`, encryption can be represented as:

`C = E(K, P)`

Decryption reverses the transformation:

`P = D(K, C)`

AES operates on 128-bit blocks, so each AES block is exactly 16 bytes. AES supports 128-bit, 192-bit, and 256-bit keys. The implementations in this project use AES-128, meaning the key is 16 bytes and the algorithm uses ten transformation rounds after the initial key addition.

A block cipher by itself does not specify how a message larger than one block should be processed. That responsibility belongs to a mode of operation or a higher-level construction.

This distinction is fundamental:

`block cipher primitive -> mode/construction -> message protocol -> application`

A correct AES primitive does not automatically make an application encryption system secure.

## Why Fixed-Size Blocks Matter

A block cipher has a defined input domain. AES accepts exactly 128 bits for each block.

A message such as:

`temperature=27.35;device=4821`

is not necessarily 16 bytes long. The application therefore needs a method for processing multiple blocks and, for some modes, a method for handling a final partial block.

CBC in this project uses PKCS#7 padding. CTR does not require padding because it transforms AES into a stream-like construction by encrypting counter values and XORing the resulting keystream with arbitrary-length data.

## Internal Structure

### Substitution

AES uses an S-box to replace each byte with another byte.

The S-box provides a nonlinear transformation. Nonlinearity makes it difficult to model the complete cipher as a simple collection of linear relationships.

The Python, JavaScript, and C++ implementations contain the AES S-box and inverse S-box explicitly. The inverse table is used during decryption.

### Permutation and diffusion

AES's `ShiftRows` operation moves bytes between state positions. `MixColumns` combines the bytes within each column.

The combination spreads local input changes through the state. A one-bit modification to plaintext should not remain localized after the complete AES transformation.

The implementations include avalanche tests that compare two encryptions whose plaintexts differ by one bit.

### Key addition

`AddRoundKey` XORs the AES state with a round key.

The original AES key is expanded into multiple round keys before block encryption begins. AES-128 produces eleven 128-bit round keys: one for the initial key addition and one for each of the ten AES rounds.

### Round structure

For AES-128, the initial transformation is `AddRoundKey`.

The first nine rounds perform:

`SubBytes -> ShiftRows -> MixColumns -> AddRoundKey`

The final round omits `MixColumns`:

`SubBytes -> ShiftRows -> AddRoundKey`

Decryption applies the corresponding inverse transformations in reverse order.

The omission of `MixColumns` in the final encryption round is part of the AES specification and is not an optimization invented by these implementations.

## Feistel Networks

The Python implementation contains a deliberately small Feistel cipher to contrast another major block-cipher architecture with AES.

A Feistel construction divides a block into two parts:

`L, R`

A typical round updates the halves according to a relationship such as:

`L' = R`

`R' = L XOR F(R, K)`

The important structural property is that the round function itself does not need to be invertible. Decryption can recover the previous state by applying the same round mechanism with the round keys in reverse order.

The toy Feistel implementation is intentionally insecure. Its purpose is to expose the structural idea without hiding it behind a production-sized algorithm.

AES is not a Feistel cipher. It uses a substitution-permutation network with a 4-by-4 byte state.

## AES State Representation

AES represents its 16-byte state as four columns of four bytes.

The implementations use the indexing relationship:

`state[4 * column + row]`

This detail matters because `ShiftRows` depends on the state layout. Treating the AES state as an ordinary row-major two-dimensional array without accounting for the specified representation produces incorrect encryption.

This is a common implementation failure when AES is written from scratch.

## Finite-Field Arithmetic

AES's `MixColumns` operation uses arithmetic in the finite field `GF(2^8)`.

The implementations provide a byte multiplication function that repeatedly shifts one operand, conditionally XORs it into the result, and reduces values with the AES polynomial represented by `0x1B`.

For example, the MixColumns transformation uses coefficients such as:

`2, 3, 1, 1`

The inverse transformation uses:

`14, 11, 13, 9`

These are not ordinary integer multiplication coefficients. They represent multiplication within the AES finite field.

## Key Expansion

AES-128 begins with a 16-byte key but needs a different round key for each round.

The key schedule divides the original key into four-byte words. Every fourth generated word undergoes:

- rotation,
- S-box substitution,
- round-constant XOR.

The resulting word is then XORed with a word four positions earlier.

The Python implementation exposes this process through `aes_key_expansion`, while the JavaScript and C++ versions encapsulate the schedule inside their AES classes.

## Padding

Padding is necessary for modes such as CBC when the plaintext does not naturally occupy complete blocks.

PKCS#7 determines the number of required padding bytes from the block size.

For AES, if a plaintext needs five bytes of padding, the appended bytes are:

`05 05 05 05 05`

If the plaintext is already exactly aligned to 16 bytes, a complete 16-byte padding block is appended. This prevents ambiguity between genuine data and padding.

Unpadding must validate every padding byte. Checking only the final byte can cause malformed ciphertext to be accepted.

The three implementations deliberately demonstrate malformed-padding rejection.

## ECB Mode

Electronic Codebook mode applies the block cipher independently to each block:

`C1 = E(K, P1)`

`C2 = E(K, P2)`

and so on.

The same key and identical plaintext block therefore produce identical ciphertext blocks.

This leaks equality patterns. If a structured document contains repeated blocks, those repetitions remain visible in the ciphertext.

The Python implementation demonstrates this property by encrypting repeated blocks and counting unique ciphertext blocks.

ECB is useful for understanding the mechanics of a block cipher but is generally inappropriate for encrypting structured application data.

## CBC Mode

Cipher Block Chaining introduces dependency between consecutive blocks.

Encryption follows:

`C1 = E(K, P1 XOR IV)`

`Ci = E(K, Pi XOR C(i-1))`

The IV is used for the first block.

The ciphertext chaining means identical plaintext blocks at different positions do not normally produce identical ciphertext blocks when their preceding ciphertext differs.

CBC requires careful IV handling. The IV is not a secret value, but for ordinary randomized encryption it should be unpredictable and must not be reused in ways that violate the protocol's security assumptions.

CBC does not authenticate the ciphertext. An attacker can potentially modify ciphertext without possessing the encryption key, and the receiver needs an independent authentication mechanism to detect unauthorized modification.

The project therefore treats CBC as an educational confidentiality construction rather than a complete application-security protocol.

## CTR Mode

Counter mode encrypts successive counter values:

`S1 = E(K, Counter1)`

`S2 = E(K, Counter2)`

The keystream is then XORed with plaintext:

`Ci = Pi XOR Si`

Decryption performs the same XOR operation:

`Pi = Ci XOR Si`

This makes CTR a stream-like construction built from a block cipher.

CTR has two important properties demonstrated by the code:

- It can process data that is not a multiple of the block size.
- The counter or nonce allocation must never repeat under the same key.

If the same keystream is reused for two plaintexts, XORing their ciphertexts removes the keystream:

`C1 XOR C2 = P1 XOR P2`

That can reveal relationships between the plaintexts and can be catastrophic when the plaintext has predictable structure.

The JavaScript `NonceRegistry` models an application policy that rejects repeated nonce values.

## IV, Nonce, and Counter Distinctions

These terms are related but should not be treated as interchangeable implementation details.

An IV is an initialization value used by a particular mode, such as CBC.

A nonce is a value whose uniqueness is required by a construction. CTR can use a nonce plus a counter field to generate its input blocks.

A counter is the changing portion that prevents consecutive keystream blocks from being identical.

The exact requirements depend on the cryptographic construction. A developer should not assume that a value safe for one mode is automatically safe for another.

## Python Implementation

The Python program is organized around an executable progression from primitive structure to application behavior.

### AES primitive

`AES128` exposes `encrypt_block` and `decrypt_block`. Both methods enforce the 16-byte AES block boundary.

The implementation includes:

- AES-128 key expansion
- S-box substitution
- inverse S-box substitution
- ShiftRows
- inverse ShiftRows
- MixColumns
- inverse MixColumns
- AddRoundKey
- AES-128 encryption
- AES-128 decryption

The implementation is verified with the standardized AES-128 known-answer example:

`key = 000102030405060708090a0b0c0d0e0f`

`plaintext = 00112233445566778899aabbccddeeff`

The expected ciphertext is:

`69c4e0d86a7b0430d8cdb78070b4c55a`

This is stronger evidence of correctness than merely checking that locally produced ciphertext can be decrypted by the same implementation.

### Mode demonstrations

The Python implementation supplies ECB, CBC, and CTR helpers.

ECB deliberately exposes equality leakage.

CBC demonstrates padding, IV use, chaining, and padding validation.

CTR demonstrates arbitrary-length processing and the fact that encryption and decryption use the same keystream transformation.

### Self-tests

The script performs repeated round-trip tests over multiple plaintext lengths. This exercises padding boundaries, empty input, partial blocks, full blocks, and different byte values.

It also tests individual AES blocks after encryption and decryption.

### Failure handling

The implementation rejects:

- AES keys of the wrong length
- AES blocks of the wrong length
- CBC IVs of the wrong length
- non-block-aligned ECB input
- empty CBC ciphertext
- malformed PKCS#7 padding

These checks make the distinction between invalid inputs and valid ciphertext explicit.

## JavaScript Implementation

The JavaScript implementation uses `Uint8Array` as the primary byte representation.

This is important because JavaScript's ordinary `number` type is not a dedicated byte type. `Uint8Array` gives explicit unsigned eight-bit storage and predictable conversion behavior.

### AES representation

The `AES128` class encapsulates the expanded round keys and AES transformation functions.

The implementation avoids converting the state into strings during cryptographic processing. Hexadecimal conversion is reserved for display and diagnostics.

### Streaming CTR

The JavaScript implementation adds a `CounterStream` abstraction.

Instead of requiring the entire plaintext to be available simultaneously, it accepts chunks and consumes the AES keystream as needed.

The `EncryptionPipeline` builds on this with `EventTarget` events:

- `start`
- `chunk`
- `complete`

This illustrates a realistic JavaScript application boundary in which encryption can be part of asynchronous or event-driven processing.

The asynchronous pipeline yields to the event loop between chunks rather than performing the entire operation inside one uninterrupted synchronous loop.

### Web Crypto boundary

The JavaScript runtime may provide the Web Crypto API through `crypto.subtle`.

The demonstration uses AES-GCM through that API. AES-GCM is materially different from the hand-written CBC example because it provides authenticated encryption.

The example also deliberately modifies one ciphertext byte and attempts decryption again. Authentication failure causes decryption to reject the tampered ciphertext.

This illustrates an important architectural rule: a production application should normally prefer a vetted authenticated-encryption API over a hand-written AES implementation plus an improvised integrity layer.

## C++ Telemetry Archive Case Study

The C++ program models an application rather than presenting AES as an isolated algorithm.

A telemetry record contains:

- device identifier
- timestamp
- temperature in milli-degrees Celsius
- sequence number

The application first serializes these fields into a fixed byte representation.

This separation is intentional. Encrypting the raw memory representation of a C++ structure would make the format dependent on object layout, padding, alignment, and potentially platform-specific representation. Explicit serialization defines exactly which bytes are protected.

### Archive architecture

The case study separates responsibilities into several components.

`TelemetryRecord` represents application data.

`serializeRecord` converts the record into a defined byte sequence.

`deserializeRecord` reconstructs the record and validates the expected serialized length.

`AES128` implements the block primitive.

`cbcEncrypt` and `cbcDecrypt` provide the selected confidentiality mode.

`IvRegistry` represents a policy layer that tracks IVs and rejects reuse.

`TelemetryArchive` coordinates serialization, encryption, IV policy, decryption, and reconstruction.

This separation makes it possible to reason about cryptographic responsibilities independently from application data structures.

### Record validation

The archive expects the serialized record to contain exactly 20 bytes.

The binary layout is explicitly encoded in big-endian order:

`deviceId` occupies four bytes.

`timestamp` occupies eight bytes.

`temperatureMilliCelsius` occupies four bytes.

`sequence` occupies four bytes.

The resulting 20-byte record is then padded to an AES block boundary before CBC encryption.

### IV policy

The `IvRegistry` is intentionally a policy demonstration rather than a secure random-number generator.

It rejects an IV that has already been reserved for the same archive object.

In a real system, IV generation should use a cryptographically appropriate random source or a construction-specific allocation strategy. The IV can normally be stored alongside ciphertext because it is not itself the secret key.

### Why the archive is not a complete secure storage protocol

The C++ case study uses CBC to make block chaining visible.

It does not claim that CBC provides integrity.

If an attacker modifies stored ciphertext, decryption may produce modified plaintext or trigger a padding failure. Padding failure is not a general-purpose authenticity mechanism.

A production telemetry archive should normally use authenticated encryption so the receiver can verify that ciphertext and associated metadata have not been modified.

## Code Review of the Three Implementations

The implementations intentionally demonstrate different engineering boundaries.

| Implementation | Primary perspective | Distinctive technical focus |
| --- | --- | --- |
| Python | Algorithmic study | AES internals, Feistel structure, modes, padding, tests, avalanche behavior |
| JavaScript | Application/runtime study | `Uint8Array`, asynchronous processing, streaming CTR, nonce policy, Web Crypto |
| C++ | Systems case study | Binary record serialization, AES integration, CBC archive processing, explicit policy enforcement |

The shared AES concept is necessary for comparison, but the surrounding implementation concerns are intentionally different.

## Security Properties

A block cipher is designed primarily as a confidentiality primitive.

Security of the complete application depends on additional properties.

### Confidentiality

The ciphertext should not reveal the plaintext to an attacker who does not possess the key.

AES is designed to provide strong confidentiality when used correctly with a secure key and suitable construction.

### Integrity

Confidentiality does not automatically imply integrity.

A system that needs to detect malicious modifications requires authentication. Authenticated-encryption modes such as AES-GCM combine encryption and authentication in one standardized construction.

### Key security

The AES key is the central secret.

Security can fail even when AES itself is implemented correctly if the key is:

- predictable
- hard-coded into source code
- exposed in logs
- stored in plaintext
- reused across unrelated security domains without a key-management strategy
- transmitted without adequate protection

The educational examples contain deterministic keys because reproducible tests require fixed inputs. Those values should not be treated as operational secrets.

### Nonce and IV management

Correct nonce or IV management is part of the cryptographic protocol.

CTR nonce reuse is especially dangerous because it reuses the same keystream.

CBC has different IV requirements, and the IV should not be confused with a password, key, or authentication tag.

### Authentication

CBC and CTR in this project do not authenticate their ciphertext.

A system that stores sensitive records must distinguish:

`encrypted`

from:

`encrypted and authenticated`

These are different security properties.

## Avalanche Effect

The avalanche effect describes the expectation that a small change in the input should produce a substantial change in the output.

The demonstrations flip one plaintext bit and compare the resulting ciphertexts.

The comparison counts changed ciphertext bits out of 128.

The test is useful as an implementation diagnostic and as an illustration of diffusion. It is not, by itself, a proof of cryptographic security.

A poorly designed cipher could exhibit substantial output changes and still have exploitable structural weaknesses.

## Common Implementation Errors

### Incorrect AES state indexing

AES uses a column-oriented state representation. Treating the state as ordinary row-major data can produce incorrect ShiftRows and MixColumns behavior.

### Incorrect finite-field multiplication

AES multiplication is not ordinary integer multiplication. The reduction step using the AES irreducible polynomial is required.

### Missing final-round distinction

The final AES encryption round does not perform MixColumns. Adding it to the final round changes the algorithm.

### Incorrect key schedule rotation

The AES key schedule rotates a four-byte word before S-box substitution at specific word boundaries. Applying the rotation at every word produces the wrong round keys.

### Weak padding validation

Accepting a padding length without verifying every padding byte allows malformed data to pass validation.

### Reusing CTR nonces

This can expose relationships between plaintexts because the same keystream is XORed with multiple messages.

### Treating CBC as authenticated

CBC encryption alone cannot establish that the ciphertext came from a trusted sender and was not modified.

### Using ECB for structured data

ECB preserves equality patterns between corresponding plaintext blocks.

### Hard-coding production keys

A source-code key is exposed to anyone who obtains the source, build artifact, logs, or deployment package containing it.

## Performance Considerations

AES operates on fixed 16-byte blocks, so the amount of data affects the number of block operations.

The educational implementations perform AES transformations byte by byte and prioritize readability over hardware acceleration.

Production implementations can use highly optimized cryptographic libraries and CPU instructions such as AES-NI where available.

CTR can be parallelized because each counter block is independent:

`E(K, Counter1)`

`E(K, Counter2)`

`E(K, Counter3)`

CBC encryption is more sequential because each plaintext block depends on the previous ciphertext block.

CBC decryption has more parallelism than CBC encryption because each ciphertext block can be decrypted independently before the previous ciphertext block is XORed into the result.

## Testing Strategy

A cryptographic implementation should not rely only on internal round-trip tests.

A round-trip test can pass even when encryption and decryption contain the same conceptual mistake.

The Python and C++ implementations therefore include a known-answer test with an independently specified AES vector.

Useful testing layers include:

- standardized known-answer vectors
- encryption/decryption round trips
- empty and boundary-length plaintext
- full-block plaintext
- malformed padding
- incorrect key length
- incorrect block length
- incorrect IV length
- counter exhaustion
- nonce reuse policy
- modified ciphertext behavior for authenticated constructions

For production cryptographic code, interoperability tests against a trusted implementation are also important.

## Debugging Strategy

Cryptographic debugging benefits from comparing intermediate state rather than only comparing final ciphertext.

For AES, useful checkpoints include:

`AddRoundKey`

`SubBytes`

`ShiftRows`

`MixColumns`

and each generated round key.

When an implementation fails a known-answer vector, the first incorrect intermediate state often identifies the defective transformation.

Hexadecimal byte dumps are appropriate for deterministic test vectors but should not be used to log operational secrets.

## Educational Boundary

These implementations intentionally expose internals that a production application normally should not reimplement.

Writing AES from scratch is valuable for understanding:

- substitution
- diffusion
- finite-field arithmetic
- key schedules
- block boundaries
- inverse transformations
- mode construction

It is usually not an appropriate production engineering decision to replace a maintained cryptographic library with custom code merely because the custom implementation passes a small test suite.

Cryptographic security depends on much more than algorithmic correctness. Side-channel resistance, constant-time behavior, secure memory handling, key lifecycle, randomness, authenticated protocols, interoperability, and extensive review all matter.

## Practical Model

A useful way to reason about block-cipher systems is:

`AES key`

becomes

`AES block primitive`

which becomes

`mode or authenticated construction`

which becomes

`message framing`

which becomes

`application protocol`

which becomes

`key and nonce lifecycle`

A defect at any layer can undermine the security objective even when AES itself remains mathematically sound.

The Python implementation emphasizes the first three layers.

The JavaScript implementation emphasizes the construction-to-runtime boundary and nonce lifecycle.

The C++ implementation emphasizes message framing and integration into a structured application.

## Limitations

The project intentionally does not implement a production-grade authenticated encryption system from scratch.

The CBC and CTR examples provide confidentiality-oriented demonstrations but should not be interpreted as complete secure messaging or secure storage protocols.

The educational AES implementation is not designed to provide hardened side-channel resistance.

The nonce registry is an in-memory demonstration and cannot by itself guarantee uniqueness across processes, machines, restarts, or distributed services.

The deterministic keys and IVs used in tests exist to make expected behavior reproducible. Real deployments require appropriate key generation, storage, rotation, and nonce or IV management.

The Web Crypto example demonstrates the preferred direction for browser applications but does not replace the need for correct application-level key handling and protocol design.

## Recommended Production Boundary

For a real application, the appropriate abstraction is generally not:

`write AES yourself`

but:

`select a vetted authenticated-encryption implementation and design the surrounding protocol correctly`

Important production concerns include authenticated encryption, secure key storage, nonce management, explicit serialization formats, versioned ciphertext envelopes, access control, rotation procedures, backup and recovery behavior, audit requirements, and protection against accidental secret disclosure.

The source code in this project is therefore best treated as an implementation study of block-cipher mechanics and their integration boundaries, not as a replacement for a reviewed cryptographic library.
