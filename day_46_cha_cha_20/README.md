# ChaCha20

## Scope

This project develops ChaCha20 from its primitive operations to complete message and artifact encryption. The six implementations use the same cryptographic specification from different engineering perspectives:

| Implementation | Primary purpose |
|---|---|
| Python | Self-contained primitive implementation, RFC verification, message handling, file processing, validation, and security demonstrations |
| JavaScript | Node.js-oriented stream-cipher implementation, structured transport messages, filesystem behavior, and comparison with ChaCha20-Poly1305 |
| C++ | Repository artifact encryption case study with an explicit envelope and large-artifact processing |
| Java | Enterprise message service with immutable domain modeling, defensive copying, validation, and transport representation |
| PostgreSQL | Relational representation of encryption operations plus a database implementation of the ChaCha20 block and XOR stream operation |

The implementations deliberately distinguish the ChaCha20 primitive from authenticated encryption. ChaCha20 encrypts by XORing plaintext with a generated keystream. It does not independently provide a mechanism for detecting malicious ciphertext modification.

## ChaCha20 construction

ChaCha20 operates on a 16-word state. Every word is an unsigned 32-bit value, so the complete internal state is 512 bits.

The state has this logical layout:

    constant constant constant constant
    key      key      key      key
    key      key      key      key
    counter  nonce    nonce    nonce

The first four words encode the ASCII constant `expand 32-byte k`. Eight words contain the 256-bit key. One word contains the block counter, and three words contain the 96-bit nonce.

The RFC 8439 layout used by these implementations is:

- Key: 256 bits
- Nonce: 96 bits
- Counter: 32 bits
- Keystream block: 512 bits
- Rounds: 20
- Double rounds: 10
- Quarter rounds per double round: 8

The counter and nonce are separate pieces of state. The nonce identifies the message-level keystream sequence, while the counter selects successive 64-byte blocks within that sequence.

## Quarter round

The quarter round is the fundamental transformation.

For four words `a`, `b`, `c`, and `d`, ChaCha20 performs additions modulo `2^32`, XOR operations, and left rotations by 16, 12, 8, and 7 bits.

Conceptually:

    a += b
    d ^= a
    d <<< 16

    c += d
    b ^= c
    b <<< 12

    a += b
    d ^= a
    d <<< 8

    c += d
    b ^= c
    b <<< 7

The addition is deliberately modulo `2^32`. The low 32 bits are retained and any carry beyond bit 31 is discarded.

The Python, JavaScript, C++, Java, and PostgreSQL implementations all preserve this arithmetic requirement. JavaScript uses unsigned 32-bit coercion and typed integers, C++ uses `uint32_t`, Java uses `int` with defined two's-complement overflow behavior, and PostgreSQL explicitly masks `bigint` calculations to 32 bits.

## Column and diagonal rounds

A ChaCha20 double round contains a column round followed by a diagonal round.

The column round applies quarter rounds to:

    (0, 4, 8, 12)
    (1, 5, 9, 13)
    (2, 6, 10, 14)
    (3, 7, 11, 15)

The diagonal round then applies quarter rounds to:

    (0, 5, 10, 15)
    (1, 6, 11, 12)
    (2, 7, 8, 13)
    (3, 4, 9, 14)

Ten double rounds produce the full 20-round ChaCha20 transformation.

The original state is then added to the transformed working state word by word. The resulting sixteen words are serialized in little-endian form to produce the 64-byte keystream block.

This feed-forward addition is distinct from the additions inside the quarter round. The quarter-round additions mix state words during permutation, while the final addition combines the transformed state with the original input state.

## Encryption and decryption

ChaCha20 uses:

    ciphertext = plaintext XOR keystream

Decryption uses exactly the same operation:

    plaintext = ciphertext XOR keystream

because:

    (P XOR K) XOR K = P

The implementations therefore do not require separate cryptographic encryption and decryption algorithms. They require the same key, nonce, counter, and block sequence.

The Python implementation exposes this directly through `chacha20_encrypt` and `chacha20_decrypt`, while the JavaScript, C++, Java, and SQL implementations use the same XOR mechanism for both directions.

## RFC 8439 verification

The implementations use the RFC 8439 encryption example:

Key:

    000102030405060708090a0b0c0d0e0f
    101112131415161718191a1b1c1d1e1f

Nonce:

    000000090000004a00000000

Initial counter:

    1

The plaintext is the well-known RFC test message beginning with:

    Ladies and Gentlemen of the class of '99:

The resulting ciphertext is checked against the RFC-defined hexadecimal vector. This is important because cryptographic implementations can appear plausible while containing a subtle endian, rotation, counter, or state-indexing error.

The test also decrypts the ciphertext and verifies exact recovery of the original plaintext.

## Nonce uniqueness

The most important operational rule in these examples is that a nonce must not be reused with the same key.

The nonce is not secret. It is normal for it to accompany ciphertext.

The security requirement is uniqueness, not confidentiality.

If the same key and nonce are reused, the same keystream is generated:

    C1 = P1 XOR K
    C2 = P2 XOR K

Therefore:

    C1 XOR C2 = P1 XOR P2

An attacker can compute the left-hand side from two ciphertexts and obtain a relationship between the plaintexts.

The Python, JavaScript, C++, and Java demonstrations explicitly reproduce this relationship. The examples use different plaintexts but intentionally reuse the same key and nonce to expose why nonce reuse is a protocol failure.

## Counter management

Each ChaCha20 block consumes 64 bytes of keystream.

The first block normally uses counter `1` in the RFC 8439 IETF construction. The next block uses counter `2`, then `3`, and so on.

The counter is 32 bits. A single key and nonce combination cannot safely continue past the available counter space.

The implementations therefore validate:

    0 <= counter <= 2^32 - 1

and reject messages whose required block count would exceed the remaining counter space.

A counter is not a substitute for nonce uniqueness. The counter identifies blocks within one nonce-defined stream. Reusing the same key and nonce sequence for another independent message recreates the same stream.

## Python implementation

The Python program is the most complete implementation-oriented demonstration.

`rotl32` implements the fixed-width left rotation. `quarter_round` contains the four additions, XOR operations, and rotations that form the basic ChaCha transformation.

`initial_state` constructs the RFC state from constants, key, counter, and nonce. `chacha20_block` performs the ten double rounds and final feed-forward addition. `chacha20_encrypt` converts those blocks into an arbitrary-length stream cipher operation.

The program also defines `ChaCha20Message`, which keeps a nonce and ciphertext together as transport metadata while deliberately keeping the secret key outside the message structure.

The file-processing functions show how nonce metadata can be stored alongside ciphertext. They are intentionally simple and memory-based. Large production files should normally be processed incrementally rather than loaded completely into memory.

The validation demonstrations cover incorrect key lengths, incorrect nonce lengths, invalid counters, and counter exhaustion.

## JavaScript implementation

The JavaScript implementation is designed around Node.js behavior.

`Uint32Array` is used for the ChaCha20 working state. JavaScript's bitwise operators operate on 32-bit integer values, which is useful for the quarter-round operations, while `>>> 0` keeps values in an unsigned 32-bit representation.

The implementation also uses Node's `crypto.randomBytes` to create nonce and key material. Cryptographic randomness should not be replaced by ordinary `Math.random()`.

The structured message functions encode the nonce and ciphertext using Base64URL. This is useful when encrypted values need to move through JSON-oriented application protocols.

A separate demonstration uses Node's `chacha20-poly1305` capability. This is intentionally separate from the hand-written raw ChaCha20 implementation because authenticated encryption is a different security construction.

The JavaScript file also demonstrates asynchronous filesystem operations, giving the primitive a practical Node.js persistence boundary without turning filesystem access into part of the cipher itself.

## C++ artifact encryption case study

The C++ program models a repository artifact service.

`SecureArtifactStore` receives a secret key and exposes an encryption/decryption boundary. The resulting `ArtifactEnvelope` contains a version, nonce, initial counter, and ciphertext.

This is a useful separation of concerns:

    key
     |
     v
    SecureArtifactStore
     |
     +--> ChaCha20 primitive
     |
     v
    ArtifactEnvelope
      +-- version
      +-- nonce
      +-- counter
      +-- ciphertext

The envelope does not contain the key.

The case study processes a multi-block artifact of 4097 bytes. This is large enough to exercise the block counter rather than only demonstrating a single 64-byte block.

The C++ implementation uses `std::array` for fixed-size keys, nonces, and blocks. This communicates the protocol's fixed-width requirements at the type level. `std::vector` represents variable-length artifact data.

The C++ integer type `std::uint32_t` directly expresses the 32-bit ChaCha word requirement and avoids depending on the implementation-defined width of ordinary integer types.

## Java enterprise model

The Java program models an encryption service rather than simply exposing a collection of static cryptographic functions.

`EncryptedEnvelope` is a record representing the transport-level result. Its compact constructor validates the version, algorithm identifier, nonce, and counter. The byte-array accessors return defensive copies, preventing callers from modifying the internal representation through a shared mutable array.

`ArtifactEncryptionService` owns a defensive copy of its key and generates a fresh nonce for every encryption operation.

The service model is particularly important for enterprise code because cryptographic correctness depends on boundaries around the primitive. A correct ChaCha20 block function can still be deployed insecurely if keys are exposed, nonces are reused, ciphertext is accepted without authentication, or protocol metadata is ambiguous.

## PostgreSQL data model

The PostgreSQL script uses three principal tables.

`cipher_keys` represents encryption keys for the demonstration. It contains a unique key name, fixed 32-byte key material, activation state, and creation timestamp.

`encryption_operations` records the relationship between a key, nonce, counter, plaintext length, and ciphertext. The unique constraint on `(key_id, nonce)` expresses an important protocol invariant at the database layer: the same nonce cannot be recorded twice for the same key.

`chacha20_test_vectors` stores deterministic test material and its expected ciphertext. This makes the RFC verification reproducible from relational data.

The schema uses domains:

    bytea_32
    bytea_12

to enforce the required sizes of keys and nonces.

The database implementation uses `bigint` because PostgreSQL does not expose a native unsigned 32-bit integer type. The helper functions `u32`, `add_u32`, `xor_u32`, and `rotl32` explicitly restrict arithmetic to the low 32 bits.

`chacha20_block` constructs the sixteen-word state and performs the ten column/diagonal double rounds. `chacha20_xor` generates successive blocks and XORs them with the supplied input.

This database implementation is primarily educational and verification-oriented. A high-throughput database should not generally become the primary location for cryptographic computation merely because the primitive can be expressed in SQL.

## Raw ChaCha20 versus ChaCha20-Poly1305

The distinction between these constructions is fundamental.

| Property | ChaCha20 | ChaCha20-Poly1305 |
|---|---|---|
| Confidentiality | Yes | Yes |
| Ciphertext authentication | No | Yes |
| Tamper detection | No | Yes |
| Associated data authentication | No | Yes |
| Suitable for general application protocols | Usually insufficient alone | Designed for authenticated encryption |

Raw ChaCha20 should not be treated as an authenticated encryption scheme.

If an attacker changes a ciphertext byte, raw ChaCha20 will generally produce a corresponding changed plaintext byte after decryption. There is no built-in authentication tag that tells the receiver the ciphertext was altered.

ChaCha20-Poly1305 combines the ChaCha20 encryption mechanism with Poly1305 authentication. The authentication tag must be verified before decrypted plaintext is trusted.

## Key handling

A 256-bit ChaCha20 key is secret.

A nonce is not secret.

These roles should not be confused.

A transport envelope can therefore contain:

    algorithm
    version
    nonce
    counter
    ciphertext
    authentication tag, when using AEAD

without containing the encryption key.

Keys should normally be managed through an appropriate key-management boundary rather than being embedded in source code, committed to repositories, printed in logs, or stored next to encrypted application data.

The Python examples generate keys with `secrets.token_bytes`. The JavaScript and Java examples use cryptographically secure random generators. The C++ case study uses a random-device demonstration, while deterministic values are used separately for reproducible test vectors.

## Authentication and tampering

Encryption alone does not establish authenticity.

For example, suppose an application encrypts a confidential database record using raw ChaCha20. An attacker who can modify the stored ciphertext may not learn the original plaintext, but the attacker can still cause controlled ciphertext modifications.

The receiving system has no cryptographic evidence that the ciphertext was produced by the expected sender or remained unchanged.

An authenticated design needs an integrity mechanism. ChaCha20-Poly1305 provides this through Poly1305 and authenticated associated data.

Associated data is useful for information that must be authenticated but does not need encryption, such as:

    protocol version
    record identifier
    tenant identifier
    algorithm identifier
    message type

Changing authenticated associated data causes authentication failure even though that data is not encrypted.

## Endianness

ChaCha20 interprets its 32-bit words in little-endian order.

This matters when converting between byte arrays and integer state words.

For example, four bytes:

    01 02 03 04

represent:

    0x04030201

under little-endian interpretation.

The Python implementation uses `int.from_bytes(..., "little")`. JavaScript uses `Buffer.readUInt32LE`. C++ explicitly assembles and writes little-endian words. Java performs the same byte-level conversion manually. PostgreSQL uses `get_byte` and explicit shifts.

A mismatch here can produce output that looks random but will fail interoperability with standards-compliant implementations.

## Security boundaries

The cryptographic primitive should not be confused with the surrounding protocol.

Important boundaries demonstrated by the implementations are:

- Key management controls secrecy of the 256-bit key.
- Nonce management prevents stream reuse under the same key.
- Counter management prevents block-space exhaustion.
- Serialization determines how protocol metadata is represented.
- Authentication determines whether tampering can be detected.
- Input validation prevents malformed protocol values from entering the primitive.
- Logging policy prevents keys and sensitive plaintext from leaking through operational telemetry.

These concerns are related, but they are not interchangeable.

## Performance characteristics

ChaCha20 processes 64 bytes per block and performs a fixed amount of arithmetic per block. Its running time is therefore approximately linear in plaintext size.

For a message containing `n` bytes:

    number of blocks = ceil(n / 64)

The block function itself always performs the same 20-round transformation regardless of message length.

The implementations allocate output proportional to the input size. The Python file example reads a complete file into memory, which is appropriate for a teaching demonstration but not ideal for very large objects.

Streaming implementations can process fixed-size chunks while retaining the same ChaCha20 state progression. The key, nonce, and counter management rules do not disappear when the processing model becomes streaming.

## Common implementation failures

### Incorrect rotation

Using the wrong rotation amount changes the state diffusion and invalidates the cipher implementation. ChaCha20 specifically uses 16, 12, 8, and 7.

### Incorrect round ordering

Column rounds must be followed by diagonal rounds. Applying diagonal rounds first or using the wrong state indices produces incompatible output.

### Incorrect endian conversion

ChaCha20's state words are little-endian. Big-endian serialization changes every state word.

### Counter overflow

The counter is 32 bits. An implementation that silently wraps it can regenerate a previous keystream block.

### Nonce reuse

A fresh nonce must be generated for each encryption under a given key. The nonce itself does not need to be secret.

### Treating ciphertext as authenticated

Raw ChaCha20 does not contain an authentication tag. A successful decryption does not prove that ciphertext was not modified.

### Weak randomness

Nonce and key generation must use a cryptographically secure random source where random nonces are selected. Predictable application-level randomness is unsuitable for cryptographic key or nonce generation.

### Exposing keys in logs

Hexadecimal output is useful for deterministic test vectors but dangerous for production secrets. Debug logging should never casually print live encryption keys.

## Testing strategy

A cryptographic implementation should not be trusted merely because encryption followed by decryption returns the original plaintext.

The artifacts therefore use several different forms of validation:

- The RFC 8439 vector verifies exact interoperability.
- Round-trip tests verify that the XOR construction is reversible.
- Input validation tests reject incorrect key and nonce lengths.
- Counter tests verify the protocol's finite counter space.
- Multi-block tests exercise counter progression.
- Nonce-reuse demonstrations expose a specific stream-cipher failure mode.
- The PostgreSQL test-vector table makes deterministic verification available inside the database.

Known-answer tests are especially valuable for cryptographic primitives because incorrect implementations often produce output that appears statistically random.

## Production considerations

The code demonstrates the ChaCha20 primitive and its protocol boundaries, but raw ChaCha20 should not normally be selected as the complete security protocol for application data.

A production system generally needs authenticated encryption, explicit key lifecycle management, nonce-generation rules, secure serialization, replay considerations where relevant, access control, secret rotation, and operational controls around logs and backups.
