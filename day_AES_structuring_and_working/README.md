# AES Structure and Working

## Scope

This learning artifact examines the Advanced Encryption Standard at two distinct levels.

The first level is the **AES block-cipher structure** itself. AES transforms a fixed 128-bit data block through a sequence of byte substitution, row permutation, column mixing, and round-key addition. AES-128 performs ten rounds, AES-192 performs twelve, and AES-256 performs fourteen.

The second level is **application use of AES**. A correct AES primitive is not by itself a complete application security design. Real systems need a mode of operation, secure key lifecycle management, nonce or IV handling, authentication where required, validation, and controlled handling of sensitive material.

The six deliverables approach these levels differently. The Python implementation exposes the internal AES-128 transformations directly. The JavaScript implementation combines a visible AES structure model with Node.js authenticated encryption. The C++ implementation turns the AES pipeline into an auditable encryption-engine case study. The Java implementation models enterprise document protection with AES-GCM. The PostgreSQL script models cryptographic operations and AES state information relationally.

## AES as a Block Cipher

AES is a symmetric block cipher standardized around a 128-bit block size. The same secret key is conceptually shared by the encryption and decryption parties, although the encryption and decryption transformations are not simply identical executions in reverse source-code order.

The fixed block size means that AES operates on exactly 16 bytes at the primitive level. A 128-bit key produces ten encryption rounds. A 192-bit key produces twelve rounds, while a 256-bit key produces fourteen.

The important structural distinction is that **block size and key size are independent properties**. AES always operates on 128-bit blocks even when the key is 192 or 256 bits.

The AES state is represented as a 4 × 4 matrix of bytes. AES fills this matrix column by column. For a block represented as:

`00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff`

the state is:

`00 44 88 cc`  
`11 55 99 dd`  
`22 66 aa ee`  
`33 77 bb ff`

This ordering is important because ShiftRows and MixColumns operate on the state matrix rather than on a simple linear sequence of four-byte chunks.

## The AES Round Structure

AES encryption begins with an **initial AddRoundKey** operation. This is followed by the regular rounds.

A regular AES encryption round contains:

- **SubBytes**, which replaces every state byte using the AES S-box.
- **ShiftRows**, which cyclically shifts each state row by a different amount.
- **MixColumns**, which transforms each state column using finite-field arithmetic.
- **AddRoundKey**, which XORs the state with the round-specific key.

The final round contains SubBytes, ShiftRows, and AddRoundKey but **does not contain MixColumns**. This omission is part of the AES specification and is not an optimization that an implementation may arbitrarily change.

For AES-128 the structural sequence is therefore:

`Initial AddRoundKey → 9 × (SubBytes → ShiftRows → MixColumns → AddRoundKey) → SubBytes → ShiftRows → AddRoundKey`

The Python, JavaScript, and C++ implementations expose this distinction directly.

## SubBytes

SubBytes provides the nonlinear component of the AES round transformation.

Every byte in the state is replaced using a fixed 256-entry substitution table called the **S-box**. The substitution is constructed from operations over the finite field GF(2^8) followed by an affine transformation.

The nonlinear S-box is important because simple linear transformations alone would not provide the desired resistance to cryptanalytic attacks. SubBytes therefore contributes substantially to AES's confusion properties.

The Python implementation stores the S-box explicitly and applies it independently to every state byte. The JavaScript and C++ implementations do the same for their internal AES demonstrations.

SubBytes does not move bytes between positions. It changes byte values while preserving the 4 × 4 state layout.

## ShiftRows

ShiftRows provides a positional permutation.

The first state row is left unchanged. The second row is rotated one byte to the left. The third row is rotated two bytes. The fourth row is rotated three bytes.

This operation moves bytes between columns. Its purpose is not simply visual rearrangement. ShiftRows ensures that subsequent MixColumns operations combine information originating from different parts of the original state.

ShiftRows therefore has a different responsibility from SubBytes:

| Transformation | Primary effect |
|---|---|
| SubBytes | Changes byte values nonlinearly |
| ShiftRows | Changes byte positions |
| MixColumns | Diffuses bytes within columns |
| AddRoundKey | Combines the state with key material |

Keeping these responsibilities separate makes the AES structure easier to reason about.

## MixColumns

MixColumns provides substantial diffusion within the AES state.

Each column contains four bytes. AES treats those bytes as elements of GF(2^8) and multiplies the column by a fixed matrix.

For an input column represented as:

`[a0, a1, a2, a3]`

the output is calculated using coefficients 2, 3, 1, and 1 in the finite field.

The first output byte is:

`2·a0 ⊕ 3·a1 ⊕ a2 ⊕ a3`

The other three rows use the corresponding rotations of these coefficients.

The multiplication is not ordinary integer multiplication. The implementation uses polynomial arithmetic over GF(2^8), with the AES reduction polynomial represented by `0x11B`.

This is why the Python and C++ implementations contain an `xtime` or equivalent finite-field multiplication mechanism.

The well-known test operation:

`0x57 × 0x13 = 0xFE`

illustrates that arithmetic.

MixColumns is applied to every encryption round except the final round.

## AddRoundKey

AddRoundKey is the AES operation that directly incorporates the expanded key into the state.

The operation is a bytewise XOR between the state and the current 128-bit round key.

XOR has useful properties for cryptographic construction:

- `x XOR 0 = x`
- `x XOR x = 0`
- `x XOR k XOR k = x`

The AES key schedule ensures that every round uses a different derived round key rather than repeatedly XORing the original key.

The initial AddRoundKey occurs before the first SubBytes operation. Subsequent round keys are added after the round's transformation stages.

## Key Expansion

AES does not use the original key unchanged in every round.

AES-128 expands the 16-byte key into eleven 16-byte round keys. These correspond to the initial key addition and the ten encryption rounds.

The key schedule works with four-byte words. Every fourth generated word undergoes:

- rotation through RotWord
- S-box substitution through SubWord
- XOR with a round constant

The transformed word is then XORed with the word four positions earlier.

This produces the expanded key material needed by each round.

The Python, JavaScript, and C++ implementations expose this process. The resulting round keys are printed or retained as explicit data so the relationship between the original key and individual rounds can be inspected.

## AES State and Diffusion

AES achieves its security through the interaction of nonlinear substitution, permutation, diffusion, and key addition.

SubBytes changes values.

ShiftRows spreads bytes across columns.

MixColumns combines bytes originating from different rows.

AddRoundKey introduces key-dependent information.

After multiple rounds, changing a single input bit produces extensive changes throughout the resulting ciphertext. This property is associated with the avalanche effect and is an important characteristic of a strong block cipher.

The transformations should therefore not be viewed as independent tricks. Their security contribution comes from their repeated composition.

## Python Implementation

The Python program is a direct AES-128 educational implementation.

It contains the S-box and round constants, converts 16-byte blocks into the AES state matrix, performs finite-field multiplication, implements SubBytes, ShiftRows, MixColumns, and AddRoundKey, and expands the AES-128 key.

`AES128.encrypt_block()` records a detailed round trace. The trace makes it possible to observe the state after each major transformation rather than treating encryption as an opaque function.

`AES128.decrypt_block()` implements the inverse transformations. The inverse sequence applies inverse ShiftRows, inverse SubBytes, AddRoundKey, and inverse MixColumns in the appropriate order.

The program validates its implementation against the well-known AES-128 test vector:

`Key:        000102030405060708090a0b0c0d0e0f`

`Plaintext:  00112233445566778899aabbccddeeff`

`Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a`

This test is important because cryptographic implementations can appear plausible while containing a subtle state-ordering, finite-field, key-expansion, or final-round error.

The Python program also validates key and block sizes and demonstrates that AES-128 requires a 16-byte key and a 16-byte primitive block.

## JavaScript Implementation

The JavaScript implementation focuses on two complementary concerns.

The first is structural inspection. The `aes128Trace()` function implements the AES-128 round pipeline and returns both expanded round keys and transformation events. JavaScript's `Buffer` type is useful for representing byte-oriented cryptographic material while the state remains an explicit four-row structure.

The second is application-oriented cryptography. Node's built-in `crypto` module is used for AES-128-GCM.

This distinction matters. Implementing AES manually is useful for studying the algorithm, but application software should normally rely on a mature cryptographic provider rather than using an educational implementation as its production encryption primitive.

The GCM example generates a fresh 12-byte nonce, encrypts application data, records the authentication tag, and authenticates additional data.

The example also modifies the authentication tag and verifies that decryption fails. This demonstrates an important distinction between encryption and authenticated encryption: confidentiality alone does not guarantee that tampering will be detected.

## C++ Case Study

The C++ program models a repository artifact encryption service.

The `AES128Engine` class owns the expanded round keys and exposes an encryption operation that records every AES transformation as a `RoundEvent`.

The `ArtifactEncryptionCaseStudy` class adds domain-level validation around the primitive. It requires an artifact identifier, restricts accepted classifications to defined values, executes AES-128 encryption, and produces an audit record containing the artifact identifier, classification, ciphertext, and structural round information.

This design separates the cryptographic engine from the business-facing workflow.

The `State` type is a four-by-four byte matrix, while `Block` represents the 16-byte AES block. This makes the relationship between the mathematical AES state and the implementation's memory representation explicit.

The C++ program also validates malformed hexadecimal input and invalid artifact identifiers. These checks illustrate that a cryptographic component still requires ordinary application validation at its boundaries.

The case study deliberately does not treat raw AES encryption as a complete application protocol. In a real system, authenticated encryption, key management, secure memory handling, access control, and audit protection would be separate security concerns.

## Java Enterprise Implementation

The Java program models protection of classified enterprise repository records.

Its domain types make several decisions explicit:

- `Classification` represents business sensitivity.
- `EncryptionPolicy` defines accepted AES key size, nonce size, authentication-tag size, and the requirement for authenticated encryption.
- `KeyMaterial` encapsulates the secret key and uses defensive copies.
- `ProtectedRecord` represents encrypted application data together with its nonce and authentication tag.
- `AuditEvent` records cryptographic operations and failure states.
- `RepositoryEncryptionService` owns the encryption and decryption workflow.

The application uses `AES/GCM/NoPadding` through the Java standard cryptographic provider.

GCM is relevant at the application layer because AES by itself is a block cipher, while an application normally needs a mode of operation to process arbitrary-length data. GCM also provides authentication, allowing the application to detect ciphertext or associated-data modification.

The Java implementation uses additional authenticated data for repository metadata. The metadata is not encrypted, but it is authenticated. Changing it causes authentication failure.

Defensive copies in `KeyMaterial` and `ProtectedRecord` prevent callers from modifying stored byte arrays through aliases. This is a Java-specific implementation concern that becomes important when cryptographic material is represented by mutable arrays.

## SQL Data Model

The PostgreSQL implementation models AES processing as an auditable relational workflow.

`aes_algorithm` contains structural AES parameters:

- fixed 128-bit block size
- AES key size
- round count
- the fact that the final round does not contain MixColumns

The table's check constraints encode these relationships. For example, AES-128 must have ten rounds, AES-192 must have twelve, and AES-256 must have fourteen.

`key_registry` contains key references and lifecycle state rather than raw secret key bytes. This is intentional. A production database should generally reference controlled key-management infrastructure instead of becoming an unrestricted secret-key repository.

`encryption_operation` records application-level encryption events. It stores operation type, status, plaintext and ciphertext lengths, nonce, authentication tag, and associated data metadata.

`aes_round_trace` records state transitions associated with individual transformations. This table demonstrates how a cryptographic processing trace can be represented relationally without storing plaintext or the secret key.

`validation_event` records explicit validation outcomes.

The SQL script creates indexes around operation status, key references, and round-trace retrieval because those are natural access paths for operational inspection.

The `validate_key_for_operation()` trigger prevents new operations from using retired or revoked keys. This demonstrates database-level enforcement of a key-lifecycle policy rather than relying entirely on application code.

## AES-128, AES-192, and AES-256

The AES variants use the same 128-bit block size but different key sizes and round counts.

| Variant | Key size | Block size | Rounds |
|---|---:|---:|---:|
| AES-128 | 128 bits | 128 bits | 10 |
| AES-192 | 192 bits | 128 bits | 12 |
| AES-256 | 256 bits | 128 bits | 14 |

The additional rounds in AES-192 and AES-256 arise from their larger key schedules.

The larger key does not create a larger AES block. A common conceptual error is to assume that AES-256 processes 256-bit blocks. It does not. AES-256 means a 256-bit key with a 128-bit block size.

## Encryption and Decryption

AES decryption uses inverse transformations.

The inverse S-box reverses SubBytes.

Inverse ShiftRows reverses the row rotations.

Inverse MixColumns uses a different finite-field matrix.

AddRoundKey remains XOR-based.

Because XOR is its own inverse, the same conceptual key-combination operation can be used when reversing the sequence.

The ordering is important. A cryptographic implementation cannot simply reverse the source-code statements without understanding how the inverse transformations interact with the state and round keys.

The Python implementation provides an explicit decryption path, while the application-oriented JavaScript and Java examples rely on established cryptographic providers for production-style encryption and decryption.

## Block Cipher Versus Encryption Mode

AES itself processes a single 128-bit block.

Applications commonly process data much larger than 16 bytes. A mode of operation defines how the primitive is repeatedly applied to application data.

ECB is generally unsuitable for protecting structured application data because identical plaintext blocks produce identical ciphertext blocks under the same key.

CBC requires correct padding and IV handling and does not by itself provide authentication.

CTR turns the block cipher into a counter-based stream construction but does not itself provide authentication.

GCM combines counter-mode encryption with authentication and is therefore frequently used when authenticated encryption is required.

The examples use AES-GCM for the application-level demonstrations because it addresses both confidentiality and integrity.

## Nonces and Authentication Tags

GCM uses a nonce, commonly 12 bytes in application protocols.

Nonce uniqueness is a critical security requirement. Reusing a nonce with the same GCM key can have severe consequences.

The nonce does not have to be secret. It must be managed correctly.

The authentication tag allows the receiver to verify that ciphertext and associated authenticated data have not been modified.

Associated data is authenticated but not encrypted. Repository identifiers, protocol metadata, or classification labels can therefore be bound to encrypted content without appearing inside the ciphertext.

The JavaScript and Java programs demonstrate this distinction directly.

## Key Management

AES security depends heavily on key management.

A strong AES implementation cannot compensate for a leaked key.

Production systems should therefore separate cryptographic key storage from ordinary application data storage where appropriate. A key-management service, hardware-backed key store, or operating-system protected keystore may provide stronger controls than storing raw keys in application tables or configuration files.

The SQL model consequently stores `key_reference`, key version, and lifecycle state rather than the actual secret key.

Key rotation introduces another important distinction. A new key can be introduced for new encryption operations while older records remain associated with their previous key versions until a controlled re-encryption process occurs.

Revocation is different from rotation. A revoked key should not be used for new operations.

## Validation and Failure Handling

AES implementations have several important boundary conditions.

A primitive AES block is exactly 16 bytes.

AES-128 requires a 16-byte key.

AES-192 requires a 24-byte key.

AES-256 requires a 32-byte key.

The educational Python and C++ implementations reject invalid sizes explicitly.

Application-level AES-GCM introduces additional requirements, including nonce management and authentication-tag validation.

Authentication failure must not be interpreted as ordinary malformed input. It is a security event because it may indicate ciphertext modification, incorrect associated data, an incorrect key, or an active attack.

The Java implementation models this with `AEADBadTagException` and an explicit `AUTHENTICATION_FAILED` audit state.

## Performance Characteristics

AES is designed for efficient implementation in both software and hardware.

The primitive has a fixed number of rounds for a given key size, so the per-block computational structure is predictable.

The most expensive operations in a conceptual software implementation include S-box lookup, state transformations, finite-field arithmetic, and key-schedule processing.

Production processors often provide AES-specific hardware instructions. Modern cryptographic libraries can use these instructions automatically, making them substantially preferable to interpreted educational implementations.

The JavaScript and Java examples therefore distinguish learning-oriented internal implementations from production-oriented standard cryptographic providers.

Database indexes in the SQL implementation address a different performance problem. They optimize retrieval of operational records and traces rather than AES itself.

## Security Considerations

A correct AES primitive does not automatically produce a secure application.

The key must remain secret.

Nonce requirements must be obeyed for the selected mode.

Authentication must be verified before decrypted data is trusted.

Plaintext and keys should not be unnecessarily written to logs.

Cryptographic failures should be distinguishable internally for auditing without exposing sensitive diagnostic information to untrusted callers.

Raw AES blocks should not be assembled into a custom encryption protocol without a well-understood construction.

The educational implementations intentionally expose intermediate states. That is useful for learning and testing, but intermediate AES states and round keys should not normally be logged in production systems because they can reveal sensitive cryptographic information.

## Common Implementation Errors

A frequent error is treating the AES state as four ordinary rows of the input byte sequence. AES's column-major state representation must be respected.

Another error is applying MixColumns to the final encryption round. The final round explicitly omits it.

A third error is implementing MixColumns with ordinary integer multiplication. AES uses finite-field multiplication over GF(2^8).

Incorrect key expansion is another common source of failure. RotWord, SubWord, and Rcon must occur at the correct word boundaries.

Application developers also frequently confuse AES-256 with a 256-bit block size. AES-256 still uses a 128-bit block.

Finally, using AES-ECB merely because it is easy to call does not provide an appropriate security design for structured application data.

## Testing Strategy

The implementations use deterministic known-answer testing because cryptographic code should be verified against independently established vectors.

The AES-128 vector used by the Python, JavaScript, and C++ educational components is:

`Key = 000102030405060708090a0b0c0d0e0f`

`Plaintext = 00112233445566778899aabbccddeeff`

`Ciphertext = 69c4e0d86a7b0430d8cdb78070b4c55a`

Round tracing provides another verification mechanism. An implementation can compare intermediate states to known reference values rather than checking only the final ciphertext.

Application-level tests should also cover invalid key sizes, malformed blocks, authentication-tag modification, associated-data modification, key lifecycle restrictions, and invalid application records.

## Relationship Between the Six Implementations

The deliverables deliberately use different perspectives.

The **Python implementation** is the clearest direct examination of AES-128 internals. It is the primary learning implementation for the state transformations and inverse operations.

The **JavaScript implementation** combines a visible AES-128 structure model with Node's production-oriented cryptographic API. Its event-oriented trace makes the transformation sequence easy to inspect.

The **C++ implementation** treats AES as an auditable engine inside a repository artifact service. Strongly typed byte arrays, state structures, validation, and explicit audit events demonstrate how the primitive can be incorporated into a systems-oriented design.

The **Java implementation** moves to an enterprise domain. Its explicit policy, classification, key material, protected record, service, and audit abstractions demonstrate how AES-GCM can become part of an application security workflow.

The **SQL implementation** represents the surrounding cryptographic governance layer. It stores algorithm definitions, key references, operation records, transformation traces, validation results, and lifecycle information while deliberately avoiding raw secret-key storage.

These perspectives are related but serve different purposes. The Python and C++ implementations expose internal mechanics, while the JavaScript and Java examples show the boundary between the primitive and an application cryptographic service. SQL addresses persistence, governance, and operational auditing rather than reimplementing AES inside the database.
