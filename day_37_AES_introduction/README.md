# AES Introduction

## Scope

This project introduces the Advanced Encryption Standard (AES) from the level of a single 128-bit block through practical authenticated encryption and database-backed protected-data workflows.

The implementations deliberately use different perspectives.

- The Python program implements AES-128 directly and exposes the internal transformations, key expansion, CBC mode, CTR mode, padding, and an educational encrypt-then-MAC construction.
- The JavaScript program combines a direct AES-128 implementation with Node.js `crypto` for a production-oriented AES-256-GCM path.
- The C++ program treats AES as the cryptographic primitive inside a document-vault case study and focuses on the relationship between the primitive, block processing, and application architecture.
- The Java program models an enterprise document-protection service using JCA/JCE, explicit key lifecycle states, authenticated metadata, AES-256-GCM, and failure handling.
- The PostgreSQL script models encryption-key lifecycle and protected-document metadata while using `pgcrypto` to execute AES-256-based symmetric protection inside the database.

The implementations are educational. Hand-written cryptographic implementations should not replace established, reviewed cryptographic libraries in production systems.

## AES Fundamentals

AES is a symmetric block cipher standardized as a successor to older symmetric algorithms such as DES and 3DES. Encryption and decryption depend on secret key material shared by the communicating or processing parties.

AES always operates on a **128-bit block**, which is 16 bytes.

The standard defines three key sizes:

| Variant | Key size | AES rounds |
|---|---:|---:|
| AES-128 | 128 bits | 10 |
| AES-192 | 192 bits | 12 |
| AES-256 | 256 bits | 14 |

A frequent source of confusion is the difference between block size and key size. AES-256 does not have a 256-bit block. It still processes 128-bit blocks. The number 256 refers to the secret key length.

The Python, JavaScript, and C++ implementations use AES-128 when showing the internal AES algorithm because the smaller key schedule makes the mechanism easier to inspect.

## AES State

AES represents each 16-byte block as a 4 × 4 byte state.

The state is arranged column by column rather than as four ordinary sequential rows. This matters because `ShiftRows` and `MixColumns` operate on that representation.

The core AES encryption structure is:

`AddRoundKey`

followed by repeated rounds containing:

`SubBytes → ShiftRows → MixColumns → AddRoundKey`

The final AES round performs:

`SubBytes → ShiftRows → AddRoundKey`

The final round intentionally omits `MixColumns`.

## SubBytes

`SubBytes` replaces every state byte through a nonlinear substitution table called the S-box.

The S-box is not simply a random lookup table. It is constructed from operations in the finite field GF(2^8), followed by an affine transformation.

The nonlinear substitution is important because a purely linear cipher would be much easier to analyze.

The Python, JavaScript, and C++ implementations contain the AES S-box explicitly. This makes the byte-level transformation visible rather than hiding it behind a cryptographic API.

Decryption uses the inverse S-box.

## ShiftRows

`ShiftRows` changes the positions of bytes in the state.

The first row is unchanged. The next rows are cyclically shifted by increasing offsets.

This creates diffusion between columns. A byte that begins in one column is moved into another position before `MixColumns` processes the state.

The transformation is reversible, so AES defines an inverse row-shifting operation for decryption.

## MixColumns

`MixColumns` transforms each four-byte column using arithmetic in GF(2^8).

A column is multiplied by a fixed matrix:

`[02 03 01 01]`
`[01 02 03 01]`
`[01 01 02 03]`
`[03 01 01 02]`

This causes bytes within a column to influence one another.

The multiplication is not ordinary integer multiplication. It is finite-field multiplication modulo the AES polynomial.

The Python `gf_multiply`, JavaScript `gfMultiply`, and C++ `gfMultiply` implementations expose this mechanism directly.

The inverse matrix is used during decryption.

## AddRoundKey

`AddRoundKey` XORs the state with a round key.

XOR is appropriate for this operation because every byte has a simple inverse under XOR:

`A XOR B XOR B = A`

The security of AES does not come from XOR alone. The strength results from the interaction of nonlinear substitution, permutation, diffusion, and the secret-key schedule.

## Key Expansion

AES does not use the original key independently in every round.

For AES-128, the 16-byte input key expands into 44 four-byte words. Four words form each of the 11 round keys.

The key schedule uses:

- word rotation
- S-box substitution
- round constants
- XOR with earlier key-schedule words

The Python implementation returns 11 round keys. The JavaScript implementation builds the same schedule using JavaScript arrays and typed byte arrays. The C++ implementation stores the expanded keys in an `std::array`.

Key expansion is important because an implementation error in the schedule produces completely incorrect ciphertext even when the round transformations are otherwise correct.

## Known-Answer Testing

All three direct AES implementations contain the well-known AES-128 test vector:

Key:

`000102030405060708090a0b0c0d0e0f`

Plaintext:

`00112233445566778899aabbccddeeff`

Expected ciphertext:

`69c4e0d86a7b0430d8cdb78070b4c55a`

A known-answer test is stronger than simply encrypting and decrypting the same message. An incorrect implementation can sometimes pass a round-trip test if encryption and decryption contain matching mistakes.

Comparing against an independently defined expected ciphertext detects those errors.

## AES Modes

AES itself operates on a single 16-byte block. Real application data is usually larger, so a mode of operation is required.

The mode determines how multiple blocks are processed and what additional values, such as initialization vectors or counters, are required.

### ECB

Electronic Codebook mode encrypts each block independently.

The major problem is that identical plaintext blocks under the same key produce identical ciphertext blocks. Structured data can therefore reveal patterns.

The C++ case study intentionally works with a single AES block so that the primitive can be studied in isolation. It does not present raw block encryption as an appropriate design for a real document vault.

ECB is generally inappropriate for structured application data.

### CBC

Cipher Block Chaining combines each plaintext block with the previous ciphertext block before AES encryption.

For the first block, an initialization vector is used.

Conceptually:

`C1 = AES(K, P1 XOR IV)`

and:

`Ci = AES(K, Pi XOR C(i-1))`

CBC requires padding when the plaintext is not an exact multiple of 16 bytes.

The Python and JavaScript implementations use PKCS#7 padding and explicitly validate padding during decryption.

CBC has an important limitation: encryption alone does not authenticate the ciphertext. An application that uses CBC must provide integrity protection separately, usually through a carefully designed encrypt-then-MAC construction. Modern systems should normally prefer an authenticated-encryption mode instead.

### CTR

Counter mode turns the block cipher into a stream-like construction.

AES encrypts successive counter blocks to create keystream material. The keystream is XORed with plaintext.

The Python and JavaScript implementations demonstrate this behavior.

CTR does not require padding and can process data of arbitrary length.

The critical security rule is nonce or counter uniqueness. Reusing the same nonce with the same AES key causes the same keystream to be reused. If two ciphertexts are XORed together, the keystream cancels and relationships between the plaintexts can become visible.

### GCM

Galois/Counter Mode combines counter-mode encryption with an authentication mechanism.

It produces:

- ciphertext
- authentication tag

It can also authenticate associated data that is not encrypted.

The Java and JavaScript implementations use AES-GCM for the production-oriented path.

GCM is particularly useful for application records because it provides confidentiality and integrity as one authenticated-encryption construction.

## Python Implementation

The Python program is the most detailed low-level implementation.

It contains:

- the AES S-box and inverse S-box
- AES-128 key expansion
- finite-field multiplication
- state transformations
- AES block encryption
- AES block decryption
- PKCS#7 padding validation
- CBC encryption and decryption
- CTR encryption and decryption
- an educational encrypt-then-MAC construction
- known-answer testing
- round-trip testing
- tampering detection
- wrong-key failure behavior

The `aes_encrypt_block` function accepts exactly one 16-byte block. This makes the AES primitive boundary explicit.

The CBC functions handle multiple blocks and are therefore responsible for padding and chaining.

The CTR function does not pad because the generated keystream can be truncated to the length of the final plaintext segment.

The authenticated CBC demonstration derives separate encryption and authentication keys and verifies the HMAC before decryption. This illustrates why confidentiality and authentication are separate security properties.

The program explicitly warns that this construction is educational and that new applications should normally use a reviewed authenticated-encryption primitive such as AES-GCM.

## JavaScript Implementation

The JavaScript implementation demonstrates two distinct implementation layers.

The first layer implements AES-128 directly with `Uint8Array`. This exposes the state transformations while using JavaScript's byte-oriented data structures.

The second layer uses Node.js `crypto.createCipheriv` with `aes-256-gcm`.

This distinction is important for engineering practice. Understanding AES internals is useful for debugging, protocol analysis, and cryptographic education. It does not imply that application developers should replace a platform cryptographic implementation with handwritten cryptography.

The GCM example also demonstrates associated data.

The example authenticates:

`record-type=financial-transfer`

without encrypting it. A recipient can therefore use the metadata while still detecting unauthorized modification.

## C++ Case Study

The C++ implementation models a small document-vault scenario.

The `AES128` class owns the expanded AES-128 round keys and exposes `encrypt` and `decrypt` operations for one 16-byte block.

The `DocumentVault` class provides the application-facing boundary. Its purpose is deliberately narrow because the example is intended to show the distinction between a cryptographic primitive and the application that uses it.

The case study contains a fixed-size payroll metadata record so that the AES block transformation can be inspected without introducing a second concern such as padding.

The avalanche demonstration changes one input bit and compares the resulting ciphertexts. AES is designed so that small changes in plaintext or key produce substantial changes in ciphertext.

The C++ implementation also demonstrates a key design limitation: raw AES blocks do not provide authentication. An application that needs protected documents must select an appropriate mode and protocol rather than simply calling `AES128::encrypt` on every block.

## Java Implementation

The Java program uses the standard Java cryptographic architecture rather than implementing AES manually.

The main domain types are:

- `RecordClassification`
- `KeyState`
- `KeyMetadata`
- `ProtectedRecord`
- `AesKeyRing`
- `DocumentProtectionService`

`KeyState` represents a small key lifecycle model. An active key can encrypt and decrypt records, while retired keys are prevented from being used for new operations through the `activeKey` policy.

`ProtectedRecord` keeps ciphertext, nonce, authentication tag, classification, and key identity together. This makes the data required for decryption explicit.

The document classification is passed to GCM as authenticated associated data. It remains readable to the storage layer but cannot be modified without invalidating the authentication tag.

The service rejects a record referencing a different key identifier. It also refuses to use a retired or revoked key for the active encryption path.

The Java implementation catches authentication failures through the JCA/JCE exception path rather than trying to interpret unauthenticated plaintext.

## SQL Data Model

The PostgreSQL script models the storage side of an AES-protected system.

`encryption_keys` stores:

- key identity
- algorithm
- declared key size
- lifecycle state
- activation time
- retirement time
- revocation time

Constraints prevent unsupported AES key sizes and impossible lifecycle combinations.

`protected_documents` stores:

- document reference
- classification
- encryption-key identifier
- SHA-256 plaintext hash
- encrypted payload
- timestamps

The foreign key ensures that a protected document references an existing encryption-key record.

The indexes on key identifiers and classifications support common operational queries without indexing encrypted payload bytes as if they were searchable plaintext.

`encryption_audit` records encryption, decryption, and rekey operations together with success or failure state.

The `encrypt_document` function selects the active AES key and uses `pgcrypto` with `cipher-algo=aes256`.

The `decrypt_document` function checks key lifecycle status, decrypts the payload, recalculates the plaintext hash, and records the operation.

The database therefore demonstrates that cryptographic correctness is only one part of a larger data-protection design. Key identity, key lifecycle, integrity metadata, auditing, and database constraints also matter.

## Keys, Passwords, and Nonces

An AES key is binary cryptographic material. It should not be treated as an ordinary human password.

If a user supplies a password, a password-based key derivation function such as Argon2id, scrypt, or PBKDF2 is needed to derive cryptographic key material. The choice depends on the application and threat model.

Cryptographically secure randomness is required for generated keys and appropriate nonces.

The implementations use secure random facilities where they generate demonstration keys or nonces.

Nonce requirements depend on the mode.

For GCM, nonce uniqueness under the same key is critical. A commonly used GCM nonce size is 96 bits.

For CTR, the counter/nonce combination must never repeat under the same key.

For CBC, the IV must be unpredictable and should not be reused in a way that violates the security model.

## Confidentiality Versus Integrity

AES encryption alone answers a confidentiality question:

> Can an unauthorized party recover the plaintext from the ciphertext?

It does not automatically answer the integrity question:

> Can an unauthorized party modify the ciphertext without detection?

This distinction explains why authenticated encryption is important.

AES-GCM produces an authentication tag. During decryption, the tag must be verified before the plaintext is considered valid.

CBC combined with an independently designed MAC can also provide authenticated encryption, but constructing such a protocol correctly is more difficult than selecting a reviewed AEAD construction.

## Edge Cases

The implementations deliberately exercise several failure conditions.

Invalid AES block sizes are rejected because AES operates on exactly 16-byte blocks.

Invalid CBC ciphertext lengths are rejected because CBC ciphertext must contain complete blocks.

Invalid PKCS#7 padding is rejected rather than silently stripping arbitrary bytes.

A wrong AES key produces unusable plaintext or authentication failure depending on the construction.

Tampered GCM ciphertext is rejected by authentication.

Modified GCM associated data is also rejected even though the associated data is not encrypted.

Retired and revoked key states are handled separately from ciphertext state in the Java and SQL implementations.

## Performance Considerations

AES is designed for efficient implementation and is commonly accelerated by CPU instructions such as AES-NI on supported x86 systems and corresponding hardware acceleration on other architectures.

The hand-written Python, JavaScript, and C++ implementations perform finite-field operations directly and therefore should not be considered performance references.

Production libraries can exploit hardware acceleration, optimized memory access, batching, and constant-time implementation techniques.

For large data sets, applications should avoid repeatedly constructing cryptographic objects unnecessarily while also respecting the API's security requirements.

Database encryption introduces another performance dimension. Encrypted data may not be directly searchable or sortable like plaintext, so systems often keep carefully selected non-sensitive metadata outside the encrypted payload.

## Security Considerations

A secure AES deployment requires more than choosing AES-256.

Important design decisions include:

- selecting an authenticated-encryption mode
- generating keys with a cryptographically secure random source
- protecting keys separately from ordinary application data
- enforcing nonce uniqueness
- rotating and revoking keys when required
- avoiding ECB for structured data
- validating authentication before trusting decrypted plaintext
- avoiding logging plaintext, keys, nonces combined with sensitive context, or authentication material unnecessarily
- using reviewed cryptographic libraries instead of handwritten implementations
- separating key identifiers from actual key material
- defining how old ciphertext is handled when keys are rotated
- controlling which services and operators can access decryption keys

The Java key lifecycle model and SQL key-state constraints illustrate why key governance belongs in the system architecture rather than being left entirely to encryption calls.

## Common Implementation Mistakes

Confusing AES key size with block size leads to incorrect buffer and protocol assumptions. Every AES variant still has a 128-bit block.

Reusing a GCM nonce with the same key can seriously compromise security.

Reusing a CTR nonce with the same key can expose relationships between plaintexts.

Using ECB because it is simple can leak repeated data patterns.

Encrypting without authentication can allow undetected ciphertext manipulation.

Using a password directly as an AES key produces weak and predictable key material when the password has low entropy.

Treating a successful decryption API call as proof of authenticity is unsafe when the selected mode does not authenticate the ciphertext.

Writing a cryptographic implementation for production without independent review creates risks that are difficult to identify through ordinary unit tests.

## Production Boundary

The direct AES implementations are useful for understanding the algorithm and validating known-answer vectors.

They should not be copied into production systems merely because they produce correct ciphertext for simple test vectors.

A production system needs reviewed implementations, carefully defined key management, authenticated encryption, secure randomness, nonce management, access control, operational logging, rotation policy, recovery procedures, and a threat model.

The central distinction is between understanding a cryptographic primitive and designing a secure cryptographic system around that primitive.
