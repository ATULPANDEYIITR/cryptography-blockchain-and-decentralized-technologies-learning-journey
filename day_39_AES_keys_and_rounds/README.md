# AES Keys and Rounds

## Technical scope

The Advanced Encryption Standard (AES) is a symmetric block cipher standardized in FIPS 197. It encrypts and decrypts fixed-size blocks using a secret key. AES always processes a 128-bit block, regardless of the key length.

The key length determines the number of rounds:

| Variant | Key length | Block length | Rounds | Round keys |
|---|---:|---:|---:|---:|
| AES-128 | 128 bits | 128 bits | 10 | 11 |
| AES-192 | 192 bits | 128 bits | 12 | 13 |
| AES-256 | 256 bits | 128 bits | 14 | 15 |

A round is a sequence of transformations applied to the internal state. A round key is a 128-bit value derived from the original key by the AES key expansion algorithm. The initial key addition, intermediate rounds, and final round have distinct roles.

AES-256 does not use a larger block than AES-128. It uses a longer secret key, a different key schedule, and four additional rounds. Increasing the key size does not remove the need for correct nonce handling, authenticated encryption, secure key storage, and sound application design.

## AES state representation

AES maps each 16-byte input block to a 4-by-4 matrix of bytes. Bytes are placed into the state column by column. If the input block is `b[0]` through `b[15]`, the state entry at row `r` and column `c` is `b[4c + r]`.

This ordering is important. An implementation that fills the matrix row by row can produce incorrect ciphertext even when its individual transformations appear mathematically correct.

The state is transformed in place. Each transformation has a specific purpose:

- **SubBytes** applies a nonlinear substitution to each byte using the AES S-box.
- **ShiftRows** rotates the second, third, and fourth rows left by one, two, and three bytes, respectively.
- **MixColumns** combines the four bytes in each column using finite-field arithmetic.
- **AddRoundKey** XORs the state with a 16-byte round key.

The initial operation is AddRoundKey. Intermediate rounds use all four transformations in the order SubBytes, ShiftRows, MixColumns, and AddRoundKey. The final round omits MixColumns.

## Finite-field arithmetic and substitution

AES operates on bytes as elements of the finite field GF(2^8). Addition in this field is bitwise XOR. Multiplication is polynomial multiplication reduced modulo the irreducible polynomial

`x^8 + x^4 + x^3 + x + 1`.

Its hexadecimal representation is `0x11B`. The `xtime` operation multiplies a byte by `x`, reducing the result when the original most significant bit is set. General field multiplication can be implemented through repeated conditional XOR operations and `xtime`.

The forward S-box combines multiplicative inversion in GF(2^8) with an affine transformation. Zero is mapped through a special inverse case. For nonzero byte values, exponentiation to 254 yields the multiplicative inverse. The affine transformation uses bit rotations and the constant `0x63`.

The Python, JavaScript, and C++ implementations generate the S-box from these mathematical operations rather than embedding a 256-entry table. This makes the construction visible and testable. It is an educational choice, not a claim of side-channel resistance. Data-dependent table access and ordinary high-level implementations may expose timing or cache behavior.

## Key expansion

AES does not reuse the original key unchanged in every round. The key expansion algorithm derives a sequence of 32-bit words and groups four words into each 128-bit round key.

Let `Nk` be the original key length in 32-bit words:

| AES variant | `Nk` | Total expanded words |
|---|---:|---:|
| AES-128 | 4 | 44 |
| AES-192 | 6 | 52 |
| AES-256 | 8 | 60 |

The total number of words is `4 × (Nr + 1)`, where `Nr` is the number of rounds.

For each expanded word, the algorithm begins with the previous word. At indices divisible by `Nk`, it rotates the word, substitutes its bytes through the S-box, and XORs a round constant into the first byte. The round constant advances through multiplication by `x` in GF(2^8).

AES-256 has an additional substitution step when the word index modulo `Nk` equals four. This rule is essential to its key schedule and must not be omitted when implementing the 256-bit variant.

The new word is obtained by XORing the transformed previous word with the word `Nk` positions earlier. The resulting sequence supplies the initial AddRoundKey and the key for every round.

## Python implementation

The Python file builds an educational AES implementation using byte strings, lists, and explicit functions for the transformations.

`AESParameters.from_key_length` validates the supported key sizes and associates each size with its required round count. `bytes_to_state` and `state_to_bytes` preserve the column-major state layout. `gf_multiply` implements field multiplication, while `generate_sboxes` constructs the forward and inverse substitution tables.

`EducationalAES._expand_key` implements the word expansion rules, including the additional AES-256 substitution. The `round_keys` collection contains exactly `Nr + 1` blocks. `encrypt_block` applies the initial key addition, intermediate rounds, and the distinct final round. `decrypt_block` reverses the transformations using the inverse S-box, inverse row shifts, and inverse column mixing.

The script also includes PKCS#7 padding and an educational CBC implementation. CBC XORs each plaintext block with the preceding ciphertext block before encryption. The IV replaces the preceding ciphertext for the first block. These routines expose the mechanics of block modes and padding; they are not a production encryption format because CBC alone does not authenticate ciphertext.

The unit tests verify published AES known-answer vectors for all three key sizes, block round trips, invalid key lengths, padding edge cases, and CBC round trips. The optional `cryptography` example demonstrates AES-GCM and rejection of modified ciphertext.

## JavaScript implementation

The JavaScript file combines a visible key-schedule implementation with Node.js's built-in `node:crypto` module.

`RoundSchedule` validates key sizes and keeps its expanded keys private. Its accessor returns a copy of each round key so external code cannot mutate the internal schedule. `expandKey` uses JavaScript arrays for four-byte words and `Buffer` objects for the original key and 16-byte round keys.

`AESWorkflow` extends `EventEmitter`. Successful block encryption emits a `blockEncrypted` event containing the algorithm, input and output lengths, and round count. This event-driven design separates cryptographic operations from observability without printing the secret key.

The single-block example uses ECB with automatic padding disabled because the method explicitly requires exactly 16 input bytes. It is intended only for verification against the AES-128 test vector, not for encrypting arbitrary application messages.

The message-level API uses AES-GCM, a 12-byte random nonce, and associated authenticated data. The returned envelope separates the nonce, ciphertext, and authentication tag. Decryption checks the tag through the cryptographic provider before returning plaintext. Tampered ciphertext and incorrect associated data are tested as failure cases.

A fresh random nonce is necessary for each encryption under a given GCM key. Randomness alone does not eliminate every possible collision, and high-volume systems should establish appropriate per-key usage limits and nonce-allocation policies.

## C++ case study

The C++ program models the encryption of a software release artifact in a repository environment. It contains an educational AES implementation and a separate `ReleaseGovernance` service that evaluates whether the artifact meets its release conditions.

The AES implementation uses fixed-size `std::array` objects for 16-byte blocks, four-byte words, and the 4-by-4 state. Fixed-size structures express the block cipher's invariants directly. `std::vector` is used for variable-length keys and expanded round-key collections because AES-128, AES-192, and AES-256 have different key lengths.

`parametersForKeySize` rejects unsupported lengths before the key schedule is constructed. The `expandKey` method implements the general `Nk` and `Nr` relationships and includes the extra AES-256 substitution rule. `encryptBlock` performs the prescribed sequence of transformations, with the final round omitting MixColumns.

The hexadecimal parser validates input length and each character instead of silently interpreting malformed key material. The known-answer test compares the AES-128 result against the expected ciphertext `69c4e0d86a7b0430d8cdb78070b4c55a`.

The release governance model is deliberately separate from encryption. It requires repository identity, distinct source and target branches, a Pull Request identifier, a commit identifier, review approval, passing CI, and enabled protection. This illustrates a key architectural distinction: encrypting an artifact does not prove that its source was reviewed or that the release passed repository policy.

The C++ implementation is suitable for studying AES transformations, fixed-size data modeling, and validation. It is not constant-time cryptographic code and does not provide authenticated message encryption.

## Java enterprise implementation

The Java program uses standard cryptographic APIs for the actual AES operations and explicit domain types for release governance.

`KeySize` encodes the supported key sizes, byte lengths, and round counts. `BranchProtection`, `PullRequest`, `Reviewer`, `Review`, and `StatusCheck` records provide validated representations of the release decision. Immutable collections prevent accidental changes to policy inputs during evaluation.

`MergeEligibilityService` distinguishes a comment from an approval and from a request for changes. It counts approvals only from eligible reviewers who are not the author and whose reviews reference the current Pull Request head commit. If the head changes, earlier approvals no longer count in this model.

The service separately checks required status checks, unresolved conversations, linear history, and the Pull Request state. An administrator bypass is represented as an explicit policy exception rather than ordinary approval. In a production system, bypass authorization should identify the permitted actors and record an audit event.

`AesGcmService` uses Java's `Cipher`, `SecretKeySpec`, and `GCMParameterSpec` APIs. It creates a 12-byte nonce, uses a 128-bit authentication tag, and binds associated data to the ciphertext. The envelope contains the nonce followed by the provider's ciphertext and tag. Decryption returns plaintext only after authentication succeeds.

The code validates the key length before constructing the AES key specification. A production key-management service should obtain key material from an approved secret store or key-management system rather than embedding secrets in source code or logs.

## PostgreSQL data model

The SQL implementation models cryptographic configuration and key rotation as database-governed operational data. It intentionally stores external key references instead of raw AES secrets.

### AES profiles

`aes_key_profiles` records the algorithm name, key length, block length, and round count. A check constraint permits only the standard AES combinations: 16 bytes with 10 rounds, 24 bytes with 12 rounds, and 32 bytes with 14 rounds. The generated `round_key_count` column derives the number of round keys from the round count.

This table represents public algorithm parameters. It is not a table of secret key material or expanded round keys.

### Key registry

`key_registry` associates a repository with an AES profile and an external key reference. It tracks key versions, lifecycle timestamps, and states such as pending, active, retiring, retired, and revoked.

The unique repository-and-version constraint prevents duplicate version assignments. A partial unique index allows at most one active key per repository. Additional constraints reject invalid states and require lifecycle timestamps for active or terminal keys.

The trigger prevents terminal key states from being reversed and prevents changes to key identity, profile, version, or external reference. The database cannot verify that an external key manager actually possesses the referenced secret; that check belongs to the trusted cryptographic service.

### Rotation governance

`key_rotation_events` represents an attempted key rotation. `rotation_approvals` records independent decisions, and `rotation_checks` records validation results such as key availability, consumer compatibility, and audit completion.

`complete_key_rotation` locks the rotation event, checks the required number of independent approvals, verifies all checks, validates the old and replacement key states, and then retires the old key and activates the replacement within the calling transaction. A failed check or insufficient approval raises an exception and aborts the transaction unless the caller handles it.

The inventory view joins repositories, profiles, and registered keys to expose operational metadata without exposing key bytes. The audit query aggregates approvals and check results for each rotation event.

The script uses PostgreSQL-specific features, including identity columns, `UUID`, generated columns, partial indexes, PL/pgSQL functions, triggers, and aggregate `FILTER` clauses. It also uses `gen_random_uuid()` for key identifiers, which is available in current PostgreSQL installations.

## Round count versus key size

Key size and round count are related but distinct properties. The key size determines the number of initial 32-bit words and influences the key expansion rules. The round count determines how many transformation rounds process each 128-bit state.

The number of round keys is always one greater than the number of rounds because the algorithm performs an initial AddRoundKey before its regular rounds. For AES-128, the original key is the initial round key and ten more keys are generated.

A round key is not an independently selected secret. Every round key is derived from the same original AES key. Consequently, storing an expanded schedule as if it were unrelated to the original key would not make it safe to expose.

## Authenticated encryption and operational security

AES is a block cipher, not a complete application-level encryption protocol. Applications need a mode of operation to encrypt messages longer than one block and must define how nonces, associated data, authentication tags, and key lifecycle events are handled.

AES-GCM provides confidentiality and integrity when correctly implemented. The nonce must not repeat under the same key. Associated data can authenticate contextual information, such as a record identifier or release identifier, without encrypting that information. Any authentication failure must prevent the application from accepting the plaintext.

ECB exposes repeated plaintext-block patterns and should not be used for general message encryption. CBC requires padding for arbitrary-length messages and provides no intrinsic authentication. A padding error exposed through different responses or timing can become a padding oracle.

The educational implementations make algorithmic steps explicit but should not replace a vetted cryptographic provider. Handwritten cryptographic implementations can have timing leaks, memory-handling weaknesses, implementation defects, and insufficiently tested error behavior.

Key rotation also requires more than generating a replacement key. Services must coordinate activation, consumer compatibility, migration or re-encryption requirements, access permissions, audit records, rollback procedures, and retirement of the old key. Database transactions can preserve registry consistency, but they cannot make an external key-management operation atomic unless the external service participates in a suitable distributed workflow.
