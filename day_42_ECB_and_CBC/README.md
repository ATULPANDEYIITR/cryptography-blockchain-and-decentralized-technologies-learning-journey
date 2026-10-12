# ECB and CBC

## Scope

This project studies Electronic Codebook (ECB) and Cipher Block Chaining (CBC) as block-cipher operating modes. The two modes use the same underlying block cipher differently, which produces important differences in determinism, pattern leakage, initialization, parallelism, error propagation, and security properties.

The implementations deliberately keep the mode distinction separate from the underlying cipher. The Python and C++ programs use a small educational Feistel construction so that the transformation can be inspected without external libraries. The JavaScript and Java programs use real AES through their standard runtime cryptographic APIs. The SQL implementation models block processing and chaining inside PostgreSQL while also showing how relational constraints can protect encryption metadata.

Neither ECB nor CBC by itself provides authentication. Confidentiality and integrity are separate security requirements.

## Block Cipher Modes

A block cipher accepts a fixed-size plaintext block and produces a fixed-size ciphertext block under a secret key.

For ECB, each block is processed independently:

`C_i = E_K(P_i)`

Decryption is similarly independent:

`P_i = D_K(C_i)`

CBC introduces a chaining value:

`C_0 = IV`

`C_i = E_K(P_i XOR C_(i-1))`

During decryption:

`P_i = D_K(C_i) XOR C_(i-1)`

The difference is small mathematically but significant operationally. ECB gives every plaintext block the same deterministic mapping. CBC makes the input to each encryption operation depend on the preceding ciphertext block.

## Padding

Block ciphers operate on complete blocks. Most application messages are not naturally aligned to the cipher block size, so a padding mechanism is required when using a padded block mode.

The programs use PKCS-style padding. If seven bytes are required to complete a block, seven padding bytes with value `0x07` are added. If the plaintext already ends exactly on a block boundary, an entire padding block is added.

Padding must be validated during decryption. Invalid padding can indicate corrupted ciphertext, malformed input, or an active attack.

The JavaScript and Java AES implementations use the runtime's PKCS padding support. The Python and C++ educational implementations perform the padding operations explicitly.

## ECB

ECB has no initialization vector. Every plaintext block is encrypted independently with the same key.

That property makes ECB simple and naturally parallelizable. It also creates its most important weakness: identical plaintext blocks produce identical ciphertext blocks.

Consider a plaintext containing:

`CONFIG01 | CONFIG01 | CONFIG01`

ECB preserves the equality relationship between those blocks:

`C1 | C1 | C1`

The ciphertext does not reveal the plaintext directly, but it reveals structural information about it.

This is particularly problematic for structured data containing repeated fields, images, fixed-format records, or other predictable block arrangements.

ECB is therefore generally unsuitable for encrypting multi-block structured application data.

The Python implementation demonstrates this with `demonstrate_ecb_pattern_leakage()`. It counts distinct ciphertext blocks after encrypting repeated plaintext blocks.

The JavaScript implementation performs the same analysis using real AES-256. Its `countDistinctBlocks()` function makes the structural leakage directly measurable.

The Java implementation uses `AES/ECB/PKCS5Padding` through the JCE provider and explicitly displays the repeated ciphertext blocks.

## CBC

CBC addresses ECB's repeated-block problem by incorporating the preceding ciphertext block into each encryption operation.

For the first block, there is no previous ciphertext block, so an initialization vector is supplied:

`C_1 = E_K(P_1 XOR IV)`

For subsequent blocks:

`C_i = E_K(P_i XOR C_(i-1))`

Consequently, equal plaintext blocks at different positions normally produce different ciphertext blocks because their chaining values differ.

The IV does not need to be secret. It does need to be handled correctly. For CBC encryption, a fresh unpredictable IV is required by secure protocols. Reusing IVs can expose relationships between messages and can create security problems in applications where the first plaintext block is predictable.

CBC encryption is sequential because the encryption of block `i` depends on the ciphertext produced for block `i-1`. This is a fundamental difference from ECB.

CBC decryption has more parallelism because each ciphertext block can be decrypted independently once the previous ciphertext block is available.

## CBC Error Propagation

CBC has a characteristic response to ciphertext modification.

If a bit in `C_i` is changed:

- `P_i` becomes broadly corrupted because the block cipher receives a modified ciphertext block.
- The corresponding bit in `P_(i+1)` is flipped because CBC decryption XORs `C_i` into the next plaintext block.
- Later plaintext blocks can return to normal once the modified ciphertext block is no longer part of the chaining input.

This behavior is demonstrated by the Python, JavaScript, and C++ programs.

It is also an important security warning. CBC does not authenticate ciphertext. An application must not treat successful CBC decryption as proof that the ciphertext was produced by a trusted sender.

## IV Handling

ECB has no IV.

CBC requires an IV with the same size as the underlying block cipher. AES has a 16-byte block size, so AES-CBC uses a 16-byte IV.

The JavaScript implementation validates this explicitly through `requireIv()`.

The Java implementation constructs an `IvParameterSpec` and rejects malformed CBC records before decryption.

The Python implementation checks the educational cipher's 8-byte block size.

The SQL model stores the IV as `bytea` and uses a database constraint requiring an 8-byte IV for its educational CBC records. An ECB record must have no IV.

This distinction prevents the database from accepting contradictory metadata such as a CBC record without an IV.

## Python Implementation

The Python program separates the block cipher from the operating modes.

`EducationalFeistelCipher` exposes `encrypt_block()` and `decrypt_block()`. The mode functions then build the higher-level behavior:

- `encrypt_ecb()` processes each padded block independently.
- `decrypt_ecb()` reverses each block independently.
- `encrypt_cbc()` XORs every plaintext block with the previous ciphertext block before encryption.
- `decrypt_cbc()` decrypts a block and XORs it with the preceding ciphertext block.
- `pkcs7_pad()` and `pkcs7_unpad()` handle block alignment.
- `demonstrate_ecb_pattern_leakage()` exposes deterministic repeated-block behavior.
- `demonstrate_cbc_pattern_hiding()` exposes the effect of chaining.
- `demonstrate_iv_effect()` compares the same plaintext under different IVs.
- `demonstrate_bit_flipping()` illustrates CBC malleability.
- `demonstrate_validation()` exercises malformed block, IV, and padding inputs.

The Feistel cipher is intentionally educational. It is not an AES implementation and must not be used for actual confidential information.

## JavaScript Implementation

The JavaScript program uses Node.js's built-in `crypto` module and therefore demonstrates actual AES rather than a simulated block transformation.

ECB is instantiated as `aes-256-ecb` with no IV. CBC is instantiated as `aes-256-cbc` with a 16-byte IV.

The program demonstrates a complementary runtime perspective:

- AES-256 key validation is explicit.
- Node's cipher objects provide the block encryption and decryption primitives.
- PKCS-style padding is handled by the cryptographic API.
- Buffers are split into AES blocks for structural analysis.
- `Set` is used to count distinct ciphertext blocks.
- `crypto.randomBytes()` produces CBC IVs.
- An AES-GCM example demonstrates the difference between confidentiality-only modes and authenticated encryption.

The GCM example is intentionally separate from ECB and CBC. It shows the production-oriented property that an authenticated-encryption construction supplies an integrity mechanism in addition to confidentiality.

## C++ Case Study

The C++ program models a repository governance service that stores fixed-size policy records.

The domain is deliberately different from the Python and JavaScript demonstrations. Instead of treating encryption as a generic message-processing exercise, the program considers records containing repository policy information such as review requirements and branch governance configuration.

`EducationalFeistel` provides a reversible block transformation.

The mode layer then implements:

`encryptECB()`

and

`encryptCBC()`

The repeated policy-record scenario makes ECB's deterministic behavior visible. The CBC scenario stores an IV and carries the previous ciphertext block into the next encryption operation.

The program also includes a tampering scenario. A ciphertext block is modified before CBC decryption, exposing the characteristic error propagation behavior.

The C++ implementation uses `std::array` for fixed-size blocks, `std::vector` for block sequences, `std::map` for distinct-block analysis, and exceptions for invalid cryptographic state.

The program is designed for C++17 and does not depend on external cryptographic libraries.

## Java Enterprise Model

The Java implementation uses standard JCA/JCE APIs and models encryption as one component of an enterprise repository-governance system.

`EncryptionMode` distinguishes ECB from CBC explicitly.

`EncryptedRecord` stores the mode, IV, and ciphertext as an immutable record-like domain value.

`CryptoService` owns the cryptographic operations. It uses:

`AES/ECB/PKCS5Padding`

for ECB and:

`AES/CBC/PKCS5Padding`

for CBC.

`RepositoryPolicy` represents governance requirements such as required approvals, passing checks, linear history, and restrictions on direct pushes.

`Review` and `ReviewState` represent review decisions separately from encryption. This separation is important because cryptographic protection and repository authorization answer different questions.

`RepositoryGovernanceService` evaluates merge eligibility using approvals, change requests, status checks, and direct-push restrictions.

The example therefore demonstrates an architectural boundary: encrypted policy data can be stored securely only when the encryption mechanism is correct, but the encrypted data itself does not determine whether a Pull Request is authorized to merge.

## SQL Data Model

The PostgreSQL script models both encryption metadata and repository governance.

The repository tables establish a relational context:

`repositories` stores repositories and their default branches.

`pull_requests` represents source branches, target branches, Pull Request state, draft state, and mergeability.

`repository_reviews` stores review decisions including approvals and requested changes.

`branch_protection_policies` stores policy requirements such as required approvals, passing checks, conversation resolution, linear history, direct-push restrictions, force-push restrictions, and branch-deletion restrictions.

The encryption tables represent the mode-specific data:

`encryption_records` stores the selected mode, IV, plaintext length, and Pull Request relationship.

`encrypted_policy_blocks` stores block-level values, previous ciphertext, and ciphertext blocks.

The constraints deliberately encode mode-specific invariants. A CBC record must have an 8-byte IV in the educational model. An ECB record must have no IV.

Indexes support the queries that filter Pull Requests by repository and target branch, review records by Pull Request and state, and encryption blocks by record and block order.

## SQL ECB Representation

The SQL ECB example stores several identical plaintext blocks and applies the same demonstration transformation to each block.

Because each block is independent, equal plaintext values produce equal ciphertext values.

The `encryption_mode_analysis` view counts total blocks and distinct ciphertext blocks. When the number of distinct ciphertext blocks is smaller than the total number of blocks in an ECB record, the sample exposes repeated structure.

This query is not attempting to break encryption. It demonstrates why ECB can leak structural information even when the underlying block cipher is strong.

## SQL CBC Representation

The CBC representation stores `previous_ciphertext` for each block.

The first block receives the IV as its chaining input. Each later block depends on the ciphertext generated for the previous block.

The recursive query illustrates this dependency in relational form. The important database representation is not simply the ciphertext value. The sequence and relationship between blocks are part of the CBC mechanism.

The SQL script uses a small XOR transformation for this demonstration because the standard PostgreSQL `pgcrypto` interface does not expose a direct general-purpose AES-ECB/CBC API comparable to the Java JCE or Node.js crypto interfaces.

The SQL transformation is therefore educational and must not be interpreted as production encryption.

## ECB and CBC Comparison

| Property | ECB | CBC |
|---|---|---|
| IV required | No | Yes |
| Independent encryption blocks | Yes | No |
| Repeated plaintext blocks remain visibly repeated | Yes | Normally no |
| Encryption parallelism | Strong | Sequential |
| Decryption parallelism | Strong | More parallelizable |
| Padding required for arbitrary-length data | Usually | Usually |
| Built-in authentication | No | No |
| Ciphertext modification detection | No | No |
| Main structural concern | Pattern leakage | IV handling and malleability |
| Appropriate default for new application encryption | No | Generally no |

The most important distinction is not that CBC is simply "better ECB." CBC solves a specific structural problem by chaining blocks, but it does not solve authentication.

## Security Considerations

ECB should not be selected for ordinary multi-block confidential application data because its deterministic block mapping exposes equality patterns.

CBC requires correct IV generation and handling. The IV may be stored with the ciphertext, but it should not be reused improperly.

CBC also requires integrity protection. A system that decrypts unauthenticated CBC ciphertext can be vulnerable to ciphertext manipulation, padding-oracle attacks, or application-specific malleability problems.

Padding errors should not be exposed through overly detailed externally observable responses in security-sensitive systems. Differences in error messages, response timing, or status codes can sometimes become an oracle.

Keys should not be hard-coded in source code. The examples derive fixed demonstration keys only to make the programs deterministic and reproducible. Production keys should be generated and managed through an appropriate key-management mechanism.

The custom Python and C++ block ciphers are educational constructions. They have not undergone cryptographic analysis and provide no production security guarantee.

## Authentication Versus Confidentiality

ECB and CBC are confidentiality modes, not complete message-security protocols.

A secure system commonly needs to establish both:

- confidentiality, so unauthorized parties cannot read protected data;
- integrity and authenticity, so unauthorized parties cannot silently modify protected data.

CBC can be combined with a separate MAC in an encrypt-then-MAC design, but this requires careful protocol construction.

For new application designs, authenticated-encryption modes such as AES-GCM or ChaCha20-Poly1305 are generally preferable because encryption and authentication are designed as one construction.

The JavaScript example includes AES-GCM specifically to demonstrate this distinction.

## Performance and Parallelism

ECB encryption blocks are independent. Large ECB inputs can therefore be distributed across workers or hardware encryption units.

CBC encryption has a dependency chain:

`C1 -> C2 -> C3 -> C4`

The next ciphertext block cannot be produced until the preceding ciphertext block is available.

CBC decryption has a different dependency structure because the previous ciphertext block is already available. This makes CBC decryption more parallelizable than CBC encryption.

The performance distinction matters when selecting a mode for high-throughput systems, but performance must not be evaluated independently from security requirements.

## Common Implementation Errors

A common error is treating ECB as safe merely because AES itself is secure. AES can be a strong primitive while ECB remains an unsuitable operating mode for structured multi-block data.

Another error is treating CBC as authenticated. CBC decryption successfully returning plaintext does not establish that the plaintext was produced by a trusted party.

Reusing a CBC IV in circumstances where unpredictability is required can undermine security.

Incorrect padding validation can create decryption vulnerabilities.

Encrypting the IV as though it were a secret key is unnecessary. The IV can normally accompany the ciphertext. Its security role is different from that of the secret encryption key.

Another architectural error is mixing cryptographic decisions with application authorization. Encryption can protect a repository policy record, but it does not determine whether a reviewer is authorized to approve a Pull Request.

## Debugging Approach

ECB can be diagnosed by examining ciphertext block equality. If equal plaintext blocks are present and the corresponding ciphertext blocks are also equal, that is expected ECB behavior.

CBC debugging requires tracking the chain:

`IV -> C1 -> C2 -> C3`

For each encryption step, the relevant operation is:

`P_i XOR previous_ciphertext`

followed by block encryption.

For CBC decryption, inspect:

`D_K(C_i) XOR previous_ciphertext`

Padding should be checked only after all ciphertext blocks have been decrypted and reconstructed.

When debugging production cryptographic failures, plaintext and secret keys should not be logged. Diagnostic information should be limited to safe metadata such as algorithm identifiers, version identifiers, ciphertext lengths, and non-secret identifiers.

## Production Boundary

The educational implementations are designed to make ECB and CBC mechanics visible.

The JavaScript and Java examples use real AES implementations supplied by established cryptographic APIs, but using a correct primitive does not automatically produce a secure protocol. Key lifecycle, IV generation, authentication, error handling, storage, access control, rotation, and protocol design remain application responsibilities.

The Python and C++ implementations intentionally avoid claiming production cryptographic strength. Their value is in exposing the mathematical and control-flow differences between independent block processing and chained block processing.

For a new security-sensitive system, the decision should normally begin with the required security properties and a vetted authenticated-encryption construction rather than selecting ECB or CBC merely because the underlying cipher is familiar.
