# AES Encryption and Decryption

## Scope

This learning artifact presents AES encryption and decryption from several technical perspectives. The implementations distinguish the AES block cipher itself from the cryptographic modes and application-level controls built around it.

The central distinction is important:

- AES is a symmetric block cipher operating on 128-bit blocks.
- AES-128, AES-192, and AES-256 describe the AES key size.
- A mode of operation determines how AES processes data longer than one block.
- Authentication determines whether a recipient can detect unauthorized modification.
- AES-GCM combines encryption and authentication in a single authenticated-encryption construction.
- CTR mode turns the AES block cipher into a stream-like construction but does not authenticate ciphertext by itself.
- Database encryption protects stored values, but key management and access control remain separate security responsibilities.

The examples use realistic repository-governance records because sensitive policy information can require confidentiality while also illustrating why authenticated encryption matters.

## AES Core Mechanism

AES uses a fixed 128-bit block size. The key determines the number of transformation rounds:

| AES variant | Key size | Rounds |
|---|---:|---:|
| AES-128 | 128 bits | 10 |
| AES-192 | 192 bits | 12 |
| AES-256 | 256 bits | 14 |

AES operates on a 4 × 4 byte state matrix. Encryption applies an initial key addition followed by repeated transformation rounds. The main transformations are `SubBytes`, `ShiftRows`, `MixColumns`, and `AddRoundKey`.

The final AES round omits `MixColumns`.

`SubBytes` provides a nonlinear substitution through the AES S-box. `ShiftRows` rearranges state bytes across rows. `MixColumns` combines bytes within each column using arithmetic in the finite field GF(2^8). `AddRoundKey` combines the state with a round key using XOR.

The key expansion process derives round keys from the original AES key.

The Python and C++ implementations expose these mechanisms directly so the block-cipher operation is observable rather than hidden behind a third-party package.

## Encryption Is Not the Same as Authentication

Confidentiality means that an unauthorized observer should not be able to recover the plaintext.

Integrity means that an unauthorized modification can be detected.

These properties are different. A ciphertext can be confidential while still being vulnerable to undetected modification if the selected construction does not authenticate it.

This distinction appears directly in the implementations:

- The Python program uses AES-128-CTR and HMAC-SHA256 to construct an encrypt-then-authenticate design.
- The JavaScript program uses AES-GCM, which provides confidentiality and authentication together.
- The Java program uses AES-GCM through the Java Cryptography Architecture.
- The C++ program exposes AES-128-CTR for educational examination of the cipher and explicitly identifies its lack of authentication.
- PostgreSQL uses `pgp_sym_encrypt` with AES-256 through `pgcrypto`, demonstrating database-side symmetric encryption.

For production applications, authenticated encryption such as AES-GCM is generally preferable to manually combining unauthenticated encryption primitives.

## Modes of Operation

AES encrypts one 128-bit block at a time. Real application data is usually much larger, so a mode of operation defines how AES is applied to sequences of blocks.

### ECB

Electronic Codebook mode encrypts each block independently.

Its major weakness is that identical plaintext blocks produce identical ciphertext blocks under the same key. Repeated structure can therefore remain visible.

ECB should not be selected for encrypting ordinary structured application data.

### CBC

Cipher Block Chaining XORs each plaintext block with the previous ciphertext block before AES encryption. It requires an unpredictable initialization vector and appropriate padding.

CBC encryption alone does not authenticate the ciphertext. A separate authentication mechanism is required when integrity and tamper detection matter.

### CTR

Counter mode encrypts successive counter values and XORs the resulting keystream with plaintext.

The encryption operation can be represented as:

`C = P XOR AES(K, counter)`

Decryption uses the same operation:

`P = C XOR AES(K, counter)`

The Python and C++ examples demonstrate this property directly.

The counter or nonce must never repeat with the same key. Reusing a CTR nonce can expose relationships between plaintexts because the same keystream is reused.

### GCM

Galois/Counter Mode combines counter-mode encryption with authentication.

The JavaScript and Java implementations use AES-GCM. They also demonstrate authenticated additional data.

Additional authenticated data is not encrypted, but it is cryptographically bound to the ciphertext. A change to authenticated metadata causes decryption and authentication to fail.

This is useful when metadata such as repository identity, protected branch, record version, or policy identifier must remain visible while still being protected against modification.

## Python Implementation

The Python implementation deliberately exposes the AES-128 internals.

`expand_key()` performs AES-128 key expansion and produces eleven round keys. The AES-128 block implementation then performs the AES state transformations for encryption and decryption.

The program also implements CTR mode in `aes_ctr_crypt()`. Because CTR encryption and decryption are both XOR operations against the same keystream, the same function can perform both operations.

The higher-level `encrypt_authenticated()` function separates an application master key into an encryption key and an authentication key using domain-separated SHA-256 derivations. AES-128-CTR provides confidentiality and HMAC-SHA256 protects the nonce and ciphertext against modification.

`EncryptedMessage` stores the nonce, ciphertext, and authentication tag and provides URL-safe Base64 serialization.

The demonstration includes:

- A known AES-128 test vector.
- Plaintext encryption.
- Decryption and round-trip verification.
- Base64 transport encoding.
- Ciphertext modification.
- HMAC verification and tamper rejection.
- Explicit AES key-length validation.

The implementation is educational rather than production cryptography software. A mature cryptographic library should normally be preferred over maintaining a handwritten AES implementation.

## JavaScript Implementation

The JavaScript implementation uses the Web Crypto API rather than implementing AES manually.

`crypto.subtle.generateKey()` creates a 256-bit AES-GCM key. `encrypt()` generates a fresh 96-bit IV and passes it to AES-GCM. The resulting encrypted representation contains both ciphertext and the authentication tag.

The record also contains associated authenticated data:

`repository=security-platform;branch=main`

The associated data is not encrypted. It is authenticated by GCM. Modifying the associated data causes decryption to fail even when the ciphertext itself has not changed.

The implementation demonstrates two different failure conditions:

- Modifying a ciphertext byte invalidates the authentication tag.
- Modifying authenticated metadata also invalidates authentication.

The JavaScript example is asynchronous because Web Crypto operations return Promises. This makes it suitable for browser and modern Node.js environments where cryptographic operations are exposed through the standard Web Crypto API.

The implementation does not require an npm package.

## C++ Case Study

The C++ program models repository governance around a protected branch.

`RepositoryPolicyRecord` represents a policy containing a repository name, protected branch, approval requirement, and force-push rule.

`canMerge()` represents a separate governance decision. It requires two approvals, successful checks, a protected branch, and no merge conflict.

The `AES128` class implements the AES-128 block transformation. Its key expansion produces the eleven AES-128 round keys, and its encryption method performs the AES round sequence.

`GovernanceCipher` uses AES-CTR to process arbitrary-length policy records. CTR demonstrates why AES is a block cipher while still supporting messages longer than sixteen bytes.

The same key and initial counter are used for the reverse operation because CTR decryption uses the same XOR transformation as encryption.

The C++ program also executes the standard AES-128 known-answer vector:

`00112233445566778899aabbccddeeff`

with key:

`000102030405060708090a0b0c0d0e0f`

The expected ciphertext is:

`69c4e0d86a7b0430d8cdb78070b4c55a`

The case study explicitly reports that its CTR construction provides confidentiality but not authentication. This is a deliberate design distinction rather than an accidental omission.

## Java Enterprise Model

The Java implementation separates domain modeling from cryptographic operations.

`RepositoryPolicy` expresses protected-branch rules such as required approvals, status-check requirements, and force-push restrictions.

`PullRequest` models state and review information. Reviews are associated with a specific commit. This is important because an approval for an earlier commit should not automatically be treated as approval for a later unreviewed state.

`ReviewDecision` separates `APPROVED`, `CHANGES_REQUESTED`, and `COMMENTED` outcomes.

`MergeEligibilityService` evaluates the policy against the Pull Request's current state, current-commit approvals, status checks, and merge conflicts.

The cryptographic layer is represented by `AesGcmService`. It uses `AES/GCM/NoPadding` from the Java standard cryptographic APIs.

The Java implementation demonstrates:

- 256-bit AES key generation.
- Random 96-bit GCM IV generation.
- AES-GCM encryption.
- Authenticated additional data.
- Decryption and authentication.
- Rejection of tampered ciphertext.
- Approval counting for the current commit.
- Stale approval behavior.

The use of records, enums, classes, collections, validation, and explicit state transitions keeps cryptographic concerns separate from repository-governance rules.

## PostgreSQL Data Model

The SQL implementation models a repository-governance environment relationally.

`repositories` identifies repositories.

`branches` represents repository branches and records whether a branch is protected.

`branch_protection` stores enforcement rules such as required approvals, status-check requirements, conversation-resolution requirements, force-push restrictions, deletion restrictions, and linear-history requirements.

`pull_requests` stores source and target branches, current head and base commits, draft state, Pull Request state, and merge conflicts.

`pull_request_commits` records commits associated with a Pull Request.

`reviewers` identifies eligible reviewers.

`reviews` associates a review decision with a specific Pull Request, reviewer, and commit. This relationship is what allows the merge-eligibility query to distinguish current approvals from stale approvals.

`review_comments` represents inline review discussions and whether they have been resolved.

`status_checks` stores the state of automated checks.

The `merge_eligibility` view combines these tables and evaluates the repository policy at the database-query level.

## Database Integrity and Constraints

Several rules are enforced directly through PostgreSQL constraints.

Required approval counts cannot be negative or zero.

Branch names are unique within a repository.

Reviewer usernames are unique.

A Pull Request cannot use the same branch as both its source and target.

Review states and check states are restricted to known values.

Review comment line numbers must be positive.

Foreign keys prevent orphaned reviews, comments, status checks, or Pull Requests.

Indexes target common governance queries. The review index supports lookups by Pull Request, commit, and review state. The status-check index supports Pull Request status evaluation. The partial comment index focuses on unresolved discussions.

These constraints complement application-level validation. Application code can provide early feedback, while the database provides a second integrity boundary.

## Database Encryption

PostgreSQL's `pgcrypto` extension provides the SQL encryption demonstration.

The script uses `pgp_sym_encrypt()` with AES-256 and `pgp_sym_decrypt()` to recover the plaintext.

The SQL example is deliberately distinct from the Java and JavaScript examples. It demonstrates encryption performed inside the relational database rather than through an application runtime.

Database encryption does not automatically solve key management. A passphrase embedded in SQL source is not an acceptable production key-management strategy.

A production deployment should separate cryptographic keys from application source and database records, restrict access to decryption operations, establish rotation procedures, and audit access to sensitive plaintext.

## Nonce and IV Management

An initialization vector or nonce does not normally need to be secret.

It does need to satisfy the requirements of the selected cryptographic mode.

For AES-GCM, a unique 96-bit IV is the standard practical choice. Reusing an IV with the same key can seriously compromise GCM security.

For CTR mode, repeating the same counter initialization value with the same key can reuse the keystream. Two ciphertexts encrypted under the same keystream can expose relationships between their plaintexts.

The JavaScript and Java implementations generate random IVs for each encryption operation.

The Python and C++ educational CTR examples explicitly pass the counter into the cryptographic operation so the relationship between the counter and keystream is visible.

## Key Management

Encryption security depends heavily on key management.

A strong AES algorithm cannot compensate for an exposed key.

A production design should distinguish:

- Key generation.
- Key storage.
- Key access authorization.
- Key rotation.
- Key versioning.
- Key backup and recovery.
- Key revocation.
- Audit logging.
- Separation of encryption keys from ordinary application data.

Passwords should not normally be used directly as AES keys. If a human password is the source of a key, an appropriate password-based key derivation function such as Argon2id, scrypt, or PBKDF2 should be used according to the application's requirements.

The examples that derive demonstration keys from fixed values are educational and must not be interpreted as production secret-management guidance.

## Authenticated Additional Data

Authenticated additional data is useful when some metadata must remain readable but must not be modifiable without detection.

For example, an encrypted record might contain visible metadata identifying:

`repository=security-platform;branch=main`

The payload can be encrypted while the metadata remains available to routing or indexing code.

AES-GCM authenticates that metadata through `updateAAD()` in Java and `additionalData` in the JavaScript Web Crypto API.

Changing the metadata causes authentication failure.

This is different from encryption because the metadata remains visible. It is also different from ordinary hashing because the authentication result is cryptographically tied to the encryption key.

## Decryption Failure

A secure application must treat decryption failure as a security event rather than silently returning partially recovered data.

Typical causes include:

- Wrong key.
- Corrupted ciphertext.
- Modified authentication tag.
- Modified associated data.
- Invalid IV.
- Unsupported algorithm identifier.
- Incorrect ciphertext serialization.
- Damaged storage or transport data.

The JavaScript implementation converts authentication failures into explicit errors.

The Java implementation allows the underlying cryptographic provider to reject invalid authenticated ciphertext.

The Python implementation performs constant-time tag comparison through `hmac.compare_digest()` before decryption.

## Common Security Mistakes

Using ECB for structured data can reveal repeated plaintext patterns.

Reusing a nonce with AES-GCM can compromise authentication and confidentiality.

Using CTR without authentication leaves ciphertext modification undetected.

Using a predictable IV where unpredictability is required weakens the security assumptions of the selected construction.

Hard-coding production encryption keys in source code exposes the key through source control, backups, logs, and deployment artifacts.

Treating Base64 as encryption is incorrect. Base64 only represents binary data as text.

Using a cryptographic hash as a replacement for encryption does not provide confidentiality.

Using encryption without authentication can produce systems that decrypt attacker-modified ciphertext as if it were legitimate.

## Performance Considerations

AES is designed for efficient software and hardware implementation.

The main performance considerations are normally the selected implementation, mode, message size, key management overhead, and whether hardware acceleration is available.

AES-GCM is particularly useful for application encryption because modern processors frequently provide hardware acceleration for AES operations and GCM's underlying arithmetic.

Database-side encryption can simplify storage workflows but may increase CPU consumption for queries that decrypt many rows. Encrypting only fields that require confidentiality can reduce this overhead.

CTR mode supports parallelizable block processing in appropriate implementations, but the nonce and counter allocation rules remain critical.

## Security Boundaries

Encryption does not replace authorization.

A repository service that can decrypt every secret for every user still requires authorization controls determining which users can invoke the decryption operation.

Likewise, database encryption does not replace database permissions.

The security architecture should therefore separate:

`identity -> authorization -> key access -> cryptographic operation -> audit`

The cryptographic primitive protects data. The surrounding system determines who can request that protection to be reversed.

## Practical Relationship Between the Implementations

The six artifacts deliberately use different levels of abstraction.

The Python program exposes AES internals and builds an authenticated construction from AES-CTR and HMAC.

The JavaScript program uses the standard Web Crypto API and focuses on AES-GCM, asynchronous cryptography, and authenticated additional data.

The C++ program treats AES as a low-level systems component and integrates it into a repository-governance case study.

The Java program separates an enterprise governance domain model from an AES-GCM service and demonstrates explicit validation and state management.

The PostgreSQL script moves encryption and governance enforcement into the database layer, using relational constraints, indexes, queries, and `pgcrypto`.

The README therefore describes the implementations as related artifacts rather than as translations of the same program.
