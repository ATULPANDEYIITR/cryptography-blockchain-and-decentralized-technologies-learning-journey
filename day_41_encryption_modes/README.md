# Encryption Modes: Technical Implementation Study

## Scope

Encryption modes define how a block cipher is applied to data that is longer than a single cipher block. The choice of mode changes confidentiality behavior, error propagation, parallelism, padding requirements, nonce or IV requirements, and whether authentication is provided.

This project treats four important families separately:

- **ECB** processes each block independently. Its deterministic block mapping can expose repeated structure, which makes it unsuitable for structured confidential data.
- **CBC** chains each plaintext block with the previous ciphertext block. It requires padding for arbitrary-length plaintext and an initialization vector. CBC by itself does not authenticate ciphertext.
- **CTR** turns a block cipher into a stream-like construction by encrypting successive counter blocks and XORing the resulting keystream with plaintext. It does not require padding, supports parallel processing, and requires strict nonce/counter uniqueness for a given key.
- **AEAD modes** such as AES-GCM and ChaCha20-Poly1305 provide confidentiality and authentication together. They also authenticate associated data that does not need to be encrypted.

The central engineering distinction is that **encryption and authentication solve different security problems**. Confidentiality prevents unauthorized disclosure. Authentication detects modification and establishes that the ciphertext was produced under the expected key and associated authentication context.

The source files use educational constructions where necessary to make mode mechanics visible. Those constructions are not production cryptography. The JavaScript implementation also demonstrates Node.js's native AES-GCM interface because a production system should rely on an audited cryptographic implementation rather than a hand-written cipher.

## Fundamental Mechanisms

A block cipher has a fixed block size. AES, for example, operates on 128-bit blocks. Real application data is usually longer and frequently has a length that is not an exact multiple of the block size. A mode defines how individual cipher operations are combined to process that data.

### ECB

ECB encrypts every plaintext block independently:

`C_i = E_K(P_i)`

The same key and the same plaintext block therefore produce the same ciphertext block. This property makes repeated structures visible.

ECB can be parallelized easily because blocks do not depend on each other, but the parallelism does not compensate for its structural leakage.

The Python and C++ implementations expose the independent-block behavior. The database model marks ECB as unauthenticated and records its structural risk rather than treating it as a general-purpose secure storage mode.

### CBC

CBC introduces chaining:

`C_i = E_K(P_i XOR C_(i-1))`

The first plaintext block uses an IV in place of the previous ciphertext block:

`C_1 = E_K(P_1 XOR IV)`

Consequently, changing the IV changes the first plaintext block after decryption. Later blocks depend on preceding ciphertext.

CBC normally needs padding because a block cipher still operates on complete blocks. The Python implementation contains explicit PKCS#7 padding and validation.

CBC does not provide authentication. A system that uses CBC for legacy interoperability must therefore define a separate, correctly constructed authentication mechanism. Failure to authenticate CBC ciphertext can expose applications to ciphertext manipulation and padding-oracle attacks.

### CTR

CTR creates a keystream by encrypting counter blocks:

`S_i = E_K(Nonce || Counter_i)`

The plaintext is then combined with the keystream:

`C_i = P_i XOR S_i`

Decryption uses the same operation:

`P_i = C_i XOR S_i`

This explains why the Python, JavaScript, C++, and Java demonstrations can encrypt and decrypt with the same stream operation.

CTR does not require padding because the final keystream block can be truncated to the remaining plaintext length.

The critical security condition is uniqueness of the nonce/counter sequence under a key. Reusing the same keystream for two plaintexts produces:

`C_1 XOR C_2 = P_1 XOR P_2`

The Python and JavaScript demonstrations explicitly show this relationship.

### AEAD

Authenticated Encryption with Associated Data combines confidentiality and integrity.

A typical AEAD operation accepts:

- a secret key,
- a nonce,
- plaintext,
- optional associated data.

The associated data is authenticated but remains visible. This is useful for metadata such as protocol versions, record types, tenant identifiers, or message classifications.

The resulting ciphertext includes or accompanies an authentication tag. During decryption, the tag must be verified before plaintext is treated as trusted.

AES-GCM and ChaCha20-Poly1305 are common AEAD choices. Their security depends not only on the underlying algorithms but also on correct nonce management, key management, tag verification, and API usage.

## Relationship Between Modes

The modes should not be treated as interchangeable implementations of the same security contract.

| Property | ECB | CBC | CTR | AEAD |
|---|---|---|---|---|
| Confidentiality | Yes, but structurally weak | Yes | Yes | Yes |
| Authentication | No | No | No | Yes |
| Padding | Usually required | Usually required | Not required | Not required |
| Independent block processing | Yes | Encryption is chained | Yes after counter assignment | Commonly parallelizable |
| Nonce/IV discipline | No nonce | Unique unpredictable IV is important | Nonce/counter must not repeat | Nonce must not repeat under a key |
| Tamper detection | No | No | No | Yes |
| Appropriate general-purpose choice | No | Usually legacy only | Usually needs separate authentication | Common preferred choice |

The important distinction is not simply that one mode is "older" or "newer." Each mode provides a different security interface and therefore creates different application responsibilities.

## Python Implementation

The Python program models mode behavior directly.

`pkcs7_pad()` and `pkcs7_unpad()` make CBC and ECB padding behavior executable. Padding validation rejects malformed data rather than silently returning corrupted plaintext.

`ecb_encrypt()` processes each block independently. The accompanying demonstration uses repeated structured records to expose the central weakness of ECB.

`cbc_encrypt()` maintains a `previous` ciphertext block. Each plaintext block is XORed with that previous value before encryption. The IV supplies the initial chaining value.

`ctr_crypt()` constructs a counter block from an eight-byte nonce and an eight-byte counter. The same operation performs encryption and decryption because XOR is its own inverse.

The nonce-reuse demonstration deliberately encrypts two different messages with the same CTR nonce and shows that XORing their ciphertexts reveals the XOR of their plaintexts.

The authenticated demonstration uses an educational CTR-plus-HMAC construction to expose the separation between confidentiality and authentication. It also tests modified ciphertext and modified associated data. Neither construction should be used in a production system.

The `ModeProfile` data class separates operational properties such as padding, authentication, parallelism, nonce requirements, and principal risk. This makes mode selection a policy problem rather than a hard-coded string comparison.

## JavaScript Implementation

The JavaScript implementation emphasizes event-driven processing and the distinction between educational mode mechanics and a real cryptographic API.

`EducationalBlockCipher` provides a mode-compatible block interface. ECB, CBC, and CTR operations are implemented around that interface, but the transformation is explicitly non-secure.

The event-driven workflow uses a `Map` of event handlers. Encryption systems often process records through asynchronous or event-driven pipelines, so events such as record creation, encryption completion, and integrity verification are modeled independently from the cryptographic primitive.

The most important production-oriented part is `demonstrateNativeAead()`. It uses Node.js's built-in `crypto` module with `aes-256-gcm`.

The AES-GCM example demonstrates:

- generation of a random key,
- generation of a 12-byte nonce,
- authentication of associated data,
- extraction of the authentication tag,
- tag installation during decryption,
- successful recovery of plaintext,
- rejection of modified ciphertext.

`timingSafeEqual()` is used for the educational authentication comparison where applicable. Authentication APIs should avoid ordinary application-level equality checks when a timing-sensitive comparison is required.

## C++ Governance Case Study

The C++ program models encryption selection as a technical governance problem for financial records.

`ModePolicy` captures mode properties rather than embedding all decisions inside conditional statements. The policy engine can therefore evaluate whether a mode satisfies the requirements of a particular record-processing scenario.

The case study distinguishes confidentiality-only modes from authenticated modes. It marks ECB and CBC as inappropriate for the simulated authenticated financial-record requirement, while CTR is rejected because it provides confidentiality but no authentication.

The program also demonstrates CBC processing and CTR-style encryption. The CTR section deliberately reuses a nonce to show that successful decryption alone does not establish secure nonce management.

The implementation uses `std::map` to store mode policies, `std::array` for fixed-size blocks and nonces, `std::vector` for variable-length records, and explicit validation through exceptions.

The case study's architectural decision is important: a cryptographic mode should be selected from a security policy rather than chosen independently by each application component.

## Java Enterprise Model

The Java program models encryption decisions through explicit domain types.

`EncryptionMode` defines the supported modes. `RecordState` represents the lifecycle of an encrypted record. `ModePolicy` is an immutable record containing security requirements and approved use cases.

`EncryptionRequest` validates the basic request boundary before policy evaluation. This prevents blank record identifiers and empty plaintext from entering the workflow.

`PolicyRepository` provides a controlled store for mode policies. The use of an `EnumMap` is appropriate because the key domain is a fixed Java enum.

`EncryptionPolicyService` contains policy decisions. It rejects a mode when integrity is required but the selected mode cannot provide authentication. It also rejects a mode when a required unique nonce is unavailable.

`RecordEncryptionWorkflow` models state progression from creation to encryption and, where applicable, authentication. Rejected requests remain outside the successful processing path.

The Java implementation therefore emphasizes domain modeling, immutable policy definitions, explicit validation, state representation, and separation between policy evaluation and workflow execution.

## PostgreSQL Data Model

The SQL implementation models encryption governance relationally.

`encryption_modes` stores technical characteristics of each mode. These include whether authentication is provided, whether padding is required, whether parallel encryption is possible, whether unique nonces are required, and the principal operational risk.

`encryption_policies` maps organizational requirements to a selected mode. A policy can require integrity and specify a minimum key size.

`repositories` associates data domains with default encryption policies. This represents a realistic environment where different repositories can have different classification requirements.

`encrypted_records` stores metadata about encrypted material. The encrypted payload is represented as `BYTEA`, while the authentication tag and associated data are separate fields. The schema deliberately does not attempt to implement AES or another cryptographic primitive in SQL.

`nonce_usage` tracks nonce allocation against a key version. The unique constraint on `(key_version, nonce)` makes nonce reuse detectable and prevents duplicate registration through the normal database path.

`policy_decisions` records whether an encryption request was approved or rejected and stores the reason. This creates an auditable policy trail rather than relying only on application logs.

## Database-Level Enforcement

The database uses primary keys and foreign keys to preserve relationships between repositories, policies, records, and nonce allocations.

Check constraints enforce relationships such as the requirement for an authentication tag when a record is marked `AUTHENTICATED`.

The trigger `encrypted_record_integrity_guard` provides an additional enforcement layer for authenticated record state.

Indexes are applied to fields used for repository-state searches, policy lookups, nonce-key searches, and decision history.

The `validate_encryption_policy()` function demonstrates policy evaluation close to the data layer. It rejects authenticated workloads when the selected mode does not provide authentication and rejects nonce-dependent modes when a nonce is unavailable.

The transaction around `policy_decisions` demonstrates how a policy result can be recorded atomically.

## Initialization Vectors and Nonces

An IV and a nonce are not simply interchangeable names for the same concept.

CBC uses an IV as part of its initial chaining operation. Correct IV generation and handling are essential to the security properties expected from CBC.

CTR and AEAD modes use nonce/counter inputs to construct cryptographic state. For modes such as CTR and GCM, repeating the nonce under the same key can have severe consequences.

A nonce normally does not need to be secret. Its security requirement is usually uniqueness under the relevant key. The exact requirement depends on the algorithm and cryptographic API, so applications should follow the algorithm-specific contract rather than assuming that every nonce can be generated or reused identically.

## Authentication and Associated Data

Confidentiality alone does not guarantee message integrity.

An attacker who cannot decrypt ciphertext may still be able to modify it. Without authentication, the recipient has no cryptographic basis for deciding whether the ciphertext or its metadata was altered.

AEAD addresses this by producing an authentication tag over the ciphertext and associated data.

Associated data is useful when some metadata must remain visible. For example, a protocol might expose a record type and version while requiring both values to be authenticated. If an attacker changes authenticated metadata, verification should fail even though that metadata was never encrypted.

## Failure Conditions

A secure implementation must treat failures as security-relevant events.

Invalid padding should not be converted into a plausible plaintext. The Python implementation explicitly raises an exception for malformed PKCS#7 data.

Authentication failures must prevent untrusted plaintext from being accepted. The JavaScript AES-GCM example demonstrates that modifying a ciphertext causes finalization to fail.

Nonce allocation failures should stop encryption rather than silently generating a reused nonce.

Missing authentication tags should prevent authenticated records from reaching a trusted state. The PostgreSQL constraints and trigger enforce this relationship at the database layer.

Incorrect mode selection should be rejected by policy when the requested security properties cannot be satisfied.

## Performance Considerations

ECB and CTR can process independent blocks in parallel. CBC encryption has a sequential dependency because each plaintext block requires the previous ciphertext block. CBC decryption can be parallelized more readily, but the overall application still inherits CBC's lack of authentication.

CTR avoids padding overhead and can support random-access-style processing when counter allocation is carefully controlled.

AEAD implementations can be highly efficient because modern CPUs and cryptographic libraries often provide hardware acceleration. The performance advantage should not be evaluated separately from the security contract.

Database indexes should support metadata queries rather than ciphertext-content searches. Encrypted payloads generally cannot be queried as if they were plaintext without introducing additional design mechanisms and their associated security trade-offs.

## Security Considerations

Cryptographic algorithms and modes should come from maintained, audited libraries. Implementing a cipher, padding scheme, authentication construction, or nonce-management system manually creates risks that are difficult to detect through ordinary functional testing.

Keys require stronger lifecycle management than ordinary configuration values. They should not be embedded in source code, committed to repositories, or printed in logs.

Nonce uniqueness should be treated as a system invariant. A random nonce can be appropriate when the probability of collision is sufficiently small for the chosen algorithm and operational scale. Counter-based allocation can provide deterministic uniqueness when the complete nonce lifecycle is controlled correctly.

Authentication tags must be verified before application logic trusts decrypted content.

Error messages exposed to external callers should not become a side channel that distinguishes padding errors, authentication failures, malformed ciphertext, and other cryptographic states unnecessarily.

## Common Engineering Mistakes

Using ECB for structured data is a fundamental mode-selection error because identical blocks remain identifiable.

Using CBC without a separate authentication mechanism creates an integrity gap.

Using CTR with a reused nonce under the same key can expose relationships between plaintexts.

Treating an authentication tag as optional metadata undermines the security contract of an AEAD design.

Changing associated data during decryption can invalidate a valid ciphertext because the associated data is part of the authenticated message context.

Generating a new encryption key for every record without a key-management design can create an operational problem just as serious as using one key forever.

Logging plaintext, keys, nonces together, or authentication material can defeat the confidentiality architecture outside the cryptographic operation itself.

## Production Design Boundary

The executable examples are intended to demonstrate mechanisms and policy decisions. The educational cipher implementations are not substitutes for AES, ChaCha20, or an audited cryptographic library.

For production applications, the preferred abstraction is generally an authenticated-encryption API such as AES-GCM or ChaCha20-Poly1305, with explicit key lifecycle management, correct nonce handling, authentication of relevant associated data, controlled error handling, and appropriate audit logging.

Mode selection should be treated as part of the application's security architecture. The cipher, mode, nonce policy, authentication behavior, key lifecycle, storage model, and operational controls together determine whether encrypted data remains secure in practice.
