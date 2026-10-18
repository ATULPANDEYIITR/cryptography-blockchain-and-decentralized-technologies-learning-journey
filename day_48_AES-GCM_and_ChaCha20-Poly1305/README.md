# AES-GCM and ChaCha20-Poly1305

## Scope

AES-GCM and ChaCha20-Poly1305 are authenticated encryption with associated data (AEAD) constructions. They provide confidentiality and integrity in one cryptographic operation while allowing selected metadata to remain visible and authenticated through associated data.

The six deliverables treat the two algorithms as related but distinct mechanisms:

- AES-GCM combines the AES block cipher in counter mode with GHASH authentication.
- ChaCha20-Poly1305 combines the ChaCha20 stream cipher with Poly1305 authentication.
- Both use a nonce, plaintext, optional associated data, ciphertext, and authentication tag.
- Both require strict nonce management for every encryption under a particular key.
- Both reject modified ciphertext or modified associated data before authenticated plaintext is accepted.

The implementations use different technical perspectives. Python contains educational implementations of the underlying primitives and AEAD constructions. JavaScript uses the Node.js cryptographic provider for application-oriented envelope handling. C++ models an enterprise artifact repository around OpenSSL. Java models an enterprise configuration service using Java 17 cryptographic APIs. PostgreSQL stores the relational metadata needed to operate such a service safely without attempting to replace a dedicated cryptographic library.

## AEAD Model

An AEAD operation can be represented as:

`ciphertext, tag = Encrypt(key, nonce, plaintext, associated_data)`

and:

`plaintext = Decrypt(key, nonce, ciphertext, tag, associated_data)`

Decryption is successful only when the authentication tag verifies. The associated data is not encrypted, but it is included in authentication. This distinction matters for fields such as tenant identifiers, record types, protocol versions, or environment names.

For an application record, the cryptographic envelope can therefore be viewed as:

`algorithm + key version + nonce + ciphertext + authentication tag + AAD`

The algorithm and key version identify the cryptographic context. The nonce is required to perform decryption but does not need to be secret. The ciphertext protects confidentiality. The tag protects ciphertext and associated data from undetected modification.

## AES-GCM

AES-GCM uses AES as the underlying block cipher and Galois/Counter Mode as the authenticated-encryption construction.

AES itself operates on 128-bit blocks and supports 128-bit, 192-bit, and 256-bit keys. GCM turns the block cipher into a counter-mode encryption mechanism and uses GHASH to authenticate associated data and ciphertext.

The Python implementation contains the AES key schedule, SubBytes, ShiftRows, MixColumns, AddRoundKey, Galois-field multiplication, GHASH, counter construction, and GCM tag processing. This makes the relationship between the AES primitive and GCM visible rather than treating AES-GCM as a black-box function.

For practical software, a maintained cryptographic library is normally preferable to handwritten cryptographic primitives. The Python implementation is useful for understanding the construction and for executable testing, not as a replacement for audited cryptographic software.

### GCM nonce behavior

The common deployment profile uses a 96-bit nonce. GCM has a particularly strong nonce uniqueness requirement: the same key must not be reused with the same nonce for independent encryption operations.

Nonce reuse can reveal relationships between plaintexts and can undermine GCM's authentication security. This is a protocol-level requirement, not something a ciphertext format can repair after the fact.

The Python `AeadBox` generates a fresh 12-byte nonce with a cryptographically secure random source for every encryption. The JavaScript, C++, and Java implementations follow the same 96-bit deployment profile.

## ChaCha20-Poly1305

ChaCha20-Poly1305 uses a different cryptographic architecture.

ChaCha20 is a stream cipher based on ARX operations:

- addition modulo 2^32
- bitwise rotation
- XOR

Poly1305 is a one-time authenticator operating over a large prime-related arithmetic domain. ChaCha20 derives the one-time Poly1305 key and separately produces the encryption keystream.

The Python implementation contains the ChaCha20 quarter round, full block function, stream encryption, Poly1305 arithmetic, padding rules, and the RFC-style AEAD construction.

This is materially different from AES-GCM. AES-GCM depends on AES blocks and GHASH multiplication in GF(2^128), while ChaCha20-Poly1305 uses ARX stream-cipher operations and polynomial authentication.

## Why Both Algorithms Are Included

The two algorithms solve the same high-level AEAD problem through different primitives.

| Property | AES-GCM | ChaCha20-Poly1305 |
|---|---|---|
| Encryption primitive | AES block cipher in counter mode | ChaCha20 stream cipher |
| Authentication | GHASH | Poly1305 |
| Typical key size in these examples | 256 bits | 256 bits |
| Nonce profile | 96 bits | 96 bits |
| Authentication tag | 128 bits | 128 bits |
| AAD | Supported | Supported |
| Nonce reuse requirement | Critical | Critical |
| Main implementation style | Block-cipher based | ARX stream cipher based |

The choice should be driven by platform support, interoperability requirements, performance characteristics, hardware acceleration, protocol standards, and operational constraints rather than by treating one algorithm as universally superior.

## Python Implementation

The Python program deliberately goes below the high-level API boundary.

The AES portion implements the AES key expansion and encryption rounds. The GCM portion then builds the counter-mode encryption stream and calculates the authentication value through GHASH.

The ChaCha20 portion implements the quarter-round transformation and 20-round block function. Poly1305 processes padded AAD and ciphertext and incorporates their lengths into the authenticated input.

The high-level `AeadBox` class provides a more realistic application interface. It generates nonces, creates immutable `AeadRecord` objects, dispatches to the selected algorithm, and refuses to decrypt a record under an incompatible algorithm.

The test section checks an AES block-cipher known-answer vector, a ChaCha20 known-answer vector, AEAD round trips, modified ciphertext, modified AAD, and nonce behavior.

The authentication failure demonstrations are particularly important. A one-bit ciphertext modification is not merely detected as different data; it causes authenticated decryption to fail. The same applies when associated data is changed.

The implementation also uses a constant-time byte comparison for authentication tags. This avoids an obvious early-exit comparison pattern at the application layer.

The pure-Python implementation is intentionally educational. It is not a recommendation to replace an audited cryptographic library in a production system.

## JavaScript Implementation

The JavaScript implementation takes the opposite approach. Instead of implementing AES, GHASH, ChaCha20, and Poly1305 manually, it uses Node.js's built-in cryptographic provider.

`aes-256-gcm` and `chacha20-poly1305` are exposed through Node's `crypto` module. The application code therefore focuses on the concerns that surround cryptography in a real service.

`KeyRing` associates key versions with algorithms. `SecureEnvelopeService` serializes authenticated metadata into AAD, generates nonces, creates encrypted envelopes, and retrieves historical keys when decrypting older records.

The `EventEmitter` usage models application-level events such as encryption and decryption. This is useful for audit logging, monitoring, or security telemetry without placing event handling inside the cryptographic primitive itself.

The key-rotation demonstration keeps an old key available for decrypting historical envelopes while making a newer key active for new encryption. This separates cryptographic key rotation from immediate bulk re-encryption.

## C++ Case Study

The C++ program models a repository artifact service that encrypts deployment manifests.

The service has a `KeyRing` containing versioned 256-bit keys. Each encrypted artifact records its algorithm and key version, which allows a stored artifact to identify the correct historical key during decryption.

`AeadEngine` isolates cryptographic operations from repository logic. The implementation uses OpenSSL's EVP interface rather than implementing cryptographic primitives manually.

The OpenSSL EVP interface also demonstrates an important operational property of AEAD decryption: the authentication tag is supplied before the final decryption operation, and the final operation must succeed before the plaintext is accepted.

The case study authenticates repository metadata as AAD. The metadata is visible to the storage system, but changing it invalidates the authentication tag.

The program also tests algorithm/key mismatch. An AES-GCM key cannot silently be treated as a ChaCha20-Poly1305 key. Cryptographic algorithm identity therefore forms part of the record's security context.

### C++ failure handling

The repository rejects:

- invalid key sizes
- unsupported algorithms
- invalid nonce sizes
- invalid tag sizes
- algorithm/key mismatches
- modified ciphertext
- modified AAD
- unknown key versions
- failed OpenSSL cryptographic operations

This separation between validation errors and authentication failure is important for system design. A malformed envelope and a correctly formatted but tampered envelope are different operational events even though both must prevent unauthenticated plaintext from entering the application.

## Java Enterprise Model

The Java implementation represents encrypted configuration records in an enterprise configuration platform.

The `AeadAlgorithm` enum defines the supported algorithms and associates each with its cryptographic transformation, key length, and nonce length. This prevents algorithm names from becoming uncontrolled strings throughout the application.

`KeyVersion` represents versioned key material. The record validates the key size and copies the byte array so callers cannot mutate the internal key representation through a shared array reference.

`EncryptedRecord` represents the authenticated envelope. It keeps nonce, ciphertext, tag, and AAD separate. This makes the storage model explicit and makes validation rules visible.

`KeyRing` maintains active and historical keys. Active keys are used for new encryption, while historical versions can remain available for decryption of previously created records.

`AeadService` performs the actual encryption and decryption. AES-GCM uses `GCMParameterSpec`; ChaCha20-Poly1305 uses the corresponding Java cipher transformation and nonce specification.

The Java API returns ciphertext and authentication tag together internally and then separates them into the application's record structure. During decryption, the ciphertext and tag are reconstructed before `doFinal`. Authentication is therefore completed by the cryptographic provider before the plaintext is returned.

## Associated Data

AAD is one of the most important distinctions between encryption and authenticated encryption.

Consider:

`tenant=acme-finance;service=settlement-api;record-type=production-configuration`

This information might not require confidentiality, but it does require integrity.

If ciphertext is moved from one tenant to another while the AAD is not authenticated, an application could potentially process valid ciphertext under an incorrect security context.

With AEAD, the metadata becomes part of the authentication calculation. Changing the AAD causes decryption to fail.

The implementations use AAD for tenant, service, environment, schema, artifact, or record-type metadata. The exact values differ by implementation because the programs model different application domains.

## Nonce Discipline

A nonce is not a password and is normally not secret.

The security requirement is uniqueness under a given key.

The examples use 96-bit nonces because that is the common profile for both AES-GCM and ChaCha20-Poly1305.

Random nonce generation is convenient, but it must be evaluated against the number of encryption operations and the application's operational model. Large-scale systems may use carefully coordinated nonce allocation rather than relying exclusively on random generation.

A nonce should never be copied from a previous record merely because the plaintext is similar. It should be treated as a per-encryption value.

## Authentication Tags

The examples use 128-bit authentication tags.

The tag binds the ciphertext and AAD to the key and nonce. A modified tag, ciphertext, or authenticated metadata causes decryption to fail.

The tag is not an encrypted checksum. It is generated from the cryptographic construction and secret key and therefore provides a much stronger authenticity property than an ordinary digest.

Applications should not silently continue with plaintext when authentication fails. The correct behavior is to reject the record and record an appropriate security or operational event.

## Key Management and Rotation

Nonce management and key management solve different problems.

Nonce uniqueness protects the security assumptions of the AEAD construction for a particular key. Key rotation limits the amount of data protected by one key and provides a mechanism for replacing retired or compromised keys.

The JavaScript, C++, Java, and SQL implementations explicitly model key versions.

A stored record contains a key version rather than relying on the currently active key. This is important because changing the active key must not make every historical record undecipherable.

A normal rotation sequence is:

`old active key -> retiring key -> new active key`

Existing records can continue to reference their original key version until a controlled re-encryption process migrates them.

A compromised key is different from a normally retired key. A compromised key may require immediate containment, access revocation, investigation, and potentially re-encryption of affected data.

## SQL Data Model

The PostgreSQL script models the operational storage layer.

`tenants` separates cryptographic ownership contexts.

`repositories` associates application resources with tenants and environments.

`encryption_keys` records key versions, algorithms, lifecycle states, and external KMS references. Actual plaintext key material is deliberately not stored in the demonstration database.

`encrypted_records` stores nonce, ciphertext, authentication tag, AAD, key reference, algorithm, and plaintext length.

`encryption_events` records encryption, decryption, authentication failure, key rotation, and rejection events.

The database enforces a 12-byte nonce and 16-byte authentication tag for the selected deployment profile. It also prevents invalid key versions and empty identifiers.

The partial unique index ensures that a tenant cannot have two active key versions for the same AEAD algorithm.

## Database-Level Integrity

The SQL model deliberately separates database integrity from cryptographic verification.

A database constraint can establish that a nonce has 12 bytes and a tag has 16 bytes. It cannot establish that a particular tag was correctly generated by AES-GCM or ChaCha20-Poly1305 unless a trusted cryptographic implementation performs that operation.

The application therefore performs AEAD encryption and authentication, while PostgreSQL enforces structural and relational rules.

This division avoids confusing structural validity with cryptographic validity.

A record may be structurally valid while still failing authentication. For example, a 12-byte nonce, 16-byte tag, and arbitrary ciphertext satisfy the storage constraints but do not prove that the ciphertext was generated by the correct key.

## Transactional Key Rotation

The SQL example performs a key rotation inside a transaction.

The old key becomes `RETIRING`, and a new key becomes `ACTIVE`. The transaction ensures that the state transition is committed as a unit.

The record itself retains its original key identifier. This allows the application to locate the correct historical key.

The partial unique index prevents the database from ending with two simultaneously active keys for the same tenant and algorithm.

## Edge Cases

### Reused nonce

Reusing a nonce with the same AEAD key violates a central security requirement. Applications should design nonce allocation explicitly rather than treating the nonce as an incidental random field.

### Modified ciphertext

A single modified ciphertext bit causes authentication failure. The application must not return modified plaintext as if it were valid.

### Modified AAD

Changing tenant, environment, record type, or other authenticated metadata causes the authentication check to fail.

### Wrong key

Decryption with a different key fails authentication. Applications should avoid interpreting this merely as corrupted plaintext.

### Wrong algorithm

An AES-GCM envelope should not be sent to a ChaCha20-Poly1305 decryptor or vice versa. Algorithm identity is part of the cryptographic context.

### Retired key

Retirement does not automatically mean that historical records are immediately unreadable. A policy can keep the key available for controlled decryption while preventing it from encrypting new records.

### Compromised key

A compromised key should not be treated like an ordinary retired key. The affected data set and re-encryption strategy require security incident handling.

### Empty plaintext

AEAD can authenticate an empty plaintext. The tag still protects the AAD and the fact that an authenticated empty message was supplied.

### Large plaintext

AEAD APIs generally operate on byte sequences and may have implementation-specific size limits. Large objects are often better handled through carefully designed chunking or object-storage envelope schemes, with explicit nonce and associated-data rules for every chunk.

## Performance Considerations

AES-GCM can benefit significantly from hardware acceleration available on many modern processors. AES instruction sets and optimized GHASH implementations can make AES-GCM highly efficient on supported systems.

ChaCha20-Poly1305 is designed around simple ARX operations and is particularly attractive on platforms where dedicated AES acceleration is unavailable or undesirable.

The correct performance comparison depends on the actual processor, cryptographic provider, message sizes, batching, memory behavior, and runtime.

The pure-Python implementation is not a useful benchmark for production cryptographic throughput because Python-level arithmetic and loops add substantial overhead. Its purpose is algorithmic transparency.

The Node.js, C++, and Java implementations delegate primitive operations to optimized cryptographic providers, which makes their performance characteristics much closer to real application deployments.

## Security Considerations

Keys should be generated with a cryptographically secure random source or obtained from an appropriate key-management system.

Plaintext keys should not be embedded in source code, configuration files, SQL fixtures, logs, or exception messages.

Nonces may normally be stored with ciphertext, but nonce uniqueness must be guaranteed.

Authentication tags must be verified before application code trusts decrypted data.

AAD should include security-relevant metadata whose modification would change the meaning or authorization context of the record.

Key versions should be explicit so that rotation does not make historical records ambiguous.

Cryptographic failures should be observable without logging secrets, plaintext, complete ciphertext, or key material.

Production systems should use established, maintained cryptographic libraries and well-reviewed protocol formats rather than deploying educational implementations of cryptographic primitives.

## Common Design Mistakes

A common mistake is to encrypt data but omit authentication. AES in a raw encryption mode does not automatically provide the integrity property supplied by GCM.

Another mistake is using the same nonce repeatedly with the same key.

Another is authenticating ciphertext but leaving security-critical metadata outside the authenticated context. AAD exists specifically to authenticate metadata without encrypting it.

Storing only an algorithm name without a key version can make rotation ambiguous.

Treating an authentication failure as ordinary corrupted input can hide active tampering.

Finally, cryptographic correctness alone does not solve key-management problems. A perfectly implemented AEAD construction is still vulnerable if attackers can obtain the encryption key.

## Practical Architecture

A robust enterprise architecture can be represented as:

`Application`
→ `AEAD envelope service`
→ `Key-management service`
→ `Encrypted storage`

The application supplies plaintext and security-relevant AAD.

The AEAD service validates algorithm parameters, obtains the correct key version, generates or receives a correctly allocated nonce, performs encryption, and returns the envelope.

The key-management layer controls key generation, activation, retirement, access, and rotation.

The database stores ciphertext and metadata but does not need plaintext access.

During decryption, the stored key version selects the historical key, the algorithm is checked against the key metadata, AAD is reconstructed from trusted record context, and authenticated decryption must succeed before plaintext reaches the application.

This separation keeps cryptographic primitives, key lifecycle management, application semantics, and persistence integrity as distinct engineering responsibilities.
