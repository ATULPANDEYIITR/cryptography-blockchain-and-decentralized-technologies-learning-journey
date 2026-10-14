# Initialization Vectors in Cryptography

## Technical scope

An initialization vector (IV) is a value supplied to a cryptographic operation to influence how plaintext is transformed. A nonce is a value intended to be used only once within a defined cryptographic context. These terms overlap in practice, but their security requirements depend on the encryption mode.

An IV is not a password, encryption key, or substitute for a secure cipher. It is usually stored alongside the ciphertext because decryption needs the same value.

This project examines IV generation, nonce allocation, authenticated encryption, lifecycle management, application validation, and database enforcement. It distinguishes the unpredictable IV required by CBC from the nonce-uniqueness requirement of GCM.

## Fundamental terminology

| Term | Meaning |
|---|---|
| Encryption key | Secret material that controls the encryption and decryption operations. |
| Initialization vector | An input that initializes a cipher mode so repeated plaintext does not necessarily produce repeated ciphertext. |
| Nonce | A value whose reuse is prohibited or tightly constrained by the cryptographic construction. |
| Ciphertext | The encrypted representation of plaintext. |
| Authentication tag | A value used by authenticated encryption to detect unauthorized changes. |
| Associated data | Information authenticated by an AEAD algorithm but left unencrypted. |
| Key scope | The particular encryption key under which IV or nonce requirements apply. |
| Key rotation | Replacing an encryption key with a new key version under a controlled lifecycle policy. |

## IV requirements depend on the cipher mode

### AES-CBC

AES has a block size of 128 bits, so CBC requires a 16-byte IV. For conventional secure CBC encryption, the IV must be unpredictable to an attacker before the encryption operation.

CBC combines each plaintext block with the preceding ciphertext block before encryption. For the first block, the IV serves as that preceding input. Reusing an IV can reveal relationships between messages that begin with the same plaintext block.

CBC does not authenticate ciphertext. An application must not treat successful decryption as proof that the message is genuine. Secure designs require a sound authentication construction, commonly encrypt-then-MAC with separate keys, or a suitable authenticated-encryption mode.

### AES-GCM

AES-GCM provides authenticated encryption with associated data. A 12-byte nonce is the conventional choice and is the profile used in these implementations.

For a given key, GCM nonce reuse is a serious security failure. It can reveal relationships between plaintexts and compromise authentication security. Randomly generated nonces have a collision probability that increases with the number of encryptions under the same key.

A deterministic counter-based allocator can provide uniqueness if its state is durable, atomic, and correctly coordinated. A counter that resets after a restart, backup restoration, or deployment replacement can repeat previously used nonces.

GCM has invocation and data-volume limits beyond the basic uniqueness rule. A production service must define a conservative per-key budget and rotate keys before reaching that budget.

## Random generation and collision probability

The Python and JavaScript implementations use cryptographically secure random-number generators rather than timestamps, sequential application IDs, ordinary pseudorandom generators, or hardcoded values.

For uniformly random nonces of \(b\) bits, the birthday-bound approximation for the probability of at least one collision after \(n\) generated nonces is

\[
P(\text{collision}) \approx \frac{n(n-1)}{2^{b+1}}
\]

This approximation is useful when the probability is small. It is not a guarantee of uniqueness and does not account for every cryptographic usage limit.

The Python program calculates an approximate collision probability for 96-bit nonces. The JavaScript program creates fresh 12-byte GCM nonces for each record. Neither implementation assumes that two random values can never collide.

A production design must choose between an appropriately budgeted random strategy and a coordinated deterministic strategy based on its throughput, deployment architecture, recovery procedures, and cryptographic requirements.

## Python implementation

The Python script concentrates on IV policy and allocation behavior.

`generate_random_iv()` uses the standard-library `secrets` module. `validate_cbc_iv()` and `validate_gcm_nonce()` enforce the lengths required by the project's selected profiles.

`IVRegistry` scopes reuse detection to a key identifier. Registering an existing value raises `NonceReuseError`. This demonstrates the policy but does not provide distributed protection: its set exists only in process memory.

`estimate_collision_probability()` gives an approximate probability for random nonce collisions. `CounterNonceAllocator` demonstrates a four-byte namespace followed by an eight-byte counter. Its in-memory state is intentionally unsuitable for production persistence because restarting the process can repeat values.

The optional OpenSSL integration checks whether the installed command-line build supports the requested AES-GCM operation. It does not substitute an invented cipher if the operation is unavailable. For a complete production encryption workflow, use a maintained cryptographic library with explicit authentication-tag handling and verified decryption.

## JavaScript implementation

The Node.js implementation uses the built-in `node:crypto` module to perform real AES-256-GCM encryption and authenticated decryption.

`encryptGcm()` creates a cipher with a 32-byte key and 12-byte nonce, authenticates associated data, and returns the ciphertext and authentication tag separately. The record also stores the nonce because decryption requires it.

`decryptGcm()` reconstructs the cipher and supplies the original associated data and tag. Authentication is checked by `decipher.final()`. Modified ciphertext or an incorrect tag causes the operation to fail.

The event-driven queue processes multiple deployment records sequentially. Sequential processing makes the allocation flow easy to inspect, but the in-memory registry is not a cross-process locking mechanism. Multiple workers require durable, coordinated allocation or a correctly partitioned nonce space.

The tampering demonstration changes a ciphertext byte. GCM rejects the modified record instead of treating the altered plaintext as valid. Applications must not expose partially decrypted content before authentication succeeds.

## C++ case study: artifact governance

The C++ program models a deployment artifact service rather than implementing a cipher. Its `GovernanceService` records artifact identity, source branch, key identifier, nonce, state, and audit events.

`NonceAllocator` constructs 12-byte values from a four-byte namespace and an eight-byte counter. The representation uses big-endian counter bytes so the nonce has a stable encoding.

The service tracks the combination of key identifier and nonce in a set. A repeated combination is rejected, while the same nonce bytes under a distinct key are not automatically treated as the same reuse event.

The model includes ready and quarantined artifacts and a key-generation transition. This represents the operational context in which encrypted artifacts are registered, reviewed, and associated with a specific key version.

The program is a governance demonstration, not an encryption implementation. A real service needs a maintained cryptographic library, persistent allocation state, transactional storage, appropriate access controls, and an audited key-management process.

## Java implementation: enterprise record encryption

The Java implementation uses `Cipher`, `GCMParameterSpec`, `KeyGenerator`, and `SecureRandom` from the standard Java runtime.

`EncryptionContext` binds the tenant, record identifier, and key identifier to the cryptographic operation through associated data. A ciphertext copied into a different record context therefore fails authentication when the application verifies it against the expected context.

`EncryptedRecord` stores the nonce, ciphertext with its authentication tag, key identifier, and record identifier. Its constructor and accessors copy byte arrays to reduce accidental mutation of internal record state.

`NonceRegistry` synchronizes allocation checks within a single Java process. Synchronization prevents concurrent calls on that particular registry from independently accepting the same nonce. It does not coordinate separate JVMs or preserve allocations after a restart.

The program tests both ciphertext tampering and record-context mismatch. These checks demonstrate two distinct controls: GCM authenticates the encrypted content and associated data, while the service checks whether the record identity is appropriate for the requested operation.

## PostgreSQL data model

The SQL script represents IV allocation and encrypted artifact metadata as relational records.

| Table | Responsibility |
|---|---|
| `encryption_keys` | Records algorithm, key version, and lifecycle state without storing raw key material. |
| `nonce_allocations` | Records each allocated nonce, the key scope, allocation method, worker identity, and allocation time. |
| `encrypted_artifacts` | Associates ciphertext and optional authentication tags with their key and nonce allocation. |
| `encryption_audit` | Records security-relevant events for investigation and operational review. |

The unique constraint on `(key_id, nonce)` prevents duplicate allocation records for the same key and nonce. The unique reference from each artifact to an allocation prevents two artifacts from claiming the same allocation record.

Indexes support queries that inspect recent allocations, artifact usage by key, and audit events over time. Views provide active-key information and a per-key nonce usage count.

The script uses a savepoint to demonstrate duplicate-nonce rejection. The failed insertion is handled through a PL/pgSQL exception block, and the transaction returns to the savepoint afterward.

The schema is not a complete production enforcement layer. It does not itself guarantee that all cryptographic operations obtain nonces from the database, that counter allocation is correctly implemented, or that raw encryption keys are protected. Production deployments should use narrowly privileged allocation functions, transactional counter updates where applicable, and a managed key service.

## Counter allocation and distributed systems

A counter-based nonce scheme requires stronger operational guarantees than a local increment operation.

The allocator must ensure that two workers never receive the same counter value under the same key. A common design reserves non-overlapping ranges in durable storage and assigns each range to one worker. Another design uses an atomic database operation for every allocation.

The design must also account for crashes between allocation and encryption, database restoration, replication, failover, and key rotation. Losing an allocated value is normally safer than reusing it.

A counter namespace is not a secret. Its purpose is to separate allocations, not to replace encryption-key protection. The counter must have a defined exhaustion policy, and a new key must be activated before the available nonce space or the cryptographic usage budget is exhausted.

## Common failure modes

- **Reusing a GCM nonce:** Can compromise confidentiality and authentication. Prevent reuse for each key, including across workers and restarts.
- **Using a predictable CBC IV:** Can reveal information about messages. Generate a fresh unpredictable IV for each encryption operation.
- **Confusing IV length with key length:** AES-256 has a 32-byte key, while AES-CBC uses a 16-byte IV and the chosen GCM profile uses a 12-byte nonce.
- **Assuming an IV must be secret:** IVs and nonces are usually transmitted or stored with the encrypted data. The encryption key must remain secret.
- **Assuming successful decryption means integrity:** CBC does not authenticate its ciphertext. Use authenticated encryption or a correctly constructed authentication scheme.
- **Ignoring associated data:** GCM authenticates associated data as well as ciphertext. Decryption must supply the same associated data.
- **Releasing plaintext too early:** Applications must not expose unauthenticated plaintext when verification has not completed.
- **Treating an in-memory registry as distributed protection:** Local sets disappear after restarts and cannot coordinate independent services.
- **Ignoring key versioning:** Nonce uniqueness is evaluated within the relevant key scope. Key rotation and historical key identification must be managed explicitly.

## Security and production considerations

The IV or nonce is only one part of a secure encryption system. Production systems also require protected key storage, explicit algorithm selection, authenticated decryption, bounded key usage, key rotation, authorization, audit logging, and a recovery strategy.

The random and counter-based approaches have different failure modes. Random allocation avoids persistent counter state but carries collision risk. Counter allocation can provide deterministic uniqueness but depends on durable, correctly coordinated state. The correct choice depends on the cryptographic mode and the system's operational requirements.

The examples intentionally separate encryption correctness from allocation governance. A cipher library provides cryptographic operations; application code controls how nonces are created and associated with keys; persistence and operational policies prevent reuse across the system's full lifetime.
