# HMAC in Cryptography and Blockchain

## 1. Technical Scope

Hash-based Message Authentication Code (HMAC) is a cryptographic mechanism used to verify the authenticity and integrity of messages through a cryptographic hash function and a shared secret key.

This project implements HMAC-SHA256 across Python, JavaScript, C++17, Java 17, and PostgreSQL. The implementations demonstrate how authenticated messages can participate in a blockchain transaction workflow.

The central distinction is between three separate cryptographic operations:

| Operation | Purpose | Main mechanism |
|---|---|---|
| Cryptographic hashing | Generate a fixed-length digest | SHA-256 |
| Message authentication | Verify message integrity and possession of a shared secret | HMAC-SHA256 |
| Blockchain integrity | Link blocks and detect historical modifications | SHA-256 block hashing |

HMAC and blockchain hashing serve different purposes. A transaction HMAC authenticates an individual transaction. A block hash identifies the contents of a block and links it to its predecessor.

Neither operation independently establishes distributed consensus.

## 2. Cryptographic Foundations

### 2.1 Cryptographic Hash Functions

A cryptographic hash function transforms an arbitrary-length input into a fixed-length output.

SHA-256 produces a 256-bit digest, represented by 64 hexadecimal characters.

Important properties include:

- Deterministic output.
- Resistance to finding a preimage.
- Resistance to finding a second preimage.
- Resistance to finding practical collisions.
- Sensitivity to input modifications.

For example, changing one transaction amount changes the SHA-256 digest with overwhelming probability.

SHA-256 alone does not establish who created a message. Anyone can calculate its digest.

### 2.2 HMAC Construction

HMAC combines a secret key with a cryptographic hash function.

Its general construction is:

\[
\operatorname{HMAC}(K,m)
=
H((K' \oplus opad)
\parallel
H((K' \oplus ipad)\parallel m))
\]

Where:

- \(K\) is the secret key.
- \(m\) is the original message.
- \(H\) is the underlying hash function.
- \(K'\) is the key normalized to the hash block size.
- \(ipad\) is the inner padding value.
- \(opad\) is the outer padding value.
- \(\oplus\) represents XOR.
- \(\parallel\) represents concatenation.

For SHA-256:

| Property | Value |
|---|---:|
| Digest length | 256 bits |
| Digest length in bytes | 32 |
| SHA-256 block size | 512 bits |
| SHA-256 block size in bytes | 64 |
| Recommended key material in these implementations | 32 bytes or more |
| HMAC output | 64 hexadecimal characters |

The HMAC construction handles key normalization internally.

A key longer than the underlying hash block size is first hashed. A shorter key is padded to the required block size.

HMAC does not require the secret key to have the same length as the output digest.

### 2.3 Why HMAC Is Different from a Plain Hash

Consider a transaction message:

`ALICE transfers 500 units to BOB`.

A plain SHA-256 digest can be calculated by anyone who knows the transaction.

An HMAC requires possession of the corresponding secret key.

Consequently:

- A plain hash detects accidental or deliberate data changes only when compared against a trusted digest.
- HMAC verifies message integrity and possession of a shared secret.
- An attacker without the key cannot feasibly construct a valid authentication tag for a modified message.

HMAC is a symmetric-key authentication mechanism. It does not provide public-key signatures or non-repudiation.

## 3. HMAC-SHA256 Authentication Workflow

The implemented transaction authentication workflow is:

    Transaction Data
          |
          v
    Canonical Serialization
          |
          v
    Secret Key Selection
          |
          v
    HMAC-SHA256
          |
          v
    Authentication Tag
          |
          v
    Transaction Submission
          |
          v
    HMAC Verification
          |
          +------ Invalid ------> Reject
          |
          v
    Validated Transaction

### 3.1 Canonical Serialization

Cryptographic authentication operates on bytes rather than abstract data structures.

The following representations may describe equivalent information but produce different byte sequences:

- JSON with different property ordering.
- JSON with different whitespace.
- Different Unicode encodings.
- Different representations of numeric values.
- Different timestamp precision.

For reliable authentication, all participants must agree on the exact representation of a transaction.

The implementations use:

- Python: deterministic JSON serialization.
- JavaScript: recursively sorted object properties.
- C++17: a fixed field ordering.
- Java 17: a deterministic field sequence.
- PostgreSQL: canonical JSONB-based serialization.

These implementations demonstrate canonicalization strategies. They are not automatically interoperable with each other because their serialization formats differ.

Cross-language systems must define one shared serialization specification, including character encoding, Unicode normalization, numeric representation, field ordering, timestamp format, and handling of missing fields.

### 3.2 Authentication Verification

A receiving system independently calculates the expected HMAC using the shared key.

It then compares the calculated tag against the supplied tag.

The comparison should use a constant-time comparison function to reduce timing-based information leakage.

The implementations use:

| Language | Verification mechanism |
|---|---|
| Python | `hmac.compare_digest()` |
| JavaScript | `crypto.timingSafeEqual()` |
| C++17 | Constant-time comparison loop |
| Java 17 | `MessageDigest.isEqual()` |
| PostgreSQL | `pgcrypto` HMAC calculation and tag comparison |

The C++17 implementation is educational. Production applications should use a vetted cryptographic implementation rather than a custom cryptographic primitive.

## 4. HMAC and Key Management

HMAC security depends on the confidentiality of its secret key.

Key management therefore requires more than generating a random value.

### 4.1 Key Generation

The implementations generate cryptographically random keys.

Python uses `secrets.token_bytes()`.

JavaScript uses `crypto.randomBytes()`.

C++17 uses fixed demonstration key material, not a production random-key generator.

Java uses `SecureRandom`.

PostgreSQL demonstrates key storage using byte arrays.

Production systems should generate keys using an approved cryptographic random-number generator and manage them through a dedicated Key Management Service or Hardware Security Module.

### 4.2 Key Lifecycle

The implementations model three key states.

| State | Meaning | New signatures | Historical verification |
|---|---|---|---|
| ACTIVE | Currently authorized | Allowed | Allowed |
| RETIRED | No longer used for new transactions | Rejected | Allowed |
| REVOKED | Invalidated because of a security event or policy decision | Rejected | Rejected by the demonstrated verification policy |

Key rotation involves creating a new key and retiring the previous one.

A typical lifecycle is:

    Generate Key V1
          |
          v
    Authenticate Transactions
          |
          v
    Generate Key V2
          |
          v
    Retire Key V1
          |
          v
    Sign New Transactions with V2
          |
          v
    Verify Historical Transactions
    Using Retained Key V1

Historical verification must be considered separately from permission to create new signatures.

Revocation policies require particular care. A system may retain historical verification evidence even after a key is revoked, while refusing to accept new transactions signed with that key.

### 4.3 Key Storage Security

Production key-management controls should include:

- Encryption at rest.
- Restricted access.
- Separation of key administrators and transaction operators.
- Key rotation schedules.
- Revocation procedures.
- Audit logging.
- Secure backup and recovery.
- Hardware-backed protection where appropriate.

The PostgreSQL implementation stores key material directly to demonstrate HMAC operations. This is not an appropriate production storage design.

## 5. HMAC in Blockchain

### 5.1 Blockchain Structure

A blockchain is an ordered sequence of blocks.

Each block contains transaction information and a cryptographic reference to its predecessor.

The relationship is:

    Genesis Block
         |
         v
       Block 1
         |
         v
       Block 2
         |
         v
       Block 3
         |
         v
       Block N

Each block contains:

- Block index.
- Previous block hash.
- Timestamp.
- Transaction collection.
- Current block hash.

A block hash is calculated from its defined contents.

Changing an earlier block changes its calculated hash. Its successor still contains the original previous-block reference, exposing the inconsistency.

### 5.2 Transaction Authentication Inside a Blockchain

HMAC can authenticate transactions before they are admitted to a ledger.

The implemented workflow is:

    Transaction Creation
          |
          v
    Canonical Serialization
          |
          v
    HMAC Generation
          |
          v
    Transaction Submission
          |
          v
    Authentication Verification
          |
          v
    Replay Protection
          |
          v
    Pending Transaction Queue
          |
          v
    Block Construction
          |
          v
    Block Hash Calculation
          |
          v
    Ledger Commitment

HMAC provides transaction-level authentication.

Block hashing provides tamper-evident linkage between blocks.

These operations are complementary rather than interchangeable.

### 5.3 Transaction Authentication Versus Block Hashing

| Characteristic | HMAC-SHA256 | SHA-256 block hashing |
|---|---|---|
| Secret key required | Yes | No |
| Detects message modification | Yes | Yes, when compared with a trusted tag |
| Authenticates secret possession | Yes | No |
| Publicly verifiable | No | Yes |
| Supports shared-secret authentication | Yes | No |
| Used for transaction authentication | Yes | Not by itself |
| Used for block linkage | Not normally | Yes |

A blockchain does not automatically require HMAC.

Many blockchain systems use digital signatures to authenticate transactions. Digital signatures allow public verification without distributing the signing secret.

HMAC is more appropriate for controlled environments in which participants share or are assigned trusted symmetric keys.

## 6. Transaction Domain Model

The five implementations use a transaction structure containing the following information:

| Field | Description |
|---|---|
| Transaction ID | Unique transaction identifier |
| Sender | Originating account |
| Receiver | Destination account |
| Amount | Transfer quantity |
| Nonce | Sender-specific replay protection value |
| Timestamp | Transaction creation time |
| Key ID | Identifier of the authentication key |
| Signature | HMAC-SHA256 authentication tag |

The authentication payload excludes the HMAC field itself.

Otherwise, the authentication operation would become circular.

### 6.1 Transaction Nonces

A nonce helps prevent transaction replay.

Suppose Alice submits a transaction using nonce 1.

An attacker captures the authenticated transaction and submits it again.

If the ledger accepts the same transaction repeatedly, the sender may be charged multiple times.

The ledger therefore records committed nonces and rejects reuse.

The implementations also check pending nonces to prevent duplicate submissions before block commitment.

A production ledger should define whether nonces must be strictly sequential or merely unique.

The demonstrations use uniqueness rather than implementing a complete sequential account-state protocol.

### 6.2 Transaction Validation

The implementations enforce several transaction rules:

- Sender and receiver must be present.
- Sender and receiver must be different.
- Amount must be positive.
- Nonce must be nonnegative.
- Transaction identifiers must be unique.
- The key identifier must exist.
- The HMAC must match the canonical transaction payload.
- A committed nonce cannot be reused.

The Java implementation also includes a maximum transaction amount policy.

The PostgreSQL implementation uses relational constraints and triggers for database-level integrity.

## 7. Blockchain Integrity and Replay Protection

### 7.1 Hash-Linked Blocks

Each block contains the previous block hash.

A block's integrity depends on:

1. Correct block contents.
2. Correct block hash.
3. Correct previous-block reference.
4. Valid transaction authentication.
5. Correct transaction membership.

The validation process recalculates block hashes and checks the chain relationships.

### 7.2 Tampering Detection

Consider a committed transaction:

    Sender: ALICE
    Receiver: BOB
    Amount: 500
    Nonce: 1

An attacker modifies the amount to 9000.

The original HMAC no longer authenticates the modified payload.

The transaction authentication check fails.

If the transaction is included in a block, the block hash also changes when recalculated from the modified contents.

The block integrity check therefore identifies the modification.

### 7.3 Replay Attack Scenarios

| Attack | Security control |
|---|---|
| Resubmit an identical transaction | Transaction ID uniqueness |
| Reuse a committed sender nonce | Unique sender nonce |
| Submit a duplicate pending nonce | Pending nonce tracking |
| Modify an authenticated amount | HMAC verification |
| Use an unknown key ID | Key registry validation |
| Use a revoked key | Key lifecycle validation |

Replay protection is a ledger-state requirement. HMAC alone does not prevent replay.

### 7.4 Block Integrity Is Not Consensus

The implementations create a locally validated, hash-linked transaction ledger.

They do not implement:

- Proof of Work.
- Proof of Stake.
- Byzantine Fault Tolerance.
- Distributed validator coordination.
- Network-wide fork resolution.
- Distributed finality.

A valid hash-linked chain does not establish that all network participants agree on its contents.

Blockchain consensus requires separate distributed-system protocols.

## 8. Python Implementation

**File:** `hmac_blockchain.py`

The Python implementation provides a repository-independent transaction and blockchain simulation.

### Main components

| Component | Responsibility |
|---|---|
| `canonical_json()` | Deterministic transaction serialization |
| `calculate_hmac()` | HMAC-SHA256 generation |
| `verify_hmac()` | Authentication verification |
| `KeyManager` | Key creation, rotation, and revocation |
| `TransactionFactory` | Transaction validation and creation |
| `TransactionAuthenticator` | Signing and verification |
| `Block` | Block structure and hash calculation |
| `Blockchain` | Transaction processing and chain validation |

### Important mechanisms

The implementation uses dataclasses for domain modeling and dictionaries for key and nonce management.

It separates cryptographic operations from transaction creation and ledger processing.

The blockchain maintains:

- An ordered block collection.
- A pending transaction collection.
- Sender-specific committed nonce sets.

The balance calculation uses committed transaction history.

The demonstration also tests transaction tampering, replay attempts, historical signature verification, and key rotation.

### Edge cases

The implementation rejects:

- Missing account identifiers.
- Self-transfers.
- Invalid amounts.
- Invalid nonces.
- Unknown keys.
- Revoked keys.
- Invalid HMAC tags.
- Duplicate committed nonces.

The in-memory design is suitable for learning and controlled experiments. It is not a durable distributed ledger.

## 9. JavaScript Implementation

**File:** `hmac_blockchain.js`

The JavaScript implementation emphasizes event-driven transaction processing and asynchronous application behavior.

### Main components

| Component | Responsibility |
|---|---|
| `CryptoService` | HMAC and SHA-256 operations |
| `KeyVault` | Key lifecycle management |
| `Transaction` | Transaction domain object |
| `Block` | Immutable-style block construction |
| `BlockchainEngine` | Transaction submission and block processing |

### JavaScript-specific mechanisms

The implementation uses Node.js cryptographic APIs rather than implementing cryptographic primitives manually.

`Map` stores pending transactions and key records.

`Set` stores committed transaction identifiers and nonces.

`EventEmitter` publishes transaction acceptance and block commitment events.

Asynchronous methods provide an interface suitable for integration with an application service or event-processing system.

A processing lock prevents overlapping block commitment operations in the single-process demonstration.

The block processor takes a snapshot of pending transactions before validation and commitment.

### Event workflow

    Transaction Submission
          |
          v
    HMAC Verification
          |
          v
    Pending Transaction Map
          |
          v
    transaction:accepted
          |
          v
    Block Processing
          |
          v
    block:committed
          |
          v
    Audit Consumer

This separation allows logging, notifications, and downstream processing to subscribe to ledger events.

The in-memory event model does not provide durable event delivery or distributed transaction guarantees.

## 10. C++17 Implementation

**File:** `hmac_blockchain.cpp`

The C++ implementation provides a lower-level cryptographic and ledger-engine perspective.

### Main components

| Component | Responsibility |
|---|---|
| `SHA256` | SHA-256 compression and padding |
| `hmacSha256()` | HMAC construction |
| `constantTimeEqual()` | Authentication-tag comparison |
| `KeyVault` | Key lifecycle and signing |
| `TransactionFactory` | Transaction construction |
| `Blockchain` | Nonce validation, mining and chain audit |

### SHA-256 implementation

The program implements the SHA-256 compression process using:

- Eight initial hash-state words.
- Sixty-four round constants.
- A 64-word message schedule.
- Bitwise rotation.
- Choice and majority functions.
- Modular 32-bit arithmetic.
- Standard message padding.

HMAC-SHA256 uses a 64-byte block size and the standard inner and outer padding values.

### Testing

The program includes two known-answer tests:

1. SHA-256 of the ASCII string `abc`.
2. The RFC 4231 HMAC-SHA256 test using a 20-byte key containing `0b` and the message `Hi There`.

These tests provide a basic correctness check for the cryptographic implementation.

### Performance considerations

SHA-256 processes input in 64-byte blocks.

Its time complexity is linear in the message length.

The ledger uses ordered block storage, maps, and sets to support transaction and nonce validation.

The implementation avoids scanning the entire chain for every nonce check.

The custom SHA-256 implementation is intended for technical study. Production cryptographic software should use a maintained, independently reviewed implementation.

## 11. Java 17 Implementation

**File:** `HmacBlockchainEnterprise.java`

The Java implementation models an enterprise-oriented transaction authentication service.

Its architecture separates cryptographic operations, key management, transaction policy, blockchain processing, and application orchestration.

### Main components

| Component | Responsibility |
|---|---|
| `CryptographicService` | HMAC and SHA-256 operations |
| `KeyManagementService` | Key lifecycle |
| `CanonicalSerializer` | Deterministic serialization |
| `TransactionAuthenticationService` | Transaction authentication |
| `TransactionPolicy` | Business validation contract |
| `StandardTransactionPolicy` | Amount and timestamp rules |
| `BlockchainService` | Ledger state and block commitment |
| `BlockchainApplication` | Application-level orchestration |

### Java-specific design

Java records model immutable domain data.

Enums represent key and transaction states.

Interfaces define policy contracts.

Concurrent collections store key records.

A `ReentrantLock` protects ledger state transitions.

The application service separates transaction processing from cryptographic implementation details.

### Policy enforcement

The standard transaction policy checks:

- Positive transaction amounts.
- Maximum permitted amount.
- Valid timestamps.
- Valid account identifiers.
- Nonnegative nonces.

The blockchain service performs authentication and replay checks before accepting a transaction.

It validates the entire pending batch again before committing a block.

This reduces the risk of committing a transaction that has become invalid after its initial submission.

The model remains an in-memory enterprise simulation. A production implementation would require durable transaction processing, distributed coordination, external secret management, and stronger authorization controls.

## 12. PostgreSQL Implementation

**File:** `hmac_blockchain.sql`

The PostgreSQL implementation models HMAC authentication and blockchain transactions using a relational database.

It requires the `pgcrypto` extension.

### Relational domain model

    Cryptographic Keys
           |
           v
         Accounts
           |
           v
       Transactions
           |
           v
         Blocks
           |
           v
      Audit Records

The principal database entities are:

| Table | Responsibility |
|---|---|
| `cryptographic_keys` | Key identifiers and lifecycle |
| `accounts` | Blockchain account information |
| `transactions` | Authenticated transaction records |
| `blocks` | Hash-linked blocks |
| `security_audit` | Operational and security events |

### Integrity constraints

The database applies:

- Primary keys.
- Foreign keys.
- Positive amount checks.
- Nonnegative nonce checks.
- Unique transaction identifiers.
- Unique committed sender nonces.
- HMAC format validation.
- Transaction commitment consistency.
- Account and key relationships.

These constraints prevent several invalid database states even when application validation is incomplete.

### PostgreSQL HMAC functions

`generate_transaction_hmac()` generates HMAC-SHA256 tags through `pgcrypto`.

`verify_transaction_hmac()` independently calculates the expected tag and checks the supplied value.

The database functions use `SECURITY DEFINER` and a controlled search path.

Their execution privileges must be restricted in a production environment.

### Triggers

`enforce_transaction_integrity()` validates:

- Canonical payload consistency.
- HMAC authentication.
- Account activity.
- Modification restrictions for committed records.

The trigger rejects modifications to transaction authentication fields after insertion.

### Block processing

`commit_pending_transactions()` implements transactional block creation.

The procedure:

1. Locks the block table.
2. Checks for pending transactions.
3. Revalidates transaction HMACs.
4. Checks nonce conflicts.
5. Calculates the next block height.
6. Retrieves the previous block hash.
7. Builds the ordered transaction representation.
8. Calculates the block hash.
9. Inserts the new block.
10. Marks transactions as committed.
11. Records an audit event.

The surrounding PostgreSQL transaction provides atomicity for the database operations.

### Reporting

The script includes:

- Transaction retrieval.
- Block history.
- HMAC validation.
- Replay detection.
- Account balance aggregation.
- Daily transaction volume.
- Key usage statistics.
- Blockchain integrity validation.
- Transaction eligibility determination.

The indexes target common transaction retrieval and audit queries.

The balance view calculates balances from committed transaction history. It does not enforce sufficient funds before a transaction is submitted.

## 13. Security Properties and Limitations

### 13.1 Security Properties

| Property | HMAC-SHA256 contribution |
|---|---|
| Message integrity | Detects modification when the tag is verified |
| Message authentication | Establishes possession of the shared secret |
| Secret-key dependency | Prevents unauthenticated tag generation |
| Replay resistance | Requires additional nonce or transaction-state controls |
| Confidentiality | Not provided |
| Non-repudiation | Not provided |
| Public verification | Not provided |
| Blockchain consensus | Not provided |

### 13.2 Important Limitations

**Shared-secret exposure**

Every authorized party possessing the same HMAC key can generate valid authentication tags.

A compromised key may therefore affect all transactions authorized under that key.

**No confidentiality**

HMAC does not encrypt transaction information.

Confidentiality requires a separate encryption mechanism.

**No non-repudiation**

Because HMAC uses a shared secret, it cannot establish which individual key holder created a particular tag.

Digital signatures are more appropriate where independent public verification is required.

**Canonicalization dependency**

Different serialization rules produce different HMAC values.

Interoperability requires a shared serialization specification.

**Replay protection dependency**

A valid HMAC can be replayed.

The receiving system must maintain nonce or equivalent transaction state.

**Key revocation**

Revocation changes which historical or new signatures a system accepts. Historical verification and new transaction authorization must be treated as separate policy decisions.

**Blockchain consensus**

Hash chaining does not provide consensus, validator coordination, or finality.

These capabilities require separate distributed protocols.

## 14. Complexity and Performance

Let:

- \(n\) represent the number of bytes in a message.
- \(t\) represent the number of transactions in a block.
- \(b\) represent the number of blocks.
- \(a\) represent the number of accounts.

| Operation | Approximate complexity |
|---|---|
| SHA-256 | \(O(n)\) |
| HMAC-SHA256 | \(O(n)\) |
| Transaction authentication | \(O(n)\) |
| Transaction serialization | \(O(n)\) |
| Block hash calculation | \(O(t)\) relative to serialized block size |
| Full chain verification | \(O(b+t)\) relative to stored transaction data |
| Nonce lookup using a hash set | Average \(O(1)\) |
| Account balance from complete history | \(O(t)\) |

The implementations favor straightforward verification and explicit state management over sophisticated distributed-ledger optimization.

For large transaction volumes, production systems would normally use persistent indexing, batching, bounded queues, incremental verification, and carefully designed state transitions.

## 15. Running the Implementations

### Python

Requirements: Python 3.10 or later.

File: `hmac_blockchain.py`

Run:

`python hmac_blockchain.py`

No external Python packages are required.

### JavaScript

Requirements: Node.js 18 or later.

File: `hmac_blockchain.js`

Run:

`node hmac_blockchain.js`

The implementation uses Node.js built-in modules.

### C++17

Requirements: A C++17-compatible compiler.

File: `hmac_blockchain.cpp`

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic hmac_blockchain.cpp -o hmac_blockchain`

Run:

`./hmac_blockchain`

On Windows:

`hmac_blockchain.exe`

No third-party libraries are required.

### Java 17

Requirements: JDK 17 or later.

File: `HmacBlockchainEnterprise.java`

Compile:

`javac HmacBlockchainEnterprise.java`

Run:

`java HmacBlockchainEnterprise`

The implementation uses Java's built-in cryptographic APIs.

### PostgreSQL

Requirements:

- PostgreSQL 15 or later.
- Permission to create the `pgcrypto` extension.
- Permission to create schemas, functions, procedures, and triggers.

File: `hmac_blockchain.sql`

Execute:

`psql -U postgres -d postgres -f hmac_blockchain.sql`

The script creates its own schema and relational objects.

The SQL example uses demonstration key material and should not be deployed with production credentials.

## 16. Cross-Language Implementation Comparison

| Engineering dimension | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Cryptographic API | `hashlib`, `hmac` | Node.js `crypto` | Custom educational implementation | JCA | `pgcrypto` |
| Key storage | Dictionary | Map | Map | Concurrent map | Relational table |
| Transaction model | Dataclass | Class | Struct | Record | Table |
| Replay protection | Sets | Sets | Sets | Sets | Unique index |
| Block representation | Dataclass | Class | Struct | Record | Table |
| Validation | Exceptions | Exceptions | Exceptions | Domain exceptions | Constraints and triggers |
| State management | In-memory | Event-driven | In-memory | Service-oriented | Transactional |
| Key rotation | Key manager | Key vault | Key vault | Key management service | Stored procedure |

The implementations share the same security principles but use different engineering approaches.

Their serialization formats and demonstration key arrangements are not intended to produce interchangeable transaction signatures.

## 17. Practical Applications

HMAC-SHA256 and blockchain transaction authentication are relevant to:

- Internal financial transaction systems.
- Controlled enterprise blockchain networks.
- Inter-service message authentication.
- Supply-chain transaction records.
- Permissioned distributed ledgers.
- API request authentication.
- Secure event-processing pipelines.
- Audit-oriented transaction systems.
- Device-to-server authentication.
- Integrity verification for structured records.

The suitability of HMAC depends on the trust model.

Where multiple participants need independent public verification, digital signatures generally provide a more appropriate authentication model.

Where a trusted service boundary controls shared secrets, HMAC provides an efficient mechanism for message authentication.

The central architectural distinction remains:

**HMAC authenticates a message using a shared secret. SHA-256 links and identifies blockchain data. Nonce management prevents replay. Distributed consensus determines agreement among network participants.**
