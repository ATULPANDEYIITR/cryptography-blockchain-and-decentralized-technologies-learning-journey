# Integrity in Cryptography and Blockchain

## 1. Topic Introduction

Integrity is the security property that allows a system to detect whether data has been changed without authorization or whether committed data no longer matches its authenticated representation.

In cryptography, integrity is commonly implemented with cryptographic hash functions, message authentication codes, digital signatures, authenticated data structures, and authenticated protocols.

In blockchain systems, integrity is extended through several interacting mechanisms:

- Cryptographic hashes identify data and commit to its contents.
- Hash links connect one block to another.
- Merkle trees commit efficiently to collections of transactions.
- Digital signatures can authenticate transaction authorization.
- Consensus mechanisms determine which history a distributed network accepts.
- Proof-of-work systems make large-scale historical rewriting computationally expensive.

Integrity does not mean that information is automatically true. A cryptographic system can reliably preserve an incorrect input. For example, if a valid transaction records the wrong amount because of an application bug, cryptography can preserve and authenticate that incorrect transaction rather than correct it.

The three implementations in this study approach integrity from different technical perspectives:

- Python provides a broad educational implementation of hashes, HMAC, hash chains, Merkle trees, and a proof-of-work blockchain.
- JavaScript demonstrates integrity in an application-oriented runtime and also uses Node.js cryptographic support for an actual Ed25519 digital-signature example.
- C++ develops an industry-style ledger case study with transaction validation, a SHA-256 implementation, Merkle-tree construction, block linking, proof of work, auditing, tampering simulation, and automated tests.

---

## 2. Fundamental Security Properties

Integrity is one of several major information-security properties.

### Confidentiality

Confidentiality concerns preventing unauthorized parties from reading protected information.

Encryption is normally used for confidentiality.

### Integrity

Integrity concerns detecting unauthorized or unintended modification.

Hash functions, HMACs, signatures, authenticated encryption, and authenticated data structures can contribute to integrity.

### Authentication

Authentication establishes the identity or authority associated with an entity or message.

Digital signatures and MACs can provide different forms of message authentication.

### Authorization

Authorization determines whether an authenticated entity is allowed to perform an operation.

Cryptography does not replace authorization logic.

### Availability

Availability concerns whether systems and information remain accessible when needed.

Blockchain and cryptographic integrity mechanisms do not by themselves guarantee availability.

These properties should not be treated as interchangeable. A SHA-256 hash can detect a change, but it does not encrypt the original data and does not establish who created it.

---

## 3. What Does Data Integrity Mean?

Suppose a system stores:

`employee=42;salary=50000`

The system can calculate a cryptographic digest of the data and store the digest separately.

If the stored data later becomes:

`employee=42;salary=90000`

the recalculated digest should be different.

The important relationship is:

`data -> cryptographic hash -> digest`

Verification repeats the operation:

`current data -> cryptographic hash -> calculated digest`

The calculated digest is compared with the trusted digest.

If the values differ, the data representation has changed.

The security assumption is important: the attacker must not be able to modify the data and also replace the trusted integrity information without detection.

---

## 4. Cryptographic Hash Functions

A cryptographic hash function maps input data of arbitrary practical length to a fixed-size output.

For SHA-256, the output is 256 bits, normally displayed as 64 hexadecimal characters.

Important properties include:

### Determinism

The same input produces the same digest.

### Fixed output size

Small and large inputs produce a 256-bit SHA-256 digest.

### Preimage resistance

Given a digest, finding an input that produces it should be computationally infeasible under the algorithm's security assumptions.

### Second-preimage resistance

Given one particular input, finding a different input with the same digest should be computationally infeasible.

### Collision resistance

It should be computationally infeasible to deliberately find two different inputs with the same digest.

### Avalanche behavior

A small change to the input should produce a substantially different output.

The Python, JavaScript, and C++ programs all demonstrate this property by hashing slightly different messages.

---

## 5. Hashing Is Not Encryption

A hash is not a reversible encryption operation.

Encryption normally uses a key and is designed to allow authorized recovery of plaintext.

Hashing creates a digest that acts as a compact cryptographic representation.

This distinction is important:

| Mechanism | Main purpose |
|---|---|
| Hash | Data fingerprint and commitment |
| Encryption | Confidentiality |
| HMAC | Keyed integrity and authentication |
| Digital signature | Publicly verifiable authentication and integrity |
| Merkle tree | Efficient commitment to many values |
| Blockchain | Distributed authenticated history combined with consensus rules |

---

## 6. Canonical Serialization

Cryptographic algorithms operate on bytes.

They do not understand that two different byte sequences might represent equivalent abstract data.

For example, an application could represent an object in more than one textual form. If the byte representation changes, the cryptographic hash changes.

The Python implementation addresses this through `canonical_json()`, which sorts object keys and uses deterministic JSON separators.

The JavaScript implementation provides a recursive `canonicalJson()` function.

The C++ implementation uses deterministic transaction serialization.

Production protocols should define serialization precisely. Ambiguous serialization can produce interoperability and integrity problems.

---

## 7. Tamper Detection

The Python `IntegrityRecord` stores both the original bytes and their SHA-256 digest.

The important operation is `verify_integrity()`.

It recalculates the digest from the current data and compares it with the stored digest.

The demonstration first verifies successfully and then modifies the underlying data. Verification subsequently fails.

The JavaScript `IntegrityRecord` provides the same conceptual model.

These examples demonstrate an important distinction:

> Integrity verification detects inconsistency between data and an authenticated commitment.

It does not itself prove why the data changed or identify the attacker.

---

## 8. Constant-Time Comparison

Cryptographic values should be compared carefully when timing information could reveal secrets or authentication information.

The Python implementation uses `hmac.compare_digest()`.

The JavaScript implementation uses `crypto.timingSafeEqual()` for HMAC verification.

A conventional string comparison may terminate after finding the first difference. In some security-sensitive environments, timing differences can become observable.

Constant-time comparison reduces this class of side channel when used correctly.

It is not a universal defense against every timing attack. The entire surrounding implementation must also be considered.

---

## 9. Hash Chains

A hash chain links sequential records.

A simplified structure is:

`H0 = hash(record0)`

`H1 = hash(record1 + H0)`

`H2 = hash(record2 + H1)`

and so on.

Changing an earlier record changes its hash and therefore breaks the relationship with subsequent records.

The Python `HashChain` and JavaScript `HashChain` demonstrate this mechanism.

Hash chains are useful for:

- Tamper-evident logs
- Sequential event records
- Audit structures
- Commitments between ordered records
- Building blocks for more complex authenticated structures

A hash chain is not automatically a blockchain. A blockchain normally introduces additional concepts such as blocks, distributed consensus, transaction validation, network participation, and sometimes economic incentives.

---

## 10. Merkle Trees

A Merkle tree is a tree of cryptographic hashes.

For transactions:

`TX1 -> H1`

`TX2 -> H2`

`TX3 -> H3`

`TX4 -> H4`

Parent nodes can then be constructed:

`P1 = hash(H1 || H2)`

`P2 = hash(H3 || H4)`

and the root becomes:

`Root = hash(P1 || P2)`

The root is a compact cryptographic commitment to the transaction collection.

### Merkle Root

The root is the final hash at the top of the tree.

If a transaction changes, its leaf hash changes, which changes the parent hash and eventually changes the root.

### Inclusion Proof

A Merkle inclusion proof does not require sending every transaction.

For a tree with many leaves, a verifier needs the relevant sibling hashes along the path to the root.

The proof size grows approximately as:

`O(log n)`

for `n` leaves.

### Odd Number of Leaves

There are multiple conventions for handling an odd number of nodes.

The Python and JavaScript examples duplicate the final hash at an odd level.

This is a protocol choice rather than a universal Merkle-tree rule.

Different systems may use different conventions.

---

## 11. Merkle Trees and Blockchain

A blockchain block can store many transactions.

Hashing every transaction directly into the block header would be inefficient.

Instead, the transactions can be represented by a Merkle root.

The block header can then commit to:

- Block index or height
- Previous block hash
- Merkle root
- Timestamp
- Nonce
- Other protocol-specific fields

If a transaction changes, the Merkle root changes.

If the Merkle root is part of the block header, the block hash changes.

If that block's hash is referenced by the next block, the historical chain becomes inconsistent.

This creates multiple layers of integrity dependency.

---

## 12. HMAC

HMAC stands for Hash-based Message Authentication Code.

Conceptually:

`HMAC(secret key, message) -> authentication tag`

A receiver with the same secret key can recompute the tag.

If the message changes, the expected tag changes.

The Python and JavaScript implementations demonstrate:

- Creating an HMAC
- Verifying a valid message
- Rejecting a modified message

HMAC provides keyed integrity and authentication.

It requires a shared secret.

A major limitation is that every party capable of generating valid HMAC values possesses the secret.

Therefore HMAC does not provide the same public verification model as digital signatures.

---

## 13. Digital Signatures

A digital signature normally uses an asymmetric key pair:

- Private key
- Public key

The private key is used for signing.

The public key is used for verification.

The JavaScript implementation uses Node.js's built-in Ed25519 support.

The program generates a key pair, signs a transaction message, verifies the original message, and then attempts to verify a modified message.

The modified message fails verification because the signature is bound to the original message.

Digital signatures can provide:

- Integrity
- Authentication
- Public verification
- Strong evidence of possession of the signing private key

The exact legal meaning of non-repudiation depends on the cryptographic system, key management, operational controls, and applicable legal framework.

The Python implementation deliberately does not implement a public-key signature algorithm from scratch. Production cryptographic algorithms should normally be implemented using established, reviewed cryptographic libraries.

---

## 14. Blockchain Integrity Model

A simplified blockchain structure is:

`Block 0 -> Block 1 -> Block 2 -> Block 3`

Each block contains a reference to the previous block.

For example:

`Block 2.previous_hash = Block 1.hash`

Therefore a modification to Block 1 changes its hash.

Block 2 still contains the old hash.

Verification can detect this inconsistency.

A block can also commit to its transactions through a Merkle root.

The integrity relationship can therefore be represented as:

`Transaction`

`-> Transaction Hash`

`-> Merkle Root`

`-> Block Header`

`-> Block Hash`

`-> Next Block's Previous Hash`

This layered dependency is a major reason blockchain histories are tamper-evident.

---

## 15. Blockchain Does Not Mean Immutable in an Absolute Mathematical Sense

The term "immutable" is often used informally.

A blockchain record can still be modified at the storage level.

The relevant security property is that unauthorized modification should be detectable or computationally/economically difficult to reconcile with the accepted history, depending on the protocol.

In a simple educational blockchain, changing an old transaction changes:

1. The transaction hash.
2. The Merkle root.
3. The block hash.
4. The previous-hash reference expected by the next block.

A sophisticated attacker attempting a historical rewrite may therefore need to reconstruct subsequent blocks and satisfy the actual network's consensus rules.

The security properties depend on the specific blockchain architecture.

---

## 16. Proof of Work

Proof of work introduces a computational requirement.

A simplified target might require a block hash to begin with:

`000`

The miner changes a nonce until the resulting hash satisfies the target.

For example:

`hash(block_header + nonce)`

The nonce is changed repeatedly until the required condition is met.

The Python, JavaScript, and C++ implementations demonstrate this mechanism.

### Why It Matters for Integrity

Proof of work does not directly make data impossible to change.

Instead, it makes the accepted history computationally expensive to rewrite because changing an old block invalidates later work and requires the attacker to reproduce the required work.

### Difficulty

Increasing the difficulty generally increases expected mining work.

The demonstration programs deliberately use small difficulties so they finish quickly.

Production blockchain systems use much more complex consensus and network mechanisms than this educational implementation.

---

## 17. Consensus and Integrity

Blockchain integrity is not produced by hashing alone.

A distributed blockchain needs rules for deciding which transactions and blocks are accepted.

Consensus mechanisms vary.

Examples include:

- Proof of work
- Proof of stake
- Byzantine fault-tolerant protocols
- Other protocol-specific consensus designs

A blockchain can therefore be understood as an interaction among:

- Data validation
- Cryptographic commitments
- Authentication
- Networking
- Replication
- Consensus
- Incentive mechanisms
- State-transition rules

The cryptographic hash is only one component.

---

## 18. Python Implementation

The Python script demonstrates the topic in a broad progression.

### Cryptographic hashing

`sha256()` provides a reusable SHA-256 operation using Python's standard library.

### Canonical data representation

`canonical_json()` produces deterministic JSON bytes for structured data.

### Integrity records

`IntegrityRecord` stores data and its expected digest.

### Hash chains

`HashChain` demonstrates sequential hash dependencies.

### Merkle trees

`MerkleTree` provides:

- Leaf hashes
- Parent hashes
- Root construction
- Inclusion proofs
- Inclusion verification

### HMAC

`create_hmac()` and `verify_hmac()` demonstrate keyed integrity.

### Blockchain

`Block` and `Blockchain` combine:

- Transactions
- Merkle roots
- Previous hashes
- Block hashes
- Nonces
- Proof of work
- Chain verification

### Testing

The Python script contains executable tests for:

- Hash-chain tampering
- Merkle-proof verification
- Blockchain tampering

---

## 19. JavaScript Implementation

The JavaScript file is designed around Node.js application behavior.

It uses the built-in `crypto` module rather than external npm packages.

### Hashing

`sha256()` uses Node.js's cryptographic hash interface.

### Deterministic serialization

`canonicalJson()` recursively sorts object keys.

### HMAC

Node's `createHmac()` demonstrates keyed integrity.

### Hash chain

`HashChain` shows how previous hashes create sequential dependencies.

### Merkle tree

`MerkleTree` implements:

- Leaves
- Parent nodes
- Root calculation
- Inclusion proofs
- Proof verification

### Blockchain

`Block` and `Blockchain` provide:

- Transaction collections
- Merkle roots
- Previous block references
- Proof of work
- Verification

### Digital signature

Node's Ed25519 support provides a meaningful public-key integrity demonstration.

The program generates a key pair, signs a message, verifies it, and then tests the signature against a modified message.

### Runtime performance

The program also measures a SHA-256 operation over a 1 MiB buffer using Node's high-resolution timer.

---

## 20. C++ Case Study

The C++ implementation models a small digital asset ledger.

The system has several layers.

### Transaction layer

Each transaction contains:

- Sender
- Recipient
- Amount

`Transaction::isValid()` performs basic business validation.

This demonstrates an important principle: cryptographic integrity does not replace application validation.

### Hash layer

`SHA256` implements SHA-256 directly for educational purposes.

The implementation includes:

- Message padding
- 512-bit blocks
- Message schedule
- Round constants
- Compression rounds
- Final digest generation
- Hexadecimal encoding

The program also checks SHA-256 against the known digest of `abc`.

### Merkle layer

`MerkleTree` converts transaction hashes into a Merkle root.

The tree commits to the entire transaction collection.

### Block layer

`Block` contains:

- Index
- Timestamp
- Transactions
- Previous hash
- Merkle root
- Nonce
- Hash

The block hash commits to the important block-header values.

### Blockchain layer

`Blockchain` manages:

- Genesis block
- Block creation
- Proof of work
- Previous-hash relationships
- Complete validation

### Service layer

`LedgerService` exposes a higher-level transfer operation.

This separates application operations from low-level blockchain mechanics.

### Audit

The audit operation verifies the complete ledger.

### Attack simulation

The program modifies an old transaction after it has been committed.

Verification then detects the inconsistency.

---

## 21. Why Three Languages Are Useful

The same security concepts appear differently at different software layers.

### Python

Python emphasizes:

- Readable cryptographic demonstrations
- Rapid experimentation
- Data structures
- Testing
- Algorithmic explanation

It is particularly effective for expressing Merkle-tree and blockchain concepts concisely.

### JavaScript

JavaScript is useful for:

- Application logic
- Node.js services
- Web-oriented systems
- Event-driven applications
- Runtime cryptographic APIs

The JavaScript implementation also demonstrates a practical built-in digital-signature API.

### C++

C++ exposes lower-level implementation concerns.

The case study demonstrates:

- Explicit data structures
- Memory-managed objects
- Strong typing
- Algorithm implementation
- Standard-library containers
- Computational costs
- System-oriented architecture

Implementing SHA-256 in C++ also makes the underlying compression process more concrete.

---

## 22. Integrity Versus Authenticity

These concepts should be separated.

A plain hash answers a question similar to:

"Does this data match the data represented by this trusted digest?"

An HMAC answers:

"Does this data match a tag that could only have been generated by someone possessing the shared secret?"

A digital signature answers:

"Does this data have a valid signature corresponding to this public key?"

The distinction matters in system design.

A downloaded file and its SHA-256 hash can provide useful integrity verification if the expected hash comes from a trusted channel.

If an attacker can replace both the file and its hash, the hash alone is insufficient.

An authenticated signature or separately protected commitment can address that problem.

---

## 23. Important Distinction: Integrity Versus Truth

Consider:

`Alice -> Bob: 1,000,000`

If an authorized system correctly signs this transaction, cryptography can prove that the signed transaction has not been changed and that the signature corresponds to the signing key.

Cryptography cannot determine whether Alice actually intended the transaction.

That requires application rules, authorization, identity management, user controls, and potentially external evidence.

Therefore:

`Integrity != Truth`

and:

`Authentication != Authorization`

These distinctions are fundamental to secure architecture.

---

## 24. Edge Cases

The implementations intentionally include several edge cases.

### Empty data

SHA-256 supports an empty byte sequence and produces a valid digest.

### Empty Merkle tree

The examples reject an empty Merkle tree because there is no transaction leaf from which to construct the demonstrated root.

### Single-leaf tree

A single transaction produces a root equal to the leaf hash under the demonstrated construction.

### Odd number of leaves

The implementations duplicate the final hash when a level has an odd number of nodes.

This is an implementation convention and must match the protocol used by all participants.

### Invalid transaction

The C++ case study rejects:

- Empty sender
- Empty recipient
- Zero amount
- Amounts above the configured demonstration limit

### Tampered transaction

Changing an existing transaction invalidates the cryptographic commitments derived from it.

### Invalid proof index

The Python and JavaScript Merkle implementations explicitly reject invalid leaf indexes.

---

## 25. Unicode and Serialization

Human-readable text can have multiple byte representations.

For example, visually equivalent Unicode text may be represented using different sequences of Unicode code points.

Cryptographic hashes operate on bytes.

Therefore systems that sign or hash structured textual data should define:

- Character encoding
- Normalization requirements where appropriate
- Field ordering
- Number representation
- Whitespace rules
- Escaping rules
- Optional-field behavior

Canonical serialization is therefore a security and interoperability concern.

---

## 26. Performance Considerations

### Hashing

For an input of `n` bytes, a hash operation is generally proportional to the amount of input processed.

The practical cost depends on:

- Algorithm
- CPU
- Hardware acceleration
- Implementation
- Input size

### Merkle trees

Constructing a Merkle tree requires approximately `O(n)` hash operations for `n` leaves.

An inclusion proof requires approximately `O(log n)` sibling hashes.

This makes Merkle structures useful when a verifier needs evidence about one item without receiving an entire dataset.

### Hash chains

Validating a chain containing `n` records is generally `O(n)`.

### Blockchain verification

For a simple blockchain that verifies every block and transaction, work grows with the number of blocks and committed transactions.

### Proof of work

Proof of work is deliberately computational.

Its purpose is not to maximize software performance. Its purpose is to impose a measurable computational cost on block production and, depending on the consensus design, historical rewriting.

---

## 27. Security Considerations

### Protect the trusted commitment

A digest is useful only when an attacker cannot silently replace the trusted digest together with the data.

### Protect secret keys

HMAC security depends on secret-key confidentiality.

Digital-signature security depends heavily on private-key protection.

### Avoid homemade production cryptography

The C++ SHA-256 implementation is educational.

A production system should generally use an established cryptographic library with professional review, testing, maintenance, and platform support.

### Avoid obsolete algorithms

Cryptographic algorithm selection should account for the current threat environment and published cryptographic guidance.

### Validate before committing

A blockchain should not treat cryptographic validity as equivalent to business validity.

Transactions must pass appropriate application-level validation before entering the ledger.

### Protect against replay

A valid transaction can potentially be submitted more than once if the protocol lacks appropriate replay protection.

Nonce fields, sequence numbers, timestamps, transaction identifiers, or protocol-specific state rules can address replay depending on the system.

### Protect private keys

A valid signature can authorize actions regardless of whether the human owner intended the action.

Private-key security is therefore central to transaction security.

### Consider side channels

Timing, memory access patterns, error behavior, and other observable implementation details can matter in cryptographic software.

---

## 28. Common Mistakes

### Mistake 1: Treating hashing as encryption

Hashing does not provide confidentiality.

### Mistake 2: Trusting an unprotected hash

If both data and digest can be replaced, an attacker may replace both.

### Mistake 3: Assuming blockchain means automatic truth

A blockchain preserves protocol-accepted state. It does not independently verify real-world facts.

### Mistake 4: Confusing HMAC and digital signatures

HMAC uses a shared secret.

Digital signatures use asymmetric keys.

### Mistake 5: Ignoring serialization

Different byte representations produce different cryptographic results.

### Mistake 6: Assuming a Merkle root proves everything by itself

The verifier must trust or authenticate the root.

### Mistake 7: Implementing cryptography from scratch in production

Cryptographic algorithms have subtle implementation requirements.

### Mistake 8: Ignoring key management

Strong algorithms cannot compensate for compromised keys.

### Mistake 9: Treating proof of work as the whole blockchain

Proof of work is one consensus mechanism component. A complete blockchain system also involves networking, validation, state rules, chain-selection rules, and operational security.

### Mistake 10: Failing to test tampering

Security mechanisms should be tested against deliberate modification, malformed data, invalid signatures, incorrect serialization, and invalid chain relationships.

---

## 29. Integrity Mechanism Comparison

| Mechanism | Key required for verification | Detects modification | Authentication | Typical role |
|---|---:|---:|---:|---|
| Cryptographic hash | Not inherently | Yes, if digest is trusted | No | Fingerprint |
| HMAC | Shared secret | Yes | Yes, to key holders | API/message authentication |
| Digital signature | Public key | Yes | Yes | Public verification |
| Hash chain | Depends on commitment protection | Yes | Not inherently | Ordered tamper evidence |
| Merkle tree | Trusted/authenticated root | Yes | Not inherently | Data-set commitment |
| Blockchain | Protocol-dependent | Yes | Protocol-dependent | Distributed ledger |

The table describes security properties in simplified terms. Actual protocol security depends on key management, trust assumptions, implementation, and the surrounding system.

---

## 30. Production Design Considerations

A production integrity architecture should define:

1. What data requires integrity protection?
2. Who is trusted?
3. Who can modify data?
4. Who must detect unauthorized modification?
5. Is public verification required?
6. Is confidentiality also required?
7. What serialization format is authoritative?
8. How are keys generated?
9. How are keys stored?
10. How are keys rotated or revoked?
11. How are cryptographic algorithms upgraded?
12. How are verification failures handled?
13. What logs are retained?
14. What replay protections are required?
15. What is the consensus or trust model?
16. What happens when verification fails?

The cryptographic mechanism should be selected from these requirements rather than selected first and fitted to the problem afterward.

---

## 31. Practical Applications

Integrity mechanisms appear in many systems.

### Software distribution

Hashes can help verify that downloaded software matches an expected artifact.

### Secure communication

HMACs, digital signatures, and authenticated encryption can protect transmitted information from undetected modification.

### Financial systems

Transaction authentication and tamper-evident audit trails can protect financial records.

### Version control

Hash-based object identifiers can connect content to cryptographic commitments.

### Digital signatures

Documents, software releases, certificates, and transactions can use signatures for public verification.

### Blockchain

Transactions and blocks use cryptographic commitments to create a tamper-evident distributed history.

### Audit logs

Hash chains can make unauthorized alteration of historical records easier to detect.

### Distributed storage

Merkle trees can efficiently compare and verify large collections of data.

---

## 32. Threat Model Perspective

Security properties must be interpreted relative to an attacker model.

A system might consider attackers who can:

- Modify stored files
- Modify network messages
- Replay valid messages
- Alter transactions
- Attempt to forge signatures
- Obtain public keys
- Attempt to replace integrity metadata
- Compromise application credentials
- Attempt historical blockchain rewrites
- Exploit implementation bugs

The correct integrity mechanism depends on what the attacker can control.

For example, a hash stored next to a file provides limited protection if an attacker has write access to both the file and the hash.

A digital signature can provide stronger public verification because the attacker would need to produce a valid signature without possessing the private key.

---

## 33. Layered Integrity Model

A useful conceptual architecture is:

`Application Validation`

↓

`Transaction Authentication`

↓

`Transaction Hash`

↓

`Merkle Tree`

↓

`Block Header`

↓

`Block Hash`

↓

`Previous-Block Reference`

↓

`Consensus`

Each layer addresses a different part of the security problem.

Application validation determines whether an operation is acceptable according to business rules.

Authentication determines whether an authorized key or entity approved the operation.

Hashing commits to the exact data representation.

Merkle trees efficiently commit to collections.

Block hashes connect historical states.

Consensus determines which distributed history is accepted by participants.

---

## 34. Testing Strategy

Integrity systems should be tested using both valid and invalid cases.

Important tests include:

- Original data verifies successfully.
- One-byte modification fails.
- Transaction amount modification fails.
- Sender modification fails.
- Recipient modification fails.
- Merkle proof for the correct leaf succeeds.
- Merkle proof for modified data fails.
- Incorrect previous hash fails.
- Incorrect block hash fails.
- Invalid proof-of-work target fails.
- Invalid transaction fails.
- Empty data is handled deterministically.
- Odd transaction counts produce the expected Merkle root.
- Serialization is deterministic.
- Signatures fail after message modification.
- Invalid indexes are rejected.

The three implementations contain executable tests and deliberate tampering demonstrations to illustrate these principles.

---

## 35. Key Technical Relationships

Several relationships are central to understanding blockchain integrity.

### Transaction to hash

A transaction is converted into bytes and hashed.

### Hash to Merkle leaf

The transaction hash becomes a leaf.

### Merkle leaf to root

Sibling hashes are combined until the root is produced.

### Merkle root to block

The root becomes part of the block commitment.

### Block to next block

The next block stores the previous block's hash.

### Block to consensus

The network's consensus rules determine whether the block becomes part of the accepted history.

This creates a chain of cryptographic dependencies.

---

## 36. What the Implementations Deliberately Simplify

These programs are educational implementations rather than complete production blockchain protocols.

The simplified blockchain does not implement:

- Peer-to-peer networking
- Distributed consensus among independent nodes
- Proof-of-stake economics
- Wallet infrastructure
- Full account or UTXO models
- Production key storage
- Transaction fee markets
- Fork resolution
- Network synchronization
- Persistent database storage
- Smart-contract execution
- Byzantine network simulation
- Production-grade difficulty adjustment

These omissions are intentional because the focus is integrity.

The cryptographic and data-structure mechanisms shown here are the foundations upon which larger systems can be constructed.

---

## 37. Core Principles to Retain

The central technical principles are:

1. Integrity means detecting unauthorized or unintended modification.
2. Cryptographic hashes provide compact commitments to data.
3. Hashes do not provide confidentiality.
4. Hashes do not inherently authenticate the data source.
5. HMAC adds a shared secret to integrity verification.
6. Digital signatures enable public-key-based verification.
7. Hash chains make changes to earlier records detectable through later dependencies.
8. Merkle trees provide compact commitments to large collections.
9. Blockchain blocks can combine Merkle roots with previous-block hashes.
10. Consensus is essential to the security model of a distributed blockchain.
11. Proof of work makes certain historical rewrites computationally expensive.
12. Cryptography preserves and verifies commitments but does not establish the truth of arbitrary real-world information.
13. Secure serialization is part of cryptographic system design.
14. Key management is as important as algorithm selection.
15. Production cryptographic systems should rely on well-established implementations and carefully defined protocols.
