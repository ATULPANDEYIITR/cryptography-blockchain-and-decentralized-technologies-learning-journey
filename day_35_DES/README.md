# DES in Cryptography and Blockchain

## Scope

This repository presents Data Encryption Standard (DES) as a historical block cipher and examines how encryption relates to blockchain data structures, integrity, authentication, validation, and consensus.

The central distinction is important:

- **DES** is a symmetric block cipher designed primarily for confidentiality.
- **Hash functions** provide fixed-length digests used for integrity and blockchain block linking.
- **HMAC** provides message authentication when a shared secret is available.
- **Digital signatures** establish authorization and non-repudiation properties that symmetric encryption does not provide.
- **Consensus mechanisms** determine how a distributed blockchain network agrees on accepted state.
- **Database constraints** protect relational consistency inside one database system but do not constitute blockchain consensus.

DES therefore should not be treated as a blockchain security mechanism by itself. A blockchain can contain encrypted data, but encryption, hashing, signatures, and consensus solve different problems.

## DES fundamentals

DES operates on a 64-bit block and uses a 64-bit transmitted key containing 56 effective key bits and eight parity bits. Its 16-round Feistel construction repeatedly transforms a 64-bit state split into 32-bit left and right halves.

The implementations expose the principal internal stages:

- The initial permutation rearranges the 64 input bits before the Feistel rounds.
- The key schedule applies PC-1 to remove parity positions, rotates two 28-bit halves according to the DES rotation schedule, and applies PC-2 to create sixteen 48-bit round keys.
- The Feistel function expands a 32-bit right half to 48 bits, XORs it with a round key, passes the result through eight 6-to-4-bit S-boxes, and applies the P permutation.
- The final permutation reverses the initial permutation's arrangement after the sixteen Feistel rounds.
- Decryption uses the same Feistel construction with the round keys in reverse order.

The Python implementation performs these operations explicitly. The JavaScript implementation uses `BigInt` so that JavaScript's numeric representation does not lose significant bits during DES transformations. The C++ implementation uses fixed-width integer types to make the 32-bit and 64-bit state representation explicit. The Java implementation uses the Java Cryptography Architecture for a standard-provider DES known-answer test while concentrating its custom code on the surrounding ledger domain.

## DES key limitations

The most important weakness of DES is its 56-bit effective key size. The key space is small enough that exhaustive key search is practical with specialized hardware and distributed computation.

Parity bits do not increase the effective key space. They are transmitted with the DES key but are excluded by the PC-1 permutation before the round-key schedule.

DES also has known weak and semi-weak keys. A secure implementation should reject inappropriate keys rather than assuming that every eight-byte value has equivalent cryptographic quality.

The Python implementation includes parity normalization, key validation, and detection for the classical weak-key set. These checks are useful for understanding the structure of a DES key, but they do not make DES suitable for modern deployments.

## Block modes and authentication

A block cipher does not by itself define how arbitrary-length messages are encrypted. The Python and JavaScript implementations use DES-CBC to demonstrate block chaining.

CBC combines each plaintext block with the previous ciphertext block before encryption. The first block uses an initialization vector. The IV does not need to be secret, but it must be handled correctly. Padding is required when the plaintext does not naturally occupy an integral number of DES blocks.

CBC encryption alone does not authenticate ciphertext. An attacker may modify ciphertext without possessing the encryption key. Padding errors can expose one kind of manipulation, but successful padding does not prove that the plaintext is authentic.

The Python blockchain model therefore calculates an HMAC over the IV and ciphertext. This separates confidentiality from authentication:

`DES-CBC -> ciphertext`

`HMAC-SHA-256 -> authenticity and integrity of the encrypted payload`

For modern applications, an authenticated encryption mode such as AES-GCM or ChaCha20-Poly1305 is preferable because confidentiality and authentication are designed into one construction.

## Blockchain relationship

A blockchain normally represents an ordered collection of blocks. A simplified block contains a reference to the previous block's digest, application data, a timestamp or similar metadata, and possibly a consensus-related value such as a proof-of-work nonce.

The important relationship is:

`block N -> hash(block N) -> previous_hash of block N+1`

Changing an earlier block changes its digest. The next block still contains the old digest, so the chain relationship becomes inconsistent.

Encryption changes the confidentiality properties of the payload but does not itself create this chain linkage.

For example, a blockchain block may conceptually contain:

`previous_hash | encrypted_payload | transaction_metadata | nonce | block_hash`

The encrypted payload hides selected information from parties that do not possess the decryption key. The block hash detects modification of the serialized block. A consensus mechanism determines whether the network accepts the resulting history.

These mechanisms are complementary rather than interchangeable.

## Python implementation

The Python program contains a complete educational DES implementation instead of calling a third-party cryptographic library.

The `permute` function implements the table-driven bit permutations used by DES. `generate_round_keys` performs PC-1, the sixteen rotations, and PC-2. `des_f` contains the Feistel transformation, including expansion, XOR with the round key, S-box substitution, and the P permutation.

`des_block` performs the sixteen-round Feistel network and uses the reversed key schedule for decryption.

The program also provides CBC encryption and decryption with padding validation. The padding code explicitly rejects malformed lengths, invalid padding values, and inconsistent padding bytes.

The `EducationalBlockchain` class demonstrates a more important systems-level boundary. It encrypts a payload with DES-CBC, calculates an HMAC over the IV and ciphertext, stores a block containing the resulting metadata, and performs a proof-of-work loop. Its validation process checks block indices, previous-hash links, proof-of-work, HMAC validity, and payload decryption.

The blockchain demonstration deliberately exposes tampering. Modifying a stored payload or encrypted representation without recomputing the necessary authentication and chain information causes validation failure.

## JavaScript implementation

The JavaScript file takes a different perspective by implementing DES with `BigInt` and modeling the encrypted ledger as an event-driven object.

JavaScript's normal `Number` type cannot safely represent arbitrary 64-bit integer values. DES requires exact manipulation of 64-bit state, so `BigInt` is used for the permutation, key schedule, and Feistel operations.

The `EncryptedLedger` class extends Node.js `EventEmitter`. Appending a block emits a `blockAppended` event, allowing an audit consumer to observe the operation without being embedded inside the append method.

The ledger separately computes an HMAC using Node's `crypto` module. `timingSafeEqual` is used for comparing authentication values, avoiding a simple byte-by-byte comparison that can expose timing differences.

The JavaScript example also modifies ciphertext after a block has been created. The authentication check detects the modification before the plaintext is accepted.

## C++ case study

The C++ program presents a compact blockchain governance engine.

Its DES implementation uses fixed-width integer types. The key schedule stores sixteen 48-bit round keys inside 64-bit containers, while the Feistel halves use 32-bit values. This makes the bit-width assumptions visible at the type level.

The `GovernanceEngine` validates transactions before accepting them. A transaction requires a sender, receiver, positive amount, distinct participants, and a purpose. The engine then creates an encrypted representation, links the block to its predecessor, and searches for a nonce satisfying a configurable proof-of-work prefix.

The case study demonstrates an important engineering trade-off: proof-of-work increases the computational cost of rewriting a block, but it does not strengthen DES. The two mechanisms address different threats.

The C++ program intentionally names its standard-library digest helper `deterministicDigest` rather than claiming that `std::hash` is SHA-256. C++17 does not provide a standard SHA-256 implementation, and `std::hash` must not be substituted for a standardized cryptographic hash in production blockchain software.

## Java enterprise model

The Java program focuses on domain boundaries and state management.

`TransactionState` represents the lifecycle of a transaction from proposal through validation and commitment. `TransactionValidator` centralizes business validation rather than allowing invalid transactions to reach the ledger service.

`MergeEligibilityService` represents an explicit policy decision. It requires two approvals and successful checks before a transaction can be committed. Although the terminology resembles software delivery workflows, the same policy pattern applies to controlled blockchain transaction processing: a proposed state must satisfy defined conditions before it becomes committed state.

`LedgerService` creates immutable-style records using Java records, validates the transaction, creates encrypted payload metadata, calculates a block digest, and performs a simple proof-of-work search.

The program also demonstrates exception-based failure handling. Invalid sender/receiver relationships, non-positive amounts, missing purposes, insufficient approvals, and failed checks prevent commitment.

The encryption portion is deliberately conservative in its claims. The surrounding ledger model demonstrates cryptographic metadata and security boundaries rather than presenting a simple XOR construction as real DES encryption. The historical DES test vector is performed through the Java Cryptography Architecture using `DES/ECB/NoPadding`.

## SQL data model

The PostgreSQL script models the domain relationally.

`repositories` and `branches` represent the repository and branch boundaries needed by the governance workflow. `pull_requests` records source and target branches, authors, lifecycle state, and merge strategy.

`commits` and `pull_request_commits` represent the relationship between a proposed change and its constituent commits.

The review model is deliberately separate from the Pull Request record. `reviews` stores reviewer identity, review state, the reviewed commit, and review text. `review_comments` stores file-level and line-level discussion and whether each discussion has been resolved.

`status_checks` models automated validation independently from human review. This prevents a passing human approval from being interpreted as equivalent to successful automated validation.

`branch_protection_policies` contains repository governance conditions such as required review count, stale-approval dismissal, required status checks, conversation resolution, direct-push restrictions, force-push restrictions, deletion restrictions, linear-history requirements, and administrator bypass policy.

`approval_requirements` allows a policy to require specific reviewer roles. This is different from merely counting approvals because a security-sensitive repository may require one security reviewer and one blockchain reviewer rather than any two arbitrary accounts.

The `merge_eligibility` view evaluates these independent conditions together. It considers the latest review from each reviewer, approval count, change requests, status-check results, and unresolved review comments.

## Approvals and stale decisions

An approval is a review decision associated with a particular state of a change. The commit associated with the review matters because a reviewer can approve one version of a change and then the author can push additional commits.

The SQL model stores the reviewed commit with each review. The latest-review query makes the review state explicit instead of treating an old approval as permanently valid.

A branch policy can require stale approvals to be dismissed when new changes arrive. This prevents an approval for an earlier changeset from automatically authorizing a materially different changeset.

Approval eligibility also depends on reviewer identity and role. An approval from an unauthorized contributor should not be equivalent to an approval from a designated security reviewer.

## Branch protection

Branch protection is a repository governance layer rather than an encryption primitive.

A protected branch can require:

- Successful automated status checks before merge.
- A minimum number of human approvals.
- Specific reviewer roles for sensitive areas.
- Resolution of review conversations.
- No direct pushes.
- No force-push operations.
- No branch deletion.
- Linear history where the project requires it.
- Explicit administrator bypass rules.

These controls reduce the probability that an otherwise valid Pull Request can bypass the repository's intended governance process.

The distinction from cryptography is important. DES cannot prevent an authorized maintainer from bypassing branch policy, and a branch-protection policy cannot encrypt transaction data. They protect different layers of the system.

## Pull Request, review, approval, and protection relationship

The four workflow concepts have different responsibilities.

A **Pull Request** provides the change-management boundary. It identifies a source branch, target branch, author, changeset, commits, lifecycle state, and merge operation.

**Code Review** evaluates the technical content of the proposed change. Reviewers inspect the changeset, leave inline comments, discuss design decisions, request changes, or approve the reviewed version.

An **Approval** is a specific review decision. It contributes to merge eligibility when the reviewer is eligible and the approval remains valid under the repository's policy.

**Branch Protection** establishes repository-level enforcement. It can require reviews and checks, prevent direct changes to important branches, and control whether exceptional bypasses are permitted.

The relationship can therefore be expressed as:

`Pull Request -> proposes change`

`Code Review -> evaluates change`

`Approval -> records review decision`

`Branch Protection -> enforces merge conditions`

`Cryptography -> protects selected data and authenticity properties`

`Blockchain consensus -> establishes distributed acceptance rules`

None of these layers should be collapsed into another.

## Failure modes

A blockchain record can fail integrity validation even when its DES ciphertext decrypts correctly. Decryption only shows that a key and ciphertext produced a syntactically valid plaintext. It does not prove that the record is the expected blockchain state.

A ciphertext can be confidential but unauthenticated. CBC encryption illustrates this distinction.

A block can have a valid local hash while still being unacceptable to a network because the transaction lacks a valid signature or the block violates consensus rules.

A Pull Request can have enough approvals but still be blocked by failing status checks or unresolved review discussions.

A reviewer can have approved an earlier commit while the current Pull Request contains additional changes. Treating the old approval as automatically valid can create a stale-approval failure.

A protected branch can prohibit direct pushes while still allowing an explicitly configured administrative bypass. Governance therefore depends on the actual policy configuration rather than the word "protected" alone.

## Security considerations

DES should be treated as legacy cryptography. Its 56-bit effective key makes exhaustive search feasible and prevents it from meeting modern confidentiality requirements.

DES-CBC also lacks built-in authentication. Combining encryption with a correctly implemented MAC can provide an authenticated construction, but new systems should generally use a standardized authenticated-encryption mode.

Keys should not be embedded in source code or stored in ordinary blockchain records. The examples use fixed educational keys only where required by known-answer tests. A production architecture should separate key generation, storage, rotation, access control, and cryptographic operations.

Blockchain data is frequently replicated. Encrypting a payload does not automatically make the data private because metadata such as transaction timing, participants, block size, frequency, and access patterns can remain visible.

Encryption also creates a key-management dependency. If a blockchain stores ciphertext permanently and the corresponding decryption key is destroyed, the encrypted historical data may become permanently inaccessible. Conversely, compromise of a long-lived key can expose historical records.

## Performance considerations

DES operates on small 64-bit blocks and requires sixteen Feistel rounds for each block. Pure-language implementations are primarily useful for education and protocol analysis rather than high-throughput production encryption.

The blockchain examples add hashing and proof-of-work operations. Increasing proof-of-work difficulty increases the expected number of hash attempts exponentially with the number of required leading zero bits.

Database indexes in the SQL implementation target common governance queries. Pull Requests are indexed by target branch and state, reviews by Pull Request and review state, status checks by Pull Request and state, and blockchain blocks by repository and block index.

A production blockchain database may require partitioning, append-only storage, replication, archival policies, and carefully designed indexes depending on transaction volume.

## Why DES should not secure a new blockchain

Using DES inside a blockchain does not make the blockchain secure.

The effective 56-bit key is too small for modern confidentiality requirements. DES also has a small 64-bit block size, which becomes increasingly problematic for large amounts of encrypted data.

A modern architecture should use authenticated encryption for confidential application data and use standardized cryptographic hashes and digital signatures for blockchain integrity and authorization.

The blockchain layer should define who can create transactions, how transactions are authenticated, how blocks are accepted, how conflicting histories are handled, and how validators reach agreement.

The cryptographic layer should define how confidential information is protected and how unauthorized modification is detected.

Keeping those responsibilities separate makes the security architecture easier to analyze, test, and audit.

## Practical architecture

A conceptual architecture for a system containing legacy DES data might look like:

`Client`

`  -> transaction validation`

`  -> authorization/signature verification`

`  -> encrypted payload service`

`  -> authenticated storage`

`  -> block construction`

`  -> hash calculation`

`  -> consensus validation`

`  -> replicated blockchain state`

The DES component belongs only where legacy interoperability requires it. It should not be allowed to define the integrity or consensus model of the blockchain.

For migration systems, a safer pattern is to decrypt legacy DES records under controlled conditions and re-encrypt them using an approved authenticated-encryption construction. The migration process itself should be auditable and should preserve the relationship between the original record, its migration event, and its replacement ciphertext.

## Testing strategy

The Python, C++, and Java implementations use the classic DES known-answer vector:

`Key: 133457799BBCDFF1`

`Plaintext: 0123456789ABCDEF`

`Expected ciphertext: 85E813540F0AB405`

A correct implementation should reproduce the expected ciphertext exactly.

Round-trip testing checks that encryption followed by decryption returns the original block.

Negative tests are equally important. Invalid key sizes, invalid padding, tampered ciphertext, invalid transaction states, broken block links, insufficient approvals, and failed status checks should be rejected.

Cryptographic testing should also include known-answer vectors, randomized round trips, boundary conditions, malformed input, key handling, and interoperability tests against independent implementations.

## Implementation boundary

The six artifacts deliberately use different technical perspectives.

The **Python program** exposes the DES internals and builds a complete educational encrypted blockchain simulation.

The **JavaScript program** emphasizes exact bit manipulation with `BigInt`, Node.js cryptographic primitives, HMAC verification, and event-driven ledger behavior.

The **C++ program** focuses on fixed-width representation, a coherent transaction and blockchain case study, explicit validation, proof-of-work, and implementation-level trade-offs.

The **Java program** focuses on enterprise domain modeling, immutable records, transaction states, validation services, policy evaluation, exception handling, and standard Java cryptographic facilities.

The **SQL script** focuses on relational enforcement, Pull Requests, commits, reviews, comments, status checks, approvals, branch-protection policy, merge eligibility, transactions, indexes, and blockchain block relationships.

These are complementary implementations rather than translations of the same program.

## Limitations

The DES implementation is intended for understanding the algorithm and legacy interoperability. It is not a recommendation to deploy DES.

The C++ digest helper intentionally does not claim to be SHA-256 because the C++17 standard library does not provide a cryptographic SHA-256 primitive.

The Java ledger's surrounding example is a domain model rather than a complete distributed blockchain network. A real network requires authenticated peers, transaction signatures, consensus, replay protection, persistent storage, network synchronization, and fault handling.

The SQL database models blockchain and repository governance relationships but does not itself implement distributed consensus.

A real blockchain should not treat a relational transaction as equivalent to network-wide finality.

## Key distinctions

| Mechanism | Primary responsibility | What it does not provide by itself |
|---|---|---|
| DES | Symmetric confidentiality | Modern key strength, authentication, blockchain consensus |
| DES-CBC | Block-mode confidentiality | Message authentication |
| HMAC | Shared-secret authentication and integrity | Public verification or consensus |
| SHA-256 | Cryptographic digest | Confidentiality |
| Digital signature | Publicly verifiable authorization | Confidentiality |
| Pull Request | Proposed repository change | Cryptographic confidentiality |
| Code Review | Human technical evaluation | Distributed consensus |
| Approval | Review decision | Automatic permission to bypass all policies |
| Branch Protection | Repository governance | Encryption |
| Proof-of-work | Computational consensus mechanism | Confidentiality |
| Database constraint | Local data integrity | Distributed agreement |

The security architecture becomes clearer when these responsibilities remain distinct.
