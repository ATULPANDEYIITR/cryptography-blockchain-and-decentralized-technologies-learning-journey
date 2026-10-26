```markdown
# Collision Resistance in Cryptographic Hashing

## Scope

This project studies collision resistance as a cryptographic property and models how hash integrity interacts with repository-style workflows.

The central relationship is:

`Content → Cryptographic Hash → Digest Identity → Integrity Verification → Governance Decision`

Collision resistance is concerned specifically with the difficulty of finding two distinct inputs `x` and `y` such that:

`H(x) = H(y)` where `x != y`

This is different from:

- **Preimage resistance:** given `h`, finding an `x` such that `H(x) = h`.
- **Second-preimage resistance:** given a specific `x`, finding a different `y` such that `H(x) = H(y)`.
- **Collision resistance:** finding any two distinct inputs with the same digest.

For an ideal `n`-bit hash function, a generic collision search requires approximately `2^(n/2)` evaluations because of the birthday bound. A 256-bit hash therefore provides approximately 128 bits of generic collision security.

The implementations deliberately use small truncated digests for experiments. This makes collisions observable without pretending that a toy experiment represents an attack against a full cryptographic hash.

## Repository-Oriented Domain Model

The source files use a repository-development scenario to separate content integrity from repository governance.

```text
Repository
    |
    +-- Branches
    |      |
    |      +-- protected main
    |      +-- feature branch
    |
    +-- Commits
    |      |
    |      +-- commit identifier
    |      +-- content digest
    |
    +-- Pull Request
           |
           +-- source branch
           +-- target branch
           +-- head commit
           |
           +-- Reviews
           |      |
           |      +-- approval
           |      +-- requested changes
           |      +-- comments
           |
           +-- Status Checks
           |
           +-- Branch Protection
                  |
                  +-- required approvals
                  +-- passing checks
                  +-- resolved conversations
                  +-- merge eligibility
```

The repository workflow does not make collision resistance equivalent to code review or branch protection.

- A **Pull Request** proposes a particular changeset.
- **Code review** evaluates the proposed changes.
- An **approval** records a review decision.
- **Branch protection** enforces repository-level merge conditions.
- **Collision resistance** protects the cryptographic assumption used when content is represented by a digest.

A passing review does not prove that a hash function is collision resistant. A protected branch does not repair a weak hash function. Cryptographic integrity and repository governance solve different problems.

## Collision Resistance Mechanics

A cryptographic hash accepts arbitrary-length input and produces a fixed-size output.

For SHA-256:

`H : {0,1}* → {0,1}^256`

The fixed output creates an unavoidable mathematical fact: there are infinitely many possible inputs but only `2^256` possible outputs. Therefore collisions must exist.

Security comes from computational difficulty, not from the claim that collisions are mathematically impossible.

The birthday bound changes the effective generic collision search from approximately `2^256` attempts to approximately:

`2^128`

for a 256-bit ideal hash.

This distinction is important when evaluating digest sizes.

| Digest size | Generic collision work |
|---:|---:|
| 8 bits | approximately `2^4` |
| 16 bits | approximately `2^8` |
| 32 bits | approximately `2^16` |
| 128 bits | approximately `2^64` |
| 256 bits | approximately `2^128` |

The small values are useful for experiments because collisions can be found quickly. They are not appropriate security parameters.

## Python Implementation

The Python implementation models several layers of hashing behavior.

`CollisionResistanceModel` provides:

- SHA-256
- SHA3-256
- BLAKE2b with a 256-bit digest
- byte-oriented hashing
- UTF-8 text hashing
- file hashing
- digest verification

`HashResult` uses a dataclass to preserve the selected algorithm, resulting digest, and input length.

Digest verification uses constant-time comparison through `hmac.compare_digest`. This avoids an unnecessary timing distinction when comparing expected and computed digest values.

The `IntegrityRegistry` represents content-addressed storage. A digest is used as the lookup key, while the original content remains available for collision detection. If two different byte sequences somehow produce the same digest, the registry refuses to silently replace the previous record.

The demonstration also contains a deliberately truncated SHA-256 experiment. The experiment searches for two different random inputs with the same shortened digest and exposes the birthday-bound behavior.

File hashing is performed incrementally rather than loading the complete file into memory. This makes the implementation suitable for large files and gives a realistic integrity-verification workflow.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library cryptography and asynchronous file handling.

`crypto.createHash()` provides the digest operation, while `fs/promises` supports asynchronous file reads.

The implementation supports:

- SHA-256
- SHA3-256
- BLAKE2b
- text hashing
- file hashing
- digest verification
- deliberately truncated SHA-256 collision experiments
- content-addressed registration

`timingSafeEqual` is used for equal-length digest comparison.

The `ContentRegistry` stores `Buffer` objects rather than assuming that textual data is always UTF-8. This is important because cryptographic hashes operate on bytes. Different encodings can represent visually similar text using different byte sequences.

The collision experiment stores previously observed truncated digest values in a `Map`. This gives expected near-constant-time lookup for the demonstration and avoids an expensive pairwise comparison of every generated input.

## C++17 Implementation

The C++ program takes a different engineering approach.

`DemoHash` implements a deterministic FNV-1a hash and explicitly treats it as a demonstration mechanism rather than a cryptographic primitive. This avoids introducing a third-party cryptographic dependency while making the birthday-bound experiment executable with a standard C++17 environment.

The program uses:

- `enum class` for workflow states
- structures for commits and hash records
- `unordered_map` for digest-indexed storage
- `random_device` and `mt19937` for demonstration input generation
- exception handling for invalid configurations
- a governance-oriented merge-eligibility service

The important security boundary is explicit: the demonstration hash must not be used for signatures, authentication, secure identifiers, or integrity guarantees.

The `GovernanceEngine` shows why a repository system should retain the original content when validating an alleged digest collision. A digest match alone does not logically establish that two inputs are identical.

The merge-eligibility engine separately checks repository policy such as required review and passing automated checks. This prevents repository governance from being incorrectly presented as a property of the hash function.

## Java 17 Implementation

The Java implementation uses an enterprise-oriented domain model.

The principal domain types are:

- `Commit`
- `Review`
- `StatusCheck`
- `BranchPolicy`
- `PullRequest`
- `RepositoryGovernanceService`

Java records are used for immutable value-oriented objects. Enums make workflow states explicit rather than representing them as arbitrary strings.

`HashService` uses Java's `MessageDigest` API and supports:

- SHA-256
- SHA-512
- SHA3-256

Digest comparison uses `MessageDigest.isEqual`.

The `PullRequest` object explicitly controls state transitions:

`OPEN → CLOSED`

`CLOSED → OPEN`

`OPEN → MERGED`

Invalid transitions raise exceptions.

Reviews and status checks are stored as separate domain concepts. An approval is therefore not confused with a successful test, and a successful test is not confused with repository authorization.

`RepositoryGovernanceService` evaluates:

- target branch protection
- Pull Request state
- known head commit
- requested changes
- approval count
- passing status checks

The Java implementation therefore provides a clear separation between cryptographic integrity and enterprise workflow policy.

## PostgreSQL Implementation

The PostgreSQL script models the complete relational workflow.

The core relationships are:

`repositories → branches → commits`

`branches → pull_requests`

`pull_requests → reviews`

`reviews → review_comments`

`pull_requests → status_checks`

`branches → branch_protection_policies`

`branch_protection_policies → approval_requirements`

The `commits` table stores both a commit SHA and a content digest. A unique constraint on `(repository_id, content_digest)` prevents multiple rows from silently claiming the same content digest within one repository.

This is a database integrity rule rather than a proof of cryptographic collision resistance. A database constraint cannot make a weak hash function cryptographically secure.

### Database-Level Controls

The schema uses:

- primary keys
- foreign keys
- unique constraints
- check constraints
- targeted indexes
- SQL functions
- PL/pgSQL functions
- triggers
- transactional updates

The protected-branch trigger rejects direct changes to the head commit of a protected branch.

The stale-approval trigger dismisses approvals when the Pull Request head changes. This models an important workflow distinction: an approval applies to a particular reviewed state, not automatically to every future changeset.

### Merge Eligibility

`merge_eligibility()` evaluates repository-level conditions.

It checks:

1. Whether the Pull Request exists.
2. Whether the Pull Request remains open.
3. Whether a protection policy exists.
4. Whether the required number of active approvals exists for the current head commit.
5. Whether required status checks are passing.
6. Whether required review conversations are resolved.

The function returns both the boolean decision and the individual policy dimensions that produced it.

This makes failure diagnosis explicit instead of returning only an unexplained `false`.

## Review and Approval Semantics

Code review and collision resistance occupy different layers.

A review asks whether a proposed implementation is technically acceptable.

An approval records a reviewer decision about that implementation.

A cryptographic digest provides a compact representation of content.

These mechanisms interact when repository systems associate reviews with a specific commit or changeset.

For example:

```text
Commit A
   |
   +-- digest D1
   |
   +-- reviewer approves A
   |
   +-- developer pushes Commit B
          |
          +-- digest D2
          |
          +-- previous approval may become stale
```

If the head commit changes, the earlier approval may no longer describe the exact content currently proposed for merge.

The PostgreSQL trigger models this behavior by dismissing approvals tied to an older head commit.

## Branch Protection

Branch protection is a repository governance mechanism.

Typical controls include:

| Control | Purpose |
|---|---|
| Required approvals | Requires human review before merging |
| Required status checks | Requires automated validation |
| Resolved conversations | Prevents unresolved review discussions from remaining |
| Linear history | Restricts accepted merge history |
| Direct-push restriction | Requires changes to pass through the governed workflow |
| Force-push restriction | Prevents destructive history rewriting |
| Administrator bypass | Defines whether administrators can override normal policy |

These rules do not strengthen the cryptographic hash.

A branch can be perfectly protected while storing content addressed with an unsuitable hash function. Conversely, a strong hash does not prevent an unauthorized person from pushing code to an unprotected branch.

## Birthday-Bound Experiments

The demonstrations intentionally reduce digest size.

For a digest with `n` bits, after approximately `2^(n/2)` random samples, a collision becomes likely.

For example, an 8-bit digest has only 256 possible values. A collision can therefore be expected after roughly 16 random samples.

A 16-bit digest has 65,536 possible values, giving an expected collision scale near 256 samples.

The experiments demonstrate the mathematics without requiring a practical attack against a modern full-size cryptographic hash.

The experiment should not be interpreted as evidence that SHA-256 collisions are easy to find.

## Edge Cases

The implementations explicitly handle several failure conditions.

### Empty Input

Cryptographic hashes normally accept empty input. The implementations therefore do not reject an empty byte sequence merely because it has zero length.

### Modified Content

A single input modification produces a different digest with overwhelming probability for a secure cryptographic hash.

### Duplicate Content

Identical byte sequences produce identical deterministic hashes under the same algorithm.

### Digest Algorithm Changes

A digest is meaningful only together with its algorithm. SHA-256 and SHA3-256 should not be treated as interchangeable identifiers merely because both produce 256-bit outputs.

### Truncated Digests

Shortened digests have dramatically weaker collision resistance.

A system should not use an experimentally convenient short digest as a security identifier.

### Stale Review

An approval associated with an older commit should not automatically authorize a newer head commit.

### Failed Status Check

A Pull Request can have sufficient approvals and still be ineligible for merge when required automated checks fail.

### Unresolved Conversation

A repository can require all review discussions to be resolved before merge even when approvals and status checks are satisfied.

## Performance Considerations

Cryptographic hashing is generally linear in the number of input bytes:

`O(n)`

where `n` is the input size.

The Python file hashing implementation processes data in chunks, limiting memory consumption.

The JavaScript file implementation reads the file through Node.js asynchronous file APIs, keeping the file operation outside synchronous application control flow.

The C++ and Java demonstrations use in-memory values because their main purpose is domain modeling rather than high-volume file processing.

The collision experiments use a hash table for previously observed truncated digests. Expected lookup cost is approximately `O(1)` per generated candidate, making the experiment substantially more efficient than comparing every new candidate against every previous candidate.

## Security Considerations

A secure repository-integrity design should use a modern, well-studied cryptographic hash with a sufficient output size.

Important controls include:

- use an approved cryptographic hash rather than a general-purpose checksum
- preserve the algorithm identifier with the digest
- avoid insecure digest truncation
- use authenticated mechanisms when authenticity is required
- separate integrity from authorization
- bind approvals to the reviewed changeset
- invalidate stale approvals when required
- enforce repository policy at the server side
- avoid treating a digest as proof of authorship
- avoid treating a hash collision as equivalent to an authorization bypass

Collision resistance alone does not provide authentication.

If an attacker can replace both a file and its published digest, ordinary hashing does not establish which version is trustworthy. Authenticity requires an authenticated distribution channel, digital signature, trusted repository control, or another appropriate trust mechanism.

## Practical Failure Model

A useful repository integrity model is:

```text
                Proposed Content
                       |
                       v
                Cryptographic Hash
                       |
             +---------+---------+
             |                   |
          Digest             Changeset
             |                   |
             v                   v
       Integrity Check      Code Review
                                 |
                                 v
                             Approval
                                 |
                                 v
                         Status Checks
                                 |
                                 v
                       Branch Protection
                                 |
                                 v
                         Merge Eligibility
                                 |
                         +-------+-------+
                         |               |
                       Reject           Merge
```

Each stage answers a different question.

| Layer | Question |
|---|---|
| Hash | Does this content map to the expected digest? |
| Changeset | What exact content is proposed? |
| Review | Is the proposed change acceptable? |
| Approval | Has an eligible reviewer authorized it under policy? |
| Status checks | Did automated validation succeed? |
| Branch protection | Are repository-level merge conditions satisfied? |
| Merge eligibility | May this changeset enter the protected branch? |

This separation prevents a common architectural error: treating a cryptographic digest, a review decision, and repository authorization as if they were interchangeable security controls.

## Implemented Learning Artifacts

| File | Primary role | Main mechanisms |
|---|---|---|
| Python | Hashing and integrity simulation | `hashlib`, dataclasses, file hashing, registry, collision experiment |
| JavaScript | Event-oriented policy and content model | Node `crypto`, asynchronous file handling, `Map`, `Buffer`, timing-safe comparison |
| C++17 | Governance and merge engine | STL containers, explicit states, collision experiment, policy evaluation |
| Java 17 | Enterprise domain model | records, enums, services, state transitions, `MessageDigest`, validation |
| PostgreSQL | Persistent repository governance model | relational constraints, triggers, functions, policy evaluation, transactions |

## Key Distinctions

The implementation keeps four concepts separate.

**Cryptographic collision resistance** is a property of a hash construction and its effective security level.

**Pull Requests** provide a structured mechanism for proposing a changeset against a target branch.

**Code review** evaluates the technical content of that changeset.

**Approvals** record review decisions subject to eligibility and repository policy.

**Branch protection** enforces repository-level conditions before the proposed changeset can be merged.

The relationship is therefore:

`Pull Request → Code Review → Approval → Branch Protection → Merge Eligibility`

while cryptographic integrity runs alongside the workflow:

`Content → Hash → Digest Verification`

The two paths interact through the identity of the exact changeset being reviewed and merged, but they should not be treated as one security mechanism.
```
