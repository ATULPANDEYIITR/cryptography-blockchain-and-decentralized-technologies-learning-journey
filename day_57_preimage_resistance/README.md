# Preimage Resistance

## Scope

This project models preimage resistance as a cryptographic property and connects it to practical integrity verification and repository-governance workflows.

The central distinction is:

`Given a target digest y, finding an input x such that H(x) = y should be computationally infeasible.`

The project does not treat hashing as encryption. A cryptographic hash is a one-way transformation intended to make verification efficient while making recovery of an unknown input computationally impractical under the relevant security assumptions.

The implementations use repository-development scenarios because they provide a concrete setting in which digest verification, trusted state, reviews, approvals, status checks, and merge decisions can be separated.

## Core Security Model

For a hash function:

`H : {0,1}* -> {0,1}^n`

first-preimage resistance concerns the problem of selecting an arbitrary target input `x`, computing `y = H(x)`, and then finding an `x'` such that:

`H(x') = y`

without already knowing `x`.

A generic brute-force strategy against an ideal `n`-bit hash has approximately `2^n` candidate evaluations in the worst-case scale and approximately `2^(n-1)` evaluations for an average exhaustive search.

The exact security interpretation depends on the hash construction, output size, attack model, candidate distribution, and whether the original input has a small or predictable domain.

## Distinct Hash Properties

| Property | Security question | Typical generic work |
|---|---|---:|
| First-preimage resistance | Can an attacker recover an input for a specified digest? | Approximately `2^n` |
| Second-preimage resistance | Given one input, can an attacker find a different input with the same digest? | Approximately `2^n` for an ideal `n`-bit construction |
| Collision resistance | Can an attacker find any two different inputs with the same digest? | Approximately `2^(n/2)` |
| Integrity verification | Does supplied content match a trusted expected digest? | One hash evaluation |

Collision resistance is therefore not interchangeable with preimage resistance. The birthday bound makes generic collision search substantially easier than generic first-preimage search for the same output length.

## Domain Separation

A protocol can hash the same byte sequence for multiple semantic purposes. Without explicit context, those uses may be unnecessarily difficult to distinguish.

The implementations therefore use constructions conceptually similar to:

`H(length(context) || context || message)`

or:

`H(context || separator || value)`

The context identifies the protocol role of the digest.

Examples include:

| Context | Meaning |
|---|---|
| `repository-artifact-v1` | Digest of repository artifact content |
| `commitment-v1` | Commitment to a value before later opening |
| `audit-record-v1` | Digest associated with audit evidence |

Domain separation does not increase the raw output length of a hash. Its purpose is protocol-level separation of semantic uses.

## Repository Integrity Model

The repository scenario separates cryptographic evidence from governance:

`Repository`
→ `Branch`
→ `Commit`
→ `Pull Request`
→ `Review`
→ `Approval`
→ `Status Checks`
→ `Branch Protection`
→ `Merge Eligibility`
→ `Merge`

The digest verifies content. It does not determine who is authorized to approve a change, whether a branch is protected, or whether a pull request may be merged.

A trusted expected digest is essential. If an attacker can freely replace both the content and the expected digest, digest comparison alone provides no authentication.

## Python Implementation

The Python file uses `hashlib` for SHA-256 and SHA-512 operations.

Its main mechanisms are:

- `HashAlgorithm` defines supported digest algorithms.
- `hash_bytes()` and `hash_hex()` provide typed digest operations.
- `truncated_digest()` creates a deliberately small experimental output space.
- `brute_force_preimage()` searches a bounded candidate space.
- `HashCommitment` creates and verifies domain-separated commitments.
- `ArtifactVerifier` associates repository metadata with a content digest.
- `hmac.compare_digest()` is used for digest comparison.
- `dataclass` records represent immutable commitment and artifact state.
- Validation exceptions reject invalid contexts, digest sizes, and repository metadata.

The brute-force experiment intentionally uses a truncated digest. Searching the full SHA-256 output space would not be a useful executable demonstration because exhaustive inversion is computationally infeasible.

The commitment example also demonstrates that a digest can later verify a supplied opening without storing the original value inside the commitment object.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library cryptography and event infrastructure.

`HashService` provides:

- SHA-256 and SHA-512 hashing
- constant-time digest comparison using `crypto.timingSafeEqual`
- domain-separated hashing
- bounded digest truncation for experimentation

`CommitmentService` models a commitment and later opening.

`RepositoryIntegrityService` extends `EventEmitter`. It emits events for:

- artifact registration
- successful verification
- verification failure

This creates an event-driven integrity workflow rather than translating the Python control flow directly.

`MergePolicy` consumes independent evidence:

- integrity verification
- approval count
- status-check state
- protected-branch state

It returns an explicit eligibility object containing both the decision and blocking reasons.

The bounded preimage experiment uses a small alphabet, maximum candidate length, and truncated digest. This makes the search executable while preserving the conceptual distinction between an intentionally small toy search space and full SHA-256 inversion.

## C++17 Implementation

The C++ program is structured as a repository-governance engine.

The primary domain types include:

| Type | Responsibility |
|---|---|
| `User` | Reviewer identity and activity |
| `Commit` | Repository content and its digest |
| `Review` | Review decision and stale status |
| `StatusCheck` | Automated validation result |
| `PullRequest` | Proposed repository change |
| `BranchProtection` | Repository-level merge rules |
| `Repository` | Aggregate repository state |

`MergeEligibilityEngine` evaluates the conditions required for a protected-branch merge.

The engine checks:

- pull request state
- source and target branch separation
- base-branch synchronization
- resolved conversations
- active reviewers
- non-stale approvals
- required status checks
- head-commit existence
- content-digest verification

The C++17 standard library does not provide a SHA-256 implementation. The source therefore contains a clearly bounded toy digest implementation to preserve standalone compilation without external libraries.

That digest is explicitly not cryptographically secure. It must not be used for authentication, passwords, signatures, or production integrity. A production C++ implementation should use a vetted cryptographic library.

## Java 17 Implementation

The Java implementation models the same security boundary through enterprise-oriented domain types rather than a procedural simulation.

Java records represent immutable value objects such as:

- `User`
- `ArtifactDigest`
- `Commit`
- `Review`
- `StatusCheck`
- `PullRequest`
- `ApprovalPolicy`
- `BranchProtection`
- `EligibilityResult`

`HashService` uses Java's standard `MessageDigest` implementation with SHA-256.

`ApprovalPolicy` explicitly determines whether approvals are:

- submitted by eligible reviewers
- from active users
- not stale
- distinct where required

`BranchProtection` contains repository-level controls such as:

- pull-request requirements
- direct-push restrictions
- force-push restrictions
- deletion restrictions
- conversation requirements
- linear-history requirements
- required status checks

`MergeEligibilityService` combines these independent policies into an explicit `EligibilityResult`.

The cryptographic verification remains separate from approval and branch-governance decisions. This prevents a successful digest comparison from being incorrectly interpreted as authorization to merge.

## PostgreSQL Implementation

The SQL implementation represents the model as relational data.

The principal relationships are:

`repository`
→ `branch`
→ `commit_record`

and:

`pull_request`
→ `review`
→ `review_comment`
→ `conversation`

with independent automation and governance tables:

`status_check`
`branch_protection_policy`
`approval_requirement`
`eligible_reviewer`
`required_status_check`
`integrity_verification`
`merge_record`

The schema uses:

- primary keys
- foreign keys
- unique constraints
- check constraints
- enumerated workflow states
- indexes on branch, pull-request, review, and status-check access paths
- views for approval and conversation state
- a digest verification function
- triggers for merge-state enforcement and reviewer activity
- transactional merge processing

The `pgcrypto` extension supplies PostgreSQL's `digest()` function for SHA-256 content verification.

The stored `content_sha256` value is checked against:

`encode(digest(content, 'sha256'), 'hex')`

This gives the database a concrete integrity check while preserving the trust-boundary distinction: a matching digest proves that the content matches the stored expected digest, not that the person who supplied the expected digest is authorized.

## Pull Request State

A pull request is the mechanism for proposing a set of changes from a source branch toward a target branch.

The model distinguishes:

- source branch
- target branch
- head commit
- target-base synchronization
- draft state
- open state
- closed state
- merged state

A draft pull request represents a proposal that is not yet ready for final integration.

Base synchronization matters because the target branch may advance after a pull request is opened. A merge policy can require the proposed change to be evaluated against current target-branch state before accepting it.

Merge conflicts are a branch-state problem. A digest does not resolve a conflict. A new commit that resolves the conflict must itself be subject to the applicable integrity, review, approval, and status requirements.

Reopening a closed pull request creates another workflow state transition. Its previous review evidence may require reevaluation depending on the repository's policy and whether the proposed commit changed.

## Code Review

Code review evaluates the proposed changes rather than merely recording that a review exists.

The model distinguishes:

- comments
- requested changes
- approvals
- dismissed reviews
- stale approvals
- review discussions
- resolved conversations

Inline review comments identify a particular location or conceptual change. Conversations group discussion around those comments.

A requested-change review is a substantive blocking signal under policies that require changes to be addressed before merge.

Review quality depends on scope and criteria. Typical repository criteria represented by the model include:

- correctness
- security implications
- compatibility
- test evidence
- integrity of the proposed artifact
- maintainability
- consistency with repository policy

A review comment does not automatically equal an approval. Conversely, an approval does not itself prove that automated checks passed.

## Approvals

An approval is a review decision with a specific merge-policy meaning.

The model evaluates approval eligibility using:

`reviewer identity`
+ `reviewer activity`
+ `review state`
+ `stale state`
+ `reviewer eligibility policy`

A valid approval is therefore not simply any row whose state is `approved`.

Stale approvals are important when the reviewed commit changes. A repository may require approvals to be refreshed because the code that was reviewed is no longer identical to the code proposed for merge.

Dismissed approvals are also excluded from the valid approval count.

The approval policy can require a number of distinct eligible reviewers. This prevents multiple review records from the same person from being treated as independent approvals.

## Branch Protection

Branch protection is repository-level enforcement.

Its responsibility is different from code review and approval.

The protected-branch policy can require:

| Control | Purpose |
|---|---|
| Pull request | Prevent direct integration without the review workflow |
| Required approvals | Require independent review decisions |
| Required status checks | Require automated validation |
| Resolved conversations | Require review discussions to be addressed |
| Direct-push restriction | Prevent ordinary direct updates to the protected branch |
| Force-push restriction | Preserve branch history |
| Deletion restriction | Prevent accidental removal |
| Linear history | Enforce a selected history shape |
| Administrator bypass policy | Define whether privileged bypass is permitted |

Branch protection does not make SHA-256 more resistant to preimage attacks. It uses cryptographic evidence as one input into a larger governance decision.

## Merge Eligibility

The project treats merge eligibility as a conjunction of independently evaluated conditions.

Conceptually:

`Merge Eligible = Open PR`
`AND Base Synchronized`
`AND Required Approvals`
`AND Required Checks Passing`
`AND Conversations Resolved`
`AND Integrity Valid`
`AND Branch Policy Satisfied`

A failure in one category does not become a failure in another category.

For example:

- a digest mismatch is an integrity failure
- an absent approval is an approval-policy failure
- a failing test is a status-check failure
- an unresolved review thread is a conversation-policy failure
- a direct push to a protected branch is a branch-governance failure

This separation makes the resulting decision explainable and auditable.

## Preimage Search Experiment

The Python and JavaScript implementations contain bounded brute-force demonstrations.

The experiment deliberately reduces the hash output space and candidate domain.

For example:

`H(x) truncated to 16 bits`

has only `2^16 = 65,536` possible outputs.

An exhaustive search is therefore practical on ordinary hardware.

This must not be interpreted as evidence that full SHA-256 can be inverted practically. A 256-bit output has a generic first-preimage work factor on the order of `2^256` evaluations for an idealized attack.

The experiment exists to expose the relationship between:

`digest size → candidate space → exhaustive search cost`

rather than to provide a practical attack against SHA-256.

## Integrity Versus Authentication

A digest provides an integrity comparison only when the expected digest is trusted.

Consider:

`content → H(content) → expected digest`

A verifier computes the digest of received content and compares it with the trusted expected value.

If an attacker can replace both:

`content`

and:

`expected digest`

the comparison can still succeed.

Authentication therefore requires another trust mechanism, such as:

- authenticated transport
- digital signatures
- a trusted key hierarchy
- an authenticated repository service
- another protected source of expected digest values

Preimage resistance alone does not provide identity or authorization.

## Security Considerations

### Hash selection

Production systems should use standardized cryptographic hash functions with appropriate security margins.

The main examples use SHA-256 because it provides a well-defined 256-bit digest and is available through standard cryptographic APIs in Python, Java, Node.js, and PostgreSQL through `pgcrypto`.

The C++ example uses a toy digest only because portable C++17 has no built-in SHA-256 implementation.

### Small input domains

Preimage resistance does not mean that every real-world secret is safe when hashed.

If the input has a small candidate domain, an attacker can enumerate likely values and compare their hashes.

Examples include:

- short PINs
- common passwords
- small identifiers
- predictable configuration values

For passwords, a dedicated password hashing or key-derivation scheme with a unique salt and appropriate work factor is required.

### Truncated digests

Truncating a cryptographic digest reduces the security level.

A digest with `n` effective bits has a generic first-preimage search scale related to `2^n`.

The examples therefore use truncated digests only for controlled experiments.

### Timing behavior

Digest comparisons should avoid unnecessary timing leakage. The Python and JavaScript implementations use constant-time comparison facilities where appropriate.

### Trusted digest storage

Storing an expected digest does not automatically establish trust. The storage mechanism and update process must themselves be protected.

## Failure Conditions

The implementations deliberately model invalid states.

Examples include:

- empty commitment contexts
- unsupported hash algorithms
- invalid digest lengths
- missing repository metadata
- unknown commits
- inactive reviewers
- stale approvals
- missing required status checks
- failing status checks
- unresolved conversations
- stale target branches
- invalid pull-request states
- digest mismatches
- merge attempts without required governance evidence

Failure reporting is kept separate from successful state transitions so that blocked operations retain useful diagnostic information.

## Performance Considerations

For an `n`-bit cryptographic digest, hashing one candidate is normally inexpensive compared with exhaustive inversion.

The practical difficulty of a generic preimage attack comes from the number of candidates that must be evaluated.

The repository workflow also benefits from targeted database indexes:

| Index | Purpose |
|---|---|
| `idx_commit_branch_created` | Recent commits by branch |
| `idx_pull_request_target_state` | Open or active pull requests for a target branch |
| `idx_pull_request_head` | Locate pull requests by head commit |
| `idx_review_pr_state` | Review-state aggregation |
| `idx_conversation_pr_state` | Unresolved conversation checks |
| `idx_status_check_pr_state` | Status evaluation |

The SQL design avoids adding indexes to every column. Indexes are applied where the merge-eligibility queries repeatedly filter or join.

## Educational Boundaries

The project deliberately distinguishes executable demonstrations from production cryptography.

| Implementation | Cryptographic mechanism | Production position |
|---|---|---|
| Python | `hashlib` SHA-256/SHA-512 | Suitable standard-library primitives |
| JavaScript | Node.js `crypto` | Suitable standard-library cryptographic API |
| C++17 | Explicit toy digest | Demonstration only |
| Java 17 | `MessageDigest` SHA-256 | Suitable standard-library primitive |
| PostgreSQL | `pgcrypto.digest()` | Database-side digest verification |

The C++ toy digest must never be substituted for a vetted cryptographic implementation.

## Practical Workflow

A repository integrity workflow can be represented as:

`1. Commit content`
`2. Compute trusted digest`
`3. Propose change through a pull request`
`4. Run automated status checks`
`5. Perform code review`
`6. Record eligible approvals`
`7. Resolve required conversations`
`8. Verify current commit integrity`
`9. Evaluate branch-protection policy`
`10. Determine merge eligibility`
`11. Record merge`

The cryptographic check is one component in this workflow. It does not replace review, approval, authorization, status validation, or branch governance.

## Limitations

The project does not attempt to implement a complete production Git service.

It does not provide:

- a real Git object database
- network authentication
- signed Git commits
- distributed consensus
- a production-grade C++ cryptographic library
- password authentication
- a complete repository hosting API
- a formal proof of a hash function's security

Its purpose is to provide executable models of preimage resistance and its relationship to integrity verification and repository governance.

## File Map

| File | Main responsibility |
|---|---|
| Python | Hashing, commitments, bounded preimage search, integrity verification, validation |
| JavaScript | Event-driven integrity verification, domain separation, merge policy evaluation |
| C++17 | Repository governance and merge-eligibility engine |
| Java 17 | Enterprise domain model, approval policy, branch protection, eligibility service |
| PostgreSQL | Relational persistence, integrity verification, policy queries, triggers, and transactional merge |
| README.md | Technical model, distinctions, implementation decisions, security boundaries, and limitations |

## Key Distinction

The four repository concepts remain separate:

`Pull Request`
provides the workflow for proposing changes.

`Code Review`
evaluates the proposed changes and records review discussions and decisions.

`Approvals`
represent review decisions that may satisfy explicit reviewer and approval requirements.

`Branch Protection`
enforces repository-level conditions before changes can be merged.

Preimage resistance is a separate cryptographic property used here to reason about the difficulty of recovering an input from a trusted digest.

The relationship is therefore:

`Preimage Resistance`
→ supports cryptographic integrity assumptions

`Integrity Verification`
→ provides evidence about the proposed artifact

`Pull Request`
→ provides the change-proposal workflow

`Code Review`
→ evaluates the proposed changes

`Approvals`
→ satisfy explicit human-review requirements

`Branch Protection`
→ enforces repository governance

`Merge Eligibility`
→ combines the independently required conditions
