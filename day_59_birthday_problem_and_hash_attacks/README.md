# Birthday Problem and Hash Attacks

## Scope

This artifact studies the birthday problem as a probability model and connects it to generic collision attacks against cryptographic hash functions.

The four central ideas are kept distinct:

- The **birthday problem** describes how quickly duplicate outcomes become likely when samples are drawn from a finite space.
- A **hash collision** occurs when two different inputs produce the same digest.
- A **birthday attack** exploits the approximately square-root relationship between digest-space size and generic collision-search effort.
- A **hash security policy** converts digest length and collision resistance into engineering decisions.

The implementations deliberately use small hash spaces for demonstrations. They do not attempt to break full-strength cryptographic hashes.

## Core Relationship

For a uniform hash function with `N` possible outputs and `k` independently selected inputs, the probability of at least one collision is:

`P(collision) = 1 - product((N-i)/N)` for `i = 0 ... k-1`

For practical estimation, the expression is commonly approximated by:

`P(collision) ≈ 1 - exp(-k(k-1)/(2N))`

The important scaling rule is:

`k ≈ sqrt(N)`

For a `b`-bit hash, `N = 2^b`, so generic collision resistance is approximately:

`2^(b/2)`

This means a 256-bit hash has approximately 128 bits of generic collision security, not 256 bits.

## Birthday Problem

A familiar finite-space example is a set of calendar birthdays. There are 365 possible outcomes when leap years are ignored.

With 23 people, the probability of at least one shared birthday is already close to one half.

The important lesson is not the particular calendar example. The lesson is the square-root behavior of collisions in a finite space.

The Python implementation computes the probability using a product represented in logarithmic form. This avoids unnecessary numerical loss when the collision probability is very small.

The C++ implementation provides the same mathematical model using `long double`, while the JavaScript and Java implementations use logarithmic probability calculations supported by their standard numerical libraries.

## Hash Collision Attacks

A cryptographic hash maps an arbitrary input to a fixed-size output.

Conceptually:

`message -> hash function -> digest`

Because the input domain is much larger than the digest domain, different inputs must eventually share a digest. A secure cryptographic hash does not attempt to make collisions mathematically impossible. It attempts to make useful collisions computationally infeasible to find.

For a `b`-bit digest:

| Digest size | Generic collision work |
|---:|---:|
| 64 bits | approximately `2^32` |
| 128 bits | approximately `2^64` |
| 160 bits | approximately `2^80` |
| 256 bits | approximately `2^128` |

These values describe generic birthday-style collision resistance. They are not guarantees about every possible attack against a particular hash construction.

## Controlled Collision Demonstration

The source files deliberately truncate SHA-256 to 16 bits for collision demonstrations.

A 16-bit output contains only:

`2^16 = 65,536`

possible values.

A birthday collision therefore becomes likely after a number of attempts on the order of:

`sqrt(65,536) = 256`

The demonstration stores previously observed digest prefixes in a map and stops when two distinct inputs produce the same truncated value.

This is intentionally different from attacking SHA-256 itself. The full SHA-256 digest is not being treated as practically breakable. The experiment exposes the mathematical relationship by reducing the output space.

The same approach is implemented in Python, JavaScript, and Java using secure random input generation and SHA-256 from their standard libraries.

## Python Implementation

The Python program models the problem as a reusable security-analysis component.

### Probability model

`birthday_collision_probability()` calculates the exact finite-space probability for a manageable sample count. The calculation uses logarithms and `expm1`-style behavior to retain precision for small probabilities.

`approximate_collision_probability()` implements the standard birthday approximation.

`samples_for_probability()` performs binary search to find the smallest sample count that reaches a requested collision probability.

### Hash demonstration

`truncated_sha256()` computes SHA-256 and deliberately retains only a configurable prefix.

`find_truncated_hash_collision()` uses a dictionary as the collision table. The first input associated with each digest prefix is retained. A second distinct input with the same prefix establishes the collision.

### Policy model

`HashPolicy` represents a digest-security policy. It derives approximate collision-security strength from digest length and classifies the resulting risk.

The program also performs assertions covering:

- one-sample collision probability
- a sample count exceeding the entire outcome space
- the 365-outcome birthday threshold
- 256-bit collision-security expectations
- deterministic hashing behavior

The implementation uses only the Python standard library.

## JavaScript Implementation

The JavaScript implementation emphasizes event-driven state management.

### Collision calculations

The probability functions use JavaScript's `Math.log1p()` and `Math.expm1()` to avoid avoidable precision problems in expressions involving values close to zero.

The controlled hash demonstration uses Node.js `crypto` and `Buffer` rather than third-party packages.

### Event-driven workflow

`GovernanceEngine` extends `EventEmitter`.

Its state contains:

- draft/open status
- reviewer decisions
- automated checks
- conversation status
- merge state

Important events include:

- `pull-request-published`
- `review-recorded`
- `status-updated`
- `merged`

This provides a separate engineering perspective on how security-policy state can change as independent events arrive.

### Validation

The engine rejects:

- invalid review states
- invalid check states
- attempts to merge before requirements are met
- attempts to republish an already merged change

The implementation uses `Map` for reviewer and check state, providing expected constant-time lookup for individual entries.

## C++17 Implementation

The C++ program models repository governance as a merge-eligibility engine.

The domain contains:

- `PullRequest`
- `Review`
- `StatusCheck`
- `BranchProtection`
- `MergeEligibilityEngine`

The engine evaluates several independent conditions:

1. The Pull Request cannot remain a draft.
2. A source and target branch must exist and differ.
3. At least one commit must exist.
4. The source branch must be synchronized.
5. A merge conflict must not exist.
6. The required number of distinct approved reviewers must be present.
7. All required status checks must pass.
8. Required review conversations must be resolved.

The review calculation uses a hash-based container to deduplicate reviewers before counting approvals.

### Failure-state demonstration

The program evaluates the same Pull Request several times while changing its state:

- valid and mergeable
- changes requested
- security check failure
- unresolved conversation
- merge conflict
- conflict resolved

This demonstrates that merge eligibility is a current-state decision rather than a permanent property of a Pull Request.

The program uses only the C++17 standard library.

## Java 17 Implementation

The Java implementation uses explicit enterprise-style domain modeling.

Important types include:

- `PullRequestState`
- `ReviewState`
- `CheckState`
- `RiskLevel`
- `Review`
- `StatusCheck`
- `BranchPolicy`
- `PullRequest`
- `MergeEligibilityService`
- `HashSecurityService`

Java records are used for immutable value objects such as reviews and status checks.

The Pull Request itself is mutable because its lifecycle requires explicit state transitions.

The workflow moves through states such as:

`DRAFT -> OPEN -> BLOCKED -> ELIGIBLE -> MERGED`

A Pull Request can become blocked again when a relevant repository condition changes.

### Review semantics

The service stores the latest review state for each reviewer in a `Map`.

This prevents a reviewer who previously approved a change and later requested changes from being counted as an active approval.

The service also rejects the merge when a current review requests changes.

### Branch policy

`BranchPolicy` separates repository-level governance from individual review decisions.

It can require:

- a minimum approval count
- successful status checks
- resolved conversations
- linear history
- restrictions on direct pushes
- restrictions on force pushes

The implementation does not assume that an approval alone makes a Pull Request mergeable.

## PostgreSQL Implementation

The PostgreSQL model represents the domain relationally.

The major relationships are:

`Repository -> Branch -> Commit`

`Repository -> Pull Request -> Review`

`Review -> Review Comment`

`Pull Request -> Status Check`

`Branch -> Branch Protection Policy`

`Branch Protection Policy -> Approval Requirement`

`Pull Request -> Merge Eligibility`

### Repository and branch state

The `repositories` table stores repository identity and visibility.

The `branches` table associates branches with repositories and records whether they are protected.

The branch protection table contains repository-level enforcement such as:

- required reviews
- required status checks
- required resolved conversations
- direct-push restrictions
- force-push restrictions
- deletion restrictions
- linear-history requirements
- administrator bypass policy

These are deliberately separated from Pull Request review records.

### Pull Requests

`pull_requests` records:

- source branch
- target branch
- author
- current state
- source head
- target head
- synchronization state
- merge-conflict state
- merge strategy
- merge timestamp

`pull_request_commits` provides the many-to-many relationship between Pull Requests and commits while preserving commit order.

### Reviews and comments

`reviewers` records assigned reviewers.

`reviews` records actual review decisions.

A trigger prevents an unassigned user from submitting a review.

`review_comments` stores inline discussion records and their resolution state.

The model distinguishes an approval decision from a discussion comment. Resolving a comment does not itself create an approval.

### Status checks

`status_checks` records named automated checks against a particular source commit.

The merge-eligibility function treats failed and pending checks differently from successful checks.

A required check that has not executed is not treated as successful.

### Merge eligibility

`evaluate_merge_eligibility()` evaluates the current repository state.

The function checks:

- Pull Request lifecycle state
- branch synchronization
- merge conflicts
- latest reviewer decisions
- approval count
- requested changes
- unresolved conversations
- failed checks
- pending checks
- absence of required checks

Latest reviewer decisions are selected with PostgreSQL's `DISTINCT ON` feature.

This is important because approval state can become stale when the source branch changes or when a reviewer submits a new review.

### Transactional merge

The final SQL section starts a transaction, locks the selected Pull Request, evaluates its current eligibility, records the decision, and performs the merge only if the decision is `ELIGIBLE`.

This prevents a simple read-then-write workflow from treating an outdated eligibility result as authoritative.

## Distinguishing the Security Concepts

The birthday problem and a hash attack are related but not identical.

| Concept | Meaning | Engineering implication |
|---|---|---|
| Birthday problem | Probability of duplicate outcomes in a finite space | Explains why collisions appear earlier than a linear search intuition suggests |
| Hash collision | Two distinct inputs share a digest | Fundamental property of finite-output hash functions |
| Birthday attack | Generic strategy for finding a collision | Reduces expected collision-search work to roughly the square root of the output space |
| Truncated hash | Hash output deliberately reduced in size | Reduces collision security |
| Preimage attack | Finding an input for a specified digest | Different security property from collision resistance |
| Second-preimage attack | Finding another input matching a specified existing input's digest | Different from finding any arbitrary collision |

Collision resistance must not be confused with preimage resistance.

A 256-bit hash has approximately 128 bits of generic collision security, while its generic preimage security is associated with a substantially larger search space.

## Edge Cases

The implementations account for several important boundary conditions.

### One sample

With only one sample, a collision is impossible.

The collision probability is exactly zero.

### More samples than outcomes

If more distinct samples are selected than there are possible outputs, a collision is guaranteed.

For a space of size `N`, more than `N` samples necessarily produce a collision.

### Very small hash spaces

Small digests are useful for teaching and testing because collisions can be observed directly.

They are not appropriate substitutes for production cryptographic hashes.

### Repeated identical inputs

A repeated identical input is not a cryptographic collision in the usual sense. A collision requires distinct inputs with the same digest.

The collision demonstrations explicitly check that the second input differs from the first.

### Stale security decisions

A previously successful state can become invalid when:

- the source branch changes
- a status check fails
- a review changes from approval to requested changes
- a conversation becomes unresolved
- a merge conflict appears

The governance implementations therefore recalculate eligibility.

## Performance Considerations

The direct probability calculation iterates over the number of samples.

For a very large sample count, the exact product is not the right operational approach. The exponential birthday approximation provides a constant-time mathematical estimate:

`1 - exp(-k(k-1)/(2N))`

Collision demonstrations require memory proportional to the number of generated candidates because observed digest values must be retained.

For a `b`-bit output, a generic birthday search has expected work on the order of `2^(b/2)` and comparable storage if all observed outputs are retained.

The PostgreSQL model uses indexes on:

- Pull Requests by repository and state
- Reviews by Pull Request, reviewer, and submission time
- Status checks by Pull Request and state
- Review comments by review and state

These indexes support the primary workflow queries without indexing every column indiscriminately.

## Security Considerations

A cryptographic hash should be selected according to the security property required by the application.

Important controls include:

- Use modern collision-resistant hash functions.
- Do not assume digest length equals collision-security strength.
- Account for the birthday bound when selecting digest sizes.
- Avoid unnecessary digest truncation.
- Authenticate security-sensitive data when attackers can modify inputs.
- Treat hash collisions separately from password security.
- Do not use ordinary fast cryptographic hashes as password-storage algorithms.
- Re-evaluate security decisions when the underlying data changes.
- Protect audit records from unauthorized modification.
- Validate algorithm parameters rather than accepting arbitrary digest sizes.
- Do not interpret a successful demonstration against a deliberately tiny digest as an attack against a full-size production hash.

## Practical Failure Model

A collision-sensitive application should distinguish at least these conditions:

`VALID INPUT`
→ hash computation succeeds
→ digest stored or compared

`DUPLICATE DIGEST`
→ determine whether inputs are identical
→ if inputs differ, treat as a collision event

`SECURITY POLICY FAILURE`
→ digest configuration is below the required collision-security threshold
→ reject or escalate the configuration

`STATE CHANGE`
→ previously calculated security or workflow decision becomes stale
→ recompute the decision

This distinction prevents a mathematical collision event from being confused with an ordinary duplicate record.

## Implementation Comparison

| Implementation | Primary perspective | Important mechanism |
|---|---|---|
| Python | Mathematical model and simulation | Dataclasses, dictionaries, exact probability calculations, controlled collision search |
| JavaScript | Event-driven policy model | `EventEmitter`, `Map`, asynchronous event processing, Node.js crypto |
| C++17 | Governance and merge engine | STL containers, explicit evaluation engine, value-oriented domain structures |
| Java 17 | Enterprise domain model | Records, enums, immutable collections, service layer, explicit state transitions |
| PostgreSQL | Persistent relational workflow | Constraints, triggers, CTEs, functions, indexes, transaction-controlled merge |

The implementations are intentionally complementary rather than line-for-line translations.

The Python implementation emphasizes probability and simulation.

The JavaScript implementation emphasizes event-driven state.

The C++ implementation emphasizes deterministic policy evaluation.

The Java implementation emphasizes explicit enterprise domain types and state transitions.

The PostgreSQL implementation makes repository governance and merge eligibility persistent, queryable, and transactionally enforceable.

## Limitations

The probability models assume uniformly distributed outcomes.

Real cryptographic hash functions are designed to approximate the properties needed for security, but a theoretical birthday calculation does not prove that a particular algorithm has no structural weakness.

The collision demonstrations use truncated SHA-256 because full SHA-256 collision searches are intentionally impractical at normal security levels.

The repository governance models are educational domain simulations. Real source-control platforms contain additional concerns such as authentication, authorization, signed commits, merge queues, deployment environments, repository rules, audit logs, and distributed event consistency.

The PostgreSQL model records branch and commit metadata but does not implement a complete Git commit-graph parser. Linear-history enforcement is therefore represented as a policy condition rather than as a full graph-theoretic verification engine.

## Key Technical Distinctions

The complete workflow can be represented as:

`Finite output space`
        |
        v
`Birthday probability`
        |
        v
`Collision becomes likely near sqrt(N)`
        |
        v
`Generic collision attack`
        |
        v
`Digest-size security requirement`
        |
        v
`Hash policy validation`

For repository-oriented security workflows, the corresponding state model is:

`Repository`
        |
        v
`Branches`
        |
        v
`Commits`
        |
        v
`Pull Request`
        |
        +----> `Reviews`
        |
        +----> `Review Comments`
        |
        +----> `Status Checks`
        |
        v
`Branch Protection`
        |
        v
`Merge Eligibility`
        |
        v
`Merge`

The two models meet at the security-policy layer: cryptographic assumptions determine whether a hash-based integrity mechanism provides an acceptable security margin, while repository governance determines whether a proposed change is permitted to become part of protected history.
