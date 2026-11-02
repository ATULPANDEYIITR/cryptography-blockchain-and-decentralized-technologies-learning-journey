# Key Derivation in Blockchain and Cryptography

## Scope

This project models key derivation as a cryptographic engineering problem and connects it to blockchain wallet structures and repository governance.

The five implementations use the same domain at different engineering layers:

| File | Primary perspective | Main implementation |
|---|---|---|
| Python | Cryptographic workflow simulation | PBKDF2, scrypt, HKDF, hierarchical derivation |
| JavaScript | Event-driven processing | Node.js KDF APIs, asynchronous PBKDF2, workflow events |
| C++17 | Low-level cryptographic engine | SHA-256, HMAC, PBKDF2, HKDF, governance evaluation |
| Java 17 | Enterprise domain model | KDF interfaces, records, policies, state transitions |
| PostgreSQL | Persistent security and governance model | Relational KDF metadata, wallet paths, reviews, policies, eligibility |

The implementations intentionally do not claim compatibility with a particular production wallet protocol when they use custom hierarchical derivation. The HD-style examples demonstrate derivation structure, domain separation, chain-code handling, and deterministic paths without presenting a custom construction as BIP-32.

## Key-Derivation Model

A key derivation function converts secret material into cryptographically independent key material under defined parameters.

The project separates three important cases:

1. Password-based derivation
2. Expansion of existing high-entropy key material
3. Hierarchical derivation of related blockchain keys

### Password-Based Derivation

PBKDF2-HMAC-SHA256 is used where a human-entered secret must be transformed into key material.

The Python, JavaScript, C++, Java, and PostgreSQL implementations validate a minimum salt size and use a substantial PBKDF2 iteration count.

A password and salt therefore have the conceptual relationship:

`password + salt + work factor -> derived key`

The salt is not required to be secret. Its purpose is to prevent identical password inputs from producing identical derived values across independent records.

PBKDF2 increases computational cost through repeated HMAC operations. It is not memory-hard, so a production password-storage design may prefer a memory-hard construction such as Argon2id where the platform supports it.

### scrypt

The Python implementation uses the standard-library `hashlib.scrypt` implementation.

The JavaScript implementation uses Node.js `crypto.scryptSync`.

The examples configure scrypt with `N = 2^14`, `r = 8`, and `p = 1`. These values are demonstration parameters rather than a universal production configuration. Real deployments should select parameters according to hardware, latency targets, threat model, and current security requirements.

scrypt differs from PBKDF2 by deliberately increasing memory requirements as part of its cost model.

### HKDF

HKDF is used when the input is already suitable as cryptographic key material.

The two conceptual phases are:

`IKM -> Extract -> PRK -> Expand(info) -> subkey`

The `info` value provides domain separation.

The implementations use distinct labels such as:

- `blockchain/signing-key/v1`
- `blockchain/storage-key/v1`
- `blockchain/account`
- `blockchain/demo`

A signing key and an encryption key should not be created by simply taking adjacent bytes from one generic key. Independent derivation contexts make the intended cryptographic purpose explicit.

## Hierarchical Blockchain Derivation

The Python, JavaScript, C++, and Java implementations construct an educational hierarchical key tree.

The conceptual structure is:

`Seed`
`  -> Root key + chain code`
`      -> Account node`
`          -> External chain`
`              -> Address node`
`                  -> Purpose-specific subkeys`

A derivation path such as `m/44'/0'/0'/0/0` identifies a deterministic location in the tree.

The apostrophe marks a hardened-style index in these educational implementations.

Each child derivation incorporates:

- parent key material
- parent chain code
- derivation index
- derivation depth
- a domain label

The resulting child key and child chain code are independent values derived with HMAC-SHA256.

The custom tree is deliberately not a BIP-32 implementation. A real Bitcoin-compatible wallet must follow the exact standardized key serialization, elliptic-curve operations, child-key rules, hardened and non-hardened semantics, and extended-key formats required by its protocol.

## Domain Separation

Domain separation prevents the same secret input from being interpreted as unrelated cryptographic material.

The project uses explicit context labels before producing purpose-specific values.

For example:

`address key + chain code + signing context -> signing key`

and:

`address key + chain code + storage context -> encryption key`

Changing the context changes the resulting output while retaining deterministic derivation.

This is especially important when one root secret supports several cryptographic purposes.

## Secret Handling

The source implementations intentionally separate secret material from audit information.

The following values must not be placed in application logs, source repositories, issue descriptions, Pull Requests, or ordinary database tables:

- mnemonic phrases
- passwords
- private keys
- wallet seeds
- raw derived signing keys
- raw encryption keys
- unprotected chain secrets

The examples print fingerprints instead of raw wallet-derived key material in their higher-level demonstrations.

A fingerprint is not a replacement for secure storage. It is only a compact identifier that allows a system to refer to key material without displaying the key itself.

## Python Implementation

The Python file uses standard-library cryptographic primitives.

### PBKDF2

`hashlib.pbkdf2_hmac` provides the password-based derivation mechanism.

Input validation rejects:

- empty passwords
- short salts
- insufficient iteration counts
- invalid output sizes

### scrypt

`hashlib.scrypt` provides a memory-hard KDF without an external package.

The implementation validates the required power-of-two property of `N`.

### HKDF

HKDF is implemented using HMAC-SHA256 so that the extract and expand stages remain visible.

The expansion loop follows the RFC 5869 construction:

`T(1) = HMAC(PRK, T(0) || info || 0x01)`

and subsequent blocks append the previous block before the context and counter.

### HDKeyTree

`HDKeyTree` provides:

- root generation
- child derivation
- derivation-path parsing
- depth limits
- hardened-style index encoding
- chain-code derivation

The code also includes validation and audit-file handling. The audit file contains only non-secret metadata and is deleted after verification.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library cryptography.

`crypto.pbkdf2` is used asynchronously so that password derivation does not require a synchronous CPU-bound call on the main event loop.

`scryptSync` is used for a compact demonstration of memory-hard derivation. A production server handling concurrent requests should carefully evaluate synchronous versus asynchronous execution because expensive synchronous KDF calls can block the event loop.

The `DerivationWorkflow` class uses `EventEmitter` to expose workflow state:

`started -> completed`

or:

`started -> failed`

The events make cryptographic processing observable without exposing the secret values themselves.

The JavaScript implementation also uses `fs/promises` for a restricted audit file. The file records only operational metadata.

## C++17 Implementation

The C++ implementation takes a lower-level engineering perspective.

It implements:

- SHA-256
- HMAC-SHA256
- PBKDF2-HMAC-SHA256
- HKDF-SHA256
- hierarchical derivation
- repository governance evaluation

The SHA-256 implementation contains the message padding, schedule expansion, compression function, and final digest construction.

The HMAC implementation follows the standard block construction:

`H((K xor opad) || H((K xor ipad) || message))`

The PBKDF2 implementation calculates each output block using repeated HMAC operations and XOR accumulation.

This implementation is useful for understanding what higher-level cryptographic APIs abstract away. It should not be used as a replacement for an audited cryptographic library in a production blockchain wallet.

### Governance Engine

The C++ program also evaluates a Pull Request against a protected branch policy.

The policy considers:

- required approvals
- stale approvals
- required status checks
- draft state
- merge conflicts
- target branch protection

This separates cryptographic key derivation from repository governance while showing how security-sensitive development workflows can be evaluated by explicit rules.

## Java 17 Implementation

The Java implementation uses an enterprise-oriented domain model.

Java records represent immutable domain values such as:

- `DerivedNode`
- `Review`
- `StatusCheck`
- `BranchProtectionPolicy`
- `PullRequest`
- `Eligibility`

The `KeyDerivationFunction` interface defines the password-derivation contract. `Pbkdf2Sha256` implements that contract using Java's `SecretKeyFactory`.

`PBEKeySpec.clearPassword()` is used after derivation to reduce the lifetime of password material held by the specification object.

HKDF is implemented using Java's `Mac` API because standard Java 17 does not expose HKDF as a general-purpose `SecretKeyFactory` algorithm.

The `MergeEligibilityService` treats merge eligibility as a domain decision rather than a boolean hidden inside unrelated code.

It separately evaluates:

- Pull Request state
- commit presence
- merge conflicts
- unresolved conversations
- linear history
- non-stale approvals
- required status checks

This makes failure reasons explicit and testable.

## PostgreSQL Model

The PostgreSQL implementation models the persistent parts of a blockchain-development security environment.

The central relationship is:

`Repository`
`  -> Branch`
`      -> Commit`
`          -> Pull Request`
`              -> Review`
`                  -> Review Comment`
`              -> Status Check`
`      -> Branch Protection Policy`
`          -> Required Status Check`

Cryptographic metadata is represented separately:

`KDF Operation -> Wallet Key -> Derivation Path`

Raw secrets are intentionally absent from the relational model.

### Repository and Branches

Repositories have owners, visibility, and members.

Branches identify their current commit and whether they are protected.

The database trigger prevents direct modification of a protected branch when its policy prohibits direct pushes.

### Pull Requests

A Pull Request stores:

- source branch
- target branch
- author
- state
- draft state
- merge-conflict state
- unresolved conversation count
- linear-history state

The commit association table preserves the ordered changeset associated with the Pull Request.

### Reviews

Reviews have explicit states:

- `PENDING`
- `APPROVED`
- `CHANGES_REQUESTED`
- `DISMISSED`

An approval also has a `stale` state.

This distinction matters because an earlier approval may no longer represent approval of the current changeset.

The reviewer-validation trigger prevents inactive reviewers from submitting reviews.

### Review Comments

Inline comments identify a file and line number.

Each comment has a resolved state.

The merge-eligibility view requires zero unresolved conversations when the branch policy requires conversation resolution.

### Status Checks

Status checks are attached to individual Pull Requests.

The branch policy identifies which checks are mandatory.

A Pull Request can therefore have optional checks without treating every check in the repository as a merge requirement.

### Branch Protection

Branch protection is represented as repository-level enforcement.

The policy can require:

- minimum approvals
- resolved conversations
- linear history
- no direct pushes
- no force pushes
- no branch deletion
- no administrator bypass

Required status checks are stored separately so the policy can define an explicit allow-list.

## Merge Eligibility

The database view `merge_eligibility` combines independent conditions.

Conceptually:

`Pull Request state`
`+ changeset`
`+ conflict state`
`+ conversations`
`+ approval policy`
`+ status checks`
`+ history policy`
`= merge eligibility`

This is different from code review.

A review records an evaluator's decision about the changes.

An approval records a specific positive review decision.

Branch protection defines repository-level conditions.

Merge eligibility evaluates whether the current Pull Request satisfies all relevant conditions.

## Distinguishing the Governance Concepts

The four governance concepts have separate responsibilities.

| Concept | Primary responsibility |
|---|---|
| Pull Request | Proposes a changeset from a source branch toward a target branch |
| Code Review | Evaluates the proposed changes |
| Approval | Records a positive review decision subject to eligibility and staleness rules |
| Branch Protection | Enforces repository-level conditions before merging |

A Pull Request can exist without approval.

A review can request changes rather than approve.

An approval can become stale after the changeset changes.

A Pull Request can have sufficient approvals and still fail branch protection because a required status check is failing.

## Approval Staleness

The PostgreSQL model demonstrates an important state transition.

When a new commit is associated with a Pull Request, the trigger marks existing approvals as stale.

The sequence becomes:

`Approved`
`  -> new commit`
`  -> approval becomes stale`
`  -> fresh review required`
`  -> new approval`
`  -> merge eligibility restored`

This prevents a reviewer approval from silently applying to a materially changed changeset.

## Security Boundaries

The implementations establish several security boundaries.

### Password-derived material

Password-derived keys require a salt and an appropriate work factor.

The salt does not need to be secret.

The password does.

### High-entropy key material

HKDF is appropriate for deriving multiple purpose-specific keys from an already-secret input.

It is not a password-hardening function.

### Hierarchical derivation

A hierarchical wallet system must define exact derivation semantics.

A custom derivation scheme should not be represented as a standards-compatible wallet format.

### Repository security

Cryptographic source code requires normal software-development controls:

- protected branches
- mandatory reviews
- successful automated checks
- resolved review discussions
- restricted direct pushes
- restricted force pushes
- stale-approval handling

The repository model treats these as enforcement mechanisms rather than informal conventions.

## Failure Conditions

The implementations reject or block several invalid states.

| Failure | Handling |
|---|---|
| Empty password | KDF validation error |
| Short salt | KDF validation error |
| Weak PBKDF2 iteration count | KDF validation error |
| Invalid scrypt cost parameters | KDF validation error |
| Invalid derivation path | Path validation error |
| Excessive derivation depth | Derivation failure |
| Empty Pull Request changeset | Merge blocked |
| Merge conflict | Merge blocked |
| Insufficient approvals | Merge blocked |
| Stale approval | Does not satisfy approval requirement |
| Missing status check | Merge blocked |
| Failed status check | Merge blocked |
| Unresolved required conversation | Merge blocked |
| Non-linear history under linear policy | Merge blocked |
| Direct protected-branch mutation | Database trigger rejects operation |
| Inactive reviewer | Database trigger rejects review |

## Performance Considerations

PBKDF2 intentionally consumes CPU time. Increasing its iteration count increases derivation latency.

scrypt adds substantial memory consumption, making it more resistant to large-scale parallel guessing than a CPU-only construction with comparable nominal work.

HKDF is comparatively inexpensive because it is intended for key expansion rather than password hardening.

Hierarchical derivation is efficient because each child requires a small number of HMAC operations.

Database indexes target common access paths:

- repository branch lookup
- Pull Request state by target branch
- review state by Pull Request
- status checks by Pull Request
- unresolved review comments

The merge-eligibility view performs aggregation across reviews and status checks. Large deployments may require materialized state, carefully tuned indexes, or application-level caching after measuring actual workload characteristics.

## Operational Boundaries

The examples are learning-oriented technical implementations.

The custom hierarchical derivation structures are not replacements for standardized blockchain wallet specifications.

A production wallet should use an audited implementation of the exact protocol required by the target blockchain.

Production key-management architecture also needs controls outside these files, including secure entropy sources, hardware-backed key storage where appropriate, recovery procedures, access control, secret rotation, incident response, and carefully reviewed cryptographic protocol integration.

The PostgreSQL design deliberately stores key fingerprints and derivation metadata instead of wallet secrets.

## Relationship Between Cryptography and Repository Governance

The project treats cryptographic correctness and repository governance as distinct layers.

The cryptographic layer answers:

`How is secret material transformed into independent keys?`

The wallet layer answers:

`Which deterministic derivation path identifies a particular key?`

The repository layer answers:

`Which changes are permitted to reach a protected codebase?`

The review layer answers:

`Has a qualified reviewer evaluated the changes?`

The approval layer answers:

`Does a current, eligible review satisfy the required approval count?`

The branch-protection layer answers:

`Does the repository permit this Pull Request to merge under its current policy?`

These layers interact operationally without being interchangeable.

## Practical Workflow

A realistic development workflow represented by the project is:

`Developer`
`  -> feature branch`
`  -> cryptographic implementation`
`  -> Pull Request`
`  -> automated status checks`
`  -> security review`
`  -> cryptography review`
`  -> approvals`
`  -> branch-protection evaluation`
`  -> merge`

A changeset modification can invalidate previous approvals:

`New commit`
`  -> stale approvals`
`  -> fresh review`
`  -> status checks`
`  -> branch-protection evaluation`
`  -> merge`

This state model is particularly important for security-sensitive code because an approval should correspond to the actual changeset being merged.

## Limitations

The implementations intentionally avoid pretending that simplified cryptographic code is a complete blockchain wallet.

The C++ source implements core primitives to expose their internal structure, but production systems should use audited cryptographic libraries.

The PostgreSQL KDF function demonstrates HKDF mechanics using `pgcrypto`. It does not provide a complete wallet-secret-management system.

The JavaScript asynchronous PBKDF2 path is suitable for demonstrating non-blocking processing, while expensive synchronous cryptographic operations can still block a Node.js event loop.

The Python scrypt example demonstrates standard-library support but does not implement Argon2id.

The hierarchical derivation examples use custom HMAC-based nodes and therefore must not be confused with standardized BIP-32 wallet derivation.

## Technical Coverage

| Area | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---:|---:|---:|---:|---:|
| PBKDF2 | Yes | Yes | Yes | Yes | Metadata |
| scrypt | Yes | Yes | Not implemented | Not implemented | Metadata |
| HKDF | Yes | Yes | Yes | Yes | Yes |
| HMAC-SHA256 | Yes | Yes | Yes | Yes | Yes |
| Hierarchical derivation | Yes | Yes | Yes | Yes | Metadata |
| Domain separation | Yes | Yes | Yes | Yes | Yes |
| Validation | Yes | Yes | Yes | Yes | Yes |
| Failure handling | Yes | Yes | Yes | Yes | Yes |
| Repository governance | Simulation | Workflow | Engine | Domain service | Relational enforcement |
| Approval state | Simulation | Workflow | Evaluation | Explicit model | Persistent model |
| Branch protection | Simulation | Policy workflow | Governance engine | Policy object | Database policy |
| Merge eligibility | Yes | Yes | Yes | Yes | View |

## File Responsibilities

The five source files are intentionally complementary.

The Python implementation emphasizes readable cryptographic workflow and deterministic derivation.

The JavaScript implementation emphasizes asynchronous execution, event-driven state, and Node.js cryptographic APIs.

The C++17 implementation exposes the lower-level mechanics of SHA-256, HMAC, PBKDF2, and HKDF while implementing a governance engine.

The Java 17 implementation models cryptographic and repository governance concepts as explicit enterprise domain types and services.

The PostgreSQL implementation persists repository, Pull Request, review, approval, status-check, branch-protection, KDF, and derivation metadata while enforcing selected rules through constraints and triggers.
