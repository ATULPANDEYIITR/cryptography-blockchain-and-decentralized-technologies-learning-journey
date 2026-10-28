# Second-Preimage Resistance

## Purpose

This project models and tests **second-preimage resistance**, a fundamental property of cryptographic hash functions.

Given a fixed message `M`, its digest is:

`H(M) = d`

A second-preimage attack attempts to construct a different message `M'` such that:

`M' != M`

and:

`H(M') = H(M)`

The defining feature is that the original message is fixed before the attacker searches. This distinguishes second-preimage resistance from collision resistance, where the attacker is generally free to select both messages.

The implementations deliberately separate the cryptographic property from message authenticity. A hash can provide strong second-preimage resistance without proving who created or approved the message.

## Domain Model

The project uses the following relationship:

    Fixed Artifact
         |
         v
    Target Message
         |
         v
    Cryptographic Digest
         |
         v
    Candidate Generation
         |
         v
    Candidate Digest
         |
         +-------------------+
         |                   |
         | equal             | different
         v                   v
    Candidate is        Continue Search
    second preimage

A candidate is valid only when both conditions hold:

| Condition | Requirement |
|---|---|
| Message identity | Candidate must differ from the fixed original |
| Digest equality | Candidate digest must equal the target digest |
| Hash algorithm | Both messages must be processed by the same algorithm |
| Search model | The original message remains fixed |
| Security interpretation | A successful match indicates failure of the tested hash configuration |

## Second-Preimage Resistance

Second-preimage resistance addresses a targeted substitution problem.

Suppose a signed or otherwise trusted record contains:

`M`

and its hash:

`H(M)`

An attacker who cannot alter the trusted record may try to create another message:

`M'`

that produces the same digest. If such a message can be constructed efficiently, a system that relies on the digest to identify the original data may become vulnerable to substitution.

The security goal is therefore that, for a properly designed cryptographic hash, finding such an `M'` for a given `M` should require computational work that is infeasible with available resources.

For an ideal `n`-bit hash, generic second-preimage search has approximately `2^n` work rather than the approximately `2^(n/2)` birthday-bound work associated with generic collision searching.

The exact security analysis of a concrete hash function can be more complicated because structural attacks, message restrictions, reduced-round variants, and implementation weaknesses may change the effective security level.

## What Is Fixed

The attack model is important.

A second-preimage experiment begins with a known message:

`M`

The digest is calculated:

`d = H(M)`

The search then tests alternatives:

`M1, M2, M3, ...`

Each candidate is compared with the fixed target digest.

A successful result therefore requires:

`Mi != M`

and:

`H(Mi) = d`

Changing the original message during the search would describe a different problem.

## Distinction From Related Properties

| Property | Attacker controls | Required relationship |
|---|---|---|
| Preimage resistance | Target digest, but not its original message | Find `M` such that `H(M) = d` |
| Second-preimage resistance | Fixed original message `M` | Find different `M'` with `H(M') = H(M)` |
| Collision resistance | Both messages can generally be selected | Find `M != M'` with equal digests |

These properties are related but are not interchangeable.

A system that needs protection against replacement of one known document with another must consider second-preimage resistance specifically.

## Python Implementation

The Python program is a self-contained laboratory and verification model.

### Core mechanisms

`HashModel` uses SHA-256 and deliberately truncates its output to a configurable number of bits. The reduced digest width allows an experimental second-preimage search to terminate within a practical demonstration budget.

`Message` and `SearchResult` are immutable dataclasses. They make the target artifact and attack result explicit rather than representing all information as loosely related variables.

`find_second_preimage()` fixes the original message, generates distinct candidates, hashes each candidate, and compares its digest with the target digest.

`verify_second_preimage()` independently checks the defining conditions:

- the original and candidate are non-empty;
- the candidate differs from the original;
- the two digests are equal.

The comparison uses `hmac.compare_digest()` rather than an ordinary equality expression for digest comparison.

The script also demonstrates full SHA-256 verification without attempting an exhaustive attack against a 256-bit digest.

### Failure handling

The Python implementation rejects:

- non-byte messages;
- empty messages;
- invalid digest widths;
- non-positive search budgets.

The controlled search returns a structured result when no candidate is found rather than treating search exhaustion as a successful verification.

## JavaScript Implementation

The JavaScript implementation uses Node.js standard-library functionality and emphasizes event-driven processing.

`HashModel` provides configurable digest truncation while using Node's `crypto` module for SHA-256.

`SecondPreimageEngine` extends `EventEmitter`. It emits progress information during long experimental searches and emits a `found` event when a valid candidate is detected.

The asynchronous search periodically yields with `setImmediate()`. This prevents the experimental loop from monopolizing the Node.js event loop for its entire execution.

`constantTimeEqual()` uses Node's timing-safe comparison facility after validating digest lengths.

The implementation also demonstrates full SHA-256 comparison separately from the reduced laboratory search.

This design illustrates a practical distinction between:

- CPU-intensive search work;
- application responsiveness;
- event-driven status reporting;
- final security verification.

## C++17 Implementation

The C++17 program treats second-preimage checking as part of a repository security engine.

`Artifact` represents a fixed protected object. It contains an identifier, content, and declared hash algorithm.

`EducationalHash` provides a compact deterministic hash model with configurable output width. It is intentionally not a production cryptographic hash implementation. Its purpose is to make the security workflow executable without external dependencies.

`SecondPreimageEngine` performs the targeted search and records:

- target digest;
- candidate digest;
- whether the messages are distinct;
- number of attempts.

`RepositorySecurityPolicy` is intentionally separate from the attack engine. A repository may require both a sufficiently large digest and authenticated origin.

The resulting policy can distinguish:

- acceptable hash strength;
- discovered second-preimage failure;
- missing authentication;
- acceptable verification.

This prevents the common design error of treating hash integrity as equivalent to authentication.

## Java 17 Implementation

The Java implementation uses explicit enterprise-style domain objects and services.

`Artifact` is a Java record representing the protected object and its lifecycle state.

`HashService` owns digest computation and supports both a reduced experimental width and full SHA-256.

`CandidateFactory` controls the construction of candidate messages and enforces valid attempt identifiers.

`SecondPreimageService` contains the attack workflow and returns a structured `SearchResult`.

`GovernanceService` evaluates the result against an explicit `Policy`. This separates technical hash testing from operational acceptance decisions.

The policy considers:

- minimum digest strength;
- whether the original source has been authenticated;
- whether a second preimage has been demonstrated.

The Java program also uses immutable collections for static security criteria and control definitions.

## PostgreSQL Implementation

The PostgreSQL model represents second-preimage testing as an auditable relational workflow.

The main entities are:

| Table | Responsibility |
|---|---|
| `repositories` | Owning repository or logical system |
| `artifacts` | Fixed messages being protected |
| `hash_records` | Recorded target digests |
| `attack_runs` | Search execution and state |
| `candidates` | Candidate messages and digest results |
| `security_policies` | Acceptance requirements |
| `verification_decisions` | Policy evaluation results |

The resulting relationship is:

    repositories
        |
        +-- artifacts
                |
                +-- hash_records
                |
                +-- attack_runs
                        |
                        +-- candidates
                |
                +-- verification_decisions
                                |
                                +-- security_policies

### Database enforcement

The `artifacts` table constrains digest width and requires a known artifact state.

The `attack_runs` table prevents negative attempt counts and prevents completed states from being recorded without a completion timestamp.

The `candidates` trigger rejects a record that simultaneously claims:

- the candidate is identical to the original; and
- the candidate is a valid digest match.

The attack-completion trigger requires a real distinct matching candidate before an attack can transition to `FOUND`.

These checks keep important security semantics at the database layer rather than relying only on application code.

## Policy Evaluation

The PostgreSQL function `evaluate_security_policy()` evaluates three important conditions:

1. Digest width must meet the configured minimum.
2. A known successful second-preimage attack may require rejection.
3. Authentication may be required independently of hashing.

This produces one of:

| Decision | Meaning |
|---|---|
| `ACCEPT` | Configured hash and authentication conditions are satisfied |
| `REJECT` | A mandatory security condition failed |
| `REVIEW_REQUIRED` | Hash conditions may be sufficient, but an operational security requirement remains unresolved |

The same separation is present in the C++ and Java implementations.

## Reduced Digest Experiments

The examples use reduced digest widths such as 16 bits because a direct search against a full 256-bit digest would be impractical.

This is a deliberate laboratory technique.

For a 16-bit digest, there are only:

`2^16 = 65,536`

possible digest values.

For a 256-bit digest, there are:

`2^256`

possible digest values.

The difference is enormous. A successful experiment against a reduced digest demonstrates the mechanics of a targeted search, not a practical attack against SHA-256.

The reduced hash must therefore never be interpreted as evidence that full SHA-256 is similarly vulnerable.

## Security Considerations

### Hash strength

A production system should use a standardized cryptographic hash such as SHA-256 or a suitable SHA-3 variant rather than an educational hash.

Digest truncation reduces the available security margin. Truncation should only be used when the resulting security level has been explicitly analyzed.

### Authenticity

A hash does not establish who created the data.

For example:

`H(M) = d`

does not prove that a trusted organization produced `M`.

When origin authentication is required, appropriate mechanisms include digital signatures or message authentication codes.

### Candidate validation

A second-preimage candidate must be different from the original message. Testing the original message against itself is not an attack.

A correct implementation therefore evaluates:

`M' != M`

before treating digest equality as significant.

### Domain separation

The candidate generators append structured markers to the original data. This makes the experiment deterministic and avoids accidental ambiguity in the laboratory candidate construction.

Real protocols should use formally specified encodings and domain separation where multiple message types share cryptographic infrastructure.

### Timing behavior

Digest comparisons are performed using timing-resistant comparison facilities where the runtime provides them. This does not make the entire application side-channel resistant, but it avoids unnecessary variable-time digest comparisons in security-sensitive verification paths.

## Failure Modes

| Failure | Consequence | Control |
|---|---|---|
| Candidate equals target | Not a second preimage | Require distinct messages |
| Digest sizes differ | Invalid comparison | Validate digest parameters |
| Weak or truncated hash | Reduced security margin | Use an appropriate production hash |
| Search budget exhausted | No proof of existence or absence | Report `NOT_FOUND`, not success |
| Hash equality treated as authentication | Untrusted data may be accepted | Add signatures or MACs |
| Candidate generated ambiguously | Incorrect security interpretation | Use explicit encoding |
| Experimental hash used in production | Inadequate cryptographic security | Restrict laboratory primitive to testing |
| Incomplete audit record | Difficult incident investigation | Record algorithm, digest, attempts, and decision |

## Complexity

For a generic second-preimage search against an ideal `n`-bit hash, the expected work is approximately proportional to `2^n`.

The implementations perform a bounded sequential search.

If `k` candidates are tested, the computational work is approximately:

`O(k * C_hash)`

where `C_hash` is the cost of hashing one candidate.

Memory consumption is approximately `O(1)` for the search itself because candidates can be generated and checked one at a time.

The PostgreSQL reporting queries add indexing on repository/state and attack-run state because those attributes are used in recurring operational queries.

## Practical Workflow

A secure artifact-verification workflow can be represented as:

    Register Artifact
          |
          v
    Calculate H(M)
          |
          v
    Store Algorithm + Digest
          |
          v
    Authenticate Source When Required
          |
          v
    Verify Retrieved Artifact
          |
          v
    Compare H(M_retrieved)
          |
       +--+--+
       |     |
      Equal  Different
       |     |
       v     v
    Continue  Reject / Investigate
    Integrity
    Checks

Second-preimage resistance strengthens the hash-based integrity layer. It does not replace authentication, authorization, secure key management, access controls, or audit procedures.

## Implementation Comparison

| Implementation | Primary perspective | Distinctive mechanism |
|---|---|---|
| Python | Hash experiment and verification | Dataclasses, validation, bounded search |
| JavaScript | Interactive search model | EventEmitter and asynchronous progress |
| C++17 | Security engine | Artifact and policy engine with explicit decisions |
| Java 17 | Enterprise governance | Records, services, policy objects, immutable collections |
| PostgreSQL | Persistent security workflow | Relational model, triggers, policy function, reporting views |

## Educational Boundary

The experimental components intentionally reduce the digest size so that second-preimage behavior can be observed.

They do not implement a new cryptographic hash construction and should not be deployed as cryptographic primitives.

The production-oriented portions instead demonstrate the engineering boundary around a cryptographic hash:

- selecting an appropriate algorithm;
- retaining algorithm metadata;
- verifying fixed messages;
- requiring distinct candidates for second-preimage classification;
- separating integrity from authenticity;
- enforcing security policy;
- recording verification evidence;
- handling failed and incomplete searches explicitly.
