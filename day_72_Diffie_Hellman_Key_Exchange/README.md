# Diffie-Hellman Key Exchange

## 1. Technical Scope

Diffie-Hellman (DH) is a public-key cryptographic key-agreement mechanism that allows two participants to calculate an identical shared secret using publicly exchanged values.

The mechanism does not require either participant to transmit their private exponent. Its security relies on the computational difficulty of recovering a private exponent from a public group element, under the discrete logarithm assumption.

The implementations examine the mathematical foundations, exchange lifecycle, parameter validation, public-key verification, key derivation, session management, and security limitations.

The five source files provide complementary implementations:

| File | Engineering perspective |
|---|---|
| Python | Mathematical modeling, simulation, validation, and testing |
| JavaScript | Asynchronous exchange lifecycle and event-driven state management |
| C++17 | Domain modeling and a compact governance-oriented exchange engine |
| Java 17 | Enterprise session management, immutable domain objects, and service policies |
| PostgreSQL | Relational exchange management, integrity enforcement, and auditing |

## 2. Mathematical Foundations

### 2.1 Modular Arithmetic

Modular arithmetic operates on the remainder after division by a positive integer.

For integers a, b, and p:

\[
a \bmod p = r
\]

where:

\[
0 \leq r < p
\]

Modular arithmetic keeps intermediate mathematical values within a bounded range when calculations are reduced modulo p.

### 2.2 Modular Exponentiation

The fundamental operation in finite-field Diffie-Hellman is:

\[
y = g^x \bmod p
\]

Where:

- \(p\) is a prime modulus.
- \(g\) is a generator or subgroup generator.
- \(x\) is a private exponent.
- \(y\) is the resulting public value.

Direct exponentiation is inefficient for large exponents.

The implementations use repeated squaring, also called binary exponentiation.

For an exponent with k binary digits, modular exponentiation requires approximately:

\[
O(\log x)
\]

modular multiplication operations.

### 2.3 Diffie-Hellman Parameters

The demonstration uses:

| Parameter | Value | Meaning |
|---|---:|---|
| p | 23 | Prime modulus |
| q | 11 | Prime subgroup order |
| g | 2 | Subgroup generator |

The parameters satisfy:

\[
p=2q+1
\]

This is a safe-prime relationship.

The generator must satisfy:

\[
g^q \bmod p=1
\]

The selected generator has order q.

These parameters are intentionally small and provide no meaningful cryptographic security.

They are used to make the mathematical operations transparent and independently verifiable.

## 3. Key Exchange Mechanism

### 3.1 Private Key Generation

Alice generates a private exponent:

\[
a \in [1,q-1]
\]

Bob independently generates:

\[
b \in [1,q-1]
\]

Private exponents must be unpredictable.

The Python implementation uses the `secrets` module.

The JavaScript implementation uses Node.js `crypto.randomBytes()`.

The C++ implementation demonstrates a standard-library random-number interface, but its randomness is not a validated cryptographic random-number generator.

The Java implementation uses `SecureRandom`.

Production systems require cryptographically secure randomness and validated cryptographic implementations.

### 3.2 Public Key Generation

Alice calculates:

\[
A=g^a \bmod p
\]

Bob calculates:

\[
B=g^b \bmod p
\]

Both values are public and can be transmitted through an untrusted communication channel.

The public values do not disclose the private exponents under the assumed computational security of the selected group.

### 3.3 Shared Secret Calculation

Alice computes:

\[
S_A=B^a \bmod p
\]

Bob computes:

\[
S_B=A^b \bmod p
\]

Substituting the public-key expressions:

\[
S_A=(g^b)^a \bmod p
\]

\[
S_B=(g^a)^b \bmod p
\]

Therefore:

\[
\boxed{S_A=S_B=g^{ab}\bmod p}
\]

The equality follows from the multiplication property of exponents.

Neither participant needs to transmit the resulting shared secret.

### 3.4 Worked Example

For the demonstration group:

\[
p=23,\quad q=11,\quad g=2
\]

Alice selects:

\[
a=3
\]

Her public key becomes:

\[
A=2^3\bmod23=8
\]

Bob selects:

\[
b=6
\]

His public key becomes:

\[
B=2^6\bmod23=18
\]

Alice computes:

\[
S_A=18^3\bmod23=13
\]

Bob computes:

\[
S_B=8^6\bmod23=13
\]

Both obtain:

\[
\boxed{S=13}
\]

The shared value is identical even though the private exponents remain different.

## 4. Group Validation and Public-Key Validation

Parameter validation is essential because the mathematical correctness of an exchange does not automatically establish its security.

### 4.1 Safe-Prime Validation

The implementations examine:

- Whether p is prime.
- Whether q is prime.
- Whether p equals 2q + 1.
- Whether g belongs to the selected subgroup.
- Whether g is greater than one.
- Whether g is smaller than p.

The Python and JavaScript implementations use Miller-Rabin probable-prime testing with multiple bases.

The Java implementation uses `BigInteger.isProbablePrime()`.

The C++ implementation uses Miller-Rabin testing for its bounded demonstration integers.

These educational primality checks must not replace standardized cryptographic parameter validation.

### 4.2 Public-Key Validation

A received public value must satisfy:

\[
1 < A < p-1
\]

For the selected subgroup:

\[
A^q\bmod p=1
\]

The same conditions apply to B.

These checks reject invalid and out-of-subgroup public values.

For the demonstration parameters:

| Public value | Result |
|---:|---|
| 8 | Valid |
| 18 | Valid |
| 1 | Rejected |
| 5 | Rejected |
| 22 | Rejected |

Subgroup validation helps prevent invalid-element attacks and inappropriate group-element acceptance.

It does not provide authentication.

## 5. Key Derivation

### 5.1 Raw Shared Secret Versus Application Key

The DH result is an intermediate secret.

It should not be used directly as an encryption key.

The implementations demonstrate deriving an application key through HKDF-SHA256 where supported.

HKDF is defined in RFC 5869.

Its two principal stages are:

**Extract**

\[
PRK=HMAC(salt,IKM)
\]

Where IKM is the input key material.

**Expand**

\[
T_1=HMAC(PRK,info\parallel 0x01)
\]

Subsequent blocks incorporate the previous block and an incrementing counter.

The requested output length determines how many blocks are produced.

The implementation supports the HKDF-SHA256 maximum output length:

\[
255\times32=8160\text{ bytes}
\]

### 5.2 Context Binding

The implementations construct a transcript containing exchange information.

The transcript includes relevant group parameters and public-key values.

Its SHA-256 digest is used as HKDF salt in the educational implementations.

The application context is passed through HKDF's `info` parameter.

This provides context separation between derived keys.

A transcript hash is not an authentication mechanism. It does not prevent an attacker from replacing exchanged public values.

Authenticated key exchange requires a protocol that authenticates the participants and binds their identities, public keys, roles, and negotiated parameters.

## 6. Pull Request and Code Review Distinctions

The cryptographic implementations are organized as independent executable artifacts. In a collaborative repository, changes to these artifacts would normally pass through a Pull Request workflow.

A Pull Request provides the mechanism for proposing changes from a source branch to a target branch.

Code Review evaluates the proposed changes.

An approval represents an individual review decision.

Branch Protection enforces repository-level conditions before integration.

These mechanisms have different responsibilities:

| Mechanism | Responsibility |
|---|---|
| Pull Request | Proposes a changeset |
| Code Review | Evaluates the changeset |
| Approval | Records an eligible review decision |
| Branch Protection | Enforces repository merge requirements |

### 6.1 Pull Request Lifecycle

A typical cryptographic implementation change follows this sequence:

1. Create a feature branch.
2. Modify the DH implementation.
3. Commit the changes.
4. Open a Pull Request against the target branch.
5. Request reviews.
6. Execute automated status checks.
7. Resolve review conversations.
8. Obtain required approvals.
9. Merge the approved changeset.

The source branch contains the proposed implementation.

The target branch represents the destination repository state.

The Pull Request changeset represents the difference between the two branch states. It is not itself a branch.

Draft Pull Requests support early collaboration without presenting the changes as ready for final integration.

Synchronizing the source branch with the target branch helps identify conflicts and integration problems.

Merge conflicts require explicit resolution before successful integration.

A closed Pull Request can be reopened when repository conditions permit and the underlying changes remain relevant.

### 6.2 Merge Strategies

| Strategy | Behavior |
|---|---|
| Merge commit | Preserves the source branch history through a merge commit |
| Squash merge | Combines the changes into one target-branch commit |
| Rebase merge | Replays source commits onto the target branch |

The selected strategy affects repository history and commit identity.

Linear-history policies may prohibit merge commits.

### 6.3 Code Review

Code Review evaluates technical correctness and maintainability.

For a Diffie-Hellman implementation, review criteria should include:

- Correct modular exponentiation.
- Proper private-key generation.
- Parameter validation.
- Public-key subgroup validation.
- Correct shared-secret computation.
- Appropriate key derivation.
- Authentication limitations.
- Secret-handling practices.
- Error handling.
- Test coverage.

Inline comments identify specific implementation problems.

Review discussions provide context for design decisions and suggested corrections.

Review states generally include:

| Review state | Meaning |
|---|---|
| Comment | Feedback without an approval decision |
| Approve | Positive review decision |
| Request changes | Changes required before acceptance |
| Dismissed | Previous review decision no longer counts |

Reviewers should examine the actual changeset rather than merely checking whether the program compiles.

Resolving a conversation indicates that the discussion has been addressed. It does not independently establish that the implementation is correct.

### 6.4 Approval Semantics

An approval represents an eligible reviewer's decision to accept the reviewed changes.

Approval policies can specify:

- Required approval count.
- Eligible reviewer identities.
- Code-owner requirements.
- Independence of reviewers.
- Approval freshness.
- Treatment of dismissed reviews.
- Whether new commits invalidate previous approvals.

A new commit may make an earlier approval stale when repository policy requires approval of the latest changes.

A dismissed approval no longer satisfies the applicable approval requirement.

An approval does not automatically guarantee that a Pull Request can be merged.

The repository's enforcement policy determines whether all required conditions have been satisfied.

### 6.5 Branch Protection

Branch Protection governs the target branch rather than the quality of an individual review.

Its controls can include:

- Required status checks.
- Required review count.
- Required conversations to be resolved.
- Direct-push restrictions.
- Force-push restrictions.
- Branch-deletion restrictions.
- Linear-history requirements.
- Merge-strategy restrictions.
- Administrator enforcement.
- Explicit bypass permissions.

For a cryptographic repository, required status checks might include compilation, unit tests, parameter-validation tests, static analysis, dependency checks, and security testing.

Administrator bypass is a governance exception, not evidence that normal enforcement requirements have been satisfied.

## 7. Python Implementation

The Python implementation provides a mathematical and operational model of the exchange.

### Main components

| Component | Responsibility |
|---|---|
| `DHGroup` | Stores and validates group parameters |
| `Participant` | Generates keys and computes shared secrets |
| `is_probable_prime` | Performs Miller-Rabin testing |
| `validate_public_key` | Checks received public values |
| `compute_shared_secret` | Calculates the DH result |
| `hkdf_sha256` | Derives application key material |
| `ExchangeResult` | Stores exchange output |
| `DiffieHellmanTests` | Executes correctness and failure tests |

The implementation uses Python's arbitrary-precision integers for modular arithmetic.

The `dataclass` mechanism provides structured exchange objects.

The `secrets` module provides cryptographically secure random-number generation for the demonstration.

Exceptions distinguish parameter errors, exchange failures, and verification problems.

The tests examine agreement equality, invalid inputs, HKDF output length, and independent session derivation.

Run the program with Python 3.10 or later.

## 8. JavaScript Implementation

The JavaScript implementation provides an event-driven exchange manager.

It uses:

- `BigInt` for integer arithmetic.
- `Map`-compatible object modeling for session-oriented extensions.
- `Set`-compatible validation concepts.
- Node.js `crypto` for randomness, SHA-256, and HKDF.
- Promises for asynchronous key derivation.
- `EventEmitter` for lifecycle notifications.
- `assert` for executable verification.

### Exchange states

The state sequence is:

`CREATED → KEYS_EXCHANGED → VERIFIED → DERIVED`

Failure moves the exchange to:

`FAILED`

Each transition produces an event containing the state and timestamp.

The audit collection preserves the sequence of lifecycle events.

The exchange manager rejects duplicate sessions and invalid public values.

Asynchronous HKDF operations are handled through a Promise-based interface.

Run with Node.js 20 or later.

## 9. C++17 Implementation

The C++ implementation focuses on explicit domain modeling and exchange lifecycle management.

### Main components

| Component | Responsibility |
|---|---|
| `DHGroup` | Represents cryptographic group parameters |
| `SecureRandom` | Demonstrates random exponent selection |
| `Participant` | Encapsulates private and public values |
| `ExchangeRecord` | Represents session state |
| `ExchangeEngine` | Controls exchange execution |
| `ExchangeState` | Defines lifecycle states |

The implementation uses STL containers, particularly `std::map`, to maintain session records.

Modular exponentiation uses repeated squaring.

`__uint128_t` provides wider intermediate multiplication for the bounded demonstration group. This is a compiler extension commonly available in GCC and Clang, rather than a portable ISO C++17 type.

The implementation deliberately avoids external libraries.

Its random-number mechanism is not suitable for production cryptographic secrets. Production use requires a validated cryptographic random-number generator and constant-time cryptographic arithmetic.

Compile with a C++17-compatible GCC or Clang compiler.

## 10. Java 17 Implementation

The Java implementation models the exchange as an enterprise-oriented service.

### Domain model

The major types include:

- `DHGroup`
- `PublicKey`
- `SessionPolicy`
- `ExchangeResult`
- `Participant`
- `KeyValidator`
- `ExchangeAudit`
- `ExchangeService`

Java records represent immutable domain data.

`BigInteger.modPow()` performs modular exponentiation.

`SecureRandom` supplies private-key randomness.

The exchange service manages sessions and enforces mandatory validation policies.

### State management

The enterprise workflow distinguishes:

`CREATED`

`PUBLIC_KEYS_EXCHANGED`

`VERIFIED`

`DERIVED`

`FAILED`

The audit trail records lifecycle transitions.

Duplicate session identifiers are rejected.

The session policy prevents mandatory subgroup validation and shared-secret verification from being disabled.

The implementation uses `MessageDigest`, `Mac`, and `SecretKeySpec` for SHA-256 and HMAC-SHA256 operations.

The HKDF implementation follows the extract-and-expand structure.

The resulting key is copied defensively when exposed through the immutable exchange result.

Run using Java 17.

## 11. PostgreSQL Implementation

The SQL implementation models the exchange lifecycle as a relational workflow.

### 11.1 Relational Structure

The main relationships are:

    DH Groups
        |
        +---- Exchange Sessions
                   |
                   +---- Public Key Submissions
                   |
                   +---- Derived Key Metadata
                   |
                   +---- Exchange Audit

    Participants
        |
        +---- Exchange Sessions
        |
        +---- Public Key Submissions
        |
        +---- Audit Events

### 11.2 Tables

| Table | Purpose |
|---|---|
| `dh_groups` | Stores group parameters |
| `participants` | Stores participant identities |
| `exchange_sessions` | Tracks exchange lifecycle |
| `public_key_submissions` | Stores public-key submissions |
| `derived_key_metadata` | Stores derivation information |
| `exchange_audit` | Records lifecycle events |

Foreign keys enforce relationships between entities.

Unique constraints prevent duplicate participant submissions and duplicate role assignments within a session.

Check constraints enforce parameter ranges, valid status values, and metadata requirements.

### 11.3 Functions

`modular_power()` performs modular exponentiation using repeated squaring.

`validate_dh_group()` checks the demonstration group.

`validate_public_submission()` validates a received public value against the configured subgroup.

### 11.4 Procedures

| Procedure | Function |
|---|---|
| `create_exchange_session()` | Creates a session after participant and group checks |
| `register_public_key()` | Registers a participant's public value |
| `validate_exchange()` | Validates both public submissions and records a transcript digest |
| `register_key_derivation()` | Registers derivation metadata and completes the session |

The SQL implementation intentionally does not calculate private exponents or persist raw shared secrets.

### 11.5 Triggers

`enforce_session_transition()` prevents invalid state transitions and changes terminal sessions only through permitted transitions.

Terminal states are:

- `DERIVED`
- `FAILED`
- `CANCELLED`

A completed session cannot return to an earlier state.

### 11.6 Reporting

`exchange_session_report` combines session information, participants, group classification, validation counts, and derivation metadata.

Additional queries support:

- Session retrieval.
- Invalid-key identification.
- Status aggregation.
- Validation reporting.
- Workflow auditing.
- Exchange-completion evaluation.
- Transaction rollback.

The database uses indexes on session status, group identifiers, participant identifiers, public-key validation state, and audit records.

The GIN index supports JSONB audit-detail searches.

PostgreSQL 15 or later is required. The script uses the built-in `gen_random_uuid()` and `sha256(bytea)` functions.

## 12. Security Properties and Limitations

### 12.1 Discrete Logarithm Problem

The security of finite-field DH depends on the difficulty of determining x from:

\[
g^x\bmod p
\]

Given g, p, and the resulting public value, recovering x should be computationally infeasible for appropriately selected production parameters.

The demonstration parameters do not provide this protection.

### 12.2 Man-in-the-Middle Attacks

Unauthenticated DH is vulnerable to man-in-the-middle attacks.

An attacker can intercept the public values and establish separate secrets with Alice and Bob.

The attacker can then relay or modify communications between them.

The fact that both parties calculate matching secrets does not establish that they share a secret with the intended identity.

Mitigations include:

- Digital signatures.
- Certificate-based authentication.
- Authenticated ephemeral key exchange.
- Pre-shared authentication keys.
- Properly implemented authenticated protocols.

### 12.3 Forward Secrecy

Ephemeral Diffie-Hellman uses fresh private exponents for individual sessions.

If ephemeral secrets are securely generated and erased, compromise of a long-term authentication key need not reveal previously established session secrets.

Forward secrecy depends on the complete protocol and its implementation.

Static DH does not automatically provide the same protection.

### 12.4 Side-Channel Risks

Mathematical correctness does not guarantee implementation security.

Private-key operations may expose information through:

- Timing differences.
- Memory-access patterns.
- Cache behavior.
- Power consumption.
- Fault injection.
- Improper secret handling.

Production cryptographic implementations should use vetted constant-time operations where required.

### 12.5 Parameter and Key Management

Production deployments require:

- Standardized, sufficiently strong parameters.
- Proper private-key generation.
- Peer public-key validation.
- Authenticated protocol negotiation.
- Session-specific key derivation.
- Secure key storage.
- Key rotation.
- Secret erasure where applicable.
- Replay protection.
- Protocol version management.

A transcript hash alone does not provide message authentication or replay protection.

### 12.6 Production Limitations of These Implementations

| Implementation | Important limitation |
|---|---|
| Python | Uses an educational group and variable-time arithmetic |
| JavaScript | Uses small demonstration parameters and does not authenticate identities |
| C++17 | Uses bounded arithmetic and a non-cryptographic random-number engine |
| Java 17 | Uses an educational group and does not provide a complete authenticated protocol |
| PostgreSQL | Manages public exchange metadata rather than performing production cryptography |

The database is not a secure key-management system.

It should not receive private exponents or raw shared secrets.

The SQL demonstration also deliberately restricts its group validation to the small educational parameters.

## 13. Complexity and Performance

Let n denote the bit length of the prime modulus.

| Operation | Computational consideration |
|---|---|
| Modular exponentiation | O(log q) modular multiplications |
| Public-key generation | One modular exponentiation |
| Shared-secret calculation | One modular exponentiation |
| Public-key validation | One subgroup exponentiation |
| Transcript hashing | Linear in transcript length |
| HKDF extraction | One HMAC operation |
| HKDF expansion | Linear in requested output length |

The complexity of individual modular multiplications depends on the underlying integer-arithmetic implementation.

The educational Python, JavaScript, C++, and Java programs are suitable for small mathematical demonstrations.

Production DH groups require large integers and optimized cryptographic implementations.

For database workloads, indexes reduce the cost of locating sessions and public-key submissions. The relational workflow should remain separate from cryptographic computation.

## 14. Edge Cases and Failure Handling

The implementations cover the following conditions:

| Condition | Expected behavior |
|---|---|
| Composite modulus | Reject group |
| Invalid subgroup order | Reject group |
| Invalid generator | Reject group |
| Private exponent equal to zero | Reject private key |
| Public value equal to one | Reject public key |
| Public value outside range | Reject public key |
| Public value outside subgroup | Reject public key |
| Trivial shared secret | Reject exchange |
| Different calculated secrets | Fail verification |
| Duplicate session identifier | Reject session |
| Missing participant identity | Reject participant |
| Incorrect participant role | Reject database registration |
| Inactive participant | Reject session creation |
| Invalid state transition | Reject state update |
| Invalid HKDF length | Reject derivation request |

These cases demonstrate that successful modular exponentiation is only one part of a reliable key-agreement workflow.

## 15. Execution Requirements

| Deliverable | Runtime | External dependencies |
|---|---|---|
| Python | Python 3.10+ | None |
| JavaScript | Node.js 20+ | None |
| C++17 | GCC or Clang with C++17 support | None |
| Java | JDK 17 | None |
| PostgreSQL | PostgreSQL 15+ | None |

The Python and JavaScript implementations execute their own tests.

The C++ and Java programs include executable assertions and failure checks.

The SQL script creates the schema, registers demonstration records, executes successful and failed exchange scenarios, and performs reporting queries.

All demonstration secrets and parameters are unsuitable for production deployment.
