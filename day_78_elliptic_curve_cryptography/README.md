# Elliptic Curve Cryptography (ECC)

## Technical Implementations in Python, JavaScript, C++17, Java 17, and PostgreSQL

## 1. Introduction

Elliptic Curve Cryptography (ECC) is a public-key cryptographic approach based on the algebraic structure of elliptic curves over finite fields.

ECC enables public-key encryption protocols, digital signatures, key agreement, identity authentication, and secure communication.

Its principal advantage is that it provides strong security with comparatively small cryptographic keys.

The security of commonly deployed elliptic-curve systems depends on the computational difficulty of the Elliptic Curve Discrete Logarithm Problem (ECDLP).

Given an elliptic curve point `G` and another point `Q`, finding the integer `d` satisfying:

`Q = dG`

is computationally infeasible for appropriately selected standardized curves and sufficiently large parameters.

The six deliverables implement different aspects of ECC:

| Deliverable | Engineering perspective |
|---|---|
| Python | Mathematical operations, ECDH, ECDSA, serialization, and key lifecycle |
| JavaScript | Event-driven cryptographic workflows and asynchronous verification |
| C++17 | Finite-field mathematics, point operations, device identity, and network authorization |
| Java 17 | Enterprise domain modeling, cryptographic policies, and authorization |
| PostgreSQL | Relational key management, exchange records, signature verification records, and governance |
| README | Mathematical foundations, protocol mechanisms, implementation distinctions, and security considerations |

The implementations deliberately use different approaches. The C++17 implementation uses a small educational curve, whereas Python, JavaScript, and Java use secp256k1.

## 2. Mathematical Foundations

### 2.1 Elliptic Curve Equation

A commonly used elliptic curve equation over a prime finite field is:

`y² ≡ x³ + ax + b (mod p)`

Where:

| Parameter | Meaning |
|---|---|
| `x` | Point x-coordinate |
| `y` | Point y-coordinate |
| `a` | Curve coefficient |
| `b` | Curve coefficient |
| `p` | Prime defining the finite field |
| `G` | Generator point |
| `n` | Order of the generator |

The coefficients must satisfy the nonsingularity condition:

`4a³ + 27b² ≠ 0 (mod p)`

This prevents the curve from having singularities that would invalidate the intended group structure.

### 2.2 Finite Fields

ECC implementations operate over finite fields rather than ordinary real-number coordinates.

For a prime modulus `p`, the field is:

`Fₚ = {0, 1, 2, ..., p-1}`

Arithmetic is performed modulo `p`.

For example:

`(15 + 7) mod 17 = 5`

`(8 × 9) mod 17 = 4`

A modular inverse of `x` is an element `x⁻¹` satisfying:

`x × x⁻¹ ≡ 1 (mod p)`

Modular inverses are necessary when calculating the slope used in elliptic-curve point addition.

For prime fields, a nonzero element has a unique modular inverse.

### 2.3 Point at Infinity

The elliptic-curve group contains a special identity element called the point at infinity.

It is represented as `O`.

Its defining property is:

`P + O = P`

For every valid point `P`.

The negative of a point is:

`-P = (x, -y mod p)`

Therefore:

`P + (-P) = O`

The identity and inverse properties are important for implementing scalar multiplication and verifying group operations.

### 2.4 Point Addition

Given two distinct points:

`P = (x₁, y₁)`

`Q = (x₂, y₂)`

The slope is:

`λ = (y₂ - y₁) / (x₂ - x₁) mod p`

The resulting point is:

`R = P + Q`

With coordinates:

`x₃ = λ² - x₁ - x₂ mod p`

`y₃ = λ(x₁ - x₃) - y₁ mod p`

Division means multiplication by the modular inverse.

### 2.5 Point Doubling

When both input points are identical, point doubling is required.

The slope becomes:

`λ = (3x₁² + a) / (2y₁) mod p`

The resulting coordinates follow the same output equations used in point addition.

Point doubling and point addition are the fundamental operations used by ECC scalar multiplication.

### 2.6 Scalar Multiplication

Scalar multiplication calculates:

`Q = dG`

Where:

- `d` is a scalar.
- `G` is the generator.
- `Q` is the resulting public point.

Repeated addition is inefficient for large scalars.

The implementations use double-and-add:

1. Initialize the result to the point at infinity.
2. Examine the least significant scalar bit.
3. Add the current point when that bit is set.
4. Double the current point.
5. Shift the scalar right.
6. Continue until the scalar becomes zero.

The number of point operations is logarithmic in the scalar value.

For a 256-bit scalar, the algorithm performs a number of operations proportional to its bit length.

The educational implementations are not constant-time. Their execution behavior can depend on secret scalar bits.

## 3. Curve Selection and Parameterization

### 3.1 secp256k1

The Python, JavaScript, and Java implementations use `secp256k1`.

Its equation is:

`y² = x³ + 7 mod p`

It has:

- A 256-bit prime field.
- A standardized generator point.
- A large prime subgroup order.
- A cofactor of 1.

It is widely associated with Bitcoin and other systems requiring elliptic-curve signatures.

Its generator and field parameters are fixed rather than selected dynamically.

### 3.2 secp256r1

`secp256r1`, also known as NIST P-256, is another widely used 256-bit elliptic curve.

It is commonly supported by cryptographic providers, TLS implementations, enterprise applications, and hardware security platforms.

Although secp256k1 and secp256r1 have the same field size, their curve parameters and generators differ.

They are not interchangeable.

### 3.3 Educational C++ Curve

The C++17 program uses:

`y² = x³ + 2x + 2 mod 17`

Its generator is:

`G = (5, 1)`

Its generator order is:

`n = 19`

The small modulus makes it possible to inspect point operations without large-integer dependencies.

This curve is intentionally insecure and is used exclusively to demonstrate group arithmetic and cryptographic workflows.

Its private scalars can be recovered by exhaustive search.

The C++ implementation must not be used for actual cryptographic protection.

### 3.4 Curve Selection Rules

Curve selection is a security and interoperability decision.

A production system should establish:

- An approved curve allowlist.
- Minimum security requirements.
- Protocol compatibility.
- Cryptographic provider support.
- Key-purpose restrictions.
- Deprecation and migration rules.

A mathematically valid curve is not automatically a secure or approved curve.

## 4. Public-Key Cryptography

### 4.1 Private Keys

An ECC private key is an integer:

`1 ≤ d < n`

It must be generated using a cryptographically secure random-number generator.

The private key must remain confidential.

Predictable values, reused nonces, weak randomness, and accidental logging can compromise the security of the entire system.

The Python implementation uses `secrets`.

JavaScript uses Node.js `crypto.randomBytes()` with rejection sampling.

Java uses `SecureRandom`.

The C++ example accepts supplied demonstration scalars rather than implementing a production random-number generator.

### 4.2 Public Keys

The public key is calculated from the private key:

`Q = dG`

The private key must never be reconstructed from the public key using ordinary feasible computation.

A public key can be shared with communication partners.

Before accepting an externally supplied public key, a system must validate its encoding, coordinate ranges, curve membership, and subgroup requirements where applicable.

### 4.3 Public-Key Validation

Validation includes:

1. Checking the expected encoding length.
2. Checking the encoding prefix.
3. Checking that coordinates belong to the finite field.
4. Verifying the elliptic-curve equation.
5. Rejecting the point at infinity as a public key.
6. Checking subgroup membership where required.

The three 256-bit implementations include these checks.

The C++ implementation validates its educational points against its selected curve.

Public-key validation prevents invalid or malicious point inputs from entering cryptographic operations.

## 5. Public-Key Serialization

Elliptic-curve points require a defined encoding before they can be transmitted or stored.

SEC 1 defines standardized point representations.

### 5.1 Compressed Encoding

A compressed point contains:

- One prefix byte.
- The x-coordinate.

For a 256-bit curve, the encoding is 33 bytes.

The prefix identifies the parity of the y-coordinate.

For secp256k1, the possible prefixes are:

| Prefix | Meaning |
|---|---|
| `02` | Even y-coordinate |
| `03` | Odd y-coordinate |

The receiving implementation reconstructs the y-coordinate using the curve equation.

### 5.2 Uncompressed Encoding

An uncompressed point begins with `04` and contains both coordinates.

For a 256-bit curve, the total length is 65 bytes.

### 5.3 Serialization Security

A valid byte sequence is not necessarily a valid curve point.

Parsing must reject:

- Incorrect lengths.
- Unsupported prefixes.
- Coordinates outside the field.
- Points that do not satisfy the curve equation.
- Invalid subgroup points.

The Python and JavaScript implementations demonstrate compressed serialization and decoding.

The PostgreSQL implementation stores public-key bytes and records the encoding format. It does not independently validate the mathematical point.

## 6. Elliptic Curve Diffie-Hellman

### 6.1 ECDH Mechanism

Elliptic Curve Diffie-Hellman (ECDH) establishes a shared secret between two participants.

Assume Alice has:

- Private key `dA`.
- Public key `QA = dA G`.

Bob has:

- Private key `dB`.
- Public key `QB = dB G`.

Alice calculates:

`SA = dA QB`

Bob calculates:

`SB = dB QA`

Both calculations produce:

`S = dA dB G`

Therefore:

`SA = SB`

The private keys are not transmitted.

### 6.2 ECDH Workflow

    Alice                         Bob
      |                            |
      |---- Public key QA -------->|
      |<--- Public key QB ---------|
      |                            |
      | Calculate dA × QB          |
      |                            | Calculate dB × QA
      |                            |
      |------- Shared point -------|
      |                            |
      |---- Key derivation --------|
      |                            |
      |======= Secure Session =====|

The shared point must not be used directly as an application encryption key.

A key derivation function should transform the shared secret into key material appropriate for the intended protocol.

### 6.3 Key Derivation

The implementations demonstrate basic hashing and HMAC-based session-key derivation.

A production implementation should use a standardized HKDF construction with appropriate extraction and expansion.

The derivation context should bind:

- Both participants.
- Their public keys.
- The protocol identifier.
- The protocol version.
- The session transcript.
- The intended key purpose.

This reduces the risk of cross-protocol and cross-session key misuse.

### 6.4 Authentication Requirement

ECDH alone does not authenticate the participants.

An attacker can intercept public keys and establish separate shared secrets with each participant.

This is a man-in-the-middle attack.

Authenticated key exchange requires an appropriate mechanism, such as:

- Digital signatures.
- Certificates.
- Pre-established trusted public keys.
- An authenticated protocol handshake.

ECDH and ECDSA serve different cryptographic purposes.

## 7. Elliptic Curve Digital Signature Algorithm

### 7.1 ECDSA Purpose

ECDSA provides digital signatures.

A signature allows a verifier to establish that a message was signed using the private key corresponding to a trusted public key.

It provides:

- Message integrity.
- Cryptographic authentication.
- Evidence of possession of the signing private key.

It does not provide message confidentiality.

### 7.2 Signature Generation

Let:

- `d` be the private key.
- `z` be the message digest interpreted as an integer.
- `k` be a fresh signing nonce.
- `G` be the generator.
- `n` be the generator order.

Calculate:

`R = kG`

Then:

`r = R.x mod n`

And:

`s = k⁻¹(z + rd) mod n`

The signature consists of:

`(r, s)`

Both components must satisfy:

`1 ≤ r < n`

`1 ≤ s < n`

### 7.3 Signature Verification

The verifier receives:

- The message.
- The signature.
- The signer's public key.

Calculate:

`w = s⁻¹ mod n`

`u1 = zw mod n`

`u2 = rw mod n`

Then:

`X = u1G + u2Q`

The signature is valid if:

`X ≠ O`

And:

`X.x mod n = r`

A signature must be verified against the exact message or authenticated message digest associated with the request.

### 7.4 Nonce Security

ECDSA nonce generation is security-critical.

A weak or reused nonce can reveal the private signing key.

The nonce must be unpredictable, unique, and correctly generated.

Deterministic nonce generation is standardized by RFC 6979.

The educational implementations use cryptographically secure random nonces, not RFC 6979.

Production systems should use a vetted ECDSA implementation with safe nonce handling.

### 7.5 Low-S Signatures

ECDSA signatures can have mathematically equivalent representations.

Low-S normalization enforces:

`s ≤ n / 2`

This reduces signature malleability in systems that require canonical signatures.

The Python, JavaScript, C++, and Java implementations apply this convention.

The verification functions reject signatures outside the accepted range.

## 8. Distinctions Between ECC Algorithms

ECDH and ECDSA use elliptic-curve mathematics but solve different problems.

| Characteristic | ECDH | ECDSA |
|---|---|---|
| Main purpose | Key agreement | Digital signatures |
| Private key use | Shared-secret computation | Signature generation |
| Public key use | Shared-secret computation | Signature verification |
| Primary output | Shared secret point | Signature pair |
| Confidentiality | Not directly | No |
| Integrity | Requires an authenticated protocol | Supports message integrity verification |
| Authentication | Requires additional authentication | Supports signer authentication when the public key is trusted |

An ECC-enabled application may use both algorithms, but key separation and purpose restrictions should be considered.

Using one key pair for unrelated operations can increase the impact of a compromise and create protocol-confusion risks.

## 9. Key Management and Lifecycle

Cryptographic security depends on key management as well as mathematical correctness.

A complete lifecycle includes:

    Key Generation
          |
          v
    Key Registration
          |
          v
    Public-Key Validation
          |
          v
    Active Use
          |
          +------> Rotation
          |           |
          |           v
          |       Replacement
          |
          +------> Revocation
          |
          +------> Expiration

### 9.1 Key Registration

Registration associates a public key with an identity.

A key record should contain:

- Key identifier.
- Identity identifier.
- Public key.
- Curve identifier.
- Key purpose.
- Key version.
- Fingerprint.
- Creation time.
- Expiration time.
- Lifecycle status.

Private keys should be maintained in appropriately protected key-storage systems.

### 9.2 Key Rotation

Rotation replaces an existing key with a new key.

A replacement should be validated before the original key is retired.

The implementation models predecessor relationships and key versions.

A production rotation process must also consider:

- Existing sessions.
- Outstanding signatures.
- Certificate replacement.
- Peer synchronization.
- Backward compatibility.
- Audit records.

Historical signatures must not be interpreted as invalid merely because the signing key has subsequently been rotated.

Their verification depends on the applicable historical trust and revocation policy.

### 9.3 Revocation

Revocation makes a key unavailable for future authorized operations.

Possible causes include:

- Private-key compromise.
- Device loss.
- Personnel separation.
- Cryptographic algorithm deprecation.
- Policy violations.
- Suspected nonce leakage.

Revocation should be recorded with a timestamp, reason, authority, and audit reference.

### 9.4 Expiration

Expiration limits the period during which a key can be used.

A key can be mathematically valid while being operationally ineligible because its validity period has ended.

Cryptographic validity and organizational authorization are separate checks.

## 10. Python Implementation

The Python program is a mathematical and workflow-oriented implementation.

### 10.1 Main Components

| Component | Responsibility |
|---|---|
| `Point` | Represents elliptic-curve coordinates |
| `ECCKeyPair` | Associates private and public keys |
| `point_add()` | Performs group addition |
| `scalar_multiply()` | Implements double-and-add |
| `is_on_curve()` | Checks curve membership |
| `encode_public_key()` | Serializes compressed and uncompressed points |
| `decode_public_key()` | Validates and reconstructs points |
| `derive_shared_secret()` | Performs ECDH |
| `ecdsa_sign()` | Generates signatures |
| `ecdsa_verify()` | Verifies signatures |
| `KeyRegistry` | Manages key lifecycle |

### 10.2 Python-Specific Design

The implementation uses:

- Dataclasses for structured domain objects.
- Enums for key states.
- Dictionaries for key registration.
- Immutable point records.
- Type annotations.
- Explicit exception classes.
- Standard-library cryptographic randomness.
- HMAC and SHA-256.
- Unit tests.

The `Point` dataclass is frozen to prevent accidental coordinate modification.

The key registry maintains mutable lifecycle state separately from the mathematical point representation.

### 10.3 Validation

The demonstration tests:

- Generator membership.
- Group identity.
- Point inverse.
- Generator order.
- Public-key serialization.
- ECDH agreement.
- ECDSA verification.
- Modified-message rejection.
- Invalid private keys.
- Key rotation.
- Revocation.

The unit tests use Python's `unittest` framework.

## 11. JavaScript Implementation

The JavaScript implementation focuses on event-driven cryptographic operations.

### 11.1 Main Components

| Component | Responsibility |
|---|---|
| `CURVE` | Immutable curve configuration |
| `modPow()` | Modular exponentiation |
| `modInverse()` | Extended Euclidean arithmetic |
| `pointAdd()` | Elliptic-curve point addition |
| `scalarMultiply()` | Scalar multiplication |
| `generateKeyPair()` | Key generation |
| `deriveSharedSecret()` | ECDH |
| `ecdsaSign()` | Signature creation |
| `ecdsaVerify()` | Signature verification |
| `VerificationService` | Asynchronous verification queue |
| `KeyManager` | Event-driven key lifecycle |

### 11.2 JavaScript-Specific Design

JavaScript uses `BigInt` because ordinary `Number` values cannot accurately represent arbitrary 256-bit integers.

The implementation uses:

- `Map` for key registries.
- `EventEmitter` for lifecycle notifications.
- `Promise` for asynchronous verification.
- `Buffer` for binary encoding.
- Node.js cryptographic randomness.
- Explicit exception classes.

The `VerificationService` processes queued verification requests and returns promises.

This design separates request submission from the verification workflow.

### 11.3 Event-Driven Key Management

The key manager emits events for:

- Registration.
- Rotation.
- Revocation.

These events can be connected to audit logging, monitoring, alerting, and operational workflows.

Event notification does not replace durable audit storage.

A production application should persist lifecycle changes transactionally before reporting a completed operation.

## 12. C++17 Implementation

The C++ program focuses on finite-field operations and a device-network security scenario.

### 12.1 Main Components

| Component | Responsibility |
|---|---|
| `Curve` | Stores mathematical parameters |
| `Point` | Represents a group element |
| `EllipticCurve` | Implements point arithmetic |
| `KeyGenerator` | Creates demonstration key pairs |
| `DeviceRegistry` | Tracks device keys |
| `NetworkPolicy` | Defines gateway restrictions |
| `NetworkGateway` | Evaluates authorization |
| `Signature` | Represents ECDSA components |

### 12.2 C++17-Specific Design

The implementation uses:

- Structs for mathematical values.
- Classes for domain services.
- `enum class` for lifecycle states.
- `std::map` for device registration.
- `std::optional`-compatible design principles.
- STL containers.
- Standard exceptions.
- Strongly typed interfaces.

The small field allows arithmetic to be implemented with standard integer types.

This removes the need for external multiprecision dependencies but makes the implementation unsuitable for production cryptography.

### 12.3 Gateway Authorization

The gateway checks:

1. Public-key validity.
2. Signature validity.
3. Message integrity.
4. Required network policy.

The device registry separately tracks whether a key is active.

This distinction is important: a valid signature from a revoked key must not automatically authorize a new operation.

## 13. Java 17 Enterprise Implementation

The Java implementation emphasizes domain modeling, enterprise authorization, and explicit policy evaluation.

### 13.1 Main Components

| Component | Responsibility |
|---|---|
| `Point` record | Immutable mathematical point |
| `KeyPairData` record | Cryptographic key pair |
| `Signature` record | ECDSA signature |
| `KeyMetadata` record | Key lifecycle metadata |
| `KeyRegistry` | Enterprise key management |
| `ApprovalPolicy` | Authorization rules |
| `ApprovalRequest` | Business authorization request |
| `AuthorizationService` | Policy enforcement |
| `AsyncVerificationService` | Background signature verification |

### 13.2 Java Records

Java 17 records provide concise immutable data structures.

They are useful for:

- Coordinates.
- Key metadata.
- Signatures.
- Authorization requests.
- Policy definitions.

Immutable records reduce accidental changes to security-sensitive data.

The registry maintains mutable lifecycle state through controlled replacement of immutable metadata records.

### 13.3 Enterprise Authorization

The authorization service evaluates:

- Request validity.
- Approved curve selection.
- Minimum approval count.
- Active key requirements.
- Signature validity.

The approval count represents an organizational authorization condition.

It does not replace cryptographic signature verification.

An authorization request can contain a valid signature and still fail because it does not satisfy the organizational policy.

### 13.4 Asynchronous Verification

`CompletableFuture` allows verification work to be executed separately from the calling thread.

The executor manages a bounded number of worker threads.

The service also provides explicit shutdown behavior.

Production services should additionally enforce request limits, timeouts, cancellation, and operational monitoring.

## 14. PostgreSQL Implementation

The PostgreSQL script models the relational and governance aspects of an ECC-enabled enterprise system.

It separates cryptographic artifacts from organizational identities and authorization decisions.

### 14.1 Database Relationship

    Organizations
         |
         v
      Identities
         |
         v
    Cryptographic Keys
         |
         +-------------------+
         |                   |
         v                   v
    ECDH Sessions      Digital Signatures
                             |
                             v
                   Authorization Requests
                             |
                             v
                   Authorization Approvals
                             |
                             v
                    Eligibility Evaluation
                             |
                             v
                   Authorization Processing
                             |
                             v
                      Audit Records

### 14.2 Main Tables

| Table | Purpose |
|---|---|
| `organizations` | Organizational ownership |
| `identities` | Users, devices, and services |
| `elliptic_curves` | Approved curve catalog |
| `cryptographic_keys` | Public-key inventory |
| `key_exchange_sessions` | ECDH session metadata |
| `digital_signatures` | Signature verification records |
| `authorization_policies` | Organizational security rules |
| `authorization_requests` | Authorization workflow |
| `authorization_approvals` | Independent approval decisions |
| `cryptographic_audit` | Security event history |

### 14.3 Integrity Constraints

The database uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated states.
- Partial indexes.
- Trigger-based validation.

These controls enforce relational consistency and prevent several invalid workflow transitions.

For example, a cryptographic key cannot be registered against a prohibited or deprecated curve through the registration trigger.

The trigger also checks the expected SEC1 encoding length.

These structural checks do not prove that the supplied coordinates represent a mathematically valid point.

That validation remains the responsibility of the cryptographic service.

### 14.4 Key Rotation Procedure

`rotate_key()`:

1. Locks the original key record.
2. Confirms that the original key is active.
3. Creates a replacement key.
4. Links the replacement to its predecessor.
5. Increments the key version.
6. Changes the previous key to `ROTATED`.

The operation executes within the calling database transaction.

### 14.5 Signature Verification Records

The database records:

- Signer key.
- Message digest.
- Digest algorithm.
- Signature algorithm.
- Signature encoding.
- Signature bytes.
- Verification status.
- Verification service.
- Verification timestamp.

The database does not perform ECDSA point arithmetic.

A trusted external verifier must calculate the mathematical result and submit an authenticated verification outcome.

The sample signatures are workflow fixtures, not mathematically generated signatures.

### 14.6 Authorization Eligibility

The `authorization_eligibility` view evaluates:

- Request state.
- Expiration.
- Requester status.
- Signing-key status.
- Curve status.
- Signature verification status.
- Required approval count.
- Rejected approval decisions.

The view returns a specific eligibility result.

`process_authorization()` then performs the state transition for eligible, expired, or explicitly rejected requests.

The row lock prevents concurrent processing of the same authorization request.

### 14.7 Performance Considerations

Indexes support common operational queries.

Examples include:

- Active keys by identity.
- Keys by curve and status.
- Pending ECDH sessions.
- Signatures by signer.
- Pending authorization requests.
- Approvals by request.
- Audit events by organization and timestamp.

Partial indexes avoid indexing rows that are irrelevant to frequently executed active-workflow queries.

Index design should be evaluated against actual query plans and production data distribution.

## 15. Security Considerations

### 15.1 Private-Key Protection

Private keys are the most sensitive ECC assets.

They should not be:

- Stored as plaintext database fields.
- Written to application logs.
- Exposed through debugging output.
- Embedded in source code.
- Included in exception messages.
- Transmitted through unprotected channels.

Production key storage should use appropriately protected cryptographic hardware or key-management infrastructure.

Examples include Hardware Security Modules (HSMs) and managed Key Management Services (KMS).

### 15.2 Side-Channel Attacks

An implementation may reveal information about secret values through:

- Execution time.
- Memory access patterns.
- Cache behavior.
- Power consumption.
- Electromagnetic emissions.

Ordinary double-and-add implementations can expose scalar-dependent execution behavior.

The educational Python, JavaScript, C++, and Java arithmetic implementations are not designed to resist side-channel attacks.

Production implementations should use vetted constant-time cryptographic primitives where applicable.

### 15.3 Invalid-Curve and Point-Validation Attacks

Accepting invalid points can expose private-key information or compromise protocol assumptions.

Every externally supplied public key must be validated before use.

Validation must include the correct curve, coordinate range, and subgroup requirements.

### 15.4 Nonce Reuse

Reusing an ECDSA nonce can reveal the signing private key.

Nonce generation must be secure.

RFC 6979 provides deterministic nonce generation for ECDSA, while carefully designed random nonce generation is another valid approach.

### 15.5 Replay Attacks

A valid signed request may be replayed.

Application protocols should include:

- Unique request identifiers.
- Nonces.
- Timestamps.
- Expiration.
- Session identifiers.
- Context binding.
- Replay-detection storage.

The signature should cover the complete security-relevant request representation.

### 15.6 Algorithm Downgrade

An attacker may attempt to force communication participants to use weaker cryptographic parameters.

Applications should enforce approved curve and algorithm policies rather than accepting arbitrary client-selected parameters.

Deprecated curves should be removed according to a controlled migration process.

### 15.7 Cryptographic Agility

A secure architecture should allow algorithm migration without redesigning the complete application.

Algorithm identifiers, key versions, certificate profiles, and policy records should be explicitly maintained.

This becomes particularly important when cryptographic requirements change.

### 15.8 Quantum Computing Considerations

Shor's algorithm can solve the integer-factorization and discrete-logarithm problems underlying conventional public-key cryptography, including ECC, on a sufficiently capable fault-tolerant quantum computer.

ECC should therefore not be treated as quantum-resistant.

Organizations planning long-lived confidentiality should assess post-quantum key-establishment and signature mechanisms.

NIST standardized the first major post-quantum cryptographic standards in 2024, including ML-KEM, ML-DSA, and SLH-DSA.

Migration planning should consider cryptographic inventory, protocol compatibility, data-retention periods, and hybrid transition strategies.

## 16. Testing and Failure Handling

The five implementations cover different classes of failures.

| Failure condition | Expected handling |
|---|---|
| Private key equals zero | Reject |
| Private key outside subgroup order | Reject |
| Invalid public-key coordinates | Reject |
| Point not on curve | Reject |
| Point at infinity used as public key | Reject |
| ECDH produces invalid shared point | Reject |
| Modified signed message | Verification fails |
| Invalid ECDSA components | Verification fails |
| Revoked key | Deny new authorized operations |
| Rotated key | Prevent new use of previous key |
| Expired request | Deny authorization |
| Unsupported curve | Reject according to policy |
| Insufficient approvals | Keep request ineligible |
| Duplicate key identifier | Reject registration |
| Invalid signature record | Prevent successful authorization |

Testing should cover both mathematical correctness and operational state transitions.

Useful mathematical properties include:

- `P + O = P`
- `P + (-P) = O`
- `nG = O`
- `aG + bG = (a+b)G`
- ECDH produces the same shared point for both participants.
- A valid ECDSA signature verifies against its original message.
- A modified message does not verify.

Property-based testing can extend these checks across large collections of valid and invalid inputs.

## 17. Performance and Complexity

Let `k` represent the scalar bit length.

| Operation | Approximate computational characteristics |
|---|---|
| Modular addition | Constant number of field operations |
| Modular multiplication | Depends on integer size |
| Modular inverse | Extended Euclidean algorithm |
| Point addition | Constant number of field operations |
| Point doubling | Constant number of field operations |
| Scalar multiplication | O(k) point operations |
| ECDH | One scalar multiplication |
| ECDSA signing | Scalar multiplication and modular arithmetic |
| ECDSA verification | Two scalar multiplications and point addition |

The double-and-add method reduces the number of point additions compared with repeated addition.

More advanced implementations use window methods, signed-digit representations, precomputation, and multi-scalar multiplication.

These techniques can improve throughput but must preserve secure handling of secret scalars.

Performance comparisons between the five implementations would not be meaningful without accounting for:

- Different integer arithmetic implementations.
- Different runtime environments.
- Curve parameters.
- Compiler optimizations.
- Cryptographic provider implementations.
- Side-channel protection.
- Hardware acceleration.

The C++ implementation is not comparable in security or performance to the 256-bit implementations because it deliberately uses a tiny field.

## 18. Practical Applications

ECC is used in several important security domains.

| Application | ECC mechanism | Purpose |
|---|---|---|
| TLS | ECDHE and ECDSA | Secure key establishment and authentication |
| Digital certificates | ECDSA | Certificate signatures |
| Secure messaging | ECDH-based protocols | Shared-secret establishment |
| Blockchain systems | Elliptic-curve signatures | Transaction authorization |
| Device authentication | ECC public keys | Device identity verification |
| Secure boot | Digital signatures | Firmware authenticity |
| IoT security | ECC key agreement and signatures | Efficient device security |
| Enterprise identity | ECC certificates and signatures | Authentication and integrity |

The exact algorithm, curve, and key lifecycle depend on the protocol and application requirements.

## 19. Standards and Protocol Distinctions

The following standards define important aspects of ECC systems:

| Standard | Subject |
|---|---|
| SEC 1 | Elliptic Curve Cryptography |
| SEC 2 | Recommended Elliptic Curve Domain Parameters |
| FIPS 186-5 | Digital Signature Standard |
| NIST SP 800-56A | Discrete Logarithm-Based Key-Establishment Schemes |
| RFC 6090 | Fundamental Elliptic Curve Cryptography Algorithms |
| RFC 6979 | Deterministic ECDSA Nonce Generation |
| RFC 7748 | X25519 and X448 |
| RFC 8032 | EdDSA |
| RFC 5869 | HKDF |
| RFC 8446 | TLS 1.3 |

Important distinctions:

- ECDSA is a digital-signature algorithm.
- ECDH is a key-agreement mechanism.
- X25519 is a Diffie-Hellman function based on Curve25519.
- Ed25519 is a digital-signature scheme based on Edwards-curve cryptography.
- HKDF is a key derivation function, not an elliptic-curve algorithm.
- TLS 1.3 defines protocol behavior and cryptographic integration rather than a single ECC algorithm.

X25519 and Ed25519 should not be treated as interchangeable with secp256k1 ECDH and ECDSA.

## 20. Implementation Limitations

These deliverables prioritize mathematical understanding, executable examples, and software architecture.

They are not substitutes for production cryptographic providers.

| Implementation | Principal limitation |
|---|---|
| Python | Variable-time big-integer arithmetic and educational nonce generation |
| JavaScript | BigInt arithmetic is not constant-time |
| C++17 | Tiny insecure curve and demonstration scalars |
| Java 17 | Educational BigInteger arithmetic and random nonce generation |
| PostgreSQL | Stores and evaluates cryptographic workflow metadata but does not independently verify curve mathematics |

The database also assumes that trusted application services correctly authenticate their interactions and report signature-verification results.

A production deployment should introduce cryptographic provider integration, protected private-key storage, certificate validation, secure session protocols, robust audit controls, and operational key-revocation procedures.

The implementations establish the mathematical and architectural distinctions needed to understand how ECC fits into a secure software system.
