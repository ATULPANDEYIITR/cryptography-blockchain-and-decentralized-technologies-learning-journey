# Comparing RSA, Diffie-Hellman and Elliptic Curve Cryptography

## 1. Introduction

RSA, Diffie-Hellman (DH) and Elliptic Curve Cryptography (ECC) are three important approaches to public-key cryptography.

They solve related but different cryptographic problems.

- RSA provides public-key encryption and digital signatures.
- Diffie-Hellman establishes a shared secret between communicating parties.
- ECC provides a mathematical framework for public-key cryptographic constructions, including elliptic curve key agreement and digital signatures.

Their security depends on different mathematical problems, parameter choices, implementation quality and protocol design.

A fundamental distinction is that key establishment, encryption and authentication are separate cryptographic functions. A successful key exchange does not automatically authenticate the participants or encrypt application data.

## 2. Mathematical Foundations

### 2.1 RSA: Integer Factorization

RSA is based on the computational difficulty of factoring a sufficiently large composite integer into its prime factors.

Two large primes are selected:

- \(p\)
- \(q\)

The RSA modulus is:

\[
n=pq
\]

Euler's totient for distinct prime factors is:

\[
\phi(n)=(p-1)(q-1)
\]

A public exponent \(e\) is selected such that:

\[
\gcd(e,\phi(n))=1
\]

The private exponent \(d\) satisfies:

\[
ed\equiv 1\pmod{\phi(n)}
\]

The public key consists of:

\[
(n,e)
\]

The private key contains \(d\), together with additional private parameters used by optimized implementations.

The mathematical encryption operation is:

\[
c=m^e\bmod n
\]

The corresponding decryption operation is:

\[
m=c^d\bmod n
\]

These equations describe textbook RSA. They do not constitute a secure encryption scheme by themselves.

Production encryption requires an approved encoding construction such as RSA-OAEP.

**Important RSA characteristics**

- Public-key encryption is supported.
- Digital signatures are supported.
- The public modulus is comparatively large.
- Private-key operations can use the Chinese Remainder Theorem for improved performance.
- Private-key material requires strong protection.
- Raw RSA is deterministic and unsuitable for direct production encryption.
- RSA does not provide forward secrecy through ordinary static-key encryption.

### 2.2 Diffie-Hellman: Discrete Logarithm

Diffie-Hellman establishes a shared secret without transmitting that secret directly.

It operates in a finite mathematical group.

The participants agree on:

- A suitable group.
- A generator \(g\).
- A group parameter, commonly a prime modulus \(p\) in traditional finite-field DH.

Alice selects a private value:

\[
a
\]

Bob selects another private value:

\[
b
\]

Their public values are:

\[
A=g^a\bmod p
\]

\[
B=g^b\bmod p
\]

Alice computes:

\[
S_A=B^a\bmod p
\]

Bob computes:

\[
S_B=A^b\bmod p
\]

Both obtain:

\[
S=g^{ab}\bmod p
\]

The shared value can subsequently be processed through a key-derivation function.

**Important Diffie-Hellman characteristics**

- Its primary function is key agreement.
- It does not directly encrypt application messages.
- It does not independently authenticate participants.
- An unauthenticated exchange is vulnerable to man-in-the-middle attacks.
- Suitable finite-field parameters are essential.
- Ephemeral DH can provide forward secrecy when correctly implemented.

Finite-field DH and elliptic curve DH are related key-agreement constructions, but they operate in different mathematical groups.

### 2.3 ECC: Elliptic Curve Cryptography

ECC uses algebraic operations on points belonging to an elliptic curve over a finite field.

A common short Weierstrass curve has the equation:

\[
y^2=x^3+ax+b\pmod p
\]

The curve must be nonsingular.

For a prime field, the discriminant condition is:

\[
4a^3+27b^2\not\equiv 0\pmod p
\]

The curve has a point at infinity, which acts as the identity element.

The main operations include:

- Point addition.
- Point doubling.
- Scalar multiplication.

Scalar multiplication is expressed as:

\[
Q=dG
\]

Where:

- \(G\) is the generator point.
- \(d\) is a private scalar.
- \(Q\) is the public point.

The reverse problem, determining \(d\) from \(G\) and \(Q\), is the elliptic curve discrete logarithm problem.

Two important ECC constructions are:

**ECDH**

Elliptic Curve Diffie-Hellman performs key agreement.

**ECDSA**

Elliptic Curve Digital Signature Algorithm provides digital signatures.

ECC is not one individual encryption algorithm. It is a family of cryptographic techniques based on elliptic curve mathematics.

## 3. Fundamental Differences

| Property | RSA | Finite-field DH | ECC |
|---|---|---|---|
| Mathematical foundation | Integer factorization | Discrete logarithm | Elliptic curve discrete logarithm |
| Primary purpose | Encryption and signatures | Key agreement | Key agreement and signatures |
| Direct encryption | Yes, with RSA-OAEP | No | Not by itself |
| Digital signatures | RSA-PSS | No | ECDSA |
| Shared-secret establishment | Not its primary function | Yes | Yes, through ECDH |
| Typical parameters | 3072-bit modulus | 3072-bit or larger group | 256-bit or stronger curve |
| Public-key size | Large | Large | Relatively small |
| Forward secrecy | Not with ordinary static RSA encryption | Possible with ephemeral DH | Possible with ephemeral ECDH |
| Quantum resistance | No | No | No |

## 4. Classical Security Equivalence

Different algorithms cannot be compared by simply comparing their parameter lengths.

A 256-bit elliptic curve key does not have the same security as a 256-bit RSA modulus.

Approximate classical security equivalences include:

| Security strength | RSA modulus | Finite-field DH modulus | ECC |
|---|---:|---:|---|
| Approximately 112 bits | 2048 bits | 2048 bits | 224 bits |
| Approximately 128 bits | 3072 bits | 3072 bits | 256 bits |
| Approximately 192 bits | 7680 bits | 7680 bits | 384 bits |
| Approximately 256 bits | 15360 bits | 15360 bits | 512 bits |

These are approximate comparisons based on suitable standardized parameters, not universal guarantees.

The finite-field DH estimates assume appropriately selected groups and parameters. A large modulus alone does not establish that a group is secure.

The Python, JavaScript, C++ and Java examples use different parameter sizes for educational and practical reasons. Their small mathematical demonstrations must not be confused with production security configurations.

## 5. RSA Encryption and Digital Signatures

RSA supports two distinct operational purposes.

### 5.1 RSA-OAEP

RSA-OAEP is a randomized encoding scheme for RSA encryption.

It addresses important weaknesses of textbook RSA by incorporating a secure encoding construction.

RSA encryption is generally unsuitable for large application documents because the maximum plaintext size is restricted by the modulus and encoding overhead.

A common architecture is:

1. Generate a random symmetric encryption key.
2. Encrypt the application data using authenticated symmetric encryption.
3. Encrypt or wrap the symmetric key using RSA-OAEP.
4. Transmit the encrypted data and encrypted key.
5. The recipient recovers the symmetric key.
6. The recipient authenticates and decrypts the application data.

### 5.2 RSA-PSS

RSA-PSS is a probabilistic digital-signature encoding scheme.

The sender signs a document using the private key.

The recipient verifies the signature using the public key.

A valid signature establishes that the signature corresponds to the supplied public key and message under the verification algorithm.

It does not independently establish that the public key belongs to a particular person or organization. That requires an appropriate identity-binding mechanism.

RSA-OAEP and RSA-PSS have different purposes and must not be interchanged.

## 6. Diffie-Hellman Key Agreement

DH is a mechanism for establishing common secret material.

Its central engineering requirement is secure public-key exchange.

A successful mathematical agreement does not prove that the communicating parties are genuine.

### 6.1 Ephemeral Diffie-Hellman

Ephemeral DH generates temporary private values for individual sessions or appropriately scoped exchanges.

Advantages include:

- Session-specific key material.
- Improved compromise isolation.
- Forward secrecy when the ephemeral private values are securely discarded.
- Reduced dependence on long-term encryption keys for historical session confidentiality.

### 6.2 Authentication Requirements

A secure DH protocol needs an authentication mechanism.

Possible approaches include:

- Digital signatures.
- Authenticated certificates.
- Pre-shared authentication keys.
- An established authenticated key-exchange protocol.

Without authentication, an attacker can establish separate shared secrets with the two legitimate participants and relay their communications.

### 6.3 Finite-Field Parameters

The selection of group parameters is important.

Implementations must consider:

- Modulus size.
- Generator properties.
- Group order.
- Subgroup validation.
- Public-value validation.
- Approved standardized groups.

A mathematically valid public value is not automatically a secure public value.

## 7. Elliptic Curve Constructions

### 7.1 ECDH

ECDH performs key agreement using elliptic curve points.

Alice and Bob generate private scalars and corresponding public points.

The shared point is:

\[
S_A=aQ_B
\]

\[
S_B=bQ_A
\]

Both obtain the same shared point.

The shared point's coordinate material is not normally used directly as an application encryption key.

A key-derivation function processes the shared secret into application-specific cryptographic keys.

### 7.2 ECDSA

ECDSA provides digital signatures.

Its security depends on the elliptic curve parameters and the correct generation of a secret per-signature nonce.

Nonce reuse or nonce leakage can expose the private signing key.

Production ECDSA implementations must use approved nonce-generation procedures and secure cryptographic libraries.

### 7.3 Curve Selection

Examples of standardized curves include:

| Curve | Approximate security strength | Common purpose |
|---|---:|---|
| P-256 | 128 bits | ECDH and ECDSA |
| P-384 | 192 bits | ECDH and ECDSA |
| P-521 | Approximately 256 bits | ECDH and ECDSA |
| Curve25519 | Approximately 128 bits | X25519 key agreement |
| Ed25519 | Approximately 128 bits | Digital signatures |

X25519 and Ed25519 are different constructions, despite both being associated with the Curve25519 family.

The examples use P-256 for standardized ECDH demonstrations.

## 8. Performance and Resource Considerations

Performance depends on hardware, implementation, parameter choices, protocol design and cryptographic library.

General engineering characteristics:

| Consideration | RSA | Finite-field DH | ECC |
|---|---|---|---|
| Public-key representation | Large | Large | Small |
| Private-key operations | Relatively expensive | Exponentiation | Scalar multiplication |
| Public-key exchange size | Large | Large | Small |
| Memory requirements | Generally higher | Generally higher | Generally lower |
| Embedded-system suitability | Depends on workload | Depends on workload | Often favorable |
| Signature verification | Often efficient | Not applicable | Depends on curve and implementation |
| Key agreement | Not primary purpose | Native | Native through ECDH |

These characteristics are architectural observations rather than guaranteed benchmark results.

The Python implementation uses straightforward mathematical operations and does not attempt performance optimization.

The C++ implementation uses modular exponentiation and double-and-add elliptic curve multiplication.

The JavaScript and Java implementations delegate cryptographic arithmetic to established runtime providers.

## 9. Hybrid Cryptographic Architecture

Modern secure communication systems frequently combine public-key cryptography with symmetric cryptography.

Public-key operations establish or protect key material.

Symmetric encryption protects application data.

A representative architecture is:

Plaintext
    |
    v
Authenticated Key Exchange
    |
    v
Shared Secret
    |
    v
HKDF Key Derivation
    |
    v
AES-256-GCM Session Key
    |
    v
Authenticated Encryption
    |
    v
Ciphertext + Nonce + Authentication Tag

### 9.1 HKDF

HKDF is a key-derivation function based on HMAC.

It provides a structured way to derive cryptographic keys from shared secret material.

Its stages are:

- Extract: produce pseudorandom key material.
- Expand: derive one or more output keys using application-specific context.

Different applications and protocol purposes should use appropriately separated key material.

### 9.2 AES-GCM

AES-GCM is an authenticated encryption with associated data construction.

It provides:

- Confidentiality.
- Integrity.
- Authentication of ciphertext.
- Authentication of associated metadata.

The nonce must not repeat under the same encryption key.

Authentication failure must cause decryption to fail rather than expose unauthenticated plaintext.

### 9.3 Authentication and Forward Secrecy

Hybrid encryption does not automatically provide peer authentication.

A complete protocol must establish the identity of participants and authenticate the exchanged public values.

Forward secrecy requires an appropriate ephemeral key-exchange construction and proper lifecycle management of temporary private keys.

## 10. Python Implementation

The Python file develops the mathematical foundations before introducing security-policy evaluation.

### 10.1 Mathematical Utilities

The implementation provides:

- Extended Euclidean algorithm.
- Modular inverse calculation.
- Modular exponentiation through Python's built-in `pow`.
- Trial-division primality testing.

The modular inverse is necessary for calculating the RSA private exponent.

### 10.2 RSA Engine

The `EducationalRSA` class implements:

- Prime validation.
- Public and private exponent calculation.
- Integer encryption.
- Integer decryption.
- Educational signing and verification.

The implementation intentionally uses raw modular RSA to demonstrate the mathematical relationship.

Its signature mechanism is not RSA-PSS and must not be used for production authentication.

### 10.3 DH Engine

The `EducationalDiffieHellman` class provides:

- Parameter validation.
- Private-value generation.
- Public-value generation.
- Shared-secret calculation.

Python's `secrets` module supplies operating-system-backed random values for the educational demonstration.

### 10.4 ECC Engine

The `EducationalECC` class models a prime-field elliptic curve.

It implements:

- Curve validation.
- Point validation.
- Point addition.
- Point doubling.
- Point at infinity.
- Double-and-add scalar multiplication.

The selected small curve makes the arithmetic understandable and allows the generator order to be tested.

The implementation is not constant-time and is not suitable for secret-key operations in production.

### 10.5 Cryptographic Policy

`CryptographicPolicy` evaluates:

- Minimum parameter sizes.
- Approved parameters.
- Algorithm-purpose compatibility.
- Peer authentication.

The policy separates algorithm selection from the mathematical operation itself.

### 10.6 Testing

Assertions verify:

- Modular inverse calculations.
- RSA encryption and decryption.
- DH shared-secret agreement.
- ECC shared-point agreement.
- Generator-order properties.

These tests verify the educational mathematics, not compliance with production cryptographic standards.

## 11. JavaScript Implementation

The JavaScript implementation takes a runtime-oriented engineering approach.

It uses Node.js built-in cryptographic functionality instead of implementing the underlying cryptographic mathematics manually.

### 11.1 RSA Service

`RSAService` uses:

- RSA-3072.
- Public exponent 65537.
- RSA-OAEP with SHA-256.
- RSA-PSS with SHA-256.

It separates encryption, decryption, signing and verification.

This distinction is important because encryption and digital signatures have different security objectives.

### 11.2 DH Service

`DHService` uses a standardized finite-field group.

It exposes public-key exchange and shared-secret calculation.

Invalid public values and failed agreement operations are handled through explicit exceptions.

### 11.3 ECDH Service

`ECDHService` uses the `prime256v1` curve.

It provides:

- Private-key generation.
- Public-key extraction.
- Shared-secret derivation.

The implementation delegates point validation and arithmetic to the runtime cryptographic provider.

### 11.4 Asynchronous Workflow

`performKeyAgreement` coordinates two independent participants.

It verifies that both participants derive identical shared secrets.

It then uses HKDF to derive application-specific session keys.

This structure separates protocol coordination from individual algorithm implementations.

### 11.5 Authenticated Encryption

`AEADService` uses AES-256-GCM.

The encrypted packet contains:

- Algorithm identifier.
- Nonce.
- Ciphertext.
- Authentication tag.

Associated data is authenticated but not encrypted.

The implementation explicitly tests metadata modification and authentication failure.

### 11.6 Event-Driven Governance

`CryptographicPolicy` extends Node.js `EventEmitter`.

After evaluating a cryptographic configuration, it emits a `policyEvaluated` event.

This allows policy decisions to be connected to:

- Security audit logging.
- Deployment workflows.
- Monitoring systems.
- Compliance reporting.

## 12. C++17 Implementation

The C++ program emphasizes explicit mathematical operations, data structures and cryptographic deployment decisions.

### 12.1 Modular Arithmetic

The implementation provides:

- Modular normalization.
- Modular multiplication.
- Binary modular exponentiation.
- Primality testing.
- Extended Euclidean modular inverse.

The `__int128` intermediate type prevents overflow for the small demonstration values used in the program.

It is a compiler-supported extension commonly available in GCC and Clang, rather than a universally portable C++17 integer type.

### 12.2 RSA Engine

`RSAEngine` calculates:

- RSA modulus.
- Euler's totient.
- Public exponent.
- Private exponent.

It then verifies the integer encryption and decryption relationship.

### 12.3 DH Engine

`DiffieHellmanEngine` validates the demonstration group and calculates public values and shared secrets.

It rejects invalid private values and invalid peer public values.

### 12.4 Elliptic Curve Engine

`EllipticCurve` represents a prime-field curve.

The `Point` structure uses optional coordinates to represent the point at infinity.

The implementation includes:

- Curve membership validation.
- Point addition.
- Point doubling.
- Point negation through additive inverses.
- Scalar multiplication.

### 12.5 Governance Engine

The governance layer is separate from the mathematical algorithms.

`CryptographicGovernance` evaluates configuration against minimum parameter sizes and security requirements.

`DeploymentEngine` determines whether an application can be authorized for deployment.

This separation reflects a practical enterprise design:

Cryptographic mechanism
    |
    v
Configuration
    |
    v
Policy validation
    |
    v
Deployment authorization

The mathematical correctness of an algorithm does not automatically make its deployment compliant.

## 13. Java 17 Enterprise Implementation

The Java program uses the Java Cryptography Architecture and Java Cryptography Extension.

It emphasizes explicit domain types, reusable services, lifecycle management and centralized policy evaluation.

### 13.1 JCA/JCE Services

| Service | Java cryptographic mechanism |
|---|---|
| RSA key generation | `KeyPairGenerator` |
| RSA encryption | `Cipher` with OAEP |
| RSA signatures | `Signature` with PSS |
| DH agreement | `KeyAgreement` with DH |
| ECDH agreement | `KeyAgreement` with ECDH |
| Symmetric encryption | `Cipher` with AES-GCM |
| Key derivation | HMAC-SHA256-based HKDF |

The DH demonstration uses a finite-field parameter set, while ECDH uses the P-256 curve.

The demonstration's DH parameter construction is not a complete RFC 7919 named-group configuration. Production deployments should use approved standardized parameter sets supported by the selected provider.

### 13.2 Immutable Domain Records

Java records model:

- Algorithm profiles.
- Cryptographic configurations.
- Policy findings.
- Evaluation results.
- Deployment requests.
- Key inventory records.
- Encrypted packets.

These types make domain information explicit and reduce unnecessary mutable state.

### 13.3 Policy Evaluation

`CryptographicPolicy` evaluates:

- Parameter size.
- Supported algorithm purpose.
- Parameter approval.
- Peer authentication.
- Forward secrecy.

The policy returns structured findings rather than a simple boolean.

This supports auditability and makes rejected configurations easier to investigate.

### 13.4 Key Lifecycle Management

`KeyInventory` maintains key metadata and lifecycle transitions.

The lifecycle includes:

CREATED
    |
    v
ACTIVE
    |
    +----> ROTATION_REQUIRED
    |
    +----> EXPIRED
    |
    +----> REVOKED

Revoked keys cannot return to an active state.

The inventory stores metadata and identifiers, not private key material.

### 13.5 Deployment Authorization

`DeploymentAuthorizationService` checks audit completion and delegates cryptographic configuration validation to the central policy.

This prevents application deployment from being based solely on an algorithm name or key size.

## 14. PostgreSQL Implementation

The SQL file models an enterprise cryptographic governance database.

It records algorithm metadata, key inventories, application assignments, operational events and compliance evaluations.

It does not implement encryption or store secret cryptographic material.

### 14.1 Relational Structure

The principal relationships are:

Applications
    |
    +---- Repositories
    |
    +---- Cryptographic Keys
    |          |
    |          +---- Algorithm Catalog
    |          |
    |          +---- Key Lifecycle Events
    |
    +---- Key Agreement Sessions
    |          |
    |          +---- Algorithm Catalog
    |
    +---- Cryptographic Operations
    |
    +---- Application Policy Assignments
               |
               +---- Cryptographic Policies
               |
               +---- Policy Evaluations

### 14.2 Algorithm Catalog

The catalog distinguishes:

- RSA-OAEP.
- RSA-PSS.
- Finite-field DH.
- ECDH-P256.
- ECDSA-P256.

This is important because an algorithm family and an individual cryptographic construction are not interchangeable.

RSA-OAEP and RSA-PSS use RSA mathematics but have different purposes.

Likewise, ECDH and ECDSA are separate elliptic curve constructions.

### 14.3 Cryptographic Key Inventory

The `cryptographic_keys` table records:

- External key reference.
- Application ownership.
- Algorithm.
- Parameter size.
- Curve name.
- Key lifecycle.
- Creation time.
- Activation time.
- Expiration time.
- Rotation and revocation metadata.
- Protected key-storage reference.

The database stores references to key-management infrastructure rather than private keys.

### 14.4 Cryptographic Policies

The `cryptographic_policies` table defines minimum parameter sizes and deployment requirements.

An application receives a policy through `application_policy_assignments`.

This permits multiple applications to share a policy while preserving explicit policy assignments.

### 14.5 Key Agreement Sessions

The `key_agreement_sessions` table distinguishes the algorithm used for key agreement from the resulting application session.

It records:

- Initiator and responder key references.
- Algorithm.
- Authentication state.
- Forward-secrecy state.
- Key-derivation algorithm.
- Session lifecycle.
- Failure information.

The database does not store the shared secret.

### 14.6 Triggers and Lifecycle Integrity

Two triggers support key lifecycle management.

`record_key_lifecycle_change` records state transitions.

`enforce_key_lifecycle` prevents certain invalid transitions, including reactivation of revoked keys.

The `key_lifecycle_events` table provides an audit history.

In production, database permissions must also prevent unauthorized modification or deletion of audit records.

### 14.7 Policy Evaluation Functions

`evaluate_key_policy` checks:

- Whether the key exists.
- Whether the policy is active.
- Whether the key is active.
- Whether the parameter size satisfies policy.
- Whether the key has expired.

`evaluate_session_policy` checks:

- Whether the algorithm supports key agreement.
- Whether peer authentication is established.
- Whether forward secrecy is present when required.
- Whether the session is established.

Both functions return structured JSON findings.

### 14.8 Views and Reporting

The database defines three principal reporting views.

| View | Purpose |
|---|---|
| `v_algorithm_inventory` | Algorithm adoption and key distribution |
| `v_key_compliance` | Key-level policy compliance |
| `v_session_security` | Key-agreement session security status |

Additional SQL queries provide:

- Key inventory retrieval.
- Algorithm adoption aggregation.
- Failed operation identification.
- Execution-time analysis.
- Policy evaluation reporting.
- Key expiration monitoring.
- Lifecycle audit inspection.

### 14.9 Transaction Management

The SQL script demonstrates transactional key revocation.

The lifecycle transition and audit trigger execute within the same transaction.

If the transaction fails, the associated state change and audit insertion are rolled back together.

The deployment evaluation procedure creates policy-evaluation records for application keys.

## 15. Security Considerations

### 15.1 Authentication

Neither ordinary DH nor ECDH automatically proves the identity of the peer.

A production protocol must authenticate exchanged public keys using an appropriate mechanism.

### 15.2 Secure Randomness

Cryptographic private values, signing nonces, encryption keys and session nonces require secure random generation.

General-purpose pseudorandom generators are not appropriate substitutes.

### 15.3 Padding and Encoding

Textbook RSA is not production-safe.

Use:

- RSA-OAEP for encryption.
- RSA-PSS for signatures.

### 15.4 Side-Channel Protection

Implementations must account for:

- Timing differences.
- Memory access patterns.
- Power consumption.
- Cache behavior.
- Error-message leakage.
- Private-key exposure.

The Python and C++ mathematical implementations are not constant-time.

They must remain educational implementations.

### 15.5 Key Management

Cryptographic security depends on the entire key lifecycle.

Important controls include:

- Key generation.
- Key storage.
- Access authorization.
- Rotation.
- Revocation.
- Expiration.
- Backup protection.
- Audit logging.
- Secure destruction.

### 15.6 Quantum Computing

RSA, finite-field DH and conventional ECC depend on mathematical problems that sufficiently capable fault-tolerant quantum computers could solve using Shor's algorithm.

None of the three is post-quantum resistant.

Systems requiring long-term confidentiality should consider the migration to standardized post-quantum cryptographic mechanisms and appropriately designed hybrid key-establishment protocols.

## 16. Execution Requirements

### Python

- Python 3.10 or later.
- Standard library only.

Save as `crypto_comparison.py`.

Run using `python crypto_comparison.py`.

### JavaScript

- Node.js 18 or later.
- Built-in `crypto` and `events` modules.

Save as `crypto_comparison.js`.

Run using `node crypto_comparison.js`.

### C++17

- GCC or Clang with C++17 support.

Save as `crypto_comparison.cpp`.

Compile using `g++ -std=c++17 -O2 -Wall -Wextra -pedantic crypto_comparison.cpp -o crypto_comparison`.

Run using `./crypto_comparison`.

The implementation uses `__int128`, which is supported by common GCC and Clang toolchains but is not part of the portable C++17 standard.

### Java 17

- JDK 17 or later.

Save as `CryptoComparison.java`.

Compile using `javac CryptoComparison.java`.

Run using `java CryptoComparison`.

The selected Java cryptographic provider must support the requested RSA, DH, EC, HKDF-related HMAC and AES-GCM operations.

### PostgreSQL

- PostgreSQL 14 or later.

Save as `crypto_comparison.sql`.

Execute using `psql` with a database account authorized to create schemas, tables, functions, triggers, views and types.

The SQL script creates its own schema and sample records.

## 17. Implementation Limitations

The five implementations serve different technical purposes.

| Implementation | Main focus | Cryptographic execution |
|---|---|---|
| Python | Mathematical understanding and policy simulation | Educational arithmetic |
| JavaScript | Runtime cryptographic services and asynchronous workflows | Node.js cryptographic provider |
| C++17 | Mathematical algorithms and deployment governance | Educational arithmetic |
| Java 17 | Enterprise services and key lifecycle management | JCA/JCE providers |
| PostgreSQL | Inventory, policy enforcement and auditability | Metadata and governance |

The mathematical implementations use small parameters to make their calculations inspectable.

The JavaScript and Java implementations use real cryptographic primitives but do not constitute complete authenticated network protocols.

The database records declared cryptographic configurations and evaluation decisions. It cannot independently establish that application implementations actually follow those declarations.

A production deployment requires protocol-level security review, approved parameter sets, authenticated peer identities, protected key storage, operational monitoring and independent implementation testing.

The central distinction remains:

- RSA provides encryption and digital-signature constructions.
- Diffie-Hellman provides finite-field key agreement.
- ECC provides a family of constructions including ECDH and ECDSA.

Their mathematical foundations, capabilities, security requirements and operational roles must be evaluated separately.
