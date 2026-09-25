# Modern Cryptography

## 1. Introduction

Modern cryptography is the study and practical use of mathematical techniques for protecting information, communications, identities, software, and digital transactions.

A modern cryptographic system can provide several distinct security properties:

- **Confidentiality**: unauthorized parties should not be able to read protected information.
- **Integrity**: unauthorized modification should be detectable.
- **Authentication**: a system should be able to establish the identity or possession of a secret associated with a message.
- **Freshness**: an old valid message should not automatically be accepted again.
- **Non-repudiation**: digital-signature systems can provide evidence about possession of a private signing key, subject to the protocol, key management, and applicable legal context.
- **Key establishment**: communicating parties can establish shared secret material without directly transmitting the final secret in plaintext.

Cryptography is not a single algorithm. It is a collection of primitives, protocols, key-management procedures, implementation techniques, and operational controls.

The three implementations in this study deliberately demonstrate different aspects of the subject:

- The **Python implementation** progresses from mathematical and conceptual foundations to an integrated secure-message design.
- The **JavaScript implementation** uses Node.js's built-in cryptographic APIs to demonstrate practical modern primitives such as AES-256-GCM, RSA-OAEP, Ed25519, X25519, HMAC, and scrypt.
- The **C++ implementation** presents an industry-style secure document exchange architecture with explicit key management, authenticated envelopes, replay protection, validation, testing, and architectural separation.

The educational cryptographic constructions in the Python and C++ programs are explicitly labeled where they are not production primitives. The JavaScript program demonstrates actual standardized cryptographic primitives exposed by the Node.js `crypto` module.

---

## 2. Cryptography and the Security Problem

Cryptography starts with a threat model.

A threat model identifies:

1. What must be protected.
2. Who is trusted.
3. Who may attack the system.
4. What capabilities an attacker has.
5. What security properties are required.
6. What happens if a key is compromised.
7. How keys are generated, distributed, rotated, revoked, and destroyed.

For example, a banking transaction may require:

- confidentiality for sensitive transaction data,
- integrity so the amount cannot be altered,
- authentication of the communicating party,
- replay protection so the same transfer cannot be submitted twice,
- secure key management,
- auditability,
- protocol versioning,
- algorithm migration.

A cryptographic primitive cannot solve all of these requirements by itself.

---

## 3. Fundamental Terminology

### Plaintext

The original information before encryption.

Example:

`Account balance: INR 125000`

### Ciphertext

The transformed representation produced by encryption.

A secure encryption algorithm should make the ciphertext computationally infeasible to interpret without the appropriate key.

### Key

Secret or public information controlling a cryptographic operation.

Different cryptographic systems use different key structures.

### Nonce

A value intended to be used once within a defined cryptographic context.

Nonce requirements depend on the algorithm. For some authenticated-encryption constructions, nonce reuse can cause severe security failures.

### IV

An initialization vector is input used by certain cryptographic modes. The exact requirements differ between algorithms and modes.

### Salt

Random or unique public data used with password hashing or key derivation.

A salt does not need to be secret.

### Tag

An authentication value used to detect unauthorized modification.

### Digest

The fixed-size output of a cryptographic hash function.

### MAC

A Message Authentication Code provides integrity and authentication using a shared secret.

HMAC is a widely used MAC construction based on a cryptographic hash function.

### Digital Signature

An asymmetric cryptographic mechanism in which a private key creates a signature and a corresponding public key verifies it.

### Key Exchange

A protocol for establishing shared secret material between parties.

### KDF

A Key Derivation Function transforms secret material into one or more cryptographically useful keys.

---

## 4. Encoding Is Not Encryption

Encoding changes representation.

Base64 is a common encoding.

For example:

`Confidential message`

can be represented as a Base64 string.

Anyone who knows Base64 can reverse the transformation.

Encryption requires a cryptographic algorithm and key.

This distinction matters because systems sometimes incorrectly describe Base64, hexadecimal, URL encoding, or serialization as encryption.

The Python program demonstrates this distinction first.

---

## 5. Cryptographic Hash Functions

A cryptographic hash function maps arbitrary-length input to a fixed-length digest.

Important properties include:

### Determinism

The same input produces the same digest.

### Preimage resistance

Given a digest, finding an input that produces it should be computationally difficult.

### Second-preimage resistance

Given one input, finding a different input with the same digest should be computationally difficult.

### Collision resistance

Finding two different inputs with the same digest should be computationally difficult.

### Avalanche behavior

A small input change should normally produce a substantially different digest.

The Python and JavaScript programs demonstrate SHA-256.

The JavaScript implementation uses:

`crypto.createHash("sha256")`

The Python implementation uses:

`hashlib.sha256()`

Hashing is useful for:

- integrity checks,
- content addressing,
- digital-signature preprocessing,
- data structures,
- cryptographic protocols.

Hashing alone does not provide confidentiality.

---

## 6. Password Hashing

Passwords are different from random cryptographic keys.

A cryptographic key can contain hundreds of bits of unpredictable randomness.

A human password may have substantially less entropy and may be vulnerable to guessing.

Fast hashing is therefore inappropriate for password storage.

Password systems use password-specific key derivation functions such as:

- PBKDF2
- scrypt
- Argon2

These functions are deliberately more expensive than ordinary hashing.

The Python implementation demonstrates PBKDF2 with SHA-256.

The JavaScript implementation uses Node.js `scryptSync`.

A password-storage record generally needs at least:

- algorithm identifier,
- salt,
- work-factor parameters,
- derived value,
- version information when appropriate.

The salt is normally stored alongside the password verifier.

The salt is not intended to be a password.

---

## 7. Key Derivation

A KDF can derive cryptographic keys from existing secret material.

A common architecture is:

1. Establish or obtain secret material.
2. Combine it with protocol context.
3. Run a KDF.
4. Derive separate keys for separate purposes.

Separating keys by purpose helps prevent unintended cross-use.

For example, an application may derive independent values for:

- encryption,
- authentication,
- key wrapping,
- session identification.

Modern protocols often use HKDF or another standardized KDF for this purpose.

---

## 8. HMAC

HMAC is a keyed authentication mechanism based on a cryptographic hash function.

Its purpose is different from encryption.

HMAC can provide:

- message integrity,
- authentication based on a shared secret.

HMAC does not provide confidentiality.

The JavaScript implementation demonstrates HMAC with:

`crypto.createHmac("sha256", key)`

The Python implementation uses:

`hmac.new(key, message, hashlib.sha256)`

Authentication values should be compared using a timing-aware comparison mechanism when appropriate.

Python provides `hmac.compare_digest`.

Node.js provides `crypto.timingSafeEqual`.

---

## 9. Symmetric Cryptography

Symmetric cryptography uses related secret material for encryption and decryption.

Common modern symmetric primitives include:

- AES
- ChaCha20

Common authenticated-encryption constructions include:

- AES-GCM
- ChaCha20-Poly1305

Symmetric cryptography is generally efficient for large amounts of data.

This is why practical systems normally do not encrypt an entire large document directly with RSA or another public-key primitive.

Instead, systems commonly use a hybrid architecture.

---

## 10. Block Ciphers and Modes

AES is a block cipher.

AES operates on fixed-size blocks and supports different modes of operation.

Examples include:

- CBC
- CTR
- GCM

The security properties depend not only on AES itself but also on how the cipher is used.

For modern application encryption, authenticated encryption is generally preferred because confidentiality and integrity are handled together.

The Python program contains an educational Feistel-style block-cipher construction. It is included to demonstrate the architecture of repeated rounds, mixing, reversible transformations, and key-dependent operations.

It is explicitly not AES.

The purpose is conceptual rather than production cryptography.

---

## 11. Authenticated Encryption

Authenticated encryption combines confidentiality and integrity.

An AEAD interface normally accepts:

- key,
- nonce,
- plaintext,
- associated data.

The associated data is not encrypted but is authenticated.

Examples include:

- protocol version,
- account identifier,
- message type,
- sequence number,
- routing metadata.

The JavaScript implementation uses AES-256-GCM.

The central operations are:

`cipher.setAAD(associatedData)`

and:

`cipher.getAuthTag()`

During decryption, the authentication tag must be supplied before finalization.

If the ciphertext, associated data, nonce, or tag is modified, authentication should fail.

---

## 12. Nonces and IVs

Nonce management is a major protocol responsibility.

A nonce may be public.

A nonce does not necessarily need secrecy.

Its uniqueness requirement depends on the cryptographic construction.

A serious failure can occur if an algorithm requiring nonce uniqueness is given a reused nonce with the same key.

For this reason:

- generate nonces correctly,
- understand the requirements of the exact primitive,
- do not invent nonce-generation rules,
- do not assume that random generation alone satisfies every protocol requirement.

AES-GCM commonly uses a 96-bit nonce in practical applications.

The JavaScript example generates:

`crypto.randomBytes(12)`

for its AES-GCM nonce.

---

## 13. XOR and One-Time Pads

XOR has the useful property:

`A XOR B XOR B = A`

This means that if plaintext is XORed with a keystream, applying the same keystream again recovers the plaintext.

A true one-time pad requires:

- a uniformly random key,
- a key at least as long as the message,
- exactly one use of the key,
- secure key distribution.

Those requirements make one-time pads impractical for most modern applications.

Modern stream ciphers provide efficient pseudorandom keystreams under cryptographically defined security assumptions.

---

## 14. Public-Key Cryptography

Public-key cryptography uses a key pair:

- public key,
- private key.

The public key can normally be distributed widely.

The private key must remain protected.

Important public-key applications include:

- digital signatures,
- key establishment,
- public-key encryption,
- certificates,
- identity authentication.

Common historical and current families include:

- RSA,
- finite-field Diffie-Hellman,
- elliptic-curve cryptography.

---

## 15. RSA

RSA is based on properties of modular arithmetic and the difficulty of factoring large composite integers.

The basic educational structure uses:

1. two large primes,
2. a modulus,
3. Euler's totient-related mathematics,
4. a public exponent,
5. a private exponent.

The Python program contains a deliberately tiny RSA example.

The small values make the mathematics visible but provide no practical security.

Modern RSA encryption should use a standardized padding construction such as RSA-OAEP rather than raw textbook RSA.

The JavaScript implementation demonstrates RSA-OAEP with SHA-256.

It also uses a 3072-bit modulus for the demonstration.

---

## 16. Diffie-Hellman Key Exchange

Diffie-Hellman allows two parties to derive common secret material while communicating over a channel that may be observed.

The basic finite-field construction uses:

- a public prime,
- a public generator,
- Alice's private value,
- Bob's private value,
- public values derived from the private values.

Each side independently computes a shared secret.

The Python program demonstrates this using intentionally tiny educational parameters.

Those parameters are not secure.

---

## 17. Elliptic-Curve Cryptography

Elliptic-curve cryptography uses arithmetic over finite fields involving points on elliptic curves.

The Python program demonstrates:

- point representation,
- point addition,
- scalar multiplication,
- shared-secret derivation.

The implementation is intentionally tiny and educational.

Production ECC requires:

- standardized curves or protocols,
- secure implementations,
- validation rules,
- side-channel resistance,
- correct serialization,
- careful public-key handling.

The JavaScript implementation demonstrates X25519, which is designed for modern elliptic-curve key agreement.

---

## 18. X25519

X25519 is commonly used for elliptic-curve Diffie-Hellman-style key agreement.

The JavaScript example creates two X25519 key pairs.

Alice uses:

`crypto.diffieHellman()`

with Alice's private key and Bob's public key.

Bob performs the corresponding operation.

Both derive the same shared secret.

Key agreement alone does not automatically authenticate the peer.

A complete protocol needs an authentication mechanism or trusted key infrastructure.

---

## 19. Digital Signatures

Digital signatures differ from encryption.

A signature generally provides:

- authenticity evidence,
- integrity verification,
- proof that the holder of the corresponding private key authorized the signature, subject to the protocol and key-management assumptions.

The JavaScript program uses Ed25519.

The signing flow is:

1. Generate a private/public key pair.
2. Sign the document with the private key.
3. Verify the signature with the public key.
4. Modify the document.
5. Verify again.
6. Observe that verification fails.

The distinction between signatures and HMAC is important.

HMAC uses a shared secret.

A digital signature uses an asymmetric key pair.

---

## 20. Certificates and PKI

Public-key systems need mechanisms for associating public keys with identities.

A Public Key Infrastructure can include:

- certificates,
- certificate authorities,
- trust stores,
- certificate chains,
- validation rules,
- revocation mechanisms,
- key-usage constraints.

A certificate generally binds an identity or set of names to a public key through a signed data structure.

Transport security systems such as TLS use certificates as part of server authentication.

Certificate validation is more than checking whether a certificate exists.

Validation can include:

- signature chain validation,
- hostname verification,
- validity periods,
- key usage,
- extended key usage,
- trust-anchor selection,
- algorithm restrictions,
- revocation considerations.

---

## 21. Hybrid Encryption

Modern systems frequently combine symmetric and asymmetric cryptography.

A typical hybrid architecture is:

1. Generate a random session key.
2. Encrypt application data using an AEAD primitive.
3. Protect or establish the session key using public-key cryptography.
4. Transmit the encrypted data and protected key material.
5. Recover the session key.
6. Verify and decrypt the application data.

The JavaScript program demonstrates this architecture using:

- AES-256-GCM for payload encryption,
- RSA-OAEP for protecting the session key.

This approach is efficient because public-key operations are applied to small key material rather than arbitrarily large payloads.

Other modern protocol designs use authenticated key agreement and KDFs instead of directly wrapping a randomly generated session key with RSA.

---

## 22. Associated Data

Associated data is authenticated but not encrypted.

For example, a message might contain:

- protocol version,
- sender identifier,
- message ID,
- key identifier,
- message type.

These values may need to remain visible for routing or protocol processing but must not be alterable without detection.

The Python and JavaScript examples include associated data in their authenticated-encryption demonstrations.

---

## 23. Replay Attacks

Encryption and authentication do not automatically prevent replay.

Suppose an attacker captures a valid authenticated request:

`withdraw=1000`

If the attacker submits exactly the same authenticated message later, cryptographic verification may still succeed.

Replay protection can use:

- unique message identifiers,
- sequence numbers,
- timestamps,
- expiration windows,
- protocol state,
- challenge-response mechanisms.

The Python, JavaScript, and C++ implementations demonstrate message identifiers and freshness checks.

Distributed systems require more careful design because replay state may need to be shared across multiple instances.

---

## 24. Key Management

Cryptographic security depends heavily on key management.

Important lifecycle stages include:

1. Generation
2. Distribution
3. Activation
4. Storage
5. Rotation
6. Revocation
7. Backup
8. Recovery
9. Deactivation
10. Destruction

A cryptographically strong algorithm cannot compensate for a leaked private key.

Production systems may use:

- Key Management Services,
- Hardware Security Modules,
- operating-system credential stores,
- secure enclaves,
- controlled secret-management systems.

The Python and C++ programs model key identifiers and rotation.

They do not implement a production KMS.

---

## 25. Key Rotation

Key rotation limits the amount of data protected under a particular key and helps operational security.

A rotation strategy must define:

- when a new key becomes active,
- how old data is decrypted,
- how old keys are retained,
- when old keys become invalid,
- how compromised keys are revoked,
- how systems synchronize key versions.

A key identifier should normally be included in an authenticated protocol envelope when multiple key versions may coexist.

---

## 26. Cryptographic Agility

Cryptographic algorithms eventually become obsolete.

Reasons include:

- newly discovered attacks,
- advances in computing,
- implementation weaknesses,
- regulatory requirements,
- performance requirements,
- new security standards,
- quantum-computing concerns.

Cryptographic agility means a system can transition between cryptographic suites without redesigning its entire architecture.

A protocol should therefore avoid scattering algorithm assumptions throughout application code.

Instead, algorithms can be represented through explicit policy or protocol versions.

The Python and JavaScript examples demonstrate this concept through algorithm-policy structures.

---

## 27. Post-Quantum Cryptography

Quantum computers pose a major long-term consideration for public-key cryptography.

Algorithms based on integer factoring and discrete logarithms are threatened by sufficiently capable quantum algorithms.

This affects important classical systems such as:

- RSA,
- finite-field Diffie-Hellman,
- elliptic-curve cryptography.

Symmetric cryptography and hash functions are affected differently.

Post-quantum cryptography includes families such as:

- lattice-based cryptography,
- code-based cryptography,
- hash-based signatures.

Migration can involve hybrid mechanisms that combine classical and post-quantum security during a transition period.

The Python program introduces this architectural issue without claiming a particular post-quantum algorithm as universally appropriate.

---

## 28. Harvest Now, Decrypt Later

An attacker may collect encrypted information today even if they cannot decrypt it today.

If future technology can break the relevant public-key protection, previously collected information may become readable.

This creates a special concern for information with long confidentiality lifetimes.

Examples include:

- government records,
- long-lived intellectual property,
- strategic research,
- sensitive personal records.

Systems handling long-lived confidential information need to consider cryptographic migration timelines.

---

## 29. Timing Attacks

Security-sensitive comparisons can sometimes leak information through timing differences.

An ordinary comparison may return as soon as a mismatch is discovered.

For authentication tags, passwords, or other sensitive values, applications should use cryptographic-library comparison functions designed to reduce timing leakage.

Python uses:

`hmac.compare_digest`

Node.js uses:

`crypto.timingSafeEqual`

The C++ case study includes an educational constant-time-style comparison function while explicitly recommending a production library implementation.

---

## 30. Common Cryptographic Mistakes

### Treating Base64 as encryption

Base64 is an encoding mechanism.

### Using a fast general-purpose hash for passwords

Passwords should use a password-specific KDF.

### Hard-coding secret keys

Keys stored in source code can leak through repositories, backups, builds, or logs.

### Reusing nonces incorrectly

Nonce reuse can compromise certain authenticated-encryption schemes.

### Encrypting without authentication

Confidentiality does not automatically provide integrity.

### Using raw RSA

Modern RSA encryption requires appropriate standardized padding such as OAEP.

### Implementing cryptography from scratch

Cryptographic algorithms can be mathematically correct while the implementation remains vulnerable to:

- side channels,
- invalid input,
- nonce misuse,
- memory errors,
- serialization errors,
- protocol failures.

### Logging secrets

Sensitive plaintext, keys, tokens, and authentication material should not be written into ordinary logs.

### Ignoring replay

A valid authenticated request may still be valid when maliciously replayed unless the protocol explicitly handles freshness.

### Assuming key exchange provides identity

Diffie-Hellman-style key agreement establishes shared secret material but does not automatically tell either party who the other party is.

---

## 31. Python Implementation

The Python implementation begins with basic cryptographic concepts and gradually introduces more complex structures.

### Hashing

`hashlib.sha256()` demonstrates deterministic cryptographic hashing.

### Password derivation

`hashlib.pbkdf2_hmac()` demonstrates password-based key derivation.

### HMAC

The `hmac` module demonstrates authentication using shared secret material.

### Secure randomness

The `secrets` module demonstrates cryptographically appropriate random generation.

### Educational block cipher

The Feistel-style implementation demonstrates how repeated rounds and reversible transformations can form a block-cipher structure.

It is not a production cipher.

### Authenticated encryption

The educational construction demonstrates the conceptual relationship among:

- nonce,
- ciphertext,
- authentication tag,
- associated data.

It is not AES-GCM or ChaCha20-Poly1305.

### RSA

The small-number example demonstrates the mathematical structure of RSA.

The values are intentionally insecure.

### Diffie-Hellman

The example demonstrates how two parties can compute the same shared value.

### Elliptic curves

The toy implementation demonstrates point addition and scalar multiplication.

### Replay protection

The example tracks message identifiers and timestamps.

### Key management

`KeyRing` models key IDs, key material, activation, and deactivation.

### Integrated service

`SecureMessageService` combines:

- random message identifiers,
- key management,
- authenticated encryption,
- associated data,
- replay handling.

This provides a compact protocol-architecture demonstration.

---

## 32. JavaScript Implementation

The JavaScript implementation emphasizes practical application development using Node.js's built-in `crypto` module.

### SHA-256

`crypto.createHash("sha256")` provides hashing.

### scrypt

`crypto.scryptSync()` demonstrates password-derived key material.

### HMAC

`crypto.createHmac()` provides message authentication.

### AES-256-GCM

The AES-GCM example demonstrates actual authenticated encryption.

The code explicitly handles:

- 256-bit key,
- nonce,
- plaintext,
- associated data,
- ciphertext,
- authentication tag.

### RSA-OAEP

The RSA example uses a 3072-bit key and OAEP with SHA-256.

### Ed25519

The signature example demonstrates:

- key generation,
- signing,
- verification,
- modified-document rejection.

### X25519

The key-agreement example demonstrates two parties obtaining matching shared secret material.

### Hybrid encryption

The hybrid example combines:

- AES-GCM for payload data,
- RSA-OAEP for the session key.

### Replay protection

The `ReplayProtector` class demonstrates:

- timestamps,
- unique message IDs,
- authentication tags,
- replay rejection.

---

## 33. C++ Case Study

### Problem

The C++ implementation models a secure enterprise document exchange service.

A sender submits a document that must be:

- confidential,
- tamper detectable,
- associated with sender metadata,
- associated with a key version,
- protected against replay.

### Major components

The system contains:

- `SecureRandom`
- `EducationalDigest`
- `MessageAuthenticator`
- `KeyManager`
- `SecureEnvelope`
- `EducationalAuthenticatedEncryption`
- `ReplayGuard`
- `SecureDocumentService`

Each class has a focused responsibility.

### SecureRandom

Generates demonstration random values.

The code explicitly explains why `std::random_device` does not provide a universal standard guarantee of cryptographic randomness.

A production system should use an appropriate cryptographic library or operating-system CSPRNG.

### EducationalDigest

Creates deterministic fixed-size output to model a digest API.

It is deliberately not SHA-256.

### MessageAuthenticator

Models authentication-tag generation and verification.

It is deliberately not standardized HMAC.

### KeyManager

Stores:

- key ID,
- key material,
- creation time,
- active state.

It demonstrates key rotation and active-key lookup.

### SecureEnvelope

Represents a protocol message.

It contains:

- protocol version,
- sender,
- message ID,
- key ID,
- timestamp,
- associated data,
- nonce,
- ciphertext,
- authentication tag.

Explicit protocol metadata makes protocol behavior easier to validate and migrate.

### ReplayGuard

Prevents a message identifier from being accepted twice.

It also checks the age of a message.

### SecureDocumentService

Coordinates the components.

Its responsibilities include:

1. validating inputs,
2. generating a message identifier,
3. generating a nonce,
4. constructing associated data,
5. encrypting the document,
6. decrypting and authenticating the document,
7. rejecting replays,
8. supporting key rotation.

---

## 34. C++ Case Study Data Flow

A document encryption operation follows this conceptual sequence:

1. Validate sender.
2. Validate document.
3. Obtain the active key.
4. Generate a timestamp.
5. Generate a unique message identifier.
6. Generate a nonce.
7. Build authenticated metadata.
8. Transform the plaintext into ciphertext.
9. Authenticate the protocol data.
10. Construct the secure envelope.

Decryption follows:

1. Validate protocol version.
2. Check freshness.
3. Check replay state.
4. Obtain the referenced key.
5. Reconstruct authenticated input.
6. Verify the authentication tag.
7. Recover plaintext only after successful authentication.

This ordering is important.

An application should not treat unauthenticated ciphertext as trustworthy plaintext.

---

## 35. Edge Cases Demonstrated

The implementations explicitly handle several failure conditions.

### Empty plaintext

The encryption examples reject empty application payloads where the demonstration requires meaningful content.

### Invalid key size

The JavaScript AES-GCM implementation verifies that the supplied AES-256 key is 32 bytes.

### Modified ciphertext

The authentication tag no longer matches after ciphertext modification.

### Modified associated data

Changing authenticated metadata causes authentication failure.

### Wrong password

The password verification example rejects incorrect credentials.

### Replay

The same message identifier cannot be accepted twice.

### Expired request

The replay-protection examples reject messages outside their permitted freshness window.

### Unknown key ID

The key-management components reject key identifiers that do not exist.

### Inactive key

A deactivated key cannot be used through the active-key API.

### Unsupported protocol version

The C++ case study rejects an envelope with an unsupported protocol version.

---

## 36. Performance Considerations

Symmetric cryptography is generally efficient for large data volumes.

Hashing is generally linear in the size of the input.

For a message containing `n` bytes, a normal streaming hash requires approximately `O(n)` processing.

The C++ case study performs payload processing in linear time.

The replay guard uses a `std::set`, resulting in approximately `O(log m)` lookup and insertion for `m` stored message identifiers.

The key manager uses a `std::map`, providing approximately `O(log k)` lookup for `k` keys.

Performance depends on:

- CPU architecture,
- implementation quality,
- hardware acceleration,
- memory hierarchy,
- payload size,
- concurrency,
- cryptographic primitive,
- operating system,
- language runtime.

Benchmarks should be performed on the actual deployment environment.

---

## 37. Security Considerations

Cryptographic security has multiple layers.

### Algorithm security

The mathematical primitive must be appropriate.

### Implementation security

The implementation must avoid:

- memory errors,
- incorrect padding,
- nonce misuse,
- invalid key handling,
- timing leakage,
- serialization mistakes.

### Protocol security

The protocol must correctly define:

- message structure,
- authentication,
- key negotiation,
- replay behavior,
- error handling,
- algorithm selection.

### Operational security

The organization must protect:

- keys,
- credentials,
- logs,
- backups,
- configuration,
- deployment systems,
- access permissions.

A secure algorithm can still be deployed insecurely.

---

## 38. Authentication Versus Authorization

Cryptography can help authenticate a party or message.

Authorization answers a different question:

> What is this authenticated identity allowed to do?

For example, a valid signature from an employee does not automatically mean that the employee is authorized to approve a particular transaction.

Applications therefore need both:

- cryptographic authentication,
- authorization policy.

---

## 39. Confidentiality Versus Integrity

Encryption primarily addresses confidentiality.

Authentication mechanisms address integrity and authenticity.

Modern AEAD constructions combine both.

A system should not assume that encrypted data is automatically protected against modification.

This distinction is central to secure protocol design.

---

## 40. Security Boundary

The cryptographic boundary should be defined clearly.

Questions include:

- Where are plaintext values created?
- Where are keys generated?
- Where are keys stored?
- Which processes can access them?
- Are keys exported?
- What happens after a process crash?
- Are logs allowed to contain decrypted information?
- Can an administrator retrieve key material?
- What happens if an application server is compromised?

These questions often matter as much as algorithm selection.

---

## 41. Production Implementation Considerations

A production cryptographic system should generally:

1. Use standardized cryptographic primitives.
2. Use audited implementations.
3. Avoid custom cryptographic algorithms.
4. Use AEAD for application encryption where appropriate.
5. Use password-specific KDFs for passwords.
6. Generate cryptographic randomness using appropriate system facilities.
7. Design explicit nonce and IV management.
8. Separate keys by purpose.
9. Implement key rotation.
10. Protect keys using appropriate key-management infrastructure.
11. Authenticate important metadata.
12. Protect state-changing operations against replay.
13. Use secure comparison functions where required.
14. Avoid secret leakage through logs.
15. Maintain algorithm and protocol version information.
16. Plan cryptographic migration.
17. Test negative cases.
18. Review the entire protocol rather than individual primitives in isolation.

---

## 42. Python, JavaScript, and C++ Comparison

| Aspect | Python | JavaScript | C++ |
|---|---|---|---|
| Primary purpose in this study | Conceptual progression | Practical cryptographic APIs | System architecture |
| Hashing | `hashlib` | Node `crypto` | Educational digest |
| Password KDF | PBKDF2 | scrypt | Architecture discussion |
| HMAC | Standard library | Node `crypto` | Educational construction |
| AEAD | Educational construction | AES-256-GCM | Educational construction |
| RSA | Mathematical demonstration | RSA-OAEP | Architecture discussion |
| Key agreement | DH and toy ECC | X25519 | Architecture discussion |
| Signatures | Conceptual distinction | Ed25519 | Architecture discussion |
| Key management | `KeyRing` | Service-level key | `KeyManager` |
| Replay protection | Message IDs and timestamps | `ReplayProtector` | `ReplayGuard` |
| Integrated system | Secure message service | Secure message service | Secure document exchange |

The difference is intentional.

Python is useful for exposing algorithms and concepts with relatively little syntax.

JavaScript is useful for demonstrating real application-facing cryptographic APIs in a common server-side runtime.

C++ is useful for discussing explicit system boundaries, data structures, memory ownership, protocol objects, performance, and low-level implementation constraints.

---

## 43. Important Distinctions

### Hash versus encryption

A hash produces a digest and is not designed to be reversible.

Encryption is designed to permit authorized recovery of plaintext.

### HMAC versus digital signature

HMAC uses a shared secret.

A digital signature uses a private/public key pair.

### Password hash versus ordinary hash

Password KDFs are deliberately expensive and incorporate salts and work factors.

### Encryption versus key exchange

Encryption protects data.

Key exchange establishes shared secret material.

### Public key versus private key

The public key is intended for distribution.

The private key requires protection.

### Nonce versus secret

A nonce often does not need to be secret.

Its uniqueness requirements can be critical.

### Authentication versus authorization

Authentication establishes identity or message authenticity.

Authorization determines permitted actions.

### Primitive versus protocol

A primitive such as AES is only one component.

A secure protocol defines how cryptographic primitives interact with identity, metadata, keys, freshness, and errors.

---

## 44. Limitations of the Educational Implementations

The Python and C++ custom constructions must not be deployed as cryptographic systems.

They intentionally simplify or replace real cryptographic primitives to make the underlying architecture visible.

They do not provide the security properties of:

- AES-GCM,
- ChaCha20-Poly1305,
- SHA-256,
- standardized HMAC,
- Ed25519,
- X25519,
- RSA-OAEP,
- HKDF,
- production-grade password hashing.

The JavaScript examples are closer to practical cryptographic usage because they invoke Node.js's built-in cryptographic implementations.

Even there, correct API usage is not sufficient by itself.

The surrounding protocol, key management, authentication, storage, access control, and deployment architecture must also be secure.

---

## 45. Testing Strategy

Cryptographic software should test both successful and unsuccessful paths.

Important tests include:

- correct encryption/decryption,
- incorrect keys,
- modified ciphertext,
- modified associated data,
- modified authentication tags,
- malformed messages,
- invalid protocol versions,
- expired messages,
- replayed messages,
- invalid key identifiers,
- inactive keys,
- wrong passwords,
- signature verification failures.

The C++ case study implements explicit tests for:

- round-trip encryption,
- ciphertext tampering,
- replay,
- input validation,
- key rotation.

Negative testing is especially important because security mechanisms often fail through incorrect error handling rather than through normal successful execution.

---

## 46. Protocol Design Principles

A well-designed cryptographic protocol should make security assumptions explicit.

Important principles include:

- Authenticate what matters.
- Bind metadata to the cryptographic operation.
- Separate keys by purpose.
- Identify algorithm versions explicitly.
- Define nonce requirements.
- Define replay behavior.
- Define expiration behavior.
- Define key rotation behavior.
- Define error behavior.
- Avoid ambiguous serialization.
- Avoid accepting multiple interpretations of the same message.
- Fail safely when authentication fails.
- Keep secrets out of logs.
- Design for algorithm migration.

Cryptographic security is therefore a systems-engineering problem as well as a mathematical problem.

---

## 47. Real-World Applications

Modern cryptography is used in:

- HTTPS and TLS
- secure messaging
- banking systems
- payment processing
- password storage
- software signing
- package verification
- identity systems
- VPN protocols
- cloud services
- database encryption
- disk encryption
- digital certificates
- secure APIs
- authentication tokens
- secure backups
- electronic signatures
- blockchain systems
- confidential computing architectures

The exact algorithms and protocol combinations differ according to the threat model and operational requirements.

---

## 48. Architectural View

A mature cryptographic architecture can be viewed as several layers:

**Application layer**

Defines business operations and data.

**Protocol layer**

Defines message formats, versions, metadata, freshness, and authentication.

**Cryptographic layer**

Provides encryption, hashing, signatures, KDFs, and key agreement.

**Key-management layer**

Handles generation, storage, rotation, revocation, and destruction.

**Infrastructure layer**

Provides operating-system protections, hardware security, access control, monitoring, backups, and deployment security.

A failure at any layer can undermine the security objective.

---

## 49. Core Principles Demonstrated by the Three Programs

The Python program demonstrates how cryptographic concepts relate mathematically and algorithmically.

The JavaScript program demonstrates how an application should interact with mature cryptographic APIs.

The C++ program demonstrates how cryptography becomes part of a larger technical architecture involving:

- data structures,
- protocol state,
- validation,
- key lifecycle,
- replay detection,
- failure handling,
- testing,
- performance.

Together, these perspectives show why modern cryptography should be understood as a combination of primitives, protocols, implementation discipline, and key management rather than as encryption alone.
