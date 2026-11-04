# Introduction to Public-Key Cryptography

## 1. Technical Scope

Public-key cryptography, also called asymmetric cryptography, uses mathematically related keys to support secure communication, identity verification, digital signatures, and key establishment.

Unlike symmetric cryptography, which uses the same secret key for encryption and decryption, asymmetric cryptography uses two different keys:

- **Public key:** Distributed to other participants.
- **Private key:** Kept confidential by its owner.

The two keys are mathematically related, but deriving the private key from a properly generated public key must be computationally infeasible under the relevant security assumptions.

The five implementations demonstrate different aspects of public-key cryptography:

| Implementation | Main engineering perspective |
|---|---|
| Python | RSA mathematics, modular arithmetic, Diffie-Hellman, key registry |
| JavaScript | RSA-OAEP, RSA-PSS, ECDH, HKDF, asynchronous operations |
| C++17 | Modular arithmetic, RSA operations, key agreement, registry |
| Java 17 | Enterprise cryptographic services, authenticated encryption, key lifecycle |
| PostgreSQL | Public-key inventory, certificates, lifecycle management, audit and reporting |

The implementations deliberately distinguish mathematical demonstrations from production cryptographic services.

## 2. Public-Key Fundamentals

### 2.1 Key-pair generation

A key pair is generated using an algorithm-specific procedure.

For RSA:

1. Generate two large, distinct prime numbers, `p` and `q`.
2. Calculate the modulus:

   `n = p × q`

3. Calculate Euler's totient:

   `φ(n) = (p - 1)(q - 1)`

4. Select a public exponent `e` that is relatively prime to the totient.
5. Calculate the private exponent:

   `d = e⁻¹ mod φ(n)`

The public key contains `(n, e)`, while the private key contains `(n, d)`.

The mathematical relationship is based on modular arithmetic.

The Python implementation includes prime generation, primality testing, the extended Euclidean algorithm, and modular inversion.

The C++17 implementation uses integer modular multiplication and modular exponentiation to demonstrate the underlying mathematical operations.

### 2.2 Modular exponentiation

RSA operations use modular exponentiation:

`c = mᵉ mod n`

For decryption:

`m = cᵈ mod n`

The modular exponentiation algorithm uses repeated squaring.

Instead of calculating a potentially enormous exponent directly, it repeatedly squares intermediate values and reduces them modulo `n`.

Its time complexity is logarithmic in the exponent:

`O(log e)`

The implementations use this technique in their educational RSA operations.

### 2.3 Public-key distribution

A public key can be shared openly, but its ownership must be established.

If an attacker replaces Alice's public key with their own, another participant might unknowingly encrypt information for the attacker.

Public-key distribution therefore requires an authentication mechanism.

Common approaches include:

- Digital certificates.
- Certificate authorities.
- Public-key fingerprints.
- Trusted directories.
- Certificate-chain validation.
- Authenticated key exchange.

A fingerprint is a cryptographic hash of a canonical public-key representation.

It helps identify a particular key, but a fingerprint is useful only when its authenticity is established through a trusted channel.

## 3. RSA Cryptography

### 3.1 RSA encryption

RSA encryption uses the recipient's public key.

The recipient decrypts the ciphertext using the corresponding private key.

Workflow:

`Plaintext → RSA-OAEP Encryption → Ciphertext → RSA-OAEP Decryption → Plaintext`

RSA encryption provides confidentiality when the public key belongs to the intended recipient and the private key remains protected.

### 3.2 RSA-OAEP

Optimal Asymmetric Encryption Padding provides randomized padding for RSA encryption.

The JavaScript implementation uses Node.js `crypto.publicEncrypt` and `crypto.privateDecrypt` with SHA-256-based OAEP.

The Java implementation uses the JCA transformation:

`RSA/ECB/OAEPWithSHA-256AndMGF1Padding`

OAEP is probabilistic. Encrypting the same plaintext multiple times normally produces different ciphertexts.

This differs from textbook RSA, which is deterministic and unsuitable for secure application encryption.

RSA-OAEP also has a payload-size restriction.

For an RSA modulus of `k` bytes and a hash output of `hLen` bytes, the maximum OAEP message length is:

`k - 2hLen - 2`

Consequently, RSA is generally not used to encrypt large files directly.

### 3.3 Hybrid encryption

Practical systems combine asymmetric and symmetric cryptography.

A typical hybrid encryption workflow is:

1. Generate a random symmetric data-encryption key.
2. Encrypt the actual data using an authenticated symmetric algorithm.
3. Protect the symmetric key using the recipient's public key.
4. Send the encrypted data and protected key.
5. The recipient recovers the symmetric key using their private key.
6. The recipient decrypts and authenticates the data.

AES-GCM is suitable for authenticated symmetric encryption.

The Java implementation demonstrates AES-256-GCM using a 12-byte nonce and a 128-bit authentication tag.

The nonce must not be reused with the same AES-GCM key.

The RSA-OAEP and AES-GCM implementations illustrate the separate roles of asymmetric and symmetric encryption.

## 4. Digital Signatures

### 4.1 Purpose

Digital signatures provide:

- Authentication of the signing key.
- Integrity verification.
- Evidence that the corresponding private key was used to sign a message.

They do not provide confidentiality.

Signing workflow:

`Message → Hash → Private-Key Signature → Signature`

Verification workflow:

`Message + Signature + Public Key → Verification`

If the message changes after signing, signature verification should fail.

### 4.2 RSA-PSS

RSA-PSS is a probabilistic signature scheme.

It uses randomized padding and a cryptographic hash function.

The JavaScript and Java implementations use RSA-PSS with SHA-256.

The Python and C++ programs demonstrate the mathematical relationship between signing and verification, but their simplified implementations are not RSA-PSS.

They must not be used for authenticating real transactions.

### 4.3 Signature limitations

A valid signature establishes that the signature corresponds to the supplied message and public key.

It does not independently prove:

- The real-world identity of the signer.
- That the signer had legal authority.
- That the signing device was uncompromised.
- That the signed content was factually correct.
- That the signature remains trustworthy after a key compromise.

Identity validation, certificate validation, authorization, and audit controls are separate requirements.

## 5. Diffie-Hellman Key Exchange

### 5.1 Fundamental mechanism

Diffie-Hellman allows two participants to establish a common secret over a communication channel without transmitting that secret directly.

In the finite-field version, participants agree on public parameters:

- Prime modulus `p`.
- Generator `g`.

Alice selects a private value `a` and calculates:

`A = gᵃ mod p`

Bob selects a private value `b` and calculates:

`B = gᵇ mod p`

They exchange their public values.

Alice calculates:

`S = Bᵃ mod p`

Bob calculates:

`S = Aᵇ mod p`

Both calculations produce:

`S = gᵃᵇ mod p`

The Python and C++ implementations demonstrate this finite-field mechanism using small educational parameters.

These parameters are intentionally unsuitable for security.

### 5.2 Elliptic-Curve Diffie-Hellman

ECDH performs key agreement using elliptic-curve cryptography.

It provides a shared secret using elliptic-curve operations rather than finite-field exponentiation.

The JavaScript implementation uses Node.js `createECDH` with `prime256v1`.

The Java implementation uses the JCA `KeyAgreement` interface with `ECDH`.

ECDH can provide strong security with comparatively compact public keys.

The public keys exchanged during ECDH must still be authenticated.

Unauthenticated ECDH is vulnerable to a man-in-the-middle attack.

### 5.3 HKDF

The raw Diffie-Hellman output should not automatically be treated as an application encryption key.

A key-derivation function transforms shared secret material into keys suitable for specific cryptographic purposes.

HKDF consists of two stages:

- Extract: Produces pseudorandom key material from the input secret and salt.
- Expand: Derives one or more output keys using application context information.

The JavaScript implementation uses the Node.js HKDF function.

The Java implementation includes an HKDF construction based on HMAC-SHA-256.

The context string helps separate keys used for different application purposes.

## 6. Elliptic-Curve Cryptography

Elliptic-curve cryptography uses mathematical operations on points belonging to an elliptic curve over a finite field.

A simplified elliptic-curve equation is:

`y² = x³ + ax + b`

The curve parameters and finite field define the mathematical structure.

A private key is a randomly generated scalar.

The corresponding public key is obtained through scalar multiplication of a designated generator point.

ECC supports several distinct operations:

| Algorithm | Purpose |
|---|---|
| ECDH | Shared-secret establishment |
| ECDSA | Digital signatures |
| Ed25519 | Digital signatures |
| X25519 | Elliptic-curve key agreement |

These algorithms are not interchangeable.

The JavaScript implementation demonstrates ECDH.

The Java implementation demonstrates ECDH through the JCA API.

The PostgreSQL schema distinguishes ECDSA, ECDH, Ed25519, and X25519 as separate algorithm classifications.

## 7. Key Derivation and Authenticated Encryption

Public-key cryptography is frequently combined with symmetric encryption.

The Java implementation demonstrates the following workflow:

`ECDH → Shared Secret → HKDF → AES-256-GCM → Authenticated Ciphertext`

AES-GCM provides confidentiality and integrity protection.

Decryption succeeds only when the authentication tag verifies.

If ciphertext or authenticated data is modified, authentication fails.

The implementation stores the nonce alongside the ciphertext.

It does not store the session secret in the database.

In production, session keys should be scoped to their intended purpose, protected in memory, and discarded when no longer needed.

## 8. Public-Key Authentication and Certificates

A public key does not automatically establish the identity of its owner.

A digital certificate binds a public key to an identity through a certificate issuer's signature.

A typical certificate contains:

- Subject identity.
- Subject public key.
- Issuer identity.
- Serial number.
- Validity period.
- Signature algorithm.
- Issuer signature.

Certificate validation involves more than checking whether the certificate exists.

Validation can include:

1. Certificate signature verification.
2. Certificate-chain construction.
3. Trust-anchor verification.
4. Validity-period verification.
5. Subject-name verification.
6. Key-usage verification.
7. Extended-key-usage verification.
8. Revocation checking.

The PostgreSQL implementation stores certificate metadata and evaluates basic validity conditions.

It does not implement certificate signature verification or full PKI path validation.

Those operations belong in a cryptographic application or certificate-validation service.

## 9. Public-Key Lifecycle Management

Public keys and private keys have a lifecycle.

A practical lifecycle includes:

`Generation → Registration → Validation → Activation → Usage → Rotation or Revocation`

### 9.1 Registration

Registration associates a public key with an identity.

The Python implementation uses a dictionary-based registry.

The JavaScript implementation uses a private `Map` to maintain identity records.

The C++ implementation uses an `unordered_map`.

The Java implementation uses a concurrent map and immutable records.

The PostgreSQL implementation stores identities and public-key metadata in separate relational tables.

### 9.2 Activation

A newly registered key should not automatically become trusted.

An activation process can verify:

- Key format.
- Algorithm.
- Key size.
- Intended usage.
- Identity association.
- Registration authorization.
- Expiration policy.

The PostgreSQL procedure `activate_public_key` demonstrates controlled activation of pending keys.

### 9.3 Rotation

Key rotation replaces an existing key with a newer version.

Reasons include:

- Cryptoperiod expiration.
- Scheduled security maintenance.
- Algorithm migration.
- Organizational policy.
- Suspected exposure.

The database implementation maintains key versions and rotation relationships.

Its rotation procedure checks identity, algorithm, usage, and lifecycle state before updating the records.

### 9.4 Revocation

A compromised or untrusted key must no longer be accepted for new operations.

Revocation is distinct from expiration.

- Expiration occurs when a defined validity period ends.
- Revocation is an explicit security decision.

The implementations reject revoked identities when retrieving active public keys.

The PostgreSQL schema records revocation timestamps and reasons in the audit trail.

Historical records should remain available for investigation.

## 10. Security Threats and Controls

| Threat | Description | Relevant control |
|---|---|---|
| Private-key theft | Unauthorized access to private-key material | Hardware-backed storage, access controls, rotation |
| Man-in-the-middle | Attacker substitutes exchanged public keys | Certificate validation, authenticated key exchange |
| Weak RSA parameters | Insufficient modulus size or poor prime generation | Approved key sizes and secure generation |
| Padding attacks | Exploitation of incorrectly implemented padding | Standardized OAEP and PSS implementations |
| Signature forgery | Acceptance of an invalid or improperly constructed signature | Standard signature verification |
| Replay attacks | Reuse of previously valid messages | Nonces, timestamps, sequence numbers |
| Weak randomness | Predictable key material | Cryptographically secure random generators |
| Key compromise | Unauthorized exposure of private keys | Revocation, rotation, incident response |
| Algorithm downgrade | Negotiation of weaker cryptographic algorithms | Strict algorithm policies |
| Certificate misuse | Acceptance of invalid or inappropriate certificates | Certificate-chain and usage validation |

### 10.1 Private-key protection

Private keys should not be distributed or stored as ordinary application data.

Production controls may include:

- Hardware Security Modules.
- Trusted Platform Modules.
- Operating-system key stores.
- Encrypted key containers.
- Restricted service identities.
- Access logging.
- Key separation by purpose.

The PostgreSQL implementation intentionally stores public-key material and fingerprints rather than private-key secrets.

### 10.2 Random number generation

Cryptographic key generation requires unpredictable random values.

The JavaScript implementation uses `crypto.randomBytes` indirectly through its cryptographic APIs and Node.js secure random generator.

The Java implementation uses `SecureRandom`.

The Python educational RSA example uses the `secrets` module rather than the ordinary pseudorandom `random` module.

The C++ program uses fixed demonstration parameters and must not be interpreted as a secure key generator.

## 11. Implementation-Specific Engineering Decisions

### 11.1 Python

The Python implementation emphasizes mathematical foundations.

Its principal components are:

| Component | Responsibility |
|---|---|
| `is_prime` | Probabilistic primality testing |
| `generate_prime` | Candidate prime generation |
| `extended_gcd` | Extended Euclidean algorithm |
| `modular_inverse` | Modular multiplicative inverse |
| `RSA` | Educational encryption and signature operations |
| `DiffieHellman` | Finite-field key agreement |
| `KeyRegistry` | Registration and revocation |

The RSA implementation encrypts individual bytes using textbook RSA.

This is a mathematical demonstration, not secure message encryption.

Its simplified signature operation reduces the SHA-256 digest modulo the RSA modulus and does not implement secure signature encoding.

### 11.2 JavaScript

The JavaScript implementation emphasizes asynchronous services and event-driven application behavior.

It uses:

- Node.js built-in cryptographic APIs.
- Promise-based RSA key generation.
- RSA-OAEP encryption.
- RSA-PSS signing.
- ECDH shared-secret establishment.
- HKDF key derivation.
- SHA-256 fingerprints.
- Map-based identity management.

The private fields in `PublicKeyDirectory` prevent ordinary external access to its internal identity map.

The implementation checks the RSA modulus size and limits the plaintext length before encryption.

### 11.3 C++17

The C++ implementation emphasizes mathematical control and domain modeling.

Its main components include:

- `PublicKey`
- `PrivateKey`
- `RSAKeyPair`
- `RSA`
- `DiffieHellman`
- `PublicKeyDirectory`
- `KeyStatus`

The modular multiplication implementation uses a wider integer type to reduce overflow risk during multiplication.

The modular exponentiation implementation uses repeated squaring.

The registry separates key data from key lifecycle status.

The program deliberately uses small primes and simplified signatures for educational purposes.

### 11.4 Java 17

The Java implementation emphasizes enterprise-oriented service boundaries.

It uses:

- JCA key-pair generation.
- RSA-OAEP.
- RSA-PSS.
- ECDH.
- HKDF.
- AES-GCM.
- Immutable records.
- Concurrent collections.
- Custom exception handling.

The `Identity` record validates identity data.

The `KeyRecord` record represents a public-key registration.

The `KeyDirectory` provides registration, lookup, and revocation operations.

The cryptographic methods are separated from identity management, allowing application services to apply additional authorization and audit policies.

The HKDF implementation follows the extract-and-expand construction using HMAC-SHA-256.

### 11.5 PostgreSQL

The PostgreSQL implementation emphasizes relational integrity and governance.

Its primary tables are:

| Table | Purpose |
|---|---|
| `identities` | Registered cryptographic identities |
| `public_keys` | Public-key records and lifecycle state |
| `certificates` | Certificate metadata |
| `cryptographic_operations` | Operation audit metadata |
| `key_agreement_sessions` | Key-agreement session records |
| `security_audit` | Security and lifecycle events |

The database uses:

- Primary and foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated types.
- Partial indexes.
- GIN indexes.
- Triggers.
- Stored procedures.
- Views.
- CTEs.
- Transaction boundaries.

The `is_key_eligible` function evaluates whether a key can be used for a particular purpose.

The `rotate_public_key` procedure demonstrates transactional lifecycle management.

The audit table preserves operational evidence.

The database does not perform RSA encryption, digital signature verification, or ECDH calculations.

## 12. Important Algorithm Distinctions

| Mechanism | Main purpose | Private key required for |
|---|---|---|
| RSA-OAEP | Confidentiality | Decryption |
| RSA-PSS | Digital signatures | Signing |
| ECDSA | Digital signatures | Signing |
| Ed25519 | Digital signatures | Signing |
| DH | Shared-secret establishment | Secret calculation |
| ECDH | Shared-secret establishment | Secret calculation |
| X25519 | Shared-secret establishment | Secret calculation |
| HKDF | Key derivation | No asymmetric private key directly |
| AES-GCM | Authenticated symmetric encryption | Shared symmetric key |

Several distinctions are essential:

- Encryption and digital signatures solve different security problems.
- Public-key exchange is not the same as public-key authentication.
- A digital signature is not an encryption operation.
- Diffie-Hellman creates shared secret material but does not independently authenticate participants.
- HKDF derives application keys but does not establish trust in the original public keys.
- Certificates bind keys to identities but do not automatically establish authorization.

## 13. Testing and Failure Handling

The source implementations include assertions and validation for important operations.

### Python

Tests cover:

- Prime detection.
- Modular inverse.
- RSA encryption and decryption.
- Signature verification.
- Modified-message rejection.
- Diffie-Hellman agreement.

### JavaScript

Tests cover:

- RSA-OAEP round trips.
- RSA-PSS signature verification.
- Tampering detection.
- Public-key directory revocation.

### C++17

Tests cover:

- Primality.
- Modular exponentiation.
- RSA encryption and decryption.
- Signature verification.
- Tampering detection.

### Java 17

Tests cover:

- RSA encryption and decryption.
- Digital signature verification.
- Modified-message rejection.
- ECDH agreement.
- HKDF key derivation.
- AES-GCM authenticated encryption.

### PostgreSQL

Database validation includes:

- Invalid key sizes.
- Invalid fingerprints.
- Duplicate identities.
- Duplicate key versions.
- Invalid lifecycle transitions.
- Expired keys.
- Revoked keys.
- Invalid certificate periods.
- Missing identities.
- Failed cryptographic operations.

Database constraints enforce structural integrity, while application-level cryptographic validation establishes whether cryptographic material is actually valid.

## 14. Performance Considerations

Asymmetric cryptographic operations are generally more computationally expensive than symmetric encryption.

| Operation | Performance consideration |
|---|---|
| RSA key generation | Computationally expensive prime generation |
| RSA encryption | Relatively efficient with a small public exponent |
| RSA decryption | More expensive private-key operation |
| RSA signatures | Private-key computation and signature encoding |
| RSA verification | Efficient with an appropriate public exponent |
| ECDH | Efficient shared-secret establishment |
| HKDF | Relatively inexpensive key derivation |
| AES-GCM | Efficient bulk encryption and authentication |
| Fingerprint generation | Linear in the encoded public-key size |

Hybrid encryption reduces the need to perform asymmetric operations on large messages.

Key generation should normally occur outside latency-sensitive request paths.

Public-key fingerprints and validated key metadata can be cached, but revocation and expiration changes must be reflected promptly.

The database indexes support identity lookup, key-status filtering, expiration checks, and audit investigation.

## 15. Limitations of the Educational Implementations

The Python and C++ implementations intentionally demonstrate simplified RSA mathematics.

They do not implement:

- RSA-OAEP.
- RSA-PSS.
- Constant-time private-key operations.
- Production-grade key sizes.
- Complete cryptographic side-channel protections.
- Secure certificate validation.

The JavaScript and Java implementations use standardized cryptographic primitives from their runtime providers, but their demonstrations are not complete production communication protocols.

The PostgreSQL implementation manages public-key metadata and workflow records. It does not independently establish cryptographic trust.

A production deployment additionally requires:

- Authenticated public-key distribution.
- Private-key protection.
- Certificate-chain validation.
- Secure algorithm negotiation.
- Replay protection.
- Authorization controls.
- Key rotation procedures.
- Revocation propagation.
- Secure operational logging.
- Dependency and runtime security management.

## 16. End-to-End Public-Key Cryptography Workflow

A typical authenticated hybrid communication workflow can be represented as follows:

    Identity Registration
            |
            v
    Public-Key Generation
            |
            v
    Public-Key Authentication
            |
            v
    Certificate / Fingerprint Validation
            |
            v
    Authenticated Key Agreement
            |
            v
    Shared Secret Establishment
            |
            v
    HKDF Session-Key Derivation
            |
            v
    AES-GCM Encryption
            |
            v
    Authenticated Ciphertext Exchange
            |
            v
    AES-GCM Decryption
            |
            v
    Integrity Verification
            |
            v
    Session Termination and Key Disposal

Digital signatures can be applied independently to authenticate messages and verify their integrity.

The public-key registry and database audit mechanisms support identity management, key lifecycle control, and operational accountability.

The central engineering distinction is that asymmetric cryptography establishes confidentiality mechanisms, authentication mechanisms, and shared-secret mechanisms, while symmetric cryptography efficiently protects application data. Secure systems combine these mechanisms with authenticated identities, appropriate key management, and enforceable security policies.
