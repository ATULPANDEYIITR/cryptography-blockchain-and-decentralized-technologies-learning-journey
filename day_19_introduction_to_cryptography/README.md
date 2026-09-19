# Introduction to cryptography

## Topic introduction

Cryptography is the study and engineering of techniques that protect information against unauthorized observation, modification, impersonation, and misuse.

Modern cryptography is broader than encryption. A complete cryptographic system can involve encryption, hashing, message authentication, digital signatures, key exchange, key derivation, randomness, certificates, identity verification, replay protection, secure protocols, and key management.

The central security properties are:

- **Confidentiality:** unauthorized parties should not be able to read protected information.
- **Integrity:** unauthorized modifications should be detectable.
- **Authentication:** a recipient should be able to establish the identity or possession of a required secret or private key.
- **Non-repudiation:** under appropriate technical and legal assumptions, digital signatures can provide evidence associated with a signing key.

Cryptography does not automatically provide security merely because an algorithm is mathematically sophisticated. Secure systems depend on correct algorithms, parameters, implementation, key management, randomness, protocol design, identity verification, secure storage, and correct handling of failure conditions.

The three implementations in this repository approach the subject differently:

- The **Python implementation** is a broad educational study program. It develops cryptographic concepts from classical ciphers and modular arithmetic through hashing, HMAC, password derivation, key exchange, RSA, digital signatures, Merkle trees, key rotation, certificates, replay protection, and protocol design.
- The **JavaScript implementation** emphasizes practical application-level cryptography using Node.js's built-in `crypto` module. It demonstrates AES-GCM, HMAC, password KDFs, ECDH, RSA, digital signatures, asynchronous cryptographic operations, authenticated tokens, error handling, and performance considerations.
- The **C++ implementation** presents an industry-style secure document-transfer case study. It combines users, documents, key versions, authenticated envelopes, sequence numbers, replay protection, tamper detection, audit logging, validation, and key rotation into one application architecture.

The examples intentionally distinguish educational cryptographic demonstrations from production cryptography.

## Fundamental terminology

### Plaintext

Plaintext is the original information before encryption.

For example, a document containing:

`Quarterly revenue: 500000`

is plaintext before encryption.

### Ciphertext

Ciphertext is the transformed representation produced by an encryption operation.

A properly designed encryption system should make ciphertext computationally infeasible to interpret without the required secret key.

### Key

A key is cryptographic secret or public information used by an algorithm.

Examples include:

- symmetric encryption keys
- MAC keys
- private keys
- public keys
- key-encryption keys
- derived session keys

The security of a cryptographic system depends heavily on how keys are generated, stored, distributed, used, rotated, and revoked.

### Encryption

Encryption transforms plaintext into ciphertext using an encryption algorithm and key.

Decryption reverses that transformation for an authorized recipient.

### Symmetric cryptography

Symmetric cryptography uses shared secret key material.

The same underlying secret is used for encryption and decryption in many symmetric constructions.

Advantages include:

- high performance
- relatively small keys
- suitability for large amounts of data

The major architectural problem is secure key establishment and distribution.

AES-GCM and ChaCha20-Poly1305 are examples of authenticated symmetric encryption constructions.

### Asymmetric cryptography

Asymmetric cryptography uses mathematically related public and private keys.

The public key can normally be distributed more widely, while the private key must remain protected.

Important applications include:

- digital signatures
- key establishment
- identity authentication
- certificates

RSA and elliptic-curve cryptography are examples of asymmetric cryptographic families.

## Encoding versus encryption

Encoding changes the representation of data.

It does not provide secrecy.

The Python and JavaScript implementations demonstrate Base64 encoding. A string encoded with Base64 can be decoded without possessing a secret key.

For example, the relationship is conceptually:

`plaintext -> Base64 encoding -> encoded representation`

Encryption is different:

`plaintext + secret key -> ciphertext`

The distinction is important because Base64 is frequently mistaken for encryption in poorly designed applications.

## Classical cryptography

Classical cryptography predates modern computational cryptography.

The Python implementation includes a Caesar cipher.

A Caesar cipher shifts alphabetic characters by a fixed amount. If the shift is three:

`A -> D`

`B -> E`

`C -> F`

and so forth.

The implementation demonstrates both encryption and decryption.

Its weakness is fundamental. The key space is extremely small, and language statistics remain visible.

### Frequency analysis

Substitution-based ciphers often preserve frequency patterns.

Natural languages contain letters with different frequencies. An attacker can exploit those patterns to infer substitutions.

The Python program counts alphabetic characters to illustrate this principle.

This provides an important transition from classical cryptography to modern cryptography: security should not depend on obscuring the algorithm or relying on simple statistical transformations.

## One-time pad

A one-time pad uses a truly random key that is:

- at least as long as the plaintext
- kept secret
- used only once

The basic operation can be represented as:

`C = P XOR K`

and decryption as:

`P = C XOR K`

When the strict requirements are satisfied, a one-time pad provides information-theoretic perfect secrecy.

Its practical limitation is key management. The communicating parties need a secure random key as long as the message and must prevent key reuse.

The Python implementation demonstrates this concept with bytewise XOR.

The XOR implementation is educational and should not be mistaken for a secure general-purpose encryption construction.

## Cryptographically secure randomness

Randomness is fundamental to cryptography.

Security-sensitive random values can include:

- encryption keys
- salts
- nonces
- initialization vectors
- session identifiers
- authentication tokens
- ephemeral private keys

Ordinary pseudorandom generators designed for simulation are not necessarily suitable for cryptography.

Python uses the `secrets` module for security-sensitive randomness.

Node.js uses `crypto.randomBytes()`.

A secure random generator must make generated values difficult for an attacker to predict.

## Cryptographic hash functions

A cryptographic hash function maps input data of arbitrary length to a fixed-size digest.

Conceptually:

`H(message) = digest`

Important properties include:

### Preimage resistance

Given a digest, it should be computationally difficult to find an input producing that digest.

### Second-preimage resistance

Given one input, it should be computationally difficult to find a different input with the same digest.

### Collision resistance

It should be computationally difficult to find any two different inputs with the same digest.

### Avalanche effect

A small input change should cause a substantial change in the output digest.

The Python and JavaScript implementations demonstrate this by hashing:

`Hello`

and:

`hello`

with SHA-256.

The resulting digests are substantially different.

## Hashing is not encryption

A cryptographic hash is not intended to be decrypted.

Encryption is designed to provide reversible confidentiality when the appropriate key is available.

Hashing is normally one-way under the intended security assumptions.

This distinction is particularly important for passwords.

## Password storage

Passwords should not normally be stored as plaintext.

Plain SHA-256 is also generally unsuitable as a password-storage mechanism because it is intentionally fast.

An attacker with a stolen password database can try enormous numbers of candidate passwords against a fast hash.

Password-specific key derivation functions deliberately increase the cost of password guessing.

The Python implementation demonstrates PBKDF2.

The JavaScript implementation demonstrates scrypt.

Production password-storage systems can use dedicated password hashing algorithms such as Argon2id, scrypt, or bcrypt according to current security requirements and operational constraints.

### Salt

A salt is unique random data associated with a password derivation.

A salt does not have to remain secret.

Its purpose includes preventing identical passwords from automatically producing identical stored password hashes and reducing the usefulness of precomputed attack tables.

Each password record should normally have its own unique salt.

## HMAC

HMAC means Hash-based Message Authentication Code.

It combines a secret key with a cryptographic hash to create an authentication tag.

Conceptually:

`HMAC(key, message) -> authentication tag`

A recipient possessing the same secret key can independently calculate the expected tag.

If the received tag does not match, the message or authentication context should be rejected.

The Python and JavaScript implementations demonstrate HMAC verification.

HMAC provides:

- integrity protection
- authentication based on possession of a shared secret

HMAC does not provide confidentiality.

An attacker who can observe an HMAC-protected plaintext can still read that plaintext.

## Symmetric encryption

Symmetric encryption uses shared secret key material.

The Python implementation first demonstrates the mathematical idea with XOR and a generated keystream.

The example is explicitly educational.

The JavaScript implementation demonstrates a practical standardized construction available through Node.js:

`AES-256-GCM`

AES-GCM combines encryption and authentication.

It produces:

- ciphertext
- an initialization vector or nonce
- an authentication tag

The authentication tag allows the recipient to detect modification.

## Authenticated encryption

Confidentiality without integrity can create dangerous systems.

An attacker may not be able to read ciphertext but could still attempt to modify it.

Authenticated encryption addresses both properties.

Authenticated encryption with associated data, usually called AEAD, allows an application to protect:

- encrypted plaintext
- additional authenticated data

The additional authenticated data is not encrypted but is covered by the authentication mechanism.

For example, an application could encrypt a document while authenticating:

`record-type=user`

If the associated data changes unexpectedly, authentication should fail.

AES-GCM and ChaCha20-Poly1305 are common AEAD constructions.

## Nonces and initialization vectors

A nonce is a value intended to be used according to the uniqueness requirements of a cryptographic construction.

An initialization vector, or IV, serves a related construction-specific purpose.

There is no universal rule that every nonce must be secret.

Many nonces can be transmitted openly.

The critical issue is following the exact uniqueness and generation requirements of the selected algorithm.

AES-GCM is particularly sensitive to nonce reuse. Reusing a nonce with the same key can severely compromise security.

The JavaScript implementation generates a fresh 12-byte value for each AES-GCM operation.

## Message authentication versus encryption

The distinction can be represented as follows:

| Mechanism | Confidentiality | Integrity | Authentication |
|---|---:|---:|---:|
| Plain hash | No | Limited integrity use | No |
| HMAC | No | Yes | Yes, with shared secret |
| Symmetric encryption without authentication | Yes | No | No |
| AEAD | Yes | Yes | Yes, with key possession |
| Digital signature | No | Yes | Yes, based on private-key possession |

The precise security guarantees depend on the algorithm, protocol, key management, and threat model.

## Modular arithmetic

Modern public-key cryptography relies heavily on mathematical structures.

The Python implementation demonstrates:

- modular reduction
- modular exponentiation
- greatest common divisors
- extended Euclidean algorithm
- modular inverses

For example:

`7 × 15 mod 26 = 1`

Therefore, 15 is the multiplicative inverse of 7 modulo 26.

The Python function `modular_inverse()` uses the extended Euclidean algorithm.

## Prime numbers

Prime numbers are central to several public-key constructions.

The Python implementation contains a Miller-Rabin probable-prime test.

The test is probabilistic and useful for understanding how large-number primality testing can work.

Cryptographic key generation requires much more careful engineering than a small educational implementation.

Production implementations must account for:

- suitable parameter sizes
- secure random generation
- correct primality testing
- implementation side channels
- standards
- cryptographic library behavior

## Diffie-Hellman key agreement

Diffie-Hellman allows two parties to establish shared secret material without directly transmitting that secret.

The basic conceptual structure is:

1. Public parameters are selected.
2. Alice chooses a private value.
3. Bob chooses a private value.
4. Each party derives a public value.
5. Alice uses Bob's public value with her private value.
6. Bob uses Alice's public value with his private value.
7. Both obtain the same shared secret.

The Python program uses very small numbers so the mathematics can be inspected.

Those parameters are not secure.

### Man-in-the-middle limitation

Unauthenticated Diffie-Hellman does not automatically establish who is on the other side.

An attacker can potentially establish one shared secret with Alice and another with Bob.

Practical protocols combine key agreement with authentication.

TLS uses certificates and other protocol mechanisms to establish authenticated secure channels.

## Elliptic-curve Diffie-Hellman

The JavaScript implementation uses Node.js ECDH support with `prime256v1`.

ECDH performs key agreement using elliptic-curve mathematics.

The important conceptual property is the same:

`Alice shared secret = Bob shared secret`

The private values are not transmitted.

Modern protocols commonly use ephemeral key exchange to obtain forward-secrecy properties.

## RSA

RSA is based on mathematical problems related to integer factorization.

The Python implementation provides a deliberately small educational RSA system.

The basic structure is:

`n = p × q`

`phi(n) = (p - 1)(q - 1)`

A public exponent `e` is selected such that:

`gcd(e, phi(n)) = 1`

The private exponent `d` satisfies:

`e × d ≡ 1 mod phi(n)`

Encryption and decryption use modular exponentiation.

The JavaScript implementation generates a real RSA key pair using Node.js and uses OAEP padding for encryption.

### Textbook RSA

Raw textbook RSA is not suitable for application encryption.

RSA encryption requires a secure randomized encoding or padding scheme.

OAEP is designed for RSA encryption.

The Python implementation is intentionally described as mathematical education rather than secure application encryption.

## Digital signatures

Digital signatures provide a mechanism for detecting message modification and establishing that a message was signed using a particular private key, assuming the private key remains controlled by its owner and the cryptographic scheme is correctly implemented.

The general process is:

1. The signer has a private key.
2. The signer processes the message with the signature algorithm.
3. A signature is produced.
4. The recipient uses the corresponding public key.
5. Verification succeeds only when the signature matches the message and key.

The JavaScript implementation demonstrates elliptic-curve signatures.

The Python implementation demonstrates the mathematical idea with toy RSA.

A production signature system must use standardized algorithms and secure encoding rules.

## Public keys and private keys

A public key can be distributed.

A private key must be protected.

Compromise of a private signing key can allow unauthorized signatures.

Compromise of a private decryption key can expose protected data depending on the protocol and key-management design.

Private keys should therefore be treated as high-value security assets.

## Certificates

A certificate binds information such as an identity or DNS name to a public key.

A simplified certificate contains information such as:

- subject
- issuer
- public key
- validity period
- usage constraints
- issuer signature

The certificate authority signs the certificate data.

A recipient can validate the signature using a trusted CA public key and then evaluate whether the certificate is appropriate for the intended connection.

Certificate validation involves more than checking that a signature exists.

Relevant checks can include:

- trust-chain validation
- certificate validity period
- hostname or identity matching
- key usage
- extended key usage
- certificate constraints
- revocation mechanisms where applicable

## TLS

TLS is a protocol family for securing network communication.

TLS is not a single encryption algorithm.

A modern TLS connection can involve:

- negotiation
- server authentication
- certificate validation
- ephemeral key agreement
- session-key derivation
- authenticated encryption
- sequence handling
- protocol-state management

The Python implementation describes this architecture conceptually.

The JavaScript implementation demonstrates cryptographic primitives that are relevant to the components used by secure network protocols.

## Key derivation

A master secret should not necessarily be used directly for every cryptographic operation.

Key derivation can produce separate keys for different purposes.

For example:

`master secret -> encryption key`

and:

`master secret -> authentication key`

The Python and JavaScript implementations demonstrate domain-separated derivation using HMAC.

Using distinct keys for distinct purposes reduces accidental cross-protocol interactions.

Dedicated KDF constructions can provide stronger and more formally analyzed derivation behavior for particular applications.

## Domain separation

Domain separation prevents identical input data used in different protocol contexts from automatically producing identical derived cryptographic values.

For example:

`H("PAYMENT" || message)`

and:

`H("LOGIN" || message)`

represent different domains.

The Python implementation demonstrates this principle.

Domain separation is useful when a system derives several values from common secret material.

## Key management

Cryptographic algorithms are only one component of a secure system.

Key management includes:

- generation
- distribution
- storage
- access control
- versioning
- rotation
- revocation
- backup
- destruction
- auditing

The C++ case study contains a `KeyRing` class with versioned keys.

Each key has:

- a version
- key material
- an active/inactive state

The service records the key version in each encrypted envelope.

This demonstrates why cryptographic metadata is often required alongside ciphertext.

## Key rotation

Long-lived keys increase the potential impact of compromise.

Key rotation can limit the period during which a particular key is used.

A production key-management architecture may also need:

- old-key decryption support during migration
- key revocation
- emergency replacement
- key provenance
- secure key storage
- access logging

The C++ case study creates a new key version and uses it for later encryption operations.

## Replay attacks

Authentication does not automatically prevent replay.

Suppose an attacker captures a valid authenticated request:

`PAY 100`

The attacker may be unable to modify it but could attempt to send the exact valid message again.

A protocol can use:

- sequence numbers
- nonces
- timestamps
- expiration values
- state tracking

The Python implementation illustrates sequence-related replay protection.

The C++ case study maintains the highest accepted sequence number for a sender-receiver relationship and rejects messages that are not newer.

The policy is deliberately simplified. Real protocols may require more sophisticated state handling, especially when messages can arrive out of order.

## Constant-time comparison

Security-sensitive values such as MAC tags should not normally be compared with ordinary operations that can reveal information through timing differences.

Python provides `hmac.compare_digest()`.

Node.js provides `crypto.timingSafeEqual()`.

The C++ case study implements a simple constant-time comparison function for educational purposes.

The exact side-channel properties of an implementation require careful analysis. A constant-time comparison function alone does not make an entire program side-channel resistant.

## Hash chains

A hash chain repeatedly hashes the previous value:

`H0 = initial value`

`H1 = H(H0)`

`H2 = H(H1)`

and so forth.

Changing an earlier value changes later values.

Hash chains appear in several kinds of systems where sequential integrity relationships are useful.

The Python and JavaScript implementations demonstrate this structure.

## Merkle trees

A Merkle tree organizes hashes into a hierarchy.

For leaf values:

`L1, L2, L3, L4`

the system can calculate:

`H1 = H(L1)`

`H2 = H(L2)`

`H3 = H(L3)`

`H4 = H(L4)`

then combine them:

`P1 = H(H1 || H2)`

`P2 = H(H3 || H4)`

and finally:

`Root = H(P1 || P2)`

The root represents a compact commitment to the underlying data.

The Python and JavaScript implementations calculate Merkle roots for transaction-like records.

## Token authentication

The Python and JavaScript implementations include educational authenticated-token services.

The token contains:

- a version
- encoded payload
- authentication value

The authentication value covers the token's signing input.

Verification performs several checks:

1. Parse the structure.
2. Decode the payload.
3. Recalculate the expected authentication value.
4. Compare authentication values securely.
5. Validate payload fields.
6. Check expiration.

The design demonstrates several important principles:

- authentication must cover the data that is trusted
- malformed tokens must be rejected
- expiration is a protocol rule rather than an automatic property of cryptography
- cryptographic verification should occur before trusting protected claims

This implementation is educational and is not intended to replace established token standards.

## C++ secure document-transfer case study

The C++ program models a secure document service.

The scenario contains two users:

- Alice
- Bob

Alice owns a confidential document.

The service provides an encrypted envelope that contains:

- key version
- sender identity
- receiver identity
- sequence number
- nonce
- ciphertext
- authentication tag

### Major components

#### `User`

Represents an application identity.

#### `Document`

Stores document ownership and content.

#### `KeyRecord`

Stores a versioned cryptographic key.

#### `KeyRing`

Manages active key versions.

It demonstrates key rotation and key lookup.

#### `MessageAuthenticator`

Creates and verifies an educational authentication tag.

#### `EducationalEncryption`

Demonstrates the relationship between plaintext, key material, nonce, keystream, and ciphertext.

The implementation explicitly warns that its construction is not production cryptography.

#### `AuditLog`

Records security-relevant events.

#### `SecureDocumentService`

Coordinates the application-level security workflow.

### Encryption workflow

The service:

1. validates the sender
2. validates the receiver
3. validates the document
4. selects the current active key
5. creates a nonce
6. encrypts the document
7. constructs authenticated metadata
8. generates an authentication tag
9. records an audit event
10. returns the protected envelope

### Decryption workflow

The recipient-side operation:

1. validates the sender
2. validates the receiver
3. checks the sequence number
4. retrieves the referenced key version
5. verifies key status
6. reconstructs authenticated data
7. verifies the authentication tag
8. decrypts the ciphertext
9. updates replay-protection state
10. records a successful audit event

The ordering matters.

Authenticated data should be verified before an application treats decrypted content as trusted.

### Tampering case

The C++ program modifies a ciphertext byte after encryption.

The authentication tag was generated before the modification.

Verification therefore fails.

The modified message is rejected.

This demonstrates why encryption without authentication is insufficient for many application protocols.

### Replay case

The first valid message uses sequence number `1`.

The service accepts it and records that sequence number.

If the same envelope is submitted again, its sequence number is no longer newer.

The service rejects it as a replay.

### Key rotation case

The service initially uses key version `1`.

A rotation operation creates a new key version.

Subsequent encryption uses the newer version.

Including the key version in the envelope allows the recipient to identify which key should be used for verification and decryption.

## JavaScript implementation

The JavaScript file focuses on practical Node.js cryptographic APIs.

### AES-GCM

The `encryptAesGcm()` function:

- generates a 12-byte IV
- creates an AES-256-GCM cipher
- optionally authenticates associated data
- encrypts plaintext
- obtains the authentication tag

The `decryptAesGcm()` function restores the plaintext only when authentication succeeds.

Tampering with ciphertext causes decryption to fail.

### Scrypt

The password demonstration uses Node.js's asynchronous `crypto.scrypt()` API.

The example illustrates why password derivation should not simply use a fast general-purpose hash.

The KDF receives:

- password
- salt
- output length
- computational parameters

### ECDH

The ECDH demonstration creates two independent key pairs and computes the shared secret from each side.

The program verifies that both sides obtain identical secret material.

### RSA

The RSA demonstration generates a 2048-bit key pair and uses RSA-OAEP with SHA-256.

This is materially different from the small mathematical RSA example in Python.

### Digital signatures

The JavaScript implementation creates an elliptic-curve signing key pair and signs a transaction-like message.

Verification succeeds for the original message and fails for the modified message.

### Asynchronous cryptography

JavaScript applications often operate within event-driven runtimes.

The asynchronous scrypt example demonstrates how a potentially expensive password derivation operation can be performed through an asynchronous API.

## Python implementation

The Python file is structured as a progressive study program.

It begins with:

- security goals
- classical cryptography
- Caesar cipher
- frequency analysis
- one-time pad
- secure randomness
- encoding

It then moves into:

- SHA-256
- SHA-512
- SHA3-256
- avalanche behavior
- password hashing
- PBKDF2
- HMAC
- symmetric encryption concepts
- authenticated encryption concepts

The mathematical section introduces:

- modular arithmetic
- extended Euclidean algorithm
- modular inverses
- probable-prime testing
- Diffie-Hellman
- RSA
- digital signatures

The advanced section addresses:

- replay protection
- domain separation
- constant-time comparison
- hash chains
- Merkle trees
- key derivation
- key rotation
- certificates
- TLS
- common failures
- edge cases
- performance
- cryptographic agility
- post-quantum cryptography

The program concludes with assertions and an authenticated-token case study.

## Important distinctions

### Encryption versus hashing

Encryption is intended to be reversible using appropriate key material.

Hashing is designed to produce a fixed-length digest and is not intended to be reversed.

### Hashing versus HMAC

A hash does not require a secret key.

HMAC requires a secret key.

A plain hash therefore cannot authenticate a message against an attacker who can freely calculate the same hash.

### HMAC versus digital signatures

HMAC uses a shared secret.

Digital signatures use a private key for signing and a public key for verification.

HMAC is generally efficient but requires secure distribution of the shared secret.

Digital signatures are useful when many parties need to verify signatures without sharing a common authentication secret.

### Symmetric versus asymmetric cryptography

Symmetric algorithms are generally much faster and are therefore suitable for bulk data.

Asymmetric algorithms provide capabilities such as public-key authentication and key establishment but are generally more computationally expensive.

Practical systems often combine both categories.

### Authentication versus authorization

Authentication answers:

`Who are you?`

Authorization answers:

`What are you allowed to do?`

Cryptographic authentication can help establish identity or possession of credentials.

It does not automatically determine application permissions.

## Edge cases

Cryptographic applications must define behavior for unusual and malicious inputs.

Important cases include:

- empty messages
- zero-length plaintext
- binary data
- Unicode data
- malformed encodings
- invalid key lengths
- unknown key versions
- expired credentials
- invalid signatures
- invalid authentication tags
- repeated nonces
- repeated sequence numbers
- oversized messages
- truncated ciphertext
- missing metadata
- corrupted protocol fields

The Python implementation hashes several unusual inputs, including empty data and Unicode-encoded data.

The JavaScript implementation deliberately corrupts authentication tags and ciphertext.

The C++ case study tests invalid receivers, tampering, replay, and key-state failures.

## Exceptions and failure handling

Cryptographic verification failures must not be treated as successful operations.

Examples include:

- invalid MAC
- invalid signature
- invalid authentication tag
- malformed token
- expired token
- unknown key
- revoked key
- invalid certificate
- replayed message

The JavaScript program catches authentication failures from AES-GCM.

The Python program uses exceptions for invalid cryptographic parameters.

The C++ program uses exceptions for programming and validation failures while returning `std::optional` for rejected secure-message operations.

The distinction between exceptional programming errors and expected security rejection is an important architectural decision.

## Common mistakes

### Using Base64 as encryption

Base64 is encoding.

It does not protect confidentiality.

### Using SHA-256 directly for passwords

Fast hashes allow attackers to test large numbers of password guesses.

Use an appropriate password-specific KDF.

### Reusing GCM nonces

Nonce reuse under AES-GCM with the same key can seriously compromise security.

### Hard-coding secrets

Source code is often copied, logged, backed up, scanned, or exposed through development systems.

Production secrets require appropriate secret-management controls.

### Using predictable randomness

Security tokens and cryptographic keys must not be generated using predictable application-level randomness.

### Creating custom encryption

Cryptographic algorithms are difficult to design correctly.

Even mathematically correct designs can fail through incorrect padding, nonce handling, side channels, key management, protocol composition, or error handling.

### Encrypting without authentication

Confidentiality does not guarantee integrity.

An attacker may be able to modify unauthenticated ciphertext.

### Ignoring identity validation

A secure channel requires more than encrypted bytes.

The parties must establish who they are communicating with under the protocol's trust model.

### Comparing authentication tags incorrectly

Use timing-aware comparison mechanisms when comparing security-sensitive authentication values.

### Logging secrets

Audit logs should record security events without exposing:

- private keys
- passwords
- authentication tokens
- plaintext confidential data
- encryption keys
- raw session secrets

## Limitations of the educational implementations

The examples intentionally balance mathematical clarity with practical programming.

Several demonstrations are not production cryptography.

The Python toy RSA implementation uses small primes.

The Python XOR-based authenticated-encryption demonstration is an educational composition and is not an AEAD standard.

The C++ program uses an educational hash function and XOR-based encryption rather than a standardized cryptographic primitive.

The C++ random generator is also presented for educational architecture rather than as a replacement for an operating-system-backed cryptographic random facility.

The JavaScript implementation is more practical because Node.js supplies standardized cryptographic primitives through its built-in `crypto` module.

Even the JavaScript examples should not be interpreted as complete application security architectures. Secure production systems require protocol-level decisions around authentication, storage, transport, permissions, key lifecycle, operational monitoring, and dependency maintenance.

## Performance considerations

Cryptographic performance depends on algorithm, key size, message size, hardware, implementation, and workload.

General characteristics include:

- symmetric encryption is typically efficient for bulk data
- cryptographic hashes are designed for efficient processing
- password KDFs intentionally consume more computational resources
- public-key operations are generally more expensive than symmetric operations
- key generation can be significantly more expensive than ordinary symmetric encryption
- asynchronous APIs can improve application responsiveness for expensive operations

The JavaScript implementation performs a simple SHA-256 timing measurement over a 1 MiB buffer.

The purpose is to demonstrate measurement rather than establish a universal benchmark.

Benchmark results should always be interpreted in relation to the hardware, runtime, implementation, compiler, operating system, and workload.

## Security considerations

A cryptographic system should begin with a threat model.

Questions include:

- Who is the attacker?
- Can the attacker read network traffic?
- Can the attacker modify messages?
- Can the attacker replay messages?
- Can the attacker compromise a database?
- Can the attacker steal application secrets?
- Can the attacker control a client?
- Can the attacker observe timing or memory behavior?
- What happens if a private key is compromised?
- How are credentials revoked?

The selected cryptographic primitive should follow from those requirements.

### Key protection

Keys should receive stronger protection than ordinary application data.

Potential controls include:

- operating-system access controls
- dedicated key-management services
- hardware security modules
- encryption at rest
- least-privilege access
- rotation
- revocation
- audit logging

### Forward secrecy

Forward secrecy means that compromise of a long-term private key does not automatically expose previously recorded session traffic, assuming the protocol's ephemeral key material was securely erased and the construction provides the required property.

Ephemeral key agreement is an important mechanism for achieving forward secrecy in suitable protocols.

### Cryptographic agility

Systems should avoid hard-coding one algorithm so deeply that migration becomes impossible.

A protocol can include explicit algorithm and key-version identifiers.

The Python and C++ examples demonstrate versioned or selectable cryptographic contexts.

Cryptographic agility does not mean supporting unlimited algorithms. It means designing systems so that legitimate cryptographic migration can occur without rewriting the entire security architecture.

## Post-quantum cryptography

Large-scale quantum computers could threaten important public-key systems.

RSA relies on mathematical assumptions related to integer factorization.

Classical finite-field Diffie-Hellman and elliptic-curve cryptography rely on discrete-logarithm-related assumptions.

Large-scale quantum algorithms are known to threaten these mathematical problems.

Post-quantum cryptography studies alternative constructions designed to resist known quantum attacks while operating on classical computers.

This creates an important distinction:

- symmetric cryptography and many hash-based constructions are affected differently by quantum algorithms
- widely deployed public-key systems require particular attention to quantum-resistant migration

Cryptographic agility therefore has practical long-term importance.

## Implementation design principles

A reliable cryptographic application should:

- define the security property first
- select standardized algorithms
- use established libraries
- use secure randomness
- separate keys by purpose
- authenticate encrypted data
- validate protocol metadata
- protect private keys
- use appropriate password KDFs
- avoid nonce reuse
- implement replay protection where required
- rotate and revoke keys
- perform constant-time comparisons where appropriate
- handle failures securely
- avoid leaking sensitive values through logs
- test malformed inputs
- document cryptographic assumptions
- maintain cryptographic agility

## Real-world applications

Cryptography is used throughout modern computing.

### Secure web communication

TLS protects traffic between clients and servers.

### Password authentication

Password-specific KDFs protect stored password verifiers.

### Digital payments

Cryptographic authentication and signatures help protect payment transactions and financial systems.

### Software signing

Digital signatures can establish that software or updates were signed using an authorized private key.

### Secure messaging

Modern messaging systems can combine authenticated encryption, public-key mechanisms, key agreement, identity verification, and forward secrecy.

### Cloud storage

Encryption can protect data at rest and in transit.

### Databases

Sensitive fields may be encrypted, while integrity and access controls provide additional protections.

### Blockchain and distributed systems

Hashes, digital signatures, Merkle trees, and authenticated data structures are important components of many distributed systems.

### Identity systems

Public-key cryptography and certificates can establish cryptographic identities.

### Hardware security

Keys can be protected using secure elements, trusted execution environments, or hardware security modules.

## Relationship between the three implementations

The three languages intentionally emphasize different layers of the topic.

| Implementation | Primary emphasis |
|---|---|
| Python | Concepts, mathematics, progressive learning, algorithms, protocol principles |
| JavaScript | Practical application APIs, authenticated encryption, asynchronous operations, Node.js cryptography |
| C++ | System architecture, data structures, validation, key management, replay protection, auditing |

Python is useful for exposing algorithms and mathematical relationships because the syntax is compact and expressive.

JavaScript is useful for demonstrating cryptography inside event-driven application environments, particularly when using Node.js's built-in cryptographic APIs.

C++ is useful for examining explicit data structures, object lifecycles, validation boundaries, application architecture, and performance-sensitive systems programming.

## Conceptual security model

A useful way to organize cryptography is by asking which problem a mechanism solves.

| Problem | Typical mechanism |
|---|---|
| Keep data secret | Symmetric encryption |
| Detect unauthorized modification | Hash, MAC, or authenticated encryption |
| Authenticate with a shared secret | MAC/HMAC |
| Authenticate using public verification | Digital signature |
| Establish shared secret material | Diffie-Hellman or ECDH |
| Store passwords securely | Password-specific KDF |
| Bind an identity to a public key | Certificate |
| Prevent message replay | Nonces, sequence numbers, timestamps, protocol state |
| Derive independent keys | KDF and domain separation |
| Commit to large data structures | Merkle tree |
| Maintain sequential integrity relationships | Hash chain |
| Manage changing keys | Key versions and rotation |

No single mechanism provides all of these properties.

Secure systems combine mechanisms according to a defined threat model and protocol.

## Production considerations

Production cryptography requires attention beyond the algorithm itself.

Important engineering areas include:

- secure key storage
- access control
- secret lifecycle management
- certificate lifecycle management
- key rotation
- incident response
- dependency updates
- algorithm migration
- audit logging
- secure deletion where applicable
- backup and recovery
- protocol versioning
- compatibility
- performance testing
- load testing
- failure testing
- monitoring
- secure deployment

The strongest cryptographic algorithm can be defeated by a leaked key, invalid certificate validation, nonce reuse, incorrect authorization logic, insecure randomness, or a protocol implementation error.

## Educational implementation map

The Python script contains the following major demonstrations:

- `caesar_encrypt()` and `caesar_decrypt()` for classical substitution
- `letter_frequency()` for frequency analysis
- `one_time_pad_encrypt()` for XOR-based one-time-pad principles
- `password_digest()` for PBKDF2-based password derivation
- `create_hmac()` and `verify_hmac()` for message authentication
- `modular_inverse()` for modular arithmetic
- `is_probable_prime()` for Miller-Rabin primality testing
- `demonstrate_diffie_hellman()` for key agreement
- `generate_toy_rsa()` for RSA mathematics
- `demonstrate_digital_signature()` for signature concepts
- `merkle_root()` for Merkle-tree construction
- `KeyRing` for key versioning
- `SecureTokenService` for authenticated token design

The JavaScript file contains:

- Base64 encoding
- SHA-256, SHA-512, and SHA3-256
- HMAC
- cryptographically secure random bytes
- AES-256-GCM
- scrypt
- PBKDF2
- ECDH
- RSA-OAEP
- elliptic-curve signatures
- hash chains
- Merkle trees
- authenticated tokens
- key separation
- certificate concepts
- asynchronous cryptographic operations
- authentication failure handling
- performance measurement

The C++ case study contains:

- users
- documents
- key records
- key-ring management
- educational hashing
- educational authenticated encryption
- constant-time comparison
- secure message envelopes
- sequence numbers
- replay detection
- tamper detection
- key rotation
- validation
- failure handling
- audit logging

## Complexity considerations

For a message of length `n`, many hash and symmetric encryption operations have approximately linear processing cost:

`O(n)`

The amount of work grows with the size of the input.

A balanced Merkle tree can be constructed from `n` leaves in approximately:

`O(n)`

The tree height is approximately:

`O(log n)`

which makes Merkle proofs useful for demonstrating membership without transmitting the complete collection.

RSA operations depend on large-integer arithmetic and are substantially more expensive than ordinary symmetric operations.

Password KDFs are deliberately configured to consume significant computational resources.

The exact complexity and practical cost depend on the algorithm, parameter sizes, implementation, hardware, and runtime.

## Testing strategy

Cryptographic code should be tested at several levels.

### Functional tests

Verify that:

- valid plaintext encrypts and decrypts correctly
- valid tags verify
- valid signatures verify
- valid keys work
- key derivation is deterministic for the same inputs
- Merkle roots are deterministic

### Negative tests

Verify that:

- modified ciphertext is rejected
- modified tags are rejected
- wrong keys are rejected
- expired tokens are rejected
- malformed tokens are rejected
- unknown key versions are rejected
- replayed messages are rejected
- invalid users are rejected

### Boundary tests

Test:

- empty input
- one-byte input
- binary input
- Unicode input
- maximum supported input
- invalid lengths
- invalid encodings
- repeated sequence numbers

The included programs demonstrate both positive assertions and deliberate failure conditions.

## Core principles demonstrated

The implementations collectively illustrate several central cryptographic principles:

1. Security properties must be identified before selecting mechanisms.
2. Encoding is not encryption.
3. Hashing is not encryption.
4. Password hashing requires specialized treatment.
5. Confidentiality does not automatically provide integrity.
6. Authentication does not automatically prevent replay.
7. Public-key systems solve different problems from symmetric systems.
8. Key management is part of cryptographic security.
9. Nonce requirements are construction-specific and must be followed precisely.
10. Domain separation helps keep cryptographic contexts independent.
11. Secure randomness is foundational.
12. Standardized cryptographic constructions are preferable to custom algorithms.
13. Failure handling is part of security design.
14. Cryptographic agility supports long-term migration.
15. Application security depends on the entire protocol and operational environment, not only the primitive.

## File structure

The repository contains three executable study implementations and one documentation file:

- `cryptography.py` — comprehensive Python study program
- `cryptography.js` — Node.js practical cryptography demonstrations
- `cryptography.cpp` — C++ secure document-transfer case study
- `README.md` — conceptual and implementation documentation

The Python file can be executed with a modern Python 3 interpreter.

The JavaScript file can be executed with a modern Node.js runtime.

The C++ program is designed for compilation with C++17 or later.

The C++ implementation intentionally does not present its educational primitives as production-safe cryptography. Its primary purpose is to demonstrate how cryptographic concepts can be integrated into a larger application architecture.
