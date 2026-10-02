# Symmetric Encryption

Symmetric encryption is a cryptographic technique in which the communicating parties use shared secret key material to transform plaintext into ciphertext and later recover the plaintext.

The central relationship is:

`plaintext + secret key + encryption process -> ciphertext`

and, when the correct key and required public parameters are supplied:

`ciphertext + secret key + decryption process -> plaintext`

Modern symmetric encryption is designed primarily for confidentiality, but secure application protocols generally need authenticity as well. Encryption by itself does not necessarily tell the recipient whether the ciphertext was modified. Authenticated encryption combines confidentiality with integrity and authenticity checks.

This repository presents the subject through three different implementation perspectives:

- The Python program develops the underlying mechanics, including XOR, a Feistel construction, stream-style processing, password-based key derivation, AES-GCM, authenticated file handling, and validation.
- The JavaScript program focuses on Node.js cryptographic APIs, `Buffer` handling, AES-256-GCM, asynchronous key derivation, serialization, event-driven processing, and streaming files.
- The C++ program models a message gateway in which shared keys, nonces, authenticated metadata, authentication tags, key selection, tamper detection, and replay protection operate as parts of a coherent system.

The toy cryptographic constructions are deliberately separated from the production-oriented AES-GCM examples. A custom cipher should not be deployed merely because it appears to encrypt and decrypt successfully.

## Core terminology

### Plaintext

Plaintext is the original data that an application wants to protect.

Examples include:

- A financial transaction.
- A database record.
- A confidential API payload.
- A private file.
- A message exchanged between services.

Plaintext is normally represented as bytes before encryption. Text must therefore be encoded, commonly as UTF-8, before a binary encryption operation.

### Ciphertext

Ciphertext is the transformed representation produced by encryption.

A properly designed encryption scheme should make ciphertext computationally infeasible to interpret without the appropriate secret key. Ciphertext is not expected to resemble the original plaintext.

Encryption does not imply that ciphertext must be printable text. Binary ciphertext is commonly transported using encodings such as Base64 when a text-only transport format requires it.

### Secret key

The secret key is the critical shared cryptographic value.

For a symmetric system:

`Alice --shared secret--> Bob`

Both sides require compatible access to the same secret key material.

The key must be protected independently of the ciphertext. Encrypting a message correctly does not help if an attacker can simply obtain the key.

A key identifier can be public metadata used to select the correct secret from a key-management system. The identifier itself is not a substitute for the secret key.

### Nonce

A nonce is a value associated with a particular encryption operation. In many modern constructions it is transmitted alongside the ciphertext and does not need to remain secret.

For AES-GCM, nonce management is critical. Reusing a nonce with the same key can seriously compromise security.

The Python and JavaScript implementations therefore generate fresh 96-bit nonces for their AES-GCM demonstrations.

### Initialization vector

An initialization vector, or IV, is a value used by particular encryption modes to initialize the encryption process. The precise requirements depend on the algorithm and mode.

IV and nonce are sometimes used loosely as interchangeable terms, but their required properties are construction-specific. A protocol should document exactly what its selected primitive requires rather than assuming that every IV can be generated or reused in the same way.

### Authentication tag

An authentication tag is a short value used by an authenticated-encryption construction to detect unauthorized modification.

For an AEAD message, the recipient verifies the tag before releasing plaintext to the application.

Changing ciphertext, authenticated metadata, or other protected inputs should cause authentication failure.

### Associated data

Associated data is information that is authenticated but not encrypted.

For example, a protocol may need the recipient to see:

`message-type=invoice;version=1`

while still preventing an attacker from changing that value.

The AES-GCM examples authenticate associated data through the AEAD API. The C++ case study includes associated data in its authenticated input to demonstrate the same protocol relationship.

## How symmetric encryption works

At the conceptual level, a symmetric encryption system has a secret key and an encryption transformation.

A simple reversible transformation can be represented as:

`C = E(K, P)`

where:

- `P` is plaintext.
- `K` is the secret key.
- `E` is the encryption operation.
- `C` is ciphertext.

Decryption reverses that transformation:

`P = D(K, C)`

where `D` is the corresponding decryption operation.

Modern algorithms add more structure because real applications need much more than a reversible mathematical operation. They need resistance to known attacks, safe processing of arbitrary-length messages, appropriate nonce behavior, efficient implementations, and, in most application protocols, authentication.

## XOR as the basic reversible operation

XOR has an important mathematical property:

`P XOR K XOR K = P`

That means XOR is self-inverting. If a byte is XORed with a value twice, the original byte returns.

The Python and JavaScript implementations use repeating-key XOR only to expose this mechanism.

The construction is insecure because the same short key is repeatedly reused. If the same keystream material protects multiple plaintext positions or messages, an attacker can obtain relationships between plaintexts by XORing ciphertexts.

For example:

`C1 = P1 XOR K`

`C2 = P2 XOR K`

Then:

`C1 XOR C2 = P1 XOR P2`

The secret key cancels out.

This is why the existence of a reversible encryption operation is not enough to make an encryption system secure.

## Block-cipher structure

A block cipher transforms fixed-size blocks using a secret key.

A simplified representation is:

`C = E(K, P_block)`

where `P_block` has the algorithm's required block size.

The Python program includes an educational Feistel network. A Feistel construction divides a block into two halves and repeatedly transforms one half while combining it with the other.

A simplified round can be expressed as:

`L_next = R`

`R_next = L XOR F(R, K_round)`

The important structural property is that the construction can be reversed by applying the round keys in reverse order.

The Python implementation demonstrates:

- Fixed-size blocks.
- Left and right halves.
- Round-specific subkeys.
- A round function.
- Reverse-order decryption.
- Padding for arbitrary-length messages.

The implementation is intentionally not presented as a secure replacement for AES. Its purpose is to make block-cipher structure visible without hiding the mechanism behind a library call.

## Stream-style encryption

Stream encryption produces a keystream and combines that stream with plaintext.

A simplified model is:

`C = P XOR S`

where `S` is a keystream generated from secret key material and other parameters such as a nonce.

Decryption applies the same operation:

`P = C XOR S`

The important security requirement is that the keystream must be generated using a secure construction and must not be reused in a dangerous way.

The Python program demonstrates a counter-based HMAC-derived keystream. It is useful for showing how a message can be processed as a sequence of generated keystream blocks.

That demonstration is not a replacement for a standardized stream cipher. A production protocol should use a reviewed primitive and its documented nonce rules.

## AES and authenticated encryption

AES is a standardized symmetric block cipher with a 128-bit block size and supported key sizes of 128, 192, and 256 bits.

AES itself is the block cipher. Applications normally use AES through a mode of operation.

AES-GCM combines AES with a counter-based encryption mechanism and authentication functionality. It is an authenticated-encryption construction, usually described as AEAD: authenticated encryption with associated data.

The conceptual application flow is:

`plaintext + key + nonce + associated data -> ciphertext + authentication tag`

Decryption verifies the authentication data and then recovers the plaintext.

This distinction is important:

- Encryption provides confidentiality.
- Authentication detects unauthorized modification.
- AEAD provides both through one standardized construction.

The Python program uses AES-GCM through the `cryptography` package when available. The JavaScript program uses Node.js's built-in `crypto` module.

## Python implementation

The Python program is structured as an executable laboratory rather than as a collection of disconnected snippets.

### XOR foundation

`xor_bytes()` establishes the equal-length byte operation used by the demonstrations.

`xor_with_repeating_key()` then shows why a reversible XOR operation is insufficient for secure encryption. The program deliberately examines the relationship between two ciphertexts generated with the same repeating key.

### Feistel network

The educational Feistel implementation contains:

- `feistel_round_function()`
- `derive_toy_subkeys()`
- `feistel_encrypt_block()`
- `feistel_decrypt_block()`
- `feistel_encrypt_message()`
- `feistel_decrypt_message()`

The message-level functions add PKCS#7-style padding because a block transformation operates on complete blocks.

The decryption routine reverses the round order. This demonstrates a structural property of Feistel networks rather than merely calling an encryption API.

### Stream model

The Python stream demonstration uses HMAC-SHA-256 with a nonce and counter to generate deterministic keystream blocks.

A fresh nonce produces different keystream material while the secret key remains unchanged.

The implementation also validates empty keys, empty nonces, negative lengths, and other invalid inputs.

### AES-GCM

The `EncryptedMessage` dataclass models a transport representation containing:

- `nonce`
- `ciphertext_and_tag`
- `associated_data`

The AES-GCM functions use a 32-byte key for AES-256 and a 12-byte nonce.

The demonstration changes a ciphertext byte and separately changes authenticated metadata. Both modifications are expected to cause authentication failure.

This makes an important protocol property executable: ciphertext should not be trusted merely because it can be decrypted.

### Password-derived keys

The password section uses PBKDF2-HMAC-SHA-256.

A password should not normally be treated as a raw AES key because human-selected passwords have different entropy characteristics from randomly generated cryptographic keys.

PBKDF2 combines:

- A password.
- A salt.
- A configurable work factor.
- A pseudorandom function.

The salt does not have to be secret. Its purpose includes ensuring that identical passwords do not automatically produce identical derived keys across different records.

### File encryption

The file example creates a small authenticated encrypted-file format with:

`magic | version | nonce length | metadata length | ciphertext length | nonce | metadata | ciphertext`

The format is intentionally explicit about lengths so parsing does not depend on ambiguous delimiters.

The program reads the file into memory for simplicity. Very large files require a carefully designed chunked authenticated format rather than an unbounded single AES-GCM operation.

## JavaScript implementation

The JavaScript implementation takes a different perspective by using Node.js's native cryptographic and streaming facilities.

### Buffer-based cryptography

Node.js represents binary cryptographic material naturally with `Buffer`.

The implementation keeps plaintext, keys, nonces, ciphertext, authentication tags, and associated data as buffers rather than converting binary data into strings prematurely.

Hexadecimal and Base64URL encodings are used only when data needs to be displayed or serialized.

### AES-256-GCM API flow

The JavaScript implementation uses:

`crypto.createCipheriv()`

and:

`crypto.createDecipheriv()`

For encryption:

- A random 32-byte key is supplied.
- A fresh 12-byte nonce is generated.
- Associated data is supplied to the cipher.
- Ciphertext is produced.
- The authentication tag is obtained with `getAuthTag()`.

For decryption:

- The same key and nonce are supplied.
- The same associated data must be supplied.
- The received tag is installed with `setAuthTag()`.
- `decipher.final()` verifies authentication.

A modified ciphertext or modified associated data causes decryption to throw.

### Transport serialization

`encodeMessage()` converts the encrypted message into JSON containing:

- protocol version
- algorithm identifier
- nonce
- ciphertext
- authentication tag
- associated data

The binary fields use Base64URL so the JSON remains textual without exposing raw binary bytes.

The explicit algorithm and version fields demonstrate why encrypted-message formats should be self-describing enough to prevent accidental interpretation under the wrong protocol.

### Password derivation

The JavaScript implementation uses Node's asynchronous `crypto.scrypt()` API.

The asynchronous form matters in a server environment because password-based key derivation is deliberately resource-intensive. Running expensive work synchronously on an event-loop thread can prevent other requests from being processed.

The salt is random and stored separately from the derived key.

### Event-driven processing

The program also creates an AES-GCM cipher as a Node.js transform stream.

Chunks are written into the cipher, encrypted output is received through the `data` event, and the authentication tag becomes available after the stream finishes.

This demonstrates how symmetric encryption integrates with Node.js's event-driven I/O model.

For large data, streaming can reduce memory pressure, but the message format must still define how authentication is represented and when decrypted output may safely be released.

## C++ case study: secure message gateway

The C++ program models a financial message gateway.

A billing service sends:

`Invoice INV-2048: transfer 12500 INR.`

The gateway protects the message using a registered 256-bit shared secret.

The resulting message contains:

- A key identifier.
- A nonce.
- Ciphertext.
- An authentication tag.
- Associated data.

The application can transmit the key identifier, nonce, ciphertext, tag, and associated data without transmitting the secret key.

### Key registry

`MessageGateway` maintains a collection of registered `SecretKey` objects.

The key identifier allows the application to select the appropriate key without treating the identifier as secret material.

The gateway validates that registered keys contain exactly 32 bytes.

This represents a simplified form of key rotation. A production key-management system would normally control key creation, storage, access, rotation, revocation, audit records, and lifecycle policy outside the message-processing component.

### Encryption architecture

`EducationalAead::encrypt()` generates a fresh nonce for each message.

The plaintext is XORed with a generated keystream, while the authentication tag covers the key identity, nonce, associated data, and ciphertext.

The implementation uses length-prefixing when constructing authenticated input. Without unambiguous field boundaries, concatenated protocol fields can sometimes create parsing ambiguities.

The resulting structure resembles the responsibilities of a real AEAD message processor even though the underlying educational primitive is not suitable for production.

### Authentication before plaintext release

`EducationalAead::decrypt()` reconstructs the authenticated input and calculates the expected tag.

The received and calculated tags are compared using `constant_time_equal()`.

Only after authentication succeeds does the program generate the keystream and recover plaintext.

This ordering is a significant application-security property. An application should not act on unauthenticated decrypted data.

### Tampering

The case study changes one byte of ciphertext.

The authentication tag no longer matches because the tag covers the ciphertext.

The gateway therefore rejects the message.

A second test changes associated data from an invoice classification to an administrative classification. Because the metadata is authenticated, that modification is also rejected.

### Wrong keys

The message contains a key identifier.

The gateway retrieves the corresponding secret key and verifies that the message's key identifier matches the key being used.

A different key therefore cannot successfully authenticate the ciphertext.

This models a common operational issue: encrypted data may remain available while the key required to decrypt it has been rotated, revoked, deleted, or otherwise made inaccessible.

### Replay protection

Encryption and authentication do not automatically establish message freshness.

An attacker who copies a valid encrypted message may be able to transmit the exact same message again.

The C++ case study therefore adds `ReplayGuard`.

It records a sender-and-nonce fingerprint and rejects a previously processed combination.

Real systems often use stronger application-level freshness mechanisms such as:

- Monotonically increasing sequence numbers.
- Request identifiers.
- Expiration timestamps.
- Database-backed idempotency records.
- Protocol-specific replay windows.

The appropriate mechanism depends on the communication architecture.

## Authentication is not encryption

Confidentiality and integrity answer different questions.

Encryption asks:

> Can an unauthorized party recover the plaintext?

Authentication asks:

> Can the recipient detect that protected data was changed or was not produced with the required secret?

A system can encrypt data without authenticating it. Such a system may still be vulnerable to ciphertext modification.

Authenticated encryption combines both properties and is generally the appropriate abstraction for modern application messages.

## Key management

The encryption algorithm is only one component of a secure symmetric system.

A real deployment must determine:

- Where keys are generated.
- Where keys are stored.
- Which services can access them.
- How keys are rotated.
- How old keys remain available for historical decryption.
- How compromised keys are revoked.
- How key identifiers map to key versions.
- How backups protect key material.
- How access to keys is audited.

A strong AES key stored beside its ciphertext without adequate access control does not provide meaningful protection.

Key identifiers are useful for rotation because a message can identify the version of the secret that was used without revealing the secret itself.

## Nonce management

Nonce requirements depend on the cryptographic construction.

For AES-GCM, nonce reuse under the same key is particularly dangerous.

The safe application model is:

`one key + unique nonce per encryption`

The nonce can normally be transported with the ciphertext.

A nonce does not need to be hidden merely because it influences encryption. It is the uniqueness and construction-specific generation requirement that matters.

The Python and JavaScript programs use randomly generated 12-byte GCM nonces. Systems that use random nonces must also consider the collision probability and the lifetime of a key. Other protocols may use counters or deterministic nonce allocation with strict state management.

## Passwords versus encryption keys

A password is not automatically equivalent to a cryptographic key.

Passwords are often selected by humans and can have substantially less entropy than randomly generated keys.

A password-based encryption system should therefore use a password KDF such as PBKDF2, scrypt, or Argon2, with a unique salt and a suitable work factor.

The relationship is:

`password + salt + KDF parameters -> encryption key`

The salt is normally stored with the encrypted data.

A KDF does not make a weak password equivalent to a truly random high-entropy key. It makes large-scale guessing more expensive and prevents simple precomputed reuse across identical passwords and salts.

## Authentication-tag handling

Authentication tags must be treated as cryptographic values, not ordinary text.

When comparing tags manually, an implementation should avoid ordinary early-exit comparison in security-sensitive contexts.

The Python program uses `hmac.compare_digest()`.

The C++ case study uses a comparison that processes the complete available length rather than returning at the first differing byte.

The safest option is normally to let a vetted AEAD library perform tag verification rather than designing an independent authentication layer.

## Failure conditions

A secure implementation should explicitly reject:

- Invalid key lengths.
- Missing keys.
- Unknown key identifiers.
- Invalid nonce lengths.
- Missing authentication tags.
- Modified ciphertext.
- Modified authenticated metadata.
- Malformed serialized messages.
- Unsupported protocol versions.
- Oversized messages.
- Replay attempts where replay protection is required.

An important rule is to avoid treating authentication failure as a recoverable parsing condition that returns attacker-controlled plaintext.

## Common mistakes

### Reusing a GCM nonce

Using the same nonce with the same AES-GCM key can compromise the security properties of the construction.

Nonce allocation must therefore be part of protocol design rather than an incidental implementation detail.

### Encrypting without authentication

Confidentiality does not automatically provide integrity.

Using an encryption-only primitive where an attacker can modify ciphertext can create application-level vulnerabilities.

Authenticated encryption should normally be preferred for new application protocols.

### Hard-coding secret keys

A literal secret embedded in source code can leak through source repositories, build artifacts, logs, backups, or compiled binaries.

Keys should be supplied through an appropriate secret-management mechanism.

### Using passwords directly as AES keys

A password has a different security model from a random encryption key.

A KDF with a unique salt should be used when passwords are the root secret.

### Treating Base64 as encryption

Base64 changes representation but does not provide confidentiality.

For example, a Base64-encoded plaintext remains recoverable by anyone who decodes it.

### Assuming encryption prevents replay

A valid encrypted message can potentially be copied and submitted again.

Freshness and replay resistance require protocol-level state or authenticated sequence information.

### Revealing unauthenticated plaintext

A decrypt operation should not cause an application to act on plaintext before authentication succeeds.

This is particularly important for commands, financial transactions, permissions, and other security-sensitive messages.

### Inventing cryptography

Custom encryption algorithms may have subtle mathematical weaknesses that are not apparent from successful encryption and decryption tests.

The toy constructions in this repository are demonstrations of mechanisms, not production primitives.

## Performance considerations

Symmetric encryption is generally much faster than public-key encryption, which is one reason symmetric cryptography is commonly used for bulk data.

Performance depends on:

- Algorithm.
- Hardware acceleration.
- Message size.
- Number of messages.
- Key-management overhead.
- Nonce generation.
- Authentication processing.
- Memory allocation.
- I/O behavior.

The JavaScript implementation demonstrates streaming because reading a large file completely into memory can be unnecessary.

The Python file example intentionally uses a complete in-memory operation because it keeps the educational file format simple.

For large production files, authenticated chunking requires careful format design. Each chunk needs an unambiguous relationship to the key, nonce space, ordering, and authentication data.

## Security boundary of the examples

The following implementations are intentionally educational and should not be deployed as cryptographic protocols:

- Repeating-key XOR.
- The Python educational Feistel construction.
- The Python HMAC-based stream demonstration as a replacement for a standard stream cipher.
- The C++ educational authenticated stream construction.
- The simplified C++ random source.

The production-oriented demonstrations rely on standardized cryptographic APIs:

- Python uses AES-GCM through the `cryptography` package.
- JavaScript uses Node.js `crypto` AES-256-GCM.

The distinction is deliberate. A successful round trip only proves that an implementation can reverse its own transformation. It does not prove resistance to cryptanalysis, nonce misuse, key compromise, side-channel attacks, implementation bugs, or protocol attacks.

## Practical message lifecycle

A secure application message can be modeled as:

`application plaintext`
  
`-> validate input`
  
`-> select active secret key`
  
`-> generate or allocate a valid nonce`
  
`-> define authenticated metadata`
  
`-> authenticated encryption`
  
`-> transmit key identifier + nonce + ciphertext + tag + metadata`
  
`-> select key by identifier`
  
`-> validate message structure`
  
`-> verify freshness/replay policy`
  
`-> authenticate ciphertext and metadata`
  
`-> decrypt`
  
`-> release plaintext to application`

Each stage has a distinct responsibility.

Encryption protects confidentiality.

The authentication tag protects the integrity and authenticity of protected fields.

The nonce provides construction-specific uniqueness.

The key identifier supports key selection and rotation.

Replay protection addresses a threat that encryption and authentication alone do not solve.

## Algorithm comparison

| Property | Repeating XOR | Educational Feistel | AES-GCM | Educational C++ AEAD model |
|---|---|---|---|---|
| Reversible transformation | Yes | Yes | Yes | Yes |
| Fixed-size block demonstration | No | Yes | AES internally uses 128-bit blocks | No |
| Arbitrary-length messages | Yes | With padding | Yes | Yes |
| Authentication | No | No | Yes | Yes, educational |
| Nonce concept | Not safely implemented | Not implemented | Required by this use | Yes |
| Associated data | No | No | Yes | Yes |
| Production suitability | No | No | Yes with correct key/nonce management | No |
| Primary educational purpose | XOR mechanics | Block-cipher structure | Modern AEAD API | System architecture |

The table separates the mechanisms rather than treating all symmetric encryption constructions as equivalent.

## Repository execution

The Python program can be executed with:

`python symmetric_encryption.py`

The basic demonstrations use only Python's standard library. The AES-GCM and authenticated file demonstrations require the `cryptography` package.

Install that dependency with:

`python -m pip install cryptography`

The JavaScript program requires Node.js with the built-in `crypto`, `fs`, `os`, `path`, and stream modules:

`node symmetric-encryption.js`

The C++ program requires a C++17-compatible compiler:

`g++ -std=c++17 -O2 symmetric_encryption.cpp -o symmetric_encryption`

It can then be executed with:

`./symmetric_encryption`

On Windows with a compatible compiler, execute the generated `.exe` instead.

## Relationship between the three implementations

The Python implementation emphasizes progression from primitive mechanics to standardized authenticated encryption.

The JavaScript implementation emphasizes how symmetric encryption integrates with Node.js binary buffers, asynchronous password derivation, JSON transport, event-driven streams, and file pipelines.

The C++ implementation emphasizes architecture. Its message gateway treats encryption as one component of a larger security boundary involving key registration, key selection, nonce generation, authenticated metadata, constant-time verification, failure handling, and replay control.

These perspectives demonstrate an important engineering principle: symmetric encryption is not merely a function that converts a string into unreadable bytes. A usable system requires algorithm selection, key lifecycle management, nonce discipline, authenticated message formats, validation, error handling, and application-level policies around freshness and trust.
