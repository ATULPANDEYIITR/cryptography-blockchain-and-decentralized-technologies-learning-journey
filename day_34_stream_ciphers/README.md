# Stream Ciphers

## Scope

A stream cipher encrypts data by combining plaintext with a generated keystream. The central operation is XOR:

`C = P XOR K`

where `P` is plaintext, `K` is the keystream, and `C` is ciphertext.

Decryption uses the same operation:

`P = C XOR K`

because applying the same XOR value twice cancels it.

The important engineering problem is therefore not merely the XOR operation. Security depends on how the keystream is generated, how its internal state evolves, how nonces and counters are managed, and whether the resulting ciphertext is authenticated.

This repository contains three complementary implementations:

- Python develops the topic from byte-level XOR through an educational ChaCha20 implementation, chunked processing, nonce-reuse analysis, malleability, authenticated encryption, replay detection, and file-oriented streaming.
- JavaScript focuses on byte-oriented Node.js processing, asynchronous chunks, event-driven transport, protocol packets, authentication, replay handling, and the boundary between a custom educational primitive and native AEAD.
- C++ presents a coherent encrypted-record processing system in which a stream-cipher engine is combined with nonce tracking, authentication state, replay protection, protocol-version validation, and failure handling.

The custom cryptographic implementations are educational. Production applications should use maintained cryptographic libraries and standardized authenticated-encryption constructions.

## Core stream-cipher mechanism

A stream cipher generates a sequence of pseudorandom bytes called the keystream. The plaintext is combined with those bytes one segment at a time.

For example, if a plaintext byte is `P` and its corresponding keystream byte is `K`, encryption produces `P XOR K`.

The receiver must reproduce exactly the same keystream. This requires agreement on cryptographic key material and the state inputs that determine the keystream, such as a nonce and counter.

The keystream must not simply be random-looking. It must be computationally infeasible for an attacker to predict useful future keystream bytes from observed output.

## XOR and reversibility

XOR has two properties that make it useful for stream encryption.

`x XOR 0 = x`

and

`(x XOR k) XOR k = x`

The second property explains why encryption and decryption use the same transformation.

The Python implementation exposes this mechanism through `xor_bytes()` and `xor_with_keystream()`. The JavaScript implementation uses `Buffer` objects in `xorBytes()` and `xorWithKeystream()`. The C++ implementation provides `xor_bytes()` over `std::vector<std::uint8_t>`.

These functions deliberately operate on equal-length byte sequences. Silently truncating one operand would hide protocol errors and could produce an incorrectly transformed message.

## Keystream generation

A stream cipher can be viewed as a state machine:

`initial state -> state transition -> keystream block -> state transition -> next block`

A secure construction must make the generated sequence unpredictable without the secret key.

The Python program first implements an LFSR to demonstrate state-based keystream generation. An LFSR shifts register state and computes new bits from selected feedback taps. Its linear structure makes it unsuitable as a modern cryptographic generator.

This distinction is important: a generator can produce a long sequence with apparently irregular output while still being mathematically predictable.

The Python implementation then moves to a ChaCha20-style ARX construction. ARX means addition modulo `2^32`, rotation, and XOR. The quarter round repeatedly applies these operations to four 32-bit words. Column rounds and diagonal rounds spread changes through the internal state.

The JavaScript and C++ implementations use the same conceptual ChaCha20 block construction, but express the state through JavaScript arrays and C++ fixed-size arrays respectively.

## ChaCha20 state

The educational ChaCha20 implementations use:

- a 256-bit key
- a 96-bit nonce
- a 32-bit block counter
- a 64-byte output block

The state contains constants, key words, counter state, and nonce words.

A block counter is essential because consecutive keystream blocks must not all be generated from an identical state. The counter changes the input to each block.

The implementations start the data stream with counter value `1`, leaving counter value `0` available for the conventional ChaCha20 layout associated with the original specification's separate block usage.

The counter is finite. Once its usable range is exhausted, continuing as though it had wrapped would repeat state. The Python and JavaScript implementations explicitly reject counter exhaustion rather than silently wrapping.

## Nonce uniqueness

A nonce is not necessarily secret. Its purpose is to provide unique state for separate encryption operations.

For a stream cipher construction that requires nonce uniqueness, encrypting two different plaintexts with the same key and nonce is dangerous because the same keystream is generated.

Suppose:

`C1 = P1 XOR K`

and

`C2 = P2 XOR K`

Then:

`C1 XOR C2 = P1 XOR P2`

The keystream disappears.

The Python `demonstrate_nonce_reuse_failure()` function calculates this relationship directly. The JavaScript `demonstrateNonceReuse()` function does the same using `Buffer`. The C++ case study uses the same mathematical relationship in `demonstrate_nonce_reuse()`.

This does not necessarily reveal both plaintexts immediately, but it removes the protection that the independent keystreams were supposed to provide. Known plaintext, predictable message formats, redundancy, and statistical structure can make the resulting ciphertext relationship highly exploitable.

Nonce reuse is therefore a protocol-state failure, not merely a cryptographic algorithm failure.

## Stateful streaming

A major advantage of stream-oriented encryption is that a message does not have to be loaded into memory as one large object.

The keystream can be consumed as application data arrives:

`chunk -> keystream segment -> XOR -> encrypted chunk`

The important implementation detail is preserving the position inside a partially consumed keystream block.

The Python `encrypt_stream()` function retains unused keystream bytes between chunks. The JavaScript `KeystreamCursor` performs the same role through `pending` state. The C++ `StreamCipher` stores unused bytes in its internal buffer.

This matters because application boundaries are not cryptographic boundaries. A network transport may provide 17 bytes in one read and 91 bytes in the next. The cipher must continue from the exact previous keystream position rather than restarting the generator.

## Authentication is separate from encryption

Unauthenticated stream encryption does not guarantee that ciphertext has not been modified.

If:

`C = P XOR K`

an attacker can construct:

`C' = C XOR Delta`

The receiver obtains:

`P' = C' XOR K`

which becomes:

`P' = P XOR Delta`

An attacker can therefore deliberately modify plaintext bits without knowing the keystream.

The Python `demonstrate_malleability()` function changes a ciphertext byte and shows that the decrypted plaintext changes in a controlled way.

This is why confidentiality and integrity must be considered separately.

Modern applications generally use authenticated encryption with associated data, commonly abbreviated AEAD. AEAD encrypts the confidential payload while also authenticating the ciphertext and selected metadata.

## Associated data

Some protocol information must be authenticated but does not need encryption.

Examples include:

- protocol version
- message type
- service identifier
- channel identifier
- routing metadata

AEAD calls this authenticated-but-unencrypted information associated data.

The JavaScript packet model includes `associatedData`. The educational HMAC construction binds it into the authentication input, demonstrating the protocol principle that metadata should not be left outside the integrity boundary when it influences interpretation of the encrypted message.

Changing authenticated metadata must therefore cause verification to fail.

## Python implementation

The Python program is designed as a progressive executable study rather than a collection of disconnected examples.

`demonstrate_xor_principle()` establishes the reversible byte transformation. `LFSR` then demonstrates why a stateful generator is not automatically secure.

`chacha20_block()` implements the core ARX transformation, while `ChaCha20Educational` exposes a state-independent encryption interface that derives sequential 64-byte keystream blocks from the key, nonce, and counter.

The streaming layer is deliberately separate from the block primitive. `encrypt_stream()` shows how a cipher can process an iterable of byte chunks while maintaining keystream position across application-level boundaries.

The security demonstrations then examine properties that are easy to miss when studying only the encryption equation. `demonstrate_nonce_reuse_failure()` shows keystream reuse algebraically. `demonstrate_malleability()` shows why encryption without authentication is insufficient. `HMACStreamCipher` demonstrates an encrypt-then-authenticate design, while `ReplayGuard` introduces freshness tracking.

The file-oriented `transform_file()` function extends the streaming idea to disk data without reading an entire file into memory.

`demonstrate_validation()` covers malformed keys, malformed nonces, invalid lengths, and invalid LFSR state. The benchmark section measures the educational implementation while explicitly distinguishing it from production cryptographic software.

## JavaScript implementation

The JavaScript implementation emphasizes how stream encryption interacts with an event-driven runtime.

Node.js `Buffer` provides explicit byte storage and operations suitable for cryptographic data. The `KeystreamCursor` maintains cryptographic position while callers consume arbitrary-sized chunks.

`encryptAsyncChunks()` uses an asynchronous generator so encryption can operate over data that arrives incrementally. The example uses asynchronous chunk production to model the boundary between an application and a streaming transport.

The protocol layer introduces `SecurePacket`, `AuthenticatedStreamTransport`, and `SecureChannel`.

`SecurePacket` represents the data that crosses a protocol boundary. It contains a version, message identifier, nonce, ciphertext, authentication tag, and associated data.

`AuthenticatedStreamTransport` computes authentication input from those fields. This is intentionally more protocol-oriented than simply calculating an authentication tag over ciphertext.

`SecureChannel` demonstrates event-driven security decisions. Successful records emit a `message` event, while authentication and replay failures emit `security-error`.

The final JavaScript demonstration uses Node.js's native `chacha20-poly1305` interface. This illustrates the production boundary: a real application should prefer a standardized AEAD implementation rather than constructing its own cryptographic composition.

## C++ case study

The C++ program models an encrypted audit-record service.

The `StreamCipher` class maintains a key, nonce, block counter, and partially consumed keystream. Its `crypt()` method works for both encryption and decryption because XOR is self-inverting.

The case study intentionally separates byte transformation from protocol acceptance. `EncryptedRecord` represents an application-level record containing protocol metadata, an identifier, nonce, ciphertext, authentication state, and an authentication tag.

`GovernanceEngine` then determines whether a record is acceptable.

Its policy checks protocol version, rejects empty ciphertext, requires valid authentication, rejects previously accepted record identifiers, and rejects nonce reuse. A record is added to the tracking sets only after it passes validation.

This separation demonstrates an important systems-design principle: cryptographic transformation and protocol governance are different responsibilities.

The `std::set` structures provide deterministic ordered storage. In the implementation's complexity model, record and nonce lookups are `O(log r)` for `r` tracked records. A production implementation could use a hash table when its operational characteristics and security requirements make that appropriate.

## Authentication state

The C++ model represents authentication explicitly with `AuthenticationState`.

`Missing` means that a record has not established an integrity guarantee.

`Invalid` means an authentication check was attempted or represented as failed.

`Valid` permits the record to proceed to replay and nonce checks.

This ordering is deliberate. An invalid cryptographic message should not be accepted merely because its identifier and nonce are new.

In a production AEAD system, authentication verification would occur before releasing plaintext to higher application layers. The C++ case study models that principle through the governance decision process.

## Replay protection

Encryption does not automatically provide freshness.

An attacker who captures a valid encrypted message may resend the exact same bytes later. If the application interprets the message as a new transaction each time, confidentiality remains intact but the application can still be attacked.

The Python `ReplayGuard` stores message identifiers that have already been accepted.

The C++ `GovernanceEngine` tracks record identifiers and rejects a second occurrence.

The JavaScript `SecureChannel` stores message identifiers in a `Set`.

Real protocols may use sequence numbers, monotonic counters, timestamps with acceptance windows, or application-specific transaction identifiers. The correct mechanism depends on whether messages can arrive out of order and what replay semantics the application requires.

A replay cache also consumes memory. The Python and C++ examples therefore include capacity considerations rather than treating replay tracking as free.

## Key, nonce, and counter roles

These values have different purposes.

| Value | Primary role | Typical security requirement |
|---|---|---|
| Key | Secret cryptographic material | Must remain confidential |
| Nonce | Distinguishes encryption instances | Must satisfy the primitive's uniqueness requirements |
| Counter | Distinguishes keystream blocks within a stream | Must not cause state reuse |
| Keystream | Pseudorandom masking sequence | Must be unpredictable without the key |
| Authentication tag | Integrity and authenticity evidence | Must be verified before accepting protected data |

Confusing these roles can lead to serious implementation errors. A nonce is not a substitute for a secret key, and a counter is not by itself an authentication mechanism.

## Failure conditions

A robust implementation must reject invalid cryptographic state rather than silently repairing it.

The examples reject:

- keys of the wrong length
- nonces of the wrong length
- negative stream lengths
- invalid generator state
- counter exhaustion
- authentication failures
- replayed identifiers
- nonce reuse
- unsupported protocol versions
- empty encrypted records where the application policy disallows them

Error handling should be designed around the protocol's security boundary. In particular, an authentication failure should not result in modified plaintext being passed to business logic.

## Common implementation mistakes

### Reusing a nonce

The most serious stream-cipher state mistake is reusing a nonce with the same key when the construction requires uniqueness.

The result can expose relationships between plaintexts because the same keystream is applied repeatedly.

### Restarting the counter for every chunk

Application chunks do not define independent cryptographic messages. Restarting the counter for every chunk would reuse keystream state within a single message.

The streaming implementations avoid this by retaining the cipher cursor between chunks.

### Encrypting without authentication

A ciphertext can be modified even when the key remains secret. Stream-cipher XOR provides no intrinsic guarantee that the ciphertext has not changed.

Authenticated encryption should normally be preferred.

### Authenticating too little protocol state

Authenticating ciphertext while leaving important interpretation metadata outside the authentication boundary can allow an attacker to alter how a valid encrypted payload is interpreted.

Protocol fields that affect security decisions should be deliberately included in authenticated data.

### Releasing plaintext before authentication

An implementation should not hand unauthenticated decrypted content to sensitive application logic.

Authentication should be completed before the plaintext is treated as trusted protocol data.

### Treating random-looking output as proof of security

Statistical appearance is not a security proof. The LFSR example demonstrates this distinction. A generator can produce complicated-looking sequences while retaining linear relationships that allow state reconstruction.

## Performance characteristics

Stream encryption is naturally linear in the amount of data processed.

For `n` plaintext bytes, the core transformation requires `O(n)` byte operations.

Memory consumption can remain independent of the total message size when data is processed incrementally. A streaming implementation needs only cipher state, a current keystream block, and the application chunk currently being processed.

Pure Python and educational C++ or JavaScript implementations are useful for understanding internal operations, but production performance depends on optimized cryptographic implementations, CPU architecture, vectorization, native bindings, and I/O behavior.

Authentication also adds computation. AEAD implementations are designed to integrate confidentiality and integrity efficiently rather than requiring an application to invent its own composition.

## Security considerations

A production stream-encryption design should establish the following before implementation:

- the exact standardized primitive
- key-generation and key-storage rules
- nonce-generation or nonce-allocation rules
- maximum messages and bytes permitted per key
- counter exhaustion behavior
- authentication requirements
- associated-data fields
- replay semantics
- error-handling behavior
- key rotation policy
- protocol versioning

Keys should come from a cryptographically secure key-management process rather than predictable application values.

Nonces should be generated or allocated according to the selected primitive's specification. If uniqueness rather than unpredictability is the requirement, a reliable counter or allocation scheme can be appropriate, provided concurrency and persistence are handled correctly.

Nonce allocation must also consider multiple processes, machines, and restarts. A locally unique counter can become unsafe if two independent instances accidentally restart at the same state under the same key.

## Debugging considerations

Stream-cipher bugs are often state bugs.

When investigating incorrect decryption, verify the exact:

`key -> nonce -> initial counter -> block counter -> byte offset`

sequence.

If the first bytes decrypt correctly but later bytes fail, inspect block-boundary handling and partial keystream consumption.

If two independent messages fail intermittently, inspect nonce generation and state sharing.

If ciphertext decrypts correctly but modified ciphertext is still accepted, inspect authentication coverage rather than the encryption operation.

Test vectors are particularly important for cryptographic implementations. A successful round trip alone is not sufficient because an incorrect implementation can encrypt and decrypt incorrectly in exactly the same way.

## Educational boundary

The custom ChaCha20-style code is intentionally visible so that internal state, quarter rounds, counters, and keystream consumption can be studied.

That visibility should not be confused with production readiness. Real systems should use standardized cryptographic primitives implemented and reviewed by established cryptographic libraries.

The most important engineering lesson is that a secure stream-cipher system is not just an XOR loop. It is the combination of a sound keystream construction, disciplined state management, nonce uniqueness, authentication, replay semantics, key management, and protocol-level validation.
