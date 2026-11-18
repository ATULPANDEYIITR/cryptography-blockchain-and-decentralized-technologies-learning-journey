# ECDH in Blockchain

## 1. Technical Scope

Elliptic Curve Diffie-Hellman (ECDH) is a cryptographic key-agreement protocol that allows two participants to establish a common secret using their respective private keys and each other's public keys.

In blockchain systems, ECDH can support secure communication between wallets, nodes, applications, validators, and other participants. It is particularly relevant when confidential information must be exchanged outside the public transaction ledger.

ECDH is not a blockchain consensus mechanism, transaction-signing algorithm, or encryption algorithm by itself. It establishes shared cryptographic material from which symmetric encryption keys can be derived.

The implementations demonstrate the relationship between elliptic-curve cryptography, wallet identities, secure communication sessions, and blockchain transaction processing.

## 2. Mathematical Foundations

### 2.1 Elliptic curves

An elliptic curve over a finite field can be represented as:

\[
y^2 \equiv x^3 + ax + b \pmod p
\]

Where:

- \(p\) is the prime defining the finite field.
- \(a\) and \(b\) are curve parameters.
- \(x\) and \(y\) are point coordinates.
- The curve must satisfy a non-singularity condition.

A cryptographic elliptic curve defines a group of points with an identity element and a point-addition operation.

The two points used in ECDH belong to this group.

### 2.2 Private and public keys

A participant selects a private scalar:

\[
d \in [1,n-1]
\]

Where \(n\) is the order of the generator point.

The public key is:

\[
Q=dG
\]

Where:

- \(d\) is the private key.
- \(G\) is the standard generator point.
- \(Q\) is the public key.

The public key can be distributed to other participants. The private key must remain confidential.

The security of elliptic-curve cryptography depends on the difficulty of recovering \(d\) from \(Q\) and \(G\), known as the Elliptic Curve Discrete Logarithm Problem.

### 2.3 ECDH key agreement

Suppose Alice has private key \(d_A\) and public key:

\[
Q_A=d_AG
\]

Bob has private key \(d_B\) and public key:

\[
Q_B=d_BG
\]

Alice computes:

\[
S_A=d_AQ_B
\]

Bob computes:

\[
S_B=d_BQ_A
\]

Both calculations produce:

\[
S_A=S_B=d_Ad_BG
\]

The shared point is identical even though neither participant reveals their private key.

The shared point's x-coordinate is commonly used as input keying material for a key-derivation function.

## 3. ECDH and Blockchain Architecture

ECDH operates at the cryptographic communication layer rather than the consensus layer.

A blockchain architecture can separate the relevant responsibilities into the following components:

| Component | Responsibility |
|---|---|
| Wallet | Maintains participant identity and cryptographic keys |
| Elliptic-curve implementation | Performs point multiplication and validation |
| ECDH protocol | Establishes shared secret material |
| Key derivation function | Derives application-specific symmetric keys |
| Secure communication channel | Protects confidential off-chain exchanges |
| Transaction layer | Processes signed blockchain transactions |
| Block layer | Records ordered transactions |
| Consensus layer | Determines accepted blockchain state |
| Audit layer | Records session and security events |

### 3.1 Architectural workflow

The typical workflow is:

1. Alice and Bob generate their own elliptic-curve key pairs.
2. Their public keys are exchanged through an authenticated mechanism.
3. Each participant validates the other participant's public key.
4. Both independently calculate the ECDH shared secret.
5. HKDF derives an application-specific symmetric key.
6. The derived key is used by an authenticated encryption protocol.
7. A commitment or relevant public metadata can be recorded on-chain.
8. Confidential application data remains off-chain.
9. The blockchain processes independently authenticated transactions.
10. Session expiry and key revocation are enforced by the application.

Plain-text representation:

    Wallet A                    Wallet B
       |                           |
       | Generate key pair         |
       |                           | Generate key pair
       |                           |
       |---- Public key A -------->|
       |<--- Public key B ----------|
       |                           |
       | Validate public key B     |
       | Validate public key A     |
       |                           |
       | ECDH calculation          | ECDH calculation
       |                           |
       | Shared secret S           | Shared secret S
       |                           |
       | HKDF                      | HKDF
       |                           |
       | Symmetric key K            | Symmetric key K
       |                           |
       |<==== Secure channel ======>|
       |                           |
       |---- Public commitment ---> Blockchain
       |                           |
       |---- Transaction ---------> Blockchain

The blockchain does not need access to the private keys or shared secret.

## 4. ECDH and Other Cryptographic Mechanisms

The distinction between key agreement, encryption, signing, and hashing is important.

| Mechanism | Purpose | Typical blockchain application |
|---|---|---|
| ECDH | Shared-secret establishment | Wallet and node communication |
| ECDSA | Digital signatures | Transaction authentication |
| EdDSA | Digital signatures | Identity and transaction authentication |
| HKDF | Key derivation | Deriving symmetric encryption keys |
| AES-GCM | Authenticated encryption | Protecting off-chain messages |
| ChaCha20-Poly1305 | Authenticated encryption | Protecting application communication |
| SHA-256 | Cryptographic hashing | Commitments and block hashing |

ECDH does not prove the identity of the other participant.

An attacker capable of replacing exchanged public keys can conduct a man-in-the-middle attack unless public keys are authenticated.

Authentication can use certificates, digital signatures, previously trusted keys, or another appropriate identity-verification mechanism.

## 5. Python Implementation

The Python implementation demonstrates the underlying mathematical operations instead of depending on an external cryptographic package.

### 5.1 Elliptic-curve arithmetic

The implementation uses secp256k1 parameters:

\[
y^2=x^3+7 \pmod p
\]

The main operations are:

- Modular inversion.
- Elliptic-curve point addition.
- Point doubling.
- Double-and-add scalar multiplication.
- Public-key validation.
- Compressed public-key encoding.

The `point_add()` function handles the identity element, inverse points, point doubling, and ordinary point addition.

The `point_multiply()` function uses double-and-add rather than repeated point addition.

For a scalar with \(k\) bits, this requires \(O(k)\) point operations.

The Python implementation is educational. Its arithmetic is not constant-time and should not be used to protect production private keys.

### 5.2 Wallet construction

A wallet contains:

- A private scalar.
- An elliptic-curve public point.
- An address derived from the encoded public key.

The public key is encoded in compressed form before hashing.

The private key remains separate from the public wallet identity.

### 5.3 HKDF

The implementation uses HKDF-SHA256.

HKDF consists of two operations:

**Extract**

\[
PRK=HMAC(salt,IKM)
\]

**Expand**

\[
OKM=HMAC(PRK,T_{previous}\parallel info\parallel counter)
\]

Where:

- `IKM` is the shared secret.
- `PRK` is the pseudorandom key.
- `salt` provides extraction context.
- `info` identifies the application and protocol.
- `OKM` is the derived key.

The script derives a 256-bit channel key.

### 5.4 Blockchain simulation

The blockchain contains:

- Blocks.
- Transactions.
- Transaction identifiers.
- Account nonces.
- Previous-block hashes.
- Transaction commitments.

The transaction submission process checks:

- Positive transfer amounts.
- Valid sender and recipient identities.
- Unique transaction identifiers.
- Correct sender nonce.
- Correct commitment format.

The blockchain validates block hashes and previous-block references.

Tampering with a transaction changes the corresponding block hash and causes integrity verification to fail.

## 6. JavaScript Implementation

The JavaScript implementation uses Node.js cryptographic facilities instead of manually implementing elliptic-curve arithmetic.

### 6.1 Native ECDH

The `crypto.createECDH()` API creates secp256k1 key-agreement objects.

The implementation uses:

- `generateKeys()` for key-pair generation.
- `getPublicKey()` for public-key extraction.
- `computeSecret()` for shared-secret calculation.

Public keys use compressed encoding.

The implementation validates the compressed representation and asks the cryptographic provider to validate the point during shared-secret computation.

### 6.2 Event-driven processing

The blockchain extends Node.js `EventEmitter`.

It publishes events for:

- Wallet registration.
- Transaction submission.
- Block creation.

This separates event notification from transaction processing.

For example, monitoring components can subscribe to transaction events without changing the core validation logic.

### 6.3 Asynchronous transaction handling

The transaction submission method returns a Promise.

It separates transaction processing from immediate caller execution and allows the application to integrate asynchronous validation and external services.

The current example uses in-memory state and does not provide distributed transaction locking.

Production implementations require atomic nonce allocation, persistent storage, and concurrency control.

### 6.4 Deterministic serialization

The `canonicalJSON()` function sorts object keys recursively.

This prevents property ordering from changing the serialized representation used for hashing.

Deterministic serialization is essential when different participants independently calculate the same transaction or block hash.

## 7. C++17 Implementation

The C++ implementation demonstrates elliptic-curve group operations using a deliberately small finite field.

Its curve is:

\[
y^2=x^3+2x+2 \pmod {17}
\]

The generator is:

\[
G=(5,1)
\]

Its subgroup order is 19.

This configuration allows the complete ECDH process to be inspected with small integer values.

### 7.1 Point operations

The program implements:

- Modular arithmetic.
- Modular inverse.
- Point validation.
- Point addition.
- Point doubling.
- Scalar multiplication.

The double-and-add algorithm reduces scalar multiplication from repeated addition to logarithmic iteration in the scalar.

The small field is intentionally unsuitable for cryptographic security.

### 7.2 Domain modeling

The implementation defines:

| Type | Responsibility |
|---|---|
| `Point` | Represents an elliptic-curve point |
| `Wallet` | Holds wallet identity and key information |
| `Transaction` | Represents a blockchain transaction |
| `Block` | Represents a block and its transactions |
| `Blockchain` | Maintains ledger state |
| `CryptoError` | Represents cryptographic validation failures |
| `BlockchainError` | Represents ledger validation failures |

The blockchain uses STL containers:

- `vector` for ordered blocks and pending transactions.
- `map` for wallets and nonces.
- `set` for duplicate transaction detection.

The design emphasizes explicit state management and validation boundaries.

### 7.3 Important limitation

The example uses FNV-1a for deterministic block integrity demonstration and a simplified channel-key representation.

FNV-1a is not a cryptographic hash.

The C++ implementation is therefore a mathematical and architectural demonstration, not a secure wallet implementation.

A production C++ implementation must use a vetted elliptic-curve implementation, HKDF-SHA256, cryptographic hashing, authenticated encryption, and secure memory management.

## 8. Java 17 Implementation

The Java implementation adopts a more structured enterprise-oriented design.

It uses Java's cryptographic provider interfaces rather than implementing elliptic-curve arithmetic manually.

### 8.1 Cryptographic provider

The implementation uses:

- `KeyPairGenerator` for elliptic-curve key generation.
- `ECGenParameterSpec` for selecting secp256r1.
- `KeyFactory` for public-key reconstruction.
- `KeyAgreement` for ECDH.
- `MessageDigest` for SHA-256.
- `Mac` for HMAC-SHA256.
- `SecureRandom` for cryptographic randomness.

The public-key encoding uses the provider's X.509 SubjectPublicKeyInfo representation.

### 8.2 Enterprise domain model

The implementation defines records for wallets, transactions, blocks, and validation results.

Records provide compact immutable data structures.

The `TransactionPolicy` interface separates business validation from blockchain state management.

`StandardTransactionPolicy` implements the basic eligibility rules.

`BlockchainService` manages:

- Wallet registration.
- Transaction validation.
- Nonce allocation.
- Pending transactions.
- Block creation.
- Chain verification.

This separation makes it possible to introduce additional transaction policies without rewriting the ledger service.

### 8.3 Exception handling

The custom `DomainException` represents failures such as:

- Invalid public-key encoding.
- Failed ECDH agreement.
- Invalid transaction data.
- Duplicate transactions.
- Unknown wallet identities.
- Nonce mismatches.
- Blockchain validation failures.

The implementation also clears temporary byte arrays after use.

Java does not guarantee complete erasure of all copies of sensitive data from memory. Production key management requires stronger operational controls.

## 9. PostgreSQL Data Model

The PostgreSQL implementation models the persistent records required by an ECDH-enabled blockchain application.

It uses the `ecdh_chain` schema.

### 9.1 Relational entities

| Table | Purpose |
|---|---|
| `blockchain_networks` | Network configuration |
| `wallets` | Wallet identities and public keys |
| `ecdh_sessions` | Key-agreement session metadata |
| `blocks` | Blockchain block records |
| `blockchain_transactions` | Transaction records |
| `block_transactions` | Transaction-to-block relationships |
| `ecdh_audit` | Security and session events |

The schema separates cryptographic session metadata from blockchain transactions.

This separation avoids treating a secure communication session as a transaction or block.

### 9.2 Wallet registration

The `wallets` table stores:

- Wallet address.
- Public key.
- Curve identifier.
- Key fingerprint.
- Registration status.
- Registration timestamp.
- Revocation timestamp.

A unique constraint prevents duplicate wallet identities within a network.

Private keys must not be stored in this table.

### 9.3 ECDH session lifecycle

The session status is represented by an enumeration:

| State | Meaning |
|---|---|
| `INITIATED` | Key agreement has started |
| `ESTABLISHED` | A channel commitment has been registered |
| `FAILED` | Establishment failed |
| `EXPIRED` | Session lifetime ended |
| `REVOKED` | Session was invalidated |

The session trigger checks participant registration, network membership, and required establishment metadata.

The database stores a commitment rather than the shared secret.

The application must perform actual ECDH calculations and authenticate the public keys before registering an established session.

### 9.4 Transaction integrity

Transaction constraints enforce:

- Positive transfer amounts.
- Valid nonce values.
- Unique transaction hashes.
- Unique sender nonces within a network.
- Valid channel commitment format.
- Distinct sender and recipient identities.

The transaction trigger checks wallet status and network consistency.

When a session is supplied, it also checks:

- Session establishment.
- Session expiry.
- Participant correspondence.
- Channel commitment consistency.

These checks provide database-level defense in depth.

### 9.5 Block inclusion

The `block_transactions` table models the relationship between blocks and transactions.

It enforces:

- Unique transaction inclusion within a block.
- Unique transaction position within a block.
- Nonnegative transaction positions.

The `include_transaction()` function processes inclusion under row-level locks.

The `validate_block()` function checks the previous-block relationship and transaction root.

The `finalize_block()` function prevents unvalidated blocks from entering the finalized state.

These functions represent a simplified ledger workflow. They do not implement distributed consensus or complete protocol-level block validation.

## 10. ECDH Security Considerations

### 10.1 Man-in-the-middle attacks

ECDH alone does not authenticate participants.

An attacker can substitute public keys during an unauthenticated exchange.

Consequently, both participants may establish different shared secrets with the attacker.

Mitigations include:

- Digital signatures over handshake messages.
- Certificate validation.
- Trusted wallet-key registration.
- Authenticated identity binding.
- Public-key fingerprint verification.

### 10.2 Invalid-curve and point-validation attacks

Public keys must be checked before scalar multiplication.

Validation must include:

- Correct coordinate encoding.
- Coordinates within the field.
- Membership of the selected curve.
- Correct subgroup membership where required.
- Rejection of the point at infinity.

The production cryptographic provider should perform the required low-level validation.

### 10.3 Private-key exposure

Private keys should never be:

- Written to blockchain transactions.
- Included in logs.
- Transmitted to another participant.
- Stored in public database tables.
- Exposed through debugging output.

Private keys should be protected through hardware-backed storage, secure key-management services, or appropriately controlled cryptographic modules.

### 10.4 Replay protection

A valid message can be captured and transmitted again.

The implementations demonstrate transaction identifiers and account nonces to detect duplicate or out-of-order transactions.

A production ECDH protocol must also bind session identifiers, participants, protocol versions, and fresh nonces to handshake messages.

### 10.5 Forward secrecy

Ephemeral ECDH key pairs can provide forward secrecy when used with authenticated ephemeral handshakes and correctly managed session keys.

If a long-term private key is compromised, previously established sessions may remain protected when their ephemeral secrets were securely erased.

Simply using ECDH does not automatically guarantee forward secrecy.

### 10.6 Quantum computing

ECDH based on conventional elliptic curves is vulnerable to sufficiently capable fault-tolerant quantum computers running Shor's algorithm.

Blockchain systems with long-term confidentiality requirements must consider post-quantum key establishment and hybrid cryptographic approaches.

## 11. On-Chain and Off-Chain Responsibilities

A fundamental architectural decision is whether cryptographic information belongs on the blockchain.

| Information | On-chain | Off-chain |
|---|---|---|
| Wallet address | Appropriate | Possible |
| Public key | Protocol-dependent | Possible |
| Private key | Never | Protected storage |
| Raw ECDH secret | Never | Temporary application memory |
| Derived session key | Never | Protected application memory |
| Channel commitment | Possible | Possible |
| Transaction hash | Appropriate | Possible |
| Confidential message | Generally unsuitable | Appropriate |
| Session audit metadata | Possible | Possible |

Public blockchain data can be permanently replicated.

Even encrypted information may become vulnerable if encryption keys are later compromised.

A channel commitment can provide evidence that participants registered particular session metadata without publishing the shared secret.

A commitment is not proof that the underlying ECDH handshake was authentic or correctly performed.

## 12. Performance Considerations

ECDH is more computationally expensive than ordinary hashing.

Its performance depends on:

- Curve selection.
- Key size.
- Cryptographic provider implementation.
- Hardware acceleration.
- Public-key validation.
- Session establishment frequency.

Repeated ECDH operations should be avoided when a secure session can safely be reused.

Derived keys should be scoped to a specific protocol, participant pair, and session.

Blockchain transaction processing has separate performance costs associated with:

- Transaction validation.
- Nonce checking.
- Hash calculation.
- Block construction.
- Storage operations.
- Consensus and finality.

ECDH should generally remain outside the consensus-critical transaction execution path unless the blockchain protocol explicitly requires cryptographic key agreement.

## 13. Implementation Comparison

| Dimension | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Curve | secp256k1 | secp256k1 | Small educational curve | secp256r1 | Metadata only |
| ECDH arithmetic | Explicit | Native provider | Explicit | Native provider | External application |
| Key derivation | HKDF-SHA256 | HKDF-SHA256 | Simplified demonstration | HKDF-SHA256 | External application |
| Wallet management | Dataclass | Objects and Map | Structs and Map | Records and services | Relational tables |
| Transaction validation | Explicit checks | Event-driven service | Domain validation | Policy interface | Constraints and triggers |
| Replay protection | Nonces and IDs | Nonces and IDs | Nonces and IDs | Nonces and IDs | Unique constraints |
| Integrity | SHA-256 | SHA-256 | Non-cryptographic demonstration hash | SHA-256 | pgcrypto |
| Main emphasis | Cryptographic mechanics | Asynchronous event processing | Mathematical foundations | Enterprise domain modeling | Persistent data integrity |

## 14. Limitations and Production Requirements

The implementations intentionally demonstrate different levels of cryptographic abstraction.

They are not interchangeable production blockchain clients.

The following limitations must be considered:

1. The Python implementation uses custom elliptic-curve arithmetic that is not constant-time.
2. The JavaScript implementation does not implement a complete authenticated handshake.
3. The C++ implementation uses a tiny insecure curve and a non-cryptographic hash.
4. The Java implementation uses secp256r1 rather than secp256k1.
5. The PostgreSQL schema does not perform elliptic-curve operations.
6. The blockchain simulations do not implement distributed consensus.
7. A channel commitment does not replace a digital signature.
8. The examples do not implement a complete AES-GCM or ChaCha20-Poly1305 communication protocol.
9. Database transaction processing does not independently establish cryptographic identity.
10. Production deployment requires audited cryptographic libraries, secure key storage, authentication, monitoring, concurrency controls, and protocol-specific security testing.

The Java and JavaScript implementations provide the closest starting points for provider-backed ECDH integration. The Python and C++ implementations expose mathematical mechanisms for study.

## 15. Key Terminology

| Term | Definition |
|---|---|
| Elliptic curve | Algebraic curve used to construct a cryptographic group |
| Finite field | A mathematical field containing a finite number of elements |
| Generator point | Standard point used to generate public keys |
| Private scalar | Secret integer used in elliptic-curve multiplication |
| Public key | Point derived from a private scalar |
| ECDH | Protocol for establishing shared cryptographic material |
| Shared secret | Common secret independently calculated by two participants |
| HKDF | HMAC-based key-derivation function |
| Wallet | Blockchain participant identity and associated cryptographic keys |
| Commitment | Cryptographic value representing specific data |
| Nonce | Value used to prevent replay or enforce transaction ordering |
| Ephemeral key | Temporary cryptographic key used for a session |
| Forward secrecy | Protection of past sessions against later long-term key compromise |
| Authenticated encryption | Encryption that also verifies message integrity and authenticity |
| Consensus | Distributed agreement on accepted blockchain state |
| Key revocation | Process for invalidating a cryptographic identity or key |

## 16. Practical Learning Outcomes

The five implementations establish the relationship between mathematical ECDH operations and blockchain application architecture.

The central technical distinction is that ECDH establishes shared secret material, HKDF derives usable symmetric keys, authenticated encryption protects communication, digital signatures authenticate participants, and blockchain consensus governs accepted ledger state.

These mechanisms solve different security problems and must be composed correctly.
