# Man-in-the-Middle Attack on Key Exchange

## 1. Technical Scope

A Man-in-the-Middle (MITM) attack on key exchange occurs when an attacker positions themselves between two communicating participants and manipulates the exchange of cryptographic public values.

The central weakness is the absence of reliable authentication between the participants.

Diffie-Hellman key exchange can establish a shared secret over an insecure communication channel. It does not independently establish the identity of the person or system supplying a public key.

Consequently, a successful key agreement does not necessarily mean that the intended participants share a secret with each other.

This implementation examines the attack through four programming perspectives and a relational security-monitoring model.

## 2. Fundamental Cryptographic Concepts

### 2.1 Key Exchange

Key exchange is a cryptographic procedure through which two participants establish shared secret material.

The shared material is subsequently used to derive encryption and authentication keys.

Important terminology:

| Term | Meaning |
|---|---|
| Private key | Secret value retained by its owner |
| Public key | Value distributed to another participant |
| Shared secret | Secret independently calculated by both participants |
| Key agreement | Process of deriving common secret material |
| Authentication | Verification of a participant's identity |
| Transcript | Record of the protocol messages exchanged |
| Key derivation | Conversion of shared secret material into usable cryptographic keys |
| Fingerprint | Digest used to identify cryptographic public-key material |
| Ephemeral key | Temporary key generated for a particular exchange |
| Session key | Key derived for protecting a communication session |

### 2.2 Diffie-Hellman Key Exchange

Diffie-Hellman allows two participants to calculate the same shared secret without transmitting their private values.

Let:

- \(p\) represent a prime modulus.
- \(g\) represent a generator.
- \(a\) represent Alice's private value.
- \(b\) represent Bob's private value.

Alice calculates:

\[
A=g^a \bmod p
\]

Bob calculates:

\[
B=g^b \bmod p
\]

They exchange their public values.

Alice calculates:

\[
K_A=B^a \bmod p
\]

Bob calculates:

\[
K_B=A^b \bmod p
\]

Both calculations produce:

\[
K_A=K_B=g^{ab}\bmod p
\]

The private values are not transmitted.

The mathematical agreement is valid, but the protocol does not establish whether the received public value actually belongs to the intended participant.

This distinction creates the opportunity for a MITM attack.

### 2.3 Authenticated and Unauthenticated Key Exchange

| Property | Unauthenticated DH | Authenticated DH |
|---|---|---|
| Public-value exchange | Yes | Yes |
| Shared-secret calculation | Yes | Yes |
| Identity verification | No inherent verification | Yes |
| Protection against public-key substitution | No | Yes, when authentication is correctly implemented |
| Transcript authentication | Not inherent | Required by an appropriate protocol |
| MITM resistance | Not guaranteed | Achievable with secure authentication and correct protocol design |

Authentication may be established using digital signatures, certificates, pre-shared keys, or an authenticated key-exchange protocol.

A production protocol must also bind identities, algorithms, negotiated parameters, and public values to the authenticated transcript.

## 3. Man-in-the-Middle Attack Mechanics

### 3.1 Participants

The demonstration uses three participants:

| Participant | Responsibility |
|---|---|
| Alice | Initiates the key exchange |
| Bob | Receives the exchange request |
| Mallory | Intercepts and modifies exchanged public values |

### 3.2 Attack Sequence

The attack proceeds as follows:

1. Alice generates a private value and calculates her public value.
2. Bob generates a private value and calculates his public value.
3. Alice sends her public value towards Bob.
4. Mallory intercepts the message and substitutes her own public value.
5. Bob receives the substituted value and believes it belongs to Alice.
6. Bob sends his public value towards Alice.
7. Mallory intercepts this message and substitutes another attacker-controlled public value.
8. Alice receives the substituted value and believes it belongs to Bob.
9. Alice and Mallory independently calculate one shared secret.
10. Mallory and Bob independently calculate another shared secret.

The resulting relationships are:

\[
K_{Alice,Mallory}\neq K_{Mallory,Bob}
\]

Alice does not share her key with Bob. Bob does not share his key with Alice.

Mallory possesses both independently established secrets.

<diagram>
Alice → Mallory → Bob
Alice ← Mallory ← Bob

Alice ↔ Mallory: Shared Secret 1

Mallory ↔ Bob: Shared Secret 2
</diagram>

The attacker can potentially decrypt, inspect, modify, and re-encrypt messages when the communication protocol does not independently authenticate the endpoints.

### 3.3 Why Encryption Alone Does Not Prevent MITM

Encryption protects information against unauthorized reading when the correct keys are used.

It does not automatically establish that the keys belong to the intended endpoints.

If Alice encrypts information using a key supplied by Mallory, the encryption may work correctly while the communication remains compromised.

The security problem is therefore not simply encryption strength. It is the authenticity of the key exchange.

## 4. Authentication and MITM Prevention

### 4.1 Digital Signatures

Digital signatures bind an identity's trusted signing key to protocol information.

A participant signs an authenticated transcript containing relevant exchange parameters.

The receiving participant verifies the signature using a previously trusted public key.

If Mallory replaces an ephemeral public key without possessing the corresponding identity signing key, signature verification fails.

The signature should cover:

- Protocol identifier.
- Protocol version.
- Initiator identity.
- Responder identity.
- Ephemeral public keys.
- Negotiated cryptographic parameters.
- Relevant session information.

### 4.2 Certificates and Public-Key Infrastructure

A digital certificate binds an identity to a public key through a trusted certificate authority.

Certificate validation should include:

- Certificate-chain validation.
- Identity and hostname matching.
- Validity-period checking.
- Trust-anchor verification.
- Key-usage restrictions.
- Revocation checking where applicable.
- Algorithm and key-strength validation.

A certificate is useful only when the receiving participant correctly validates it.

### 4.3 Pre-Shared-Key Authentication

A pre-shared key (PSK) is a secret independently provisioned to trusted participants.

A message authentication code can bind the exchange transcript to the shared secret.

The Python implementation demonstrates HMAC-SHA256 authentication.

This approach requires secure initial provisioning, protection against secret disclosure, and appropriate key rotation.

### 4.4 Transcript Binding

Transcript authentication prevents an attacker from changing exchange parameters without detection.

A transcript may include:

\[
T=H(
Protocol \parallel
Identity_A \parallel
Identity_B \parallel
PublicKey_A \parallel
PublicKey_B
)
\]

The authentication mechanism must protect the actual protocol transcript, not merely an isolated public-key fingerprint.

### 4.5 Forward Secrecy

Forward secrecy limits the consequences of later compromise of long-term identity credentials.

Ephemeral Diffie-Hellman key pairs are generated for individual exchanges.

After an exchange, temporary private keys should be securely discarded.

Compromise of a long-term signing key should not automatically expose previously established session secrets.

Forward secrecy does not prevent an active MITM attack when authentication is absent.

## 5. Python Implementation: Repository Workflow Simulation

**File role:** Models the mathematical attack and its detection through a self-contained simulation.

The Python implementation uses the following components:

| Component | Responsibility |
|---|---|
| `Participant` | Maintains private and public key values |
| `ManInTheMiddle` | Intercepts and substitutes public values |
| `AuthenticatedKeyExchange` | Performs PSK-based authentication |
| `ExchangeState` | Represents exchange lifecycle states |
| `ExchangeResult` | Records session keys and attack outcomes |
| `SecurityTests` | Validates expected security behavior |

### 5.1 Unauthenticated Exchange

The implementation uses modular exponentiation through Python's built-in `pow()` function.

A deliberately small prime is used to make the mathematical process easy to inspect.

This is an educational demonstration, not a secure cryptographic implementation.

The attacker generates two independent private values and calculates corresponding shared secrets.

The assertions demonstrate that the attacker can derive the same secrets as each victim.

Alice and Bob nevertheless end up with different session keys.

### 5.2 Authentication Mechanism

The authenticated example uses:

- A common pre-shared secret.
- HMAC-SHA256.
- Constant-time tag comparison.
- Public-key range validation.
- Transcript construction.
- Explicit rejection states.

The implementation rejects a key exchange when the trusted secrets do not match.

### 5.3 Validation and Failure Handling

The Python implementation includes tests for:

- Successful Diffie-Hellman agreement.
- MITM creation of separate secrets.
- Successful authenticated exchange.
- Rejection of inconsistent trust secrets.
- Invalid public-key rejection.

The code uses standard-library modules, including `hashlib`, `hmac`, `secrets`, and `unittest`.

### 5.4 Important Limitation

The Python example authenticates a transcript with a PSK for educational purposes.

It does not implement a complete standardized authenticated key-exchange protocol.

The small Diffie-Hellman modulus is intentionally insecure.

## 6. JavaScript Implementation: Event-Driven Authentication

**File role:** Models a cryptographic handshake as an asynchronous, event-driven system.

The JavaScript implementation uses Node.js cryptographic APIs rather than reproducing the Python arithmetic demonstration.

### 6.1 Cryptographic Components

| Mechanism | Implementation |
|---|---|
| Ephemeral key agreement | X25519 |
| Identity authentication | Ed25519 |
| Key derivation | HKDF-SHA256 |
| Transcript digest | SHA-256 |
| Event management | EventEmitter |
| Identity storage | Map |
| Message tracking | Arrays |
| Session states | Immutable state definitions |

### 6.2 X25519

X25519 is an elliptic-curve Diffie-Hellman key-agreement function.

Each participant creates an ephemeral private/public key pair.

The parties exchange public keys and independently derive the same shared secret.

The JavaScript implementation uses Node.js `generateKeyPairSync()` and `diffieHellman()`.

### 6.3 Ed25519 Authentication

Ed25519 provides digital signatures.

Each identity has a signing key pair.

The sender signs the exchange transcript with its private signing key.

The receiver retrieves the trusted identity public key and verifies the signature.

A substituted ephemeral public key changes the transcript, causing signature verification to fail.

### 6.4 Event-Driven Workflow

The implementation defines events for:

- `offer-created`
- `message-sent`
- `authenticated`
- `rejected`
- `closed`

These events separate protocol processing from operational monitoring.

The network simulator permits interception before delivery to the receiving participant.

The attacker modifies the ephemeral public key but cannot create a valid signature for the modified transcript.

### 6.5 Session Management

The state model includes:

| State | Meaning |
|---|---|
| CREATED | Session initialized |
| WAITING_FOR_PEER | Exchange offer created |
| AUTHENTICATING | Incoming identity being verified |
| ESTABLISHED | Authentication and key derivation succeeded |
| REJECTED | Protocol verification failed |
| CLOSED | Session terminated |

Rejected sessions clear their derived session-key reference.

The implementation also demonstrates rejection of an unknown identity.

## 7. C++17 Implementation: Security Evaluation Engine

**File role:** Implements a governance-oriented engine that evaluates whether an exchange should be accepted.

The C++ program separates mathematical operations, identity trust, session tracking, and security policy evaluation.

### 7.1 Domain Components

| Component | Responsibility |
|---|---|
| `Identity` | Stores participant identity information |
| `KeyExchangeMessage` | Represents an exchange message |
| `TrustStore` | Maintains trusted identity fingerprints |
| `SessionRegistry` | Detects repeated session identifiers |
| `SecurityPolicy` | Defines mandatory security conditions |
| `GovernanceEngine` | Evaluates the exchange |
| `Evaluation` | Stores verification results |
| `ExchangeSimulator` | Executes security scenarios |

### 7.2 Modular Arithmetic

The `CryptoDemo` class implements modular exponentiation using repeated squaring.

Its time complexity is:

\[
O(\log e)
\]

where \(e\) is the exponent.

The implementation uses standard C++17 containers:

- `std::map` for identity lookup.
- `std::set` for duplicate-session detection.
- `std::vector` for verification violations.

The small arithmetic parameters are intentionally insecure and exist only to demonstrate the mathematical mechanism.

### 7.3 Governance Evaluation

The engine checks four conditions:

1. Peer identity trust.
2. Exchange transcript consistency.
3. Shared-secret agreement.
4. Session uniqueness.

Each condition produces an explicit result.

The final decision is:

\[
Eligible =
Identity \land Transcript \land
KeyAgreement \land SessionUniqueness
\]

An exchange is accepted only when all mandatory conditions pass.

### 7.4 Attack Demonstration

The attacker generates an independent public key.

Alice and Bob each calculate a secret with Mallory.

The trusted identity registry identifies that the substituted public key does not match Bob's registered identity.

The engine rejects the exchange even though the attacker has successfully established mathematical key agreement with both endpoints.

### 7.5 Engineering Considerations

The implementation uses:

- Explicit domain structures.
- Strongly typed enumerations.
- Exception-based input validation.
- Constant-time cryptography as a production requirement, not an implemented guarantee.
- Ordered identity lookup.
- Duplicate-session detection.

The sample fingerprint mechanism is an educational identifier, not a cryptographic hash or digital signature.

## 8. Java 17 Implementation: Enterprise Security Architecture

**File role:** Models enterprise key-exchange authentication through explicit domain types and services.

The implementation uses Java 17 standard cryptographic APIs.

### 8.1 Domain Architecture

| Component | Responsibility |
|---|---|
| `Identity` | Maintains an Ed25519 identity key pair |
| `ExchangeOffer` | Immutable exchange-message representation |
| `TrustRegistry` | Maintains trusted identities |
| `SessionRegistry` | Tracks session identifiers |
| `SecurityPolicy` | Defines authentication requirements |
| `KeyExchangeService` | Performs the handshake |
| `GovernanceService` | Evaluates security conditions |
| `VerificationResult` | Stores policy evaluation results |

### 8.2 Cryptographic Design

The implementation combines:

- X25519 for ephemeral key agreement.
- Ed25519 for identity signatures.
- SHA-256 for transcript hashing.
- HMAC-SHA256 for key derivation.

This separation is important.

X25519 establishes shared secret material.

Ed25519 authenticates the identity controlling the exchange.

HMAC-based derivation converts secret material into session-key material.

These mechanisms perform different functions and should not be treated as interchangeable.

### 8.3 Immutable Exchange Messages

`ExchangeOffer` is a Java record.

Its byte-array fields are copied during construction and access.

This prevents ordinary callers from modifying the stored message arrays through shared references.

### 8.4 Enterprise Policy

The default policy requires:

- Identity signatures.
- Transcript binding.
- Unique session identifiers.
- Approved algorithms.

The governance service produces a structured verification result rather than returning an unexplained Boolean.

### 8.5 State Transitions

The Java service uses synchronized state transitions for individual sessions.

It distinguishes successful authentication from session closure.

On failure, the service clears its session-key reference and marks the exchange as rejected.

The example demonstrates both public-key substitution and an unknown identity.

### 8.6 Operational Limitations

The Java example is a protocol-learning implementation, not a complete TLS replacement.

Production deployment requires additional measures:

- Authenticated certificate provisioning.
- Certificate-chain and hostname validation.
- Secure key storage.
- Standardized KDF construction and context separation.
- Protocol downgrade protection.
- Replay protection.
- Rate limiting.
- Secure lifecycle management for temporary key material.
- Side-channel and operational security review.

## 9. PostgreSQL Implementation: Relational Security Monitoring

**File role:** Stores exchange records, trust relationships, verification evidence, security events, and establishment decisions.

The database represents protocol operations and their audit history.

It does not perform private-key calculations or independently validate cryptographic signatures.

### 9.1 Relational Domain Model

The principal relationship is:

Repository-style organization
→ Identities
→ Trusted Credentials
→ Protocol Definitions
→ Security Policies
→ Exchange Sessions
→ Key Announcements
→ Exchange Transcripts
→ Verification Records
→ Security Events
→ Audit Records

### 9.2 Database Tables

| Table | Purpose |
|---|---|
| `organizations` | Administrative ownership |
| `identities` | Users, devices, and services |
| `trusted_credentials` | Trusted public-key credentials |
| `protocol_definitions` | Approved key-exchange configurations |
| `security_policies` | Exchange security requirements |
| `exchange_sessions` | Session lifecycle records |
| `key_announcements` | Public-key announcements |
| `exchange_transcripts` | Signed transcript evidence |
| `verification_records` | Individual verification outcomes |
| `security_events` | Interception and attack records |
| `exchange_audit_log` | State-transition history |

### 9.3 Referential Integrity

Primary keys identify individual records.

Foreign keys connect participants, credentials, protocols, policies, and sessions.

Unique constraints prevent duplicate credentials, protocol definitions, and session identifiers.

Check constraints enforce valid session states, timestamp relationships, and field restrictions.

### 9.4 Triggers

The state-transition trigger prevents invalid lifecycle changes.

For example:

- A closed session cannot return to negotiation.
- An established session cannot return to an earlier negotiation state.
- A rejected session cannot be reopened.
- Establishment requires a timestamp.
- Rejection requires a reason.

The audit trigger records session creation and state transitions automatically.

### 9.5 Functions and Procedures

`evaluate_exchange()` returns separate verification results.

`is_exchange_eligible()` evaluates whether the session satisfies the configured requirements.

`establish_exchange()` locks the session and checks eligibility before updating its state.

`reject_exchange()` records an explicit rejection or compromise decision.

These functions separate verification evidence from the final session decision.

### 9.6 Performance Considerations

The database uses indexes for:

- Session-state retrieval.
- Initiator and responder searches.
- Active-session expiration.
- Credential lookup.
- Verification failures.
- Security-event reporting.

A GIN index supports queries against structured JSONB event details.

Session-level row locking prevents two concurrent transactions from independently establishing the same session.

### 9.7 Database Security Limitations

A database record containing a signature is not proof that the signature is valid.

A trusted cryptographic service must perform the verification and record the result.

Production deployments should also use restricted database roles, protected audit storage, TLS, appropriate row-level security, and limited procedure permissions.

Private ephemeral keys must never be stored in the database.

## 10. The Four Security Mechanisms and Their Relationship

The four major elements of secure key exchange have distinct responsibilities.

| Mechanism | Primary responsibility | Security question |
|---|---|---|
| Key exchange | Establish shared secret material | Can both participants calculate a common secret? |
| Authentication | Verify participant identity | Is the peer actually who it claims to be? |
| Transcript protection | Bind identities and exchange parameters | Have the negotiated messages been modified? |
| Session governance | Enforce protocol and operational requirements | Should the exchange be accepted? |

A successful mathematical key agreement does not prove authentication.

A successful identity check does not automatically prove that every protocol parameter was authenticated.

A verified transcript does not compensate for an incorrectly configured trust registry.

A secure implementation requires all relevant controls to operate together.

## 11. Important Attack Variations and Failure Modes

| Attack or failure | Mechanism | Appropriate control |
|---|---|---|
| Public-key substitution | Replaces an exchanged public value | Digital signatures or authenticated key exchange |
| Unknown identity | Introduces an unrecognized endpoint | Trusted identity registry |
| Replay attack | Reuses an earlier exchange message | Nonces, session identifiers, and replay detection |
| Downgrade attack | Forces weaker protocol parameters | Authenticated algorithm negotiation |
| Certificate impersonation | Uses an untrusted or invalid certificate | Certificate-chain and identity validation |
| Transcript modification | Alters negotiated exchange information | Transcript authentication |
| Expired credential | Uses an expired identity credential | Certificate validity checking |
| Revoked credential | Uses a previously invalidated credential | Revocation checking |
| Weak key generation | Uses predictable or insufficient key material | Secure random generation and approved algorithms |
| Long-term key compromise | Exposes identity signing credentials | Key rotation and forward secrecy |

## 12. Production Security Considerations

### Cryptographic Algorithms

Use established cryptographic protocols and approved implementations.

Examples include:

- X25519 for elliptic-curve key agreement.
- Ed25519 for digital signatures.
- ECDSA with appropriate parameters where required.
- HKDF-SHA256 for key derivation.
- AES-GCM or ChaCha20-Poly1305 for authenticated encryption.

The selection must follow the applicable security policy and protocol requirements.

### Identity Management

A trusted identity must be established before key exchange.

Identity verification must not rely solely on a public key received over the same unauthenticated channel being protected.

### Session Management

A secure session should have:

- Unique session context.
- Authenticated transcript.
- Approved key-agreement algorithm.
- Valid peer credentials.
- Properly derived session keys.
- Defined expiration.
- Secure key disposal.

### Monitoring and Incident Response

Security monitoring should record:

- Failed authentication.
- Unexpected public-key fingerprints.
- Repeated session identifiers.
- Invalid transcript signatures.
- Untrusted certificates.
- Algorithm negotiation failures.
- Unusual exchange patterns.

Compromised sessions should be rejected and investigated.

Logs must not expose private keys, shared secrets, or sensitive session-key material.

## 13. Running the Five Implementations

### Python

Requirements: Python 3.10 or later.

File: `mitm_key_exchange.py`

Run:

`python mitm_key_exchange.py`

The program demonstrates the unauthenticated attack, authenticated exchange, transcript tampering, and automated tests.

### JavaScript

Requirements: Node.js 18 or later.

File: `mitm_key_exchange.js`

Run:

`node mitm_key_exchange.js`

The program uses Node.js built-in cryptographic and event modules.

### C++17

Requirements: C++17-compatible compiler.

File: `mitm_key_exchange.cpp`

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra -pedantic mitm_key_exchange.cpp -o mitm_key_exchange`

Run:

`./mitm_key_exchange`

On Windows:

`.\mitm_key_exchange.exe`

### Java 17

Requirements: JDK 17.

File: `Main.java`

Compile:

`javac Main.java`

Run:

`java Main`

The implementation uses Java's standard security providers.

### PostgreSQL

Requirements: PostgreSQL 14 or later.

File: `mitm_key_exchange.sql`

Execute:

`psql -U postgres -d security_lab -f mitm_key_exchange.sql`

The target database must exist before execution.

The SQL script creates the schema, tables, indexes, constraints, functions, procedures, triggers, sample records, and reporting queries.

## 14. Comparative Implementation Analysis

| Dimension | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Main perspective | Protocol simulation | Event-driven cryptographic handshake | Security evaluation engine | Enterprise authentication service | Relational security monitoring |
| Key agreement | Educational DH | X25519 | Educational DH | X25519 | Evidence storage |
| Authentication | HMAC-SHA256 | Ed25519 | Trust registry model | Ed25519 | Credential records |
| Transcript handling | HMAC | Digital signature | Consistency evaluation | Digital signature | Transcript records |
| State management | Enum | Event-driven state | Typed structures | Enum and service state | Enum and triggers |
| Validation | Exceptions and tests | Protocol validation | Policy checks | Domain validation | Constraints and functions |
| Audit | Console output | Events | Evaluation results | Verification results | Persistent audit records |

The implementations deliberately use different engineering approaches.

The Python and C++ programs make the mathematical structure of the attack visible.

The JavaScript and Java programs use actual standardized cryptographic primitives supplied by their respective runtimes.

The PostgreSQL implementation models the operational evidence and governance decisions surrounding the exchange.

## 15. Learning Outcomes

The implementations establish several important technical distinctions:

1. Key agreement and identity authentication are separate cryptographic functions.
2. An attacker can establish two different shared secrets by substituting public values.
3. Encryption without endpoint authentication does not guarantee protection against MITM attacks.
4. Digital signatures can authenticate ephemeral key-exchange information.
5. Transcript binding prevents undetected changes to authenticated exchange parameters.
6. Trust registries and certificate validation determine which identities are accepted.
7. Session uniqueness and replay protection address attacks beyond public-key substitution.
8. Forward secrecy limits the consequences of subsequent long-term credential compromise.
9. Cryptographic verification and security-policy evaluation are separate operational responsibilities.
10. Session establishment should occur only after every mandatory authentication and protocol check has succeeded.

The essential security requirement is that the exchanged public values must be cryptographically bound to authenticated participant identities and the complete negotiated protocol context.
