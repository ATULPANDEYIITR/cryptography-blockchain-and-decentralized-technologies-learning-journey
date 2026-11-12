# Diffie-Hellman Step by Step

## 1. Introduction

Diffie-Hellman (DH) is a cryptographic key-agreement algorithm that allows two participants to establish the same secret value over a communication channel that may be observed by an attacker.

The fundamental property is that participants can independently calculate an identical shared secret without transmitting their private values.

The algorithm relies on modular exponentiation and the computational difficulty of the discrete logarithm problem.

Diffie-Hellman is a key-agreement mechanism, not an encryption algorithm. It does not directly encrypt messages, authenticate participants, or guarantee protection against an active man-in-the-middle attack.

The implementations in this project demonstrate finite-field Diffie-Hellman using small educational parameters.

## 2. Mathematical Foundation

### 2.1 Public parameters

Two participants agree on three mathematical values:

| Symbol | Meaning |
|---|---|
| `p` | Prime modulus |
| `q` | Prime order of the selected subgroup |
| `g` | Generator of that subgroup |

For this demonstration:

| Parameter | Value |
|---|---:|
| Prime modulus (`p`) | 23 |
| Subgroup order (`q`) | 11 |
| Generator (`g`) | 2 |

The generator satisfies:

`g^q mod p = 1`

For the selected parameters:

`2^11 mod 23 = 1`

The public parameters can be known by everyone, including an attacker.

The private exponents must remain confidential.

### 2.2 Modular arithmetic

Modular arithmetic calculates remainders after division by a modulus.

For example:

`2^6 mod 23 = 18`

The result is 18 because:

`64 = 2 × 23 + 18`

Modular exponentiation allows large exponentiation calculations to be performed efficiently without constructing unnecessarily large intermediate results.

### 2.3 Discrete logarithm problem

Given:

`y = g^x mod p`

Calculating `y` from `g`, `x`, and `p` is straightforward.

Recovering `x` from `y`, `g`, and `p` is the discrete logarithm problem.

For appropriately selected cryptographic parameters, recovering the private exponent is computationally difficult.

The educational parameters in this project are deliberately small and provide no practical security.

## 3. Diffie-Hellman Exchange: Step by Step

<AsyncImageGroup query={["Diffie Hellman key exchange Alice Bob public private keys mathematical diagram","Diffie Hellman key exchange modular exponentiation educational illustration"]} aspectRatio="5:4" layout="carousel"/>

### Step 1: Agree on public parameters

Alice and Bob agree on:

- Prime modulus: `p = 23`
- Subgroup order: `q = 11`
- Generator: `g = 2`

These values do not need to be secret.

### Step 2: Generate private keys

Alice independently generates a private exponent:

`a = 6`

Bob independently generates another private exponent:

`b = 7`

The private values must not be transmitted.

The permitted private exponent range for this subgroup is:

`1 ≤ a, b < q`

### Step 3: Calculate public keys

Alice calculates:

`A = g^a mod p`

`A = 2^6 mod 23`

`A = 64 mod 23`

`A = 18`

Bob calculates:

`B = g^b mod p`

`B = 2^7 mod 23`

`B = 128 mod 23`

`B = 13`

The resulting public keys are:

| Participant | Private exponent | Public key |
|---|---:|---:|
| Alice | 6 | 18 |
| Bob | 7 | 13 |

Only the public keys are exchanged.

### Step 4: Exchange public keys

Alice sends her public key to Bob.

Bob sends his public key to Alice.

| Sender | Recipient | Transmitted value |
|---|---|---:|
| Alice | Bob | 18 |
| Bob | Alice | 13 |

The private exponents are never transmitted.

An observer may know `p`, `q`, `g`, `A`, and `B` without immediately knowing the shared secret.

### Step 5: Calculate the shared secret

Alice uses Bob's public key and her private exponent.

`S_A = B^a mod p`

`S_A = 13^6 mod 23`

`S_A = 9`

Bob uses Alice's public key and his private exponent.

`S_B = A^b mod p`

`S_B = 18^7 mod 23`

`S_B = 9`

Both calculations produce the same result.

### Step 6: Verify mathematical agreement

The equality is:

`S_A = S_B = 9`

The reason is:

`S_A = (g^b)^a mod p`

`S_A = g^(ab) mod p`

Similarly:

`S_B = (g^a)^b mod p`

`S_B = g^(ab) mod p`

Therefore:

`S_A = S_B`

<box border radius="lg" padding={3} gap={2}>
  **Complete mathematical exchange**

  <grid columns={2} gap={3}>
    <grid-item>
      **Alice**

      <math block value="a=6"/>

      <math block value="A=2^6\\bmod23=18"/>

      <math block value="S_A=13^6\\bmod23=9"/>
    </grid-item>
    <grid-item>
      **Bob**

      <math block value="b=7"/>

      <math block value="B=2^7\\bmod23=13"/>

      <math block value="S_B=18^7\\bmod23=9"/>
    </grid-item>
  </grid>
  <divider color="subtle"/>
  <title color="success" size="xl" textAlign="center">Shared secret = 9</title>
  <text color="secondary" size="xs" textAlign="center">Both participants independently calculate the same value.</text>
</box>

## 4. Important Terminology

| Term | Technical meaning |
|---|---|
| Key agreement | Process through which participants establish common secret material |
| Prime modulus | Prime number used in modular arithmetic |
| Generator | Element used to produce subgroup values |
| Subgroup | Set of mathematical elements with a defined group operation |
| Private exponent | Confidential randomly generated exponent |
| Public key | Value calculated from the private exponent |
| Shared secret | Common result calculated independently by participants |
| Discrete logarithm | Mathematical problem underlying finite-field DH security |
| Ephemeral key | Temporary key generated for a particular exchange |
| Forward secrecy | Protection of past session secrets when long-term credentials are subsequently compromised |
| Key derivation function | Function that converts shared secret material into usable cryptographic keys |
| HKDF | HMAC-based Extract-and-Expand Key Derivation Function |
| Transcript | Record of the protocol messages exchanged during a handshake |
| Authentication | Verification of the identity of the communicating participant |

## 5. Finite-Field Diffie-Hellman and X25519

The project demonstrates traditional finite-field DH. Modern systems frequently use elliptic-curve Diffie-Hellman.

| Property | Finite-field DH | X25519 |
|---|---|---|
| Mathematical basis | Discrete logarithm problem | Elliptic-curve Diffie-Hellman |
| Public values | Group elements modulo a prime | Curve public keys |
| Private values | Private exponents | Private scalar material |
| Key agreement | Modular exponentiation | Curve scalar multiplication |
| Parameter handling | Requires appropriate group selection | Uses a standardized curve |
| Implementation | More complex parameter and subgroup handling | Simpler standardized interface |
| Common use | TLS and established DH protocols | Modern TLS and secure communication protocols |

X25519 is standardized in RFC 7748.

The mathematical operations are different, but both mechanisms establish common secret material without transmitting private keys.

## 6. Python Implementation

File: `diffie_hellman.py`

The Python implementation provides an object-oriented simulation of the complete exchange.

### 6.1 Domain model

The implementation uses:

- `DHParameters` to represent the mathematical domain.
- `Participant` to manage individual key pairs.
- `DiffieHellmanExchange` to coordinate the handshake.
- `ExchangeState` to represent lifecycle states.
- Custom exceptions to distinguish parameter, public-key, and exchange failures.

The `dataclass` provides immutable parameter records.

### 6.2 Parameter validation

The implementation checks:

1. The modulus is prime.
2. The subgroup order is prime.
3. The subgroup order divides `p - 1`.
4. The generator belongs to the required subgroup.
5. The generator is not equal to one.

For small educational values, trial division is sufficient to demonstrate primality checking.

It is not suitable for production-sized cryptographic parameters.

### 6.3 Key generation

Python's `secrets` module generates private exponents.

The `Participant.generate_keys()` method computes the public value using the built-in modular exponentiation operation.

The `pow(base, exponent, modulus)` operation performs efficient modular exponentiation.

### 6.4 Public-key validation

A received public key must:

- Be an integer.
- Fall within the accepted range.
- Belong to the required subgroup.

The subgroup condition is:

`y^q mod p = 1`

This prevents accepting values outside the intended subgroup.

### 6.5 Session-key derivation

The implementation uses HMAC-SHA256 to demonstrate an HKDF-style Extract-and-Expand process.

The shared secret is input key material.

The derived key is separated by context.

Different session contexts produce different derived keys even when the input secret is identical.

The example uses a fixed educational salt. A production protocol must follow its specified HKDF salt and transcript construction.

### 6.6 Automated tests

The Python program checks:

- Successful shared-secret agreement.
- Invalid public-key rejection.
- Subgroup validation.
- Composite modulus rejection.
- Invalid secret rejection.
- Context-dependent key derivation.

The test cases are executable assertions and exception checks.

## 7. JavaScript Implementation

File: `diffie_hellman.js`

The JavaScript implementation uses Node.js capabilities to demonstrate an event-driven cryptographic exchange.

### 7.1 BigInt arithmetic

JavaScript's standard `Number` type cannot safely represent arbitrary large integers.

The implementation uses `BigInt` for all modular arithmetic.

The `modPow()` function implements square-and-multiply exponentiation.

Its time complexity is:

`O(log e)`

where `e` is the exponent.

### 7.2 Event-driven architecture

`ExchangeCoordinator` extends `EventEmitter`.

It publishes state-change events during execution.

The principal states are:

| State | Meaning |
|---|---|
| CREATED | Exchange object initialized |
| PARAMETERS_VALIDATED | Mathematical parameters accepted |
| KEYS_CREATED | Both participants generated keys |
| EXCHANGED | Public keys exchanged |
| COMPLETED | Shared secrets matched |
| FAILED | An exchange operation failed |

This separation makes the exchange lifecycle observable without mixing event handling with the mathematical operations.

### 7.3 Asynchronous execution

The coordinator exposes an asynchronous `execute()` method.

It uses promises and structured exception handling.

The current calculation is local and does not require network access. The asynchronous interface represents an integration point for an application that performs remote communication.

### 7.4 Key derivation

Node.js provides the `crypto` module.

The implementation uses:

- `createHmac()`
- `Buffer`
- `randomInt()`

The resulting HKDF-style operation produces a 256-bit demonstration key.

The random exponent generator is suitable only for the small demonstration range. Production private-key generation requires a vetted cryptographic implementation.

## 8. C++17 Implementation

File: `diffie_hellman.cpp`

The C++ implementation focuses on modular arithmetic, strongly defined domain types, and explicit state management.

### 8.1 Modular exponentiation

The `modPow()` function uses binary exponentiation.

Instead of calculating a complete power, it repeatedly squares the base and reduces intermediate results modulo the prime.

This avoids unnecessarily large intermediate values for the small demonstration parameters.

### 8.2 Domain model

The main components are:

- `DHParameters`
- `Participant`
- `GovernanceEngine`
- `SecureRandomDemo`
- `ExchangeState`

Custom exception classes separate mathematical validation failures from invalid state transitions.

### 8.3 State management

The governance engine controls the order of operations.

A participant cannot calculate a shared secret before generating a private key.

The exchange cannot report successful completion before both shared secrets match.

Failures transition the engine into a failed state.

### 8.4 Performance and limitations

Binary modular exponentiation requires logarithmic exponentiation steps.

The implementation uses 64-bit unsigned integers and is restricted to the small demonstration parameters.

The multiplication operation can overflow for sufficiently large values.

It is not a production multiprecision cryptographic implementation.

The `std::mt19937_64` random-number generator is also not cryptographically secure.

Both limitations are explicitly separated from production cryptographic requirements.

## 9. Java 17 Implementation

File: `DiffieHellmanDemo.java`

The Java implementation introduces enterprise-oriented domain modeling and policy evaluation.

### 9.1 Immutable domain types

Java records represent:

- `DHParameters`
- `ExchangePolicy`

Records reduce mutable configuration and centralize validation.

### 9.2 Exchange service

`ExchangeService` coordinates:

1. Parameter validation.
2. Policy evaluation.
3. Key generation.
4. Public-key exchange.
5. Public-key validation.
6. Shared-secret calculation.
7. Completion or failure.

The service prevents access to the completed shared secret before the exchange reaches its completed state.

### 9.3 Security policies

The `ExchangePolicy` record represents governance requirements.

It includes:

- Minimum subgroup bit length.
- Mandatory subgroup validation.
- Mandatory peer authentication.

The example intentionally allows the small mathematical parameters through its demonstration policy so that the exchange can execute.

The policy rejects disabled authentication and can reject insufficient subgroup sizes.

A production policy must enforce appropriate cryptographic sizes and authenticated protocol behavior.

### 9.4 Cryptographic API usage

The implementation uses:

- `BigInteger.modPow()` for modular exponentiation.
- `SecureRandom` for demonstration private-exponent generation.
- `Mac` for HMAC-SHA256.
- `SecretKeySpec` for HMAC key initialization.
- `Arrays` for byte-array handling.

The HKDF-style implementation separates the derivation context from the input shared secret.

## 10. PostgreSQL Implementation

File: `diffie_hellman.sql`

The database implementation models the exchange as a relational workflow.

It separates mathematical parameters, participants, sessions, public keys, exchange messages, verification records, and audit events.

### 10.1 Relational domain model

The principal relationship is:

`DH Parameters`

→ `Exchange Sessions`

→ `Participants`

→ `Participant Keys`

→ `Public Key Exchanges`

→ `Secret Verifications`

→ `Audit Events`

### 10.2 Database tables

| Table | Responsibility |
|---|---|
| `dh_parameters` | Stores modulus, subgroup order, and generator |
| `participants` | Stores participant identities and authentication state |
| `exchange_sessions` | Stores exchange lifecycle and policy state |
| `participant_keys` | Stores educational private and public key records |
| `public_key_exchanges` | Records transmitted public values |
| `secret_verifications` | Records independently calculated shared secrets |
| `audit_events` | Records workflow changes |

### 10.3 Integrity constraints

The database uses:

- Primary keys.
- Foreign keys.
- Unique constraints.
- Check constraints.
- Enumerated types.
- Indexes.
- Triggers.

These mechanisms prevent invalid relational states.

For example, a session cannot be marked completed unless the required verification records exist and authentication requirements are satisfied.

### 10.4 Modular exponentiation

The `dh_mod_pow()` function implements square-and-multiply using PostgreSQL `NUMERIC`.

The function supports the small demonstration parameters without the fixed-width overflow limitations of ordinary integer types.

The database also provides:

- `dh_is_prime()`
- `validate_dh_parameters()`
- `validate_dh_public_key()`
- `generate_public_key()`
- `compute_shared_secret()`

The primality function uses trial division and is not suitable for large production cryptographic primes.

### 10.5 Transactions

The example exchange uses a transaction.

The transaction:

1. Registers the exchange.
2. Records both participants' keys.
3. Updates the session state.
4. Records public-key exchanges.
5. Calculates both shared secrets.
6. Records verification results.
7. Marks the exchange completed.
8. Commits the changes.

If an operation fails, the transaction can be rolled back rather than leaving partially recorded exchange data.

### 10.6 Reporting and evaluation

The SQL script provides:

- Exchange retrieval queries.
- Public-key reports.
- Secret-agreement evaluation.
- Invalid-key validation.
- Exchange-status aggregation.
- Exchange-health reporting.
- CTE-based eligibility evaluation.
- Audit reporting.
- Query execution plans.

The database determines whether an exchange satisfies its recorded conditions.

It does not provide cryptographic authentication merely because the database contains matching secret values.

## 11. Man-in-the-Middle Attack

<AsyncImage query="Diffie Hellman man in the middle attack Alice Mallory Bob two independent shared keys network security diagram" aspectRatio="16:9" width="100%"/>

A fundamental weakness of unauthenticated Diffie-Hellman is that it does not establish the identity of the communicating participant.

An attacker named Mallory can intercept public-key messages.

The attack proceeds as follows:

1. Alice sends her public key to Bob.
2. Mallory intercepts the message.
3. Mallory sends her own public key to Bob.
4. Bob sends his public key to Alice.
5. Mallory intercepts that message.
6. Mallory sends another public key to Alice.
7. Alice establishes a secret with Mallory.
8. Bob independently establishes another secret with Mallory.

The result is:

`Alice ↔ Mallory`

`Mallory ↔ Bob`

Mallory can independently calculate both shared secrets.

She can decrypt, modify, and re-encrypt communication if the surrounding protocol permits it.

The participants have completed mathematical key agreement, but they have not authenticated each other.

### 11.1 Protection mechanisms

An authenticated exchange can use:

- Digital signatures.
- Certificates.
- Pre-shared authentication keys.
- Authenticated key-exchange protocols.
- Transcript authentication.

The authentication mechanism must bind the identities to the exchanged public keys and protocol transcript.

## 12. Key Derivation and Encryption

The raw DH shared secret should not be used directly as an application encryption key.

A key derivation function converts secret material into appropriately formatted cryptographic keys.

A typical workflow is:

`Private Exponents`

→ `Public Key Exchange`

→ `Shared Secret`

→ `HKDF Extract`

→ `HKDF Expand`

→ `Session Keys`

The derived key can then be used by an authenticated encryption algorithm.

Examples of authenticated encryption with associated data include:

- AES-GCM.
- ChaCha20-Poly1305.

Authenticated encryption provides confidentiality and integrity when used correctly.

Key derivation must include suitable context and protocol information to prevent unintended key reuse across different sessions or purposes.

## 13. Forward Secrecy

Forward secrecy means that compromise of a participant's long-term authentication credentials does not automatically reveal previously established session secrets.

Ephemeral Diffie-Hellman supports this property when:

1. Fresh private exponents are generated for individual sessions.
2. Private exponents are securely protected.
3. Ephemeral private material is erased when no longer required.
4. Authentication is performed independently of the ephemeral private values.
5. The protocol correctly derives and protects session keys.

Reusing private exponents across sessions weakens the intended separation between sessions.

## 14. Security Validation and Failure Conditions

| Condition | Expected behavior |
|---|---|
| Composite modulus | Reject parameters |
| Invalid subgroup order | Reject parameters |
| Generator outside subgroup | Reject parameters |
| Private exponent outside range | Reject key generation |
| Public value equal to 1 | Reject public key |
| Public value outside accepted range | Reject public key |
| Public value outside subgroup | Reject public key |
| Shared secrets differ | Fail exchange |
| Authentication fails | Reject authenticated exchange |
| Invalid HKDF output length | Reject derivation request |
| Reused session context | Apply protocol-specific key separation |
| Private-key disclosure | Treat affected sessions as compromised |

### 14.1 Constant-time execution

Cryptographic operations may leak information through:

- Execution time.
- Memory access patterns.
- Cache behavior.
- Power consumption.
- Error behavior.

Ordinary modular exponentiation implementations are not automatically constant-time.

Production cryptographic libraries must provide suitable protections against relevant side-channel attacks.

### 14.2 Random-number generation

Private exponents must be unpredictable.

The implementations demonstrate different random-number facilities:

| Language | Demonstration mechanism |
|---|---|
| Python | `secrets` |
| JavaScript | Node.js `crypto` |
| C++17 | `mt19937_64`, explicitly non-cryptographic |
| Java 17 | `SecureRandom` |
| PostgreSQL | Fixed sample exponents |

The C++ random-number generator and PostgreSQL demonstration values are not suitable for production private-key generation.

### 14.3 Private-key protection

Private exponents must never be exposed through:

- Application logs.
- Public APIs.
- Database reporting.
- Debug output.
- Error messages.
- Monitoring systems.

The sample programs print private values only to make the mathematics visible.

The SQL script stores private values only to demonstrate the calculation workflow.

Production applications must avoid these practices.

## 15. Algorithmic Complexity

Let `n` represent the bit length of the exponent and modulus.

| Operation | Computational characteristics |
|---|---|
| Parameter primality checking | Depends on the selected primality algorithm |
| Modular exponentiation | `O(log e)` modular multiplications |
| Public-key generation | One modular exponentiation |
| Shared-secret generation | One modular exponentiation |
| Public-key subgroup validation | One modular exponentiation |
| HKDF extraction | HMAC computation |
| HKDF expansion | Proportional to the number of output blocks |

The educational implementations prioritize clarity.

Production implementations must consider constant-time behavior, cryptographic parameter sizes, memory protection, and optimized arithmetic.

## 16. Implementation Comparison

| Requirement | Python | JavaScript | C++17 | Java 17 | PostgreSQL |
|---|---|---|---|---|---|
| Parameter validation | Yes | Yes | Yes | Yes | Yes |
| Modular exponentiation | Built-in `pow` | Custom BigInt | Binary exponentiation | `BigInteger.modPow` | PL/pgSQL function |
| Private-key generation | `secrets` | Node.js crypto | Non-cryptographic demo RNG | `SecureRandom` | Fixed demonstration values |
| Public-key validation | Yes | Yes | Yes | Yes | Yes |
| Subgroup validation | Yes | Yes | Yes | Yes | Yes |
| Shared secret | Yes | Yes | Yes | Yes | Yes |
| HKDF-style derivation | Yes | Yes | Not implemented | Yes | Not implemented |
| Event-driven lifecycle | State simulation | EventEmitter | Explicit state machine | Service state machine | Database triggers |
| MITM demonstration | Yes | Yes | Yes | Yes | Conceptual workflow |
| Automated tests | Yes | Yes | Yes | Yes | Validation queries |

## 17. Practical Applications

Diffie-Hellman key agreement is relevant to:

- Secure network connections.
- Transport Layer Security.
- Virtual private networks.
- Secure messaging.
- Encrypted communication protocols.
- Ephemeral session-key establishment.
- Authenticated key exchange.
- Secure distributed systems.

Its role is to establish secret material that can be transformed into cryptographic session keys.

The surrounding protocol remains responsible for authentication, key confirmation, transcript integrity, and secure application-data protection.

## 18. Limitations of the Demonstration

The small values `p = 23`, `q = 11`, and `g = 2` make the calculations easy to verify manually.

They are not cryptographically secure.

The implementations are learning models rather than interoperable cryptographic protocol implementations.

Specific limitations include:

- No production-sized finite-field parameter set.
- No production X25519 implementation.
- No complete authenticated handshake.
- No production certificate validation.
- No network transport implementation.
- No production-grade key storage.
- No complete authenticated-encryption protocol.
- No formal side-channel resistance guarantees.
- No interoperability testing against a TLS implementation.

The mathematical exchange, validation logic, state transitions, attack simulation, and database workflow provide the technical foundation for understanding how Diffie-Hellman operates.

## 19. References to Standards Used in the Technical Design

| Standard | Relevant subject |
|---|---|
| RFC 7748 | Elliptic-curve Diffie-Hellman and X25519 |
| RFC 5869 | HKDF |
| RFC 7919 | Negotiated finite-field Diffie-Hellman groups for TLS |
| RFC 8446 | TLS 1.3 handshake and key establishment |
| NIST SP 800-56A | Pair-wise key-establishment schemes |
| NIST SP 800-56C | Key derivation methods |
| NIST SP 800-57 | Key-management guidance |

These standards distinguish mathematical key agreement from the authentication, key derivation, and key-management mechanisms needed in a secure communication system.
