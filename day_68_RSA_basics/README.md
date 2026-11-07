# RSA Basics

## 1. Technical Scope

RSA (Rivest-Shamir-Adleman) is an asymmetric cryptographic algorithm that uses two mathematically related keys:

- **Public key:** Distributed to parties that need to encrypt information or verify signatures.
- **Private key:** Kept confidential and used to decrypt information or generate digital signatures.

RSA is based on the computational difficulty of factoring a sufficiently large composite integer into its prime factors.

The implementations demonstrate RSA key generation, modular arithmetic, encryption, decryption, digital signatures, verification, validation, and operational auditing.

The five source files provide different engineering perspectives:

| File | Implementation perspective |
|---|---|
| Python | Mathematical implementation, key generation and CRT |
| JavaScript | BigInt arithmetic and event-driven operation processing |
| C++17 | Modular arithmetic and repository-independent cryptographic engine design |
| Java 17 | Enterprise-oriented services, immutable domain types and audit records |
| PostgreSQL | Key registry, operation records, validation, reporting and transaction management |

All implementations are educational. They demonstrate textbook RSA rather than secure production message encoding.

---

## 2. RSA Mathematical Foundations

RSA relies on prime numbers, modular arithmetic, and Euler's totient function.

### 2.1 Prime Numbers

A prime number is an integer greater than one that has exactly two positive divisors:

- 1
- The number itself

RSA key generation requires two distinct large primes:

- \(p\)
- \(q\)

The primes must be generated using cryptographically secure randomness.

### 2.2 Modulus

The RSA modulus is calculated as:

\[
n=pq
\]

The modulus is included in both the public and private keys.

Its security depends on the difficulty of factoring \(n\) into its original prime factors.

### 2.3 Euler's Totient Function

For distinct prime factors:

\[
\phi(n)=(p-1)(q-1)
\]

The totient represents the number of positive integers smaller than \(n\) that are relatively prime to \(n\).

It is required during key generation.

### 2.4 Public Exponent

The public exponent \(e\) must satisfy:

\[
1<e<\phi(n)
\]

and:

\[
\gcd(e,\phi(n))=1
\]

A commonly used public exponent is:

\[
e=65537
\]

This value provides efficient public-key exponentiation and is widely supported by cryptographic implementations.

### 2.5 Private Exponent

The private exponent \(d\) is the modular multiplicative inverse of \(e\) modulo the totient.

\[
ed\equiv1\pmod{\phi(n)}
\]

Equivalently:

\[
d=e^{-1}\pmod{\phi(n)}
\]

The extended Euclidean algorithm calculates this inverse.

The private exponent must remain confidential.

---

## 3. RSA Key Generation Workflow

The key-generation process follows these stages:

1. Generate two distinct probable prime numbers.
2. Calculate their product.
3. Calculate Euler's totient.
4. Select a valid public exponent.
5. Calculate the modular inverse.
6. Construct the public and private keys.

Plain-text representation:

    Generate p and q
          |
          v
       n = p * q
          |
          v
    phi = (p-1)(q-1)
          |
          v
    Select public exponent e
          |
          v
    Calculate d = inverse(e, phi)
          |
          v
       RSA Key Pair
          |
          +----------------+
          |                |
          v                v
      Public Key       Private Key
       (n, e)             (n, d)

The Python and JavaScript implementations use Miller-Rabin probable-primality testing and cryptographically secure random-number generation.

The Java implementation uses `BigInteger.probablePrime()`.

The C++ implementation uses trial-division primality testing with a deliberately small educational example.

The PostgreSQL implementation registers an existing mathematical example instead of attempting production-quality prime generation.

---

## 4. Classic RSA Example

The implementations use the classic small-prime example.

Given:

\[
p=61
\]

\[
q=53
\]

The modulus becomes:

\[
n=61\times53=3233
\]

The totient is:

\[
\phi(n)=60\times52=3120
\]

Choose:

\[
e=17
\]

The private exponent is:

\[
d=2753
\]

This satisfies:

\[
17\times2753\equiv1\pmod{3120}
\]

The resulting keys are:

| Key | Values |
|---|---|
| Public key | (3233, 17) |
| Private key | (3233, 2753) |

The small values make the mathematics easy to inspect. They provide no meaningful cryptographic security.

---

## 5. RSA Encryption

RSA encryption uses the recipient's public key.

The mathematical operation is:

\[
c=m^e\bmod n
\]

Where:

- \(m\) is the plaintext integer representative.
- \(e\) is the public exponent.
- \(n\) is the modulus.
- \(c\) is the ciphertext representative.

The plaintext representative must satisfy:

\[
0\leq m<n
\]

For the classic example:

\[
m=65
\]

Therefore:

\[
c=65^{17}\bmod3233
\]

The resulting ciphertext is:

\[
c=2790
\]

The implementations validate the message range before performing modular exponentiation.

An input equal to or greater than the modulus is rejected.

---

## 6. RSA Decryption

Decryption uses the recipient's private key.

\[
m=c^d\bmod n
\]

For the example:

\[
m=2790^{2753}\bmod3233
\]

The recovered plaintext is:

\[
m=65
\]

The mathematical relationship between the exponents allows the original message representative to be recovered.

### Chinese Remainder Theorem Optimization

The Python, JavaScript, C++ and Java implementations demonstrate the Chinese Remainder Theorem (CRT).

Instead of performing one large exponentiation, decryption is divided into smaller calculations.

First:

\[
d_p=d\bmod(p-1)
\]

\[
d_q=d\bmod(q-1)
\]

Then:

\[
m_1=c^{d_p}\bmod p
\]

\[
m_2=c^{d_q}\bmod q
\]

Calculate:

\[
q^{-1}\bmod p
\]

The final reconstruction is:

\[
h=q^{-1}(m_1-m_2)\bmod p
\]

\[
m=m_2+hq
\]

CRT can substantially improve RSA private-operation performance.

A production implementation must also protect against fault attacks involving CRT computations.

---

## 7. Digital Signatures

RSA supports digital signatures using the private key.

A digital signature provides a mechanism for checking:

- Message integrity.
- Signature authenticity relative to a trusted public key.
- Whether the signature corresponds to the supplied message.

A simplified mathematical representation is:

\[
s=H(m)^d\bmod n
\]

Verification calculates:

\[
H(m)\stackrel{?}{=}s^e\bmod n
\]

Where:

- \(m\) is the original message.
- \(H(m)\) is its cryptographic digest.
- \(d\) is the private exponent.
- \(e\) is the public exponent.
- \(s\) is the signature.

The implementations include educational signature operations and verification tests.

A digest must be encoded correctly before being processed by RSA.

The simplified implementations do not implement a secure signature encoding scheme. They must not be interpreted as implementations of production RSA signatures.

**Production RSA signatures should use RSA-PSS.**

### Signature Verification Workflow

    Original Document
           |
           v
       SHA-256
           |
           v
      Digest Encoding
           |
           v
    Private Key Operation
           |
           v
        Signature
           |
           v
       Verification
           |
           v
      Public Key Operation
           |
           v
     Signature Validation

A modified document produces a different digest with overwhelming probability. Its signature should consequently fail verification.

---

## 8. Textbook RSA and Secure RSA Padding

Textbook RSA directly applies modular exponentiation to a message representative.

This is useful for understanding RSA mathematics, but it is not secure for real-world message encryption.

It has important weaknesses:

- Deterministic encryption.
- No semantic security.
- Mathematical malleability.
- No inherent message integrity.
- Inadequate protection against chosen-ciphertext attacks.
- No safe general-purpose message encoding.

Two important production schemes are:

| Scheme | Purpose |
|---|---|
| RSA-OAEP | Secure RSA encryption encoding |
| RSA-PSS | Secure RSA digital signature encoding |

RSA-OAEP incorporates randomized encoding before RSA encryption.

RSA-PSS uses randomized signature encoding and appropriate hash and mask-generation functions.

The encoding parameters, hash algorithm, key size, and implementation must be configured consistently.

The implementations deliberately separate the educational mathematical operations from production security requirements.

---

## 9. Python Implementation

The Python implementation emphasizes mathematical clarity and reusable functions.

### Important Components

| Component | Responsibility |
|---|---|
| `PublicKey` | Represents public RSA parameters |
| `PrivateKey` | Represents private RSA parameters and prime factors |
| `RSAKeyPair` | Groups public and private key material |
| `gcd()` | Calculates the greatest common divisor |
| `extended_gcd()` | Calculates Bezout coefficients |
| `modular_inverse()` | Calculates the private exponent |
| `is_probable_prime()` | Implements Miller-Rabin testing |
| `generate_prime()` | Generates probable prime candidates |
| `generate_key_pair()` | Constructs an educational RSA key pair |
| `rsa_encrypt()` | Performs public-key encryption |
| `rsa_decrypt()` | Performs CRT-based decryption |
| `rsa_sign_digest()` | Performs an educational signature operation |
| `rsa_verify_digest()` | Checks an educational signature |

The script uses:

- `secrets` for cryptographically secure random values.
- `pow()` for efficient modular exponentiation.
- `dataclasses` for immutable key representations.
- Enums for operation classification.
- Custom exceptions for invalid inputs.
- Assertions for round-trip and signature verification.

### Important Design Decision

Python integers support arbitrary precision.

This avoids fixed-width integer overflow during RSA calculations.

The Miller-Rabin implementation provides probable-primality testing rather than a mathematical proof of primality.

The default generated modulus is only 512 bits and is deliberately insecure.

---

## 10. JavaScript Implementation

The JavaScript implementation uses Node.js and native `BigInt`.

JavaScript's ordinary `Number` type cannot accurately represent arbitrary large RSA integers.

`BigInt` is therefore necessary for the mathematical operations.

### Important Components

| Component | Responsibility |
|---|---|
| `modPow()` | Efficient modular exponentiation |
| `modInverse()` | Modular multiplicative inverse |
| `isProbablePrime()` | Miller-Rabin primality testing |
| `generatePrime()` | Prime candidate generation |
| `generateKeyPair()` | RSA key construction |
| `encrypt()` | Public-key encryption |
| `decrypt()` | CRT-based private-key operation |
| `RSAOperationService` | Event-driven operation management |

### Event-Driven Processing

The service extends Node.js `EventEmitter`.

It produces two types of events:

- `completed`
- `failed`

Each operation receives an identifier and produces an audit record.

The `Map` structure maintains operation records.

This design separates mathematical operations from operation monitoring.

The asynchronous service yields to the Node.js event loop before processing each request.

This does not make the underlying modular exponentiation non-blocking. Large cryptographic operations can still block the event loop.

Production services should use Node.js cryptographic APIs or an appropriate worker-based architecture.

---

## 11. C++17 Implementation

The C++ implementation models an RSA message gateway.

Its primary emphasis is modular arithmetic, domain modeling, and operation auditing.

### Important Components

| Component | Responsibility |
|---|---|
| `PublicKey` | Public RSA key |
| `PrivateKey` | Private RSA key |
| `RSAKeyPair` | Complete educational key pair |
| `ModularArithmetic` | Modular multiplication, exponentiation and inverse |
| `PrimeService` | Trial-division primality testing |
| `RSAKeyFactory` | Key parameter validation and construction |
| `RSAEngine` | Encryption, decryption, signing and verification |
| `AuditRecord` | Operation history |

### Integer Overflow Protection

The implementation uses `unsigned __int128` for intermediate multiplication.

This is a compiler-supported extension commonly available with GCC and Clang, rather than a standard C++17 integer type.

It permits safe intermediate multiplication for the deliberately small demonstration values.

The implementation does not support arbitrary-length RSA integers.

Its trial-division prime test has square-root time complexity and is suitable only for small examples.

### CRT Processing

The decryption engine calculates:

- \(d_p\)
- \(d_q\)
- The modular inverse of \(q\) modulo \(p\)
- Two modular exponentiation results
- The reconstructed message

The implementation also records successful operations and validates incorrect key parameters.

---

## 12. Java 17 Implementation

The Java implementation models an enterprise document-security service.

It uses Java 17 features and the standard cryptographic mathematics library.

### Important Components

| Component | Responsibility |
|---|---|
| `PublicKeyData` | Immutable public-key representation |
| `PrivateKeyData` | Immutable private-key representation |
| `RSAKeyPair` | Key-pair domain record |
| `AuditEntry` | Immutable operation audit record |
| `KeyGenerationService` | Key generation |
| `RSAService` | Cryptographic operation service |
| `RSAOperations` | Operation interface |
| `OperationStatus` | Operation outcome |
| `Operation` | Operation classification |

### Enterprise Design Decisions

The implementation uses records to represent immutable key and audit data.

The service interface separates operation contracts from implementation.

Custom exceptions distinguish invalid keys from invalid messages.

The audit log stores operation identifiers, statuses, and descriptive information.

The audit retrieval method returns an unmodifiable copy, preventing callers from changing the service's internal history.

### Key Generation

`BigInteger.probablePrime()` generates probable primes.

`modInverse()` calculates the private exponent.

`modPow()` performs efficient modular exponentiation.

The generated key is used in an enterprise-style document-signature demonstration.

The implementation uses a 512-bit educational modulus, not a production key size.

---

## 13. PostgreSQL Implementation

The PostgreSQL script models a cryptographic key registry and operation-auditing workflow.

It demonstrates relational integrity and database-level mathematical operations.

### Database Schema

The schema is named `rsa_lab`.

The main entities are:

| Table | Purpose |
|---|---|
| `rsa_keys` | Stores educational RSA key parameters and lifecycle state |
| `rsa_operations` | Records encryption, decryption, signing and verification |
| `rsa_audit` | Stores operation audit events |

### RSA Key Registry

The `rsa_keys` table contains:

- Key identifier.
- Key name.
- Algorithm.
- Modulus.
- Public exponent.
- Educational private exponent.
- Prime factors.
- Modulus size.
- Padding designation.
- Key status.
- Creation timestamp.
- Retirement timestamp.

Constraints validate:

- Positive modulus.
- Valid public exponent range.
- Distinct prime factors.
- Consistency between the modulus and prime factors.
- Positive private exponent.
- Valid retirement state.

The trigger `trg_validate_rsa_key` checks the relationship between the public and private exponents.

It verifies:

\[
ed\bmod\phi(n)=1
\]

This is a consistency check, not a primality test.

### Operation Management

The `rsa_operations` table records cryptographic operations.

Each operation references an existing key through a foreign key.

It captures:

- Operation type.
- Input representative.
- Output representative.
- Execution status.
- Error information.
- Requesting database user.
- Timestamp.

A check constraint ensures that successful operations have outputs and failed operations contain error information.

### Database Functions

| Function | Responsibility |
|---|---|
| `rsa_mod_pow()` | Modular exponentiation |
| `rsa_encrypt()` | Public-key encryption |
| `rsa_decrypt()` | Private-key decryption |
| `rsa_sign()` | Educational signature generation |
| `rsa_verify()` | Educational signature verification |
| `validate_rsa_key()` | Key consistency validation |
| `audit_rsa_operation()` | Automatic operation auditing |

The modular exponentiation function uses repeated squaring.

For exponent \(e\), it repeatedly squares the base and processes the binary representation of the exponent.

Its arithmetic operation count is logarithmic in the exponent.

### Audit Trigger

The `trg_rsa_operation_audit` trigger executes after an operation record is inserted.

It creates an associated audit event automatically.

This separates operational records from their audit history.

The JSONB event details support structured reporting and indexing.

### Views

`active_public_keys` exposes active key metadata without exposing private exponents.

`operation_summary` groups operations by key, type, and status.

### Procedures and Transactions

`retire_rsa_key()` changes an active key to retired.

The procedure rejects attempts to retire a key that is not active.

The demonstration invokes this procedure inside a transaction.

The transaction commits the lifecycle change.

In production, retirement and revocation must also be coordinated with external key stores and dependent services.

---

## 14. RSA Security Considerations

RSA security depends on more than choosing a mathematically correct key pair.

### Key Size

The educational implementations use small keys.

They are intentionally unsuitable for protecting sensitive information.

Typical production RSA deployments use at least 2048-bit moduli, subject to applicable security policy and cryptographic requirements.

### Random Number Generation

Prime generation requires unpredictable random values.

Predictable primes can compromise the entire RSA key pair.

Use cryptographically secure random-number generators.

### Private Key Protection

Private keys must not be exposed through:

- Application logs.
- Public repositories.
- Unrestricted database queries.
- Debugging output.
- Unprotected configuration files.
- Unauthorized API responses.

Production systems should use protected key stores or hardware-backed key management where appropriate.

### Timing and Side-Channel Attacks

RSA operations can leak information through execution timing, memory behavior, power consumption, or fault behavior.

Production cryptographic implementations must use appropriate side-channel protections.

### Key Lifecycle

A production key-management process should cover:

1. Key generation.
2. Key registration.
3. Access authorization.
4. Key distribution.
5. Key rotation.
6. Key retirement.
7. Key revocation.
8. Secure destruction.
9. Recovery and backup controls.

### Encryption and Digital Signatures Are Different

Encryption provides confidentiality.

Digital signatures provide authenticity and integrity when the public key is correctly associated with its owner.

Encryption does not automatically authenticate the sender.

A digital signature does not automatically encrypt the signed document.

These operations solve different security problems.

---

## 15. Performance and Complexity

Let \(k\) represent the number of bits in the RSA modulus.

| Operation | Main computational consideration |
|---|---|
| Prime generation | Repeated probable-primality testing |
| Greatest common divisor | Euclidean algorithm |
| Modular inverse | Extended Euclidean algorithm |
| Modular exponentiation | Logarithmic number of exponentiation steps |
| RSA encryption | Public exponentiation |
| RSA decryption | Private exponentiation |
| CRT decryption | Two smaller exponentiations and reconstruction |
| Signature generation | Private-key exponentiation |
| Signature verification | Public-key exponentiation |

The cost of big-integer multiplication depends on the underlying arithmetic implementation.

For a public exponent of 65537, encryption and signature verification can be relatively efficient.

Private-key operations are generally more expensive.

CRT reduces private-operation computational cost.

Database indexing improves retrieval of keys and operation records but does not make database-based cryptographic calculations suitable for production.

---

## 16. Validation and Failure Conditions

The implementations demonstrate several failure conditions.

| Condition | Expected behavior |
|---|---|
| Negative message | Reject |
| Message greater than or equal to modulus | Reject |
| Ciphertext outside modulus range | Reject |
| Duplicate prime factors | Reject |
| Composite prime candidate | Reject |
| Invalid public exponent | Reject |
| Missing private exponent | Reject decryption |
| Invalid modular inverse | Raise an error |
| Incorrect signature | Return verification failure |
| Modified message | Reject signature |
| Unknown key identifier | Reject operation |
| Retired key | Prevent new encryption and decryption operations |

These controls distinguish mathematical validity, operational validity, and security policy.

A mathematically valid RSA key does not automatically satisfy production security requirements.

---

## 17. Important Implementation Limitations

The source files intentionally demonstrate textbook RSA.

They do not provide interoperable implementations of RSA-OAEP or RSA-PSS.

Other limitations include:

- No secure production message encoding.
- No certificate infrastructure.
- No certificate authority validation.
- No complete public-key distribution protocol.
- No production key rotation service.
- No hardware security module integration.
- No side-channel resistance guarantees.
- No secure multi-process key-management infrastructure.
- No production-grade cryptographic audit architecture.

The C++ implementation is restricted to small integer arithmetic.

The Python and JavaScript implementations use educational 512-bit generated moduli.

The Java implementation also uses a 512-bit demonstration modulus.

The PostgreSQL script stores small private exponents for mathematical demonstration.

These limitations are deliberate boundaries between learning RSA mathematics and deploying cryptographic systems.

---

## 18. Execution and Expected Behavior

| File | Runtime |
|---|---|
| Python | Python 3 |
| JavaScript | Node.js with BigInt support |
| C++17 | C++17-compatible compiler supporting `__int128` |
| Java | Java 17 |
| PostgreSQL | PostgreSQL with PL/pgSQL |

The Python, JavaScript, C++17 and Java programs demonstrate the classic RSA example.

The expected mathematical values are:

| Parameter | Value |
|---|---:|
| p | 61 |
| q | 53 |
| n | 3233 |
| phi(n) | 3120 |
| e | 17 |
| d | 2753 |
| Original message | 65 |
| Ciphertext | 2790 |
| Decrypted message | 65 |

The PostgreSQL script reproduces the same mathematical workflow through database functions and relational records.

Successful execution should demonstrate that encryption followed by decryption restores the original message representative and that a valid educational signature passes verification.
