# Mathematical concepts used in cryptography

## Introduction

Cryptography is strongly connected to mathematics. Modern cryptographic systems use concepts from number theory, abstract algebra, finite fields, probability, information theory, discrete mathematics, and computational complexity.

The central mathematical objective is not simply to perform complicated calculations. A cryptographic construction must create a useful asymmetry between operations that legitimate users can perform efficiently and operations that an attacker should find computationally difficult under the intended security model.

This repository contains three complementary implementations:

- Python provides a broad mathematical laboratory with direct implementations of the major concepts.
- JavaScript demonstrates the same mathematical foundations while highlighting language-specific issues such as `BigInt`, asynchronous APIs, and exact integer arithmetic.
- C++ develops a larger case study in which mathematical key establishment is connected to a simplified message-session architecture.

All numerical cryptographic examples use deliberately small parameters so that the calculations can be inspected. These examples are educational and are not secure production cryptographic implementations.

## Fundamental mathematical vocabulary

### Integer

An integer is a whole number belonging to the set

`..., -3, -2, -1, 0, 1, 2, 3, ...`

Cryptographic number theory frequently operates on nonnegative integers, primes, residues, and large integer values.

### Divisibility

An integer `a` divides an integer `b` if there exists an integer `k` such that

`b = ak`.

This relationship is written as `a | b`.

Divisibility is fundamental to modular arithmetic, factorization, primality, RSA, and many number-theoretic algorithms.

### Prime number

A prime number greater than one has exactly two positive divisors: one and itself.

Examples include 2, 3, 5, 7, 11, 13, and 17.

Prime numbers are important because arithmetic modulo a prime produces a finite field, while products of large primes form the basis of RSA's mathematical structure.

### Composite number

A composite integer greater than one has more than two positive divisors.

For example,

`15 = 3 × 5`.

The distinction between prime and composite integers is central to RSA key construction and many number-theoretic algorithms.

### Factorization

Integer factorization expresses an integer as a product of prime factors.

For example,

`60 = 2² × 3 × 5`.

Factoring small integers is easy. The security of RSA relies on the computational difficulty of factoring appropriately selected very large integers with currently known practical methods.

This should not be interpreted as a universal proof that factoring is impossible. Cryptographic security assumptions concern the resources available to attackers and the algorithms known within the relevant security model.

## Greatest common divisor

The greatest common divisor of two integers `a` and `b`, written

`gcd(a, b)`,

is the largest positive integer dividing both.

For example,

`gcd(240, 46) = 2`.

The Euclidean algorithm repeatedly replaces a pair with the divisor and the remainder:

`gcd(a, b) = gcd(b, a mod b)`.

This gives an efficient algorithm whose running time grows logarithmically with the magnitude of the inputs.

The Python, JavaScript, and C++ implementations all implement the Euclidean algorithm directly.

## Bézout's identity

For integers `a` and `b`, there exist integers `x` and `y` such that

`ax + by = gcd(a, b)`.

The extended Euclidean algorithm computes these coefficients.

This is especially important because a modular multiplicative inverse can be obtained when the greatest common divisor is one.

For example, if

`17x + 3120y = 1`,

then reducing the equation modulo 3120 gives

`17x ≡ 1 mod 3120`.

Therefore `x` is an inverse of 17 modulo 3120.

## Modular arithmetic

The expression

`a mod n`

is the remainder after division by `n`.

Congruence notation is

`a ≡ b mod n`

and means that `n` divides `a - b`.

For example,

`29 ≡ 1 mod 7`

because both values have remainder 1 when divided by 7.

Congruences preserve addition and multiplication:

`a ≡ b mod n`

and

`c ≡ d mod n`

imply

`a + c ≡ b + d mod n`

and

`ac ≡ bd mod n`.

This allows large calculations to be reduced modulo a fixed modulus after intermediate operations.

## Modular inverses

A number `a` has a multiplicative inverse modulo `n` when there exists a value `x` satisfying

`ax ≡ 1 mod n`.

The inverse exists exactly when

`gcd(a, n) = 1`.

For example,

`3 × 4 = 12 ≡ 1 mod 11`.

Therefore,

`3⁻¹ ≡ 4 mod 11`.

A common mistake is assuming that every nonzero value has an inverse modulo every modulus. This is false for composite moduli.

For example, 6 has no inverse modulo 15 because

`gcd(6, 15) = 3`.

## Fast modular exponentiation

Cryptographic algorithms frequently need to calculate

`a^b mod n`

where `b` is extremely large.

Computing every multiplication separately would require a number of operations proportional to `b`.

Repeated squaring reduces the number of multiplications to approximately

`O(log b)`.

The basic idea is to repeatedly square the base and process the exponent one binary bit at a time.

This algorithm appears in the Diffie-Hellman and RSA demonstrations.

## Euler's totient function

Euler's totient function, written `φ(n)`, counts integers from 1 through `n` that are relatively prime to `n`.

For a prime `p`,

`φ(p) = p - 1`.

If `p` and `q` are distinct primes,

`φ(pq) = (p - 1)(q - 1)`.

The RSA implementation uses this formula.

For a general factorization

`n = p₁^a₁ p₂^a₂ ... pₖ^aₖ`,

the totient can be computed using

`φ(n) = n × product over distinct p of (1 - 1/p)`.

## Fermat's little theorem

For a prime `p` and an integer `a` not divisible by `p`,

`a^(p-1) ≡ 1 mod p`.

For example,

`5^12 ≡ 1 mod 13`.

The theorem explains important properties of multiplication modulo a prime and is related to modular inversion and finite-field arithmetic.

## Euler's theorem

For `gcd(a, n) = 1`,

`a^φ(n) ≡ 1 mod n`.

Fermat's little theorem is a special case of Euler's theorem when the modulus is prime.

These results help explain why modular exponentiation has repeating structures and why certain RSA exponent relationships work.

## Chinese Remainder Theorem

The Chinese Remainder Theorem states that a system such as

`x ≡ 2 mod 3`

`x ≡ 3 mod 5`

`x ≡ 2 mod 7`

has a unique solution modulo

`3 × 5 × 7 = 105`

when the moduli are pairwise coprime.

The implementations calculate the solution as 23.

The theorem has important applications in number theory and can also be used to accelerate certain cryptographic computations, including optimized RSA operations.

A critical condition is that the moduli used by the basic implementation must be pairwise coprime.

## Groups

A group is a mathematical structure containing a set and an operation satisfying closure, associativity, an identity element, and inverses.

Cryptography frequently uses groups because group operations provide useful algebraic structure.

For example, the nonzero integers modulo a prime `p` form a multiplicative group with `p - 1` elements.

The discrete-logarithm problem can be defined within such groups.

## Cyclic groups

A group is cyclic if a single element can generate the entire group.

If `g` is a generator, repeated multiplication or exponentiation of `g` produces group elements.

Diffie-Hellman depends on selecting suitable finite groups and group elements with appropriate order.

The choice of group is part of the security design. Merely knowing that an operation is mathematically valid does not guarantee cryptographic security.

## Finite fields

A field provides addition, subtraction, multiplication, and division by every nonzero element while satisfying the required algebraic laws.

The integers modulo a prime `p`, commonly written `GF(p)`, form a finite field.

Finite fields can also be constructed using polynomials over smaller fields.

Finite-field arithmetic is central to many symmetric and public-key cryptographic systems.

## GF(2^8)

`GF(2^8)` contains 256 elements.

Instead of ordinary integer arithmetic, field elements can be represented by eight-bit values, with addition implemented as bitwise XOR and multiplication defined using polynomial arithmetic modulo an irreducible polynomial.

The AES-related polynomial is

`x^8 + x^4 + x^3 + x + 1`.

Its binary representation is associated with `0x11B`.

The Python, JavaScript, and C++ implementations demonstrate multiplication using the corresponding reduction rule. The example

`0x57 × 0x83 = 0xC1`

illustrates finite-field multiplication.

The field inverse of a nonzero value can be obtained through exponentiation because the multiplicative group contains 255 nonzero elements.

## Quadratic residues

A value `a` is a quadratic residue modulo an odd prime `p` if there exists an `x` such that

`x² ≡ a mod p`.

The Python implementation enumerates quadratic residues and calculates the Legendre symbol.

The Legendre symbol

`(a/p)`

is

- `0` when `p` divides `a`,
- `1` when `a` is a nonzero quadratic residue modulo `p`,
- `-1` when `a` is a quadratic non-residue modulo `p`.

Quadratic-residue mathematics appears in several number-theoretic cryptographic constructions.

## Discrete logarithms

The discrete logarithm reverses an exponentiation-like operation.

Given

`g^x ≡ y mod p`,

the problem is to recover `x`.

The forward calculation can be performed efficiently with repeated squaring.

A naive reverse search tries possible exponents one by one. The Python and JavaScript implementations intentionally use this brute-force approach with small parameters.

The security relevance comes from choosing groups in which the best known algorithms require infeasible computational resources at the intended security level.

The discrete logarithm is not one universal problem. Its difficulty depends on the mathematical group and parameter choices.

## Diffie-Hellman key exchange

Diffie-Hellman demonstrates how two participants can derive a common value without directly transmitting the private exponent.

With public parameters `p` and `g`:

Alice chooses private `a` and publishes

`A = g^a mod p`.

Bob chooses private `b` and publishes

`B = g^b mod p`.

Alice computes

`B^a mod p`.

Bob computes

`A^b mod p`.

Both obtain

`g^(ab) mod p`.

An observer can see `p`, `g`, `A`, and `B`, but recovering the private exponents should be difficult under the intended discrete-logarithm security assumption.

The small example uses

`p = 23`

and

`g = 5`.

These values are far too small for security.

### Authentication requirement

Basic Diffie-Hellman does not authenticate the participants.

An active attacker can potentially establish one key with Alice and another key with Bob while relaying messages between them.

Authenticated key exchange protocols address this issue by binding the key exchange to authenticated identities or credentials.

## RSA

RSA is built from modular arithmetic, prime numbers, factorization, Euler's totient, and modular inverses.

The educational implementation chooses two primes:

`p = 61`

`q = 53`.

It calculates

`n = pq`.

It then calculates

`φ(n) = (p - 1)(q - 1)`.

A public exponent `e` must satisfy

`gcd(e, φ(n)) = 1`.

The private exponent `d` is selected so that

`ed ≡ 1 mod φ(n)`.

Encryption is represented by

`c = m^e mod n`.

Decryption is represented by

`m = c^d mod n`.

The mathematical correctness of this relationship follows from the chosen exponent relationship and the properties of modular exponentiation.

### Textbook RSA limitation

The demonstration intentionally shows textbook RSA because it makes the mathematics visible.

Textbook RSA is not an appropriate production encryption scheme.

Real RSA encryption requires standardized randomized padding such as RSA-OAEP. RSA signatures require appropriate signature encoding and hashing, such as the standardized mechanisms used with RSA-PSS.

Key sizes must also be sufficiently large.

## RSA signatures

RSA can also be used for signatures.

Conceptually, a signer uses the private operation to produce a signature and a verifier uses the public operation to verify it.

Production signature schemes do not simply exponentiate an arbitrary message directly. They use standardized encoding, hashing, parameter constraints, and verification rules.

The Python and C++ examples focus primarily on the underlying mathematical relationship rather than a production signature protocol.

## Elliptic curves

An elliptic curve over a prime field can be represented in short Weierstrass form as

`y² = x³ + ax + b mod p`.

A valid curve must be nonsingular. The discriminant condition is

`4a³ + 27b² != 0 mod p`.

Points on the curve, together with a point at infinity, form a group under a specially defined addition operation.

This creates a different algebraic environment from ordinary modular multiplication.

## Elliptic-curve point addition

For two points

`P = (x₁, y₁)`

and

`Q = (x₂, y₂)`,

the slope used in point addition is derived from the coordinates.

For distinct points,

`λ = (y₂ - y₁)/(x₂ - x₁)`.

For point doubling,

`λ = (3x₁² + a)/(2y₁)`.

All division is performed as multiplication by a modular inverse in the underlying finite field.

The resulting coordinates are

`x₃ = λ² - x₁ - x₂`

and

`y₃ = λ(x₁ - x₃) - y₁`.

The implementation also handles the point at infinity and the special case where a point is added to its inverse.

## Scalar multiplication

Elliptic-curve cryptography repeatedly applies point addition:

`kP`.

A naive implementation would perform `k` additions.

The C++ and Python implementations use double-and-add, analogous to binary modular exponentiation.

This reduces the number of point operations to approximately

`O(log k)`.

Real implementations require additional protections because mathematical correctness alone does not prevent side-channel leakage.

## Elliptic-curve Diffie-Hellman

Elliptic-curve key exchange replaces ordinary modular exponentiation with elliptic-curve scalar multiplication.

If Alice has private scalar `a` and Bob has private scalar `b`, and `G` is a public base point, they publish

`A = aG`

and

`B = bG`.

They independently compute

`aB = abG`

and

`bA = baG`.

The resulting points are equal.

The difficult reverse problem is related to the elliptic-curve discrete logarithm problem.

The toy curves in the implementations are extremely small and are intended only to expose the mathematics.

## Cryptographic hash functions

A cryptographic hash function maps an arbitrary-length input to a fixed-size output.

SHA-256 produces 256-bit digests.

Important desired properties include:

- Preimage resistance.
- Second-preimage resistance.
- Collision resistance.
- Strong diffusion.
- Deterministic output.
- Efficient computation.

The Python implementation uses the standard library's SHA-256 implementation, while the JavaScript implementation uses Node's `crypto` facilities.

Changing a message by even one character should produce a substantially different digest.

A hash function is not encryption because it is designed as a one-way transformation rather than a reversible encryption/decryption mechanism.

## Entropy and randomness

Entropy measures uncertainty.

For a discrete probability distribution, Shannon entropy is

`H(X) = -Σ p(x) log₂ p(x)`.

The Python and JavaScript implementations calculate empirical entropy from observed symbols.

Empirical entropy is not automatically the same as cryptographic entropy.

For cryptographic keys, unpredictability is critical. A value may appear random to a human while still being predictable because it was generated from a weak source.

Cryptographic systems therefore require cryptographically secure random-number generation.

### Search-space size

A uniformly random `n`-bit value has

`2^n`

possible values.

The probability of correctly guessing one particular uniformly random value on one attempt is

`2^-n`.

This explains why increasing secret entropy can dramatically increase brute-force search requirements.

It does not mean that every `n`-bit cryptographic construction automatically provides `n` bits of effective security. The algorithm, attack model, structure, implementation, and protocol all affect security.

## Hamming distance

The Hamming distance between two equal-length bit strings is the number of bit positions at which they differ.

For example,

`10101010`

and

`11100010`

differ in three positions.

The implementations calculate Hamming distance using XOR followed by bit counting.

Hamming distance is primarily associated with coding theory, but it is also useful when discussing bit-level differences and diffusion.

## Mathematical assumptions and computational hardness

Cryptographic systems often depend on problems that are believed to be difficult for attackers.

Examples include:

- Integer factorization.
- Discrete logarithms in finite groups.
- Elliptic-curve discrete logarithms.
- Finding hash preimages.
- Finding hash collisions.

The phrase "hard" has a precise computational meaning in context. It does not mean mathematically impossible.

Security analysis considers attack algorithms, available computational resources, parameter sizes, implementation leakage, and advances in algorithms or hardware.

## Python implementation

The Python program is designed as a mathematical laboratory.

It demonstrates:

- Prime testing and factorization.
- Euclidean and extended Euclidean algorithms.
- Modular inverses.
- Fast modular exponentiation.
- Euler's totient.
- Fermat's little theorem.
- Euler's theorem.
- Chinese Remainder Theorem.
- Multiplicative groups.
- Multiplicative orders.
- Legendre symbols.
- Brute-force discrete logarithms.
- Diffie-Hellman.
- RSA.
- GF(2^8) arithmetic.
- Elliptic-curve point arithmetic.
- ECDH concepts.
- SHA-256.
- Entropy.
- Hamming distance.
- Search-space reasoning.
- Side-channel considerations.
- A toy hybrid cryptography pipeline.
- Assertions for mathematical correctness.

Python is particularly suitable for this laboratory because its syntax is compact and its arbitrary-precision integers make number-theoretic calculations convenient.

The Python implementation also uses `secrets` rather than `random` when demonstrating secure random token generation.

## JavaScript implementation

The JavaScript program emphasizes exact integer arithmetic and runtime considerations.

JavaScript's ordinary `Number` type uses IEEE 754 floating-point representation. It cannot represent every integer exactly beyond the safe integer range.

Cryptographic arithmetic frequently requires much larger integers.

The JavaScript implementation therefore uses `BigInt` for operations such as:

- Modular exponentiation.
- Diffie-Hellman.
- RSA.
- Elliptic-curve coordinates.

This distinction is important because an apparently correct mathematical formula can become incorrect if the programming language silently loses integer precision.

The JavaScript implementation also demonstrates Node's cryptographic hash API and uses asynchronous module loading for the runtime cryptography facilities.

## C++ case study

The C++ program develops the mathematics into a larger architectural example.

The scenario is a simplified message-session system in which two participants establish a shared value over a public channel.

The implementation has the following conceptual stages:

`public group parameters → private values → public values → shared secret → key derivation → message transformation`

The key-establishment portion uses the mathematical structure of Diffie-Hellman.

### Case-study components

`gcd_euclid`

Implements the Euclidean algorithm.

`extended_gcd`

Computes Bézout coefficients and supports modular inversion.

`modular_inverse`

Computes multiplicative inverses when they exist.

`modular_power`

Implements repeated-squaring modular exponentiation.

`RSAKeyPair`

Stores the components of a small RSA key pair.

`EllipticCurve`

Represents a short Weierstrass curve over a prime field and implements point validation, negation, addition, and scalar multiplication.

`MessageSession`

Connects a toy shared secret to a toy derived key and reversible message transformation.

The final message transformation is deliberately not presented as secure encryption. Its purpose is to show how mathematical key establishment fits into a larger protocol architecture.

### Why C++ is useful here

C++ makes data representation, integer widths, memory behavior, object design, and performance considerations explicit.

The language is also useful for studying how mathematical algorithms become systems-level implementations.

The program uses C++17 and relies on the standard library.

For modular multiplication, the implementation uses `__int128` internally to reduce overflow risk for the small integer type used by the demonstration. This is an implementation convenience for the educational program and is not a substitute for a complete big-integer cryptographic library.

## Important distinctions

### Encryption versus hashing

Encryption is designed to be reversible using appropriate keys.

Hashing is designed to produce a fixed-size digest and is not intended to be reversed.

A hash should not be described as "encrypted text."

### Encryption versus authentication

Encryption addresses confidentiality.

Authentication and integrity address whether data came from the expected source and whether it was modified.

A system can have encryption without adequate authentication.

Modern secure protocols generally combine confidentiality and integrity through authenticated encryption.

### Public-key versus symmetric cryptography

Symmetric cryptography uses shared secret keys for operations such as encryption and decryption.

Public-key cryptography uses mathematically related public and private values.

Public-key mechanisms are useful for tasks such as key establishment and digital signatures.

Symmetric mechanisms are generally used for efficient bulk-data protection.

Hybrid cryptographic protocols combine both approaches.

### Mathematical security versus implementation security

A mathematically sound algorithm can still be insecure because of:

- Weak random-number generation.
- Timing leakage.
- Cache leakage.
- Fault attacks.
- Incorrect validation.
- Invalid parameter handling.
- Unsafe key storage.
- Incorrect protocol composition.
- Reused nonces.
- Missing authentication.
- Incorrect serialization.
- Inappropriate error handling.

Cryptographic engineering therefore requires both mathematical and systems-level reasoning.

## Edge cases

### Modular inverse does not always exist

For `a mod n`, an inverse exists only when

`gcd(a, n) = 1`.

The implementations intentionally trigger failures such as attempting to invert 6 modulo 15.

### Zero in a finite field

Zero has no multiplicative inverse.

For every nonzero field element `a`, an inverse exists.

This is one of the properties distinguishing a field from more general algebraic structures.

### Elliptic-curve point at infinity

The point at infinity acts as the identity element.

Therefore,

`P + O = P`.

Also,

`P + (-P) = O`.

The implementations explicitly represent this special point.

### Point doubling with zero y-coordinate

When doubling a point whose `y` coordinate is zero in the relevant field, the result is the point at infinity.

### Invalid elliptic-curve points

Public elliptic-curve points must be validated according to the relevant protocol and curve rules.

Accepting malformed points can create serious security problems in real implementations.

### Composite moduli

Modulo a composite number, not every nonzero residue is invertible.

This is why it is incorrect to casually treat every modular arithmetic system as a field.

## Common implementation mistakes

### Using ordinary floating-point arithmetic for cryptographic integers

Floating-point numbers do not preserve arbitrary large integers exactly.

JavaScript developers should use `BigInt` for exact integer calculations when appropriate.

### Writing a slow exponentiation loop

Computing `a^b` through `b` sequential multiplications is inefficient for large exponents.

Repeated squaring reduces the operation count to logarithmic dependence on the exponent.

### Assuming nonzero means invertible

This is true in a field but not in every modular ring.

For example, 6 is nonzero modulo 15 but has no inverse.

### Using weak randomness

Predictable random values can compromise otherwise correct cryptographic mathematics.

Cryptographic secrets require cryptographically secure random generation.

### Treating textbook RSA as secure

Textbook RSA exposes deterministic mathematical structure and lacks the randomized padding required by secure encryption protocols.

### Using unauthenticated Diffie-Hellman

A shared secret is not sufficient to establish authenticated identities.

An active attacker may interfere with an unauthenticated key exchange.

### Implementing production cryptography from educational code

The examples in this repository deliberately omit many requirements of production cryptography.

Correct formulas do not automatically provide:

- Constant-time behavior.
- Correct serialization.
- Secure randomness.
- Side-channel resistance.
- Fault resistance.
- Secure parameter validation.
- Secure protocol composition.
- Key lifecycle management.

## Performance considerations

### Euclidean algorithm

The Euclidean algorithm is highly efficient and has logarithmic behavior in relation to the magnitude of its inputs.

### Fast modular exponentiation

Repeated squaring requires approximately `O(log e)` modular multiplication steps for exponent `e`.

### Brute-force discrete logarithms

The educational discrete-log implementation is intentionally inefficient. It demonstrates the problem directly but is not appropriate for large groups.

Real discrete-log algorithms exploit mathematical structure and are substantially more sophisticated.

### Elliptic-curve scalar multiplication

Double-and-add requires approximately `O(log k)` point operations for scalar `k`.

Production implementations use more advanced methods and side-channel-aware algorithms.

### Chinese Remainder Theorem

CRT can reduce certain computations by replacing one large modular computation with multiple smaller computations.

In optimized RSA implementations, CRT can significantly improve private-key operation performance.

### Finite-field arithmetic

GF(2^8) operations can be implemented efficiently with bitwise operations and table-free algorithms.

Production cryptographic implementations may use carefully optimized techniques while considering timing and cache behavior.

## Security considerations

### Small parameters

Every numerical public-key example in the repository is deliberately tiny.

For example, the RSA primes 61 and 53 are trivial to factor.

The Diffie-Hellman modulus 23 is also trivial to attack.

The elliptic curve over the field of size 17 has negligible security.

Their purpose is to expose mathematical relationships.

### Randomness

Private keys, nonces, salts, initialization values, and other secret or security-sensitive values require appropriate randomness.

The security property is unpredictability, not merely statistical appearance.

### Side channels

Cryptographic algorithms can leak information through:

- Execution time.
- Memory-access patterns.
- Cache behavior.
- Power consumption.
- Electromagnetic emissions.
- Fault responses.
- Error behavior.

The Python implementation includes a conceptual comparison of variable-time and fixed-iteration exponentiation.

The simplified example is not a constant-time implementation. Python-level control flow itself cannot be treated as a constant-time cryptographic primitive.

### Input validation

Public-key cryptographic implementations should validate:

- Numeric ranges.
- Group membership.
- Point validity.
- Subgroup conditions where applicable.
- Key formats.
- Encodings.
- Protocol state.
- Message structure.

Validation requirements depend on the protocol and cryptographic primitive.

### Key separation

A derived key should not automatically be reused for unrelated cryptographic purposes.

Real protocols commonly use domain separation or dedicated derivation steps to distinguish encryption keys, authentication keys, exporter values, and other purposes.

### Nonces

Many symmetric encryption modes require nonces with strict uniqueness requirements.

Nonce misuse can completely undermine otherwise strong cryptographic algorithms.

The toy XOR implementation intentionally avoids pretending to solve nonce management.

## Limitations of the implementations

The programs are mathematical teaching implementations rather than production cryptographic libraries.

Important omissions include:

- Production-size big-integer infrastructure in C++.
- Standardized secure padding for RSA.
- Complete digital-signature encoding.
- Production authenticated encryption.
- Full protocol authentication.
- Secure key storage.
- Secure serialization.
- Constant-time guarantees.
- Hardware side-channel defenses.
- Complete subgroup and cofactor handling for elliptic curves.
- Formal protocol verification.
- Comprehensive fuzz testing.
- Production-grade error taxonomy.
- Interoperability specifications.

These limitations are intentional because the goal is to make the underlying mathematics visible.

## Practical applications

### Secure key establishment

Finite groups and elliptic curves provide mathematical foundations for public-key key-establishment mechanisms.

### Digital signatures

Modular arithmetic and group operations support signature systems used for authentication, software integrity, certificates, and transaction authorization.

### Symmetric cryptography

Finite-field and binary arithmetic are used in the internal structure of modern block ciphers and related constructions.

### Password protection

Hash functions, salts, password-specific key derivation, and memory-hard computation are used to protect stored password verifiers.

### Data integrity

Cryptographic hashes can identify changes to files, messages, and other data.

### Public-key infrastructure

Certificates and digital signatures rely on mathematical public-key constructions to bind identities or attributes to public keys.

### Secure communication protocols

Real secure communication protocols combine multiple mathematical primitives rather than relying on one isolated algorithm.

A typical architecture can contain:

`authentication + key establishment + key derivation + authenticated encryption + key lifecycle management`

## Relationship among the concepts

The major concepts in the implementations are interconnected.

Prime numbers lead to finite fields.

Finite fields support multiplicative groups.

Groups provide structures in which discrete-logarithm problems can be defined.

Discrete-logarithm assumptions support Diffie-Hellman-style constructions.

Integer factorization and Euler's totient support RSA.

Polynomial arithmetic over finite fields supports constructions such as GF(2^8).

Elliptic curves create alternative finite groups whose group operation supports public-key constructions.

Hash functions provide fixed-size representations and integrity-oriented primitives.

Probability and entropy explain why unpredictable secrets are difficult to guess.

Computational complexity explains why an operation can be efficient for legitimate users while its inverse or attack problem can be expensive.

## Mathematical design versus protocol design

A cryptographic primitive is only one component of a complete security system.

For example, Diffie-Hellman can establish a mathematical shared secret, but a practical protocol must also determine:

- Who is communicating.
- How public parameters are authenticated.
- How keys are derived.
- How messages are encrypted.
- How message integrity is verified.
- How nonces are generated.
- How keys are rotated.
- How failures are handled.
- How replay is prevented.
- How keys are stored and destroyed.

The difference between a mathematical construction and a secure protocol is therefore fundamental.

## Python, JavaScript, and C++ comparison

| Aspect | Python | JavaScript | C++ |
|---|---|---|---|
| Mathematical readability | Very high | High | Moderate |
| Large integers | Built in | `BigInt` required | Requires appropriate integer or big-integer design |
| Main educational role | Broad mathematical laboratory | Exact integer and runtime behavior | Systems-oriented case study |
| Finite-field demonstration | Yes | Yes | Yes |
| RSA demonstration | Yes | Yes | Yes |
| Elliptic curves | Yes | Yes | Yes |
| Hash demonstration | Yes | Node cryptographic API | Architectural discussion |
| Systems-level control | Lower | Runtime dependent | High |
| Memory-management visibility | Low | Managed runtime | High |
| Production cryptography suitability | Library-dependent | Library-dependent | Library-dependent |

The languages do not change the underlying mathematics. They change how those mathematical operations are represented, executed, validated, and integrated into software.

## Testing strategy

The three implementations include correctness checks for important mathematical identities.

Examples include:

`gcd(240, 46) = 2`

`240x + 46y = 2`

`3 × 4 ≡ 1 mod 11`

`2^10 mod 1000 = 24`

`φ(35) = 24`

The CRT solution is checked against all supplied congruences.

Finite-field multiplication is checked using the GF(2^8) example.

Elliptic-curve points are checked for curve membership.

Point plus its inverse is checked against the point at infinity.

RSA encryption followed by decryption is checked against the original educational message.

Testing mathematical identities is useful because many cryptographic implementation errors are arithmetic errors before they become protocol errors.

## Design principles demonstrated

The implementations consistently separate mathematical components into functions or classes.

This provides several benefits:

- Individual algorithms can be tested independently.
- Mathematical assumptions can be documented locally.
- Edge cases can be isolated.
- Larger constructions can reuse primitive operations.
- Complexity can be discussed at the algorithm level.
- The relationship between mathematical notation and executable code becomes clearer.

The C++ case study extends this approach into an object-oriented architecture where an `EllipticCurve` encapsulates curve operations and `MessageSession` represents a higher-level protocol component.

## Production considerations

A production cryptographic system should normally use a well-reviewed cryptographic library rather than treating educational implementations as deployable primitives.

Production engineering must consider:

- Standardized algorithms.
- Standardized parameter sets.
- Cryptographically secure randomness.
- Key generation.
- Key storage.
- Key rotation.
- Key destruction.
- Secure serialization.
- Authentication.
- Nonce management.
- Error handling.
- Side-channel resistance.
- Dependency management.
- Versioning.
- Interoperability.
- Security testing.
- Threat modeling.
- Protocol composition.

The mathematical algorithms are necessary foundations, but they are only one layer of a complete cryptographic system.
