# Modular inverse

## Introduction

A modular inverse is the multiplicative counterpart of ordinary division in modular arithmetic.

For an integer `a` and a positive modulus `m`, an integer `x` is called the modular inverse of `a` modulo `m` when

`a × x ≡ 1 (mod m)`

The inverse is commonly written as

`a⁻¹ mod m`

The central condition is:

`gcd(a, m) = 1`

A modular inverse exists if and only if `a` and `m` are relatively prime.

For example, the inverse of `3` modulo `7` is `5` because

`3 × 5 = 15`

and

`15 ≡ 1 (mod 7)`.

The Python script develops this concept from basic modular arithmetic through the Extended Euclidean Algorithm, Fermat's little theorem, Euler's theorem, modular division, linear congruences, the Chinese Remainder Theorem, combinatorics, affine ciphers, RSA-style arithmetic, and batch inversion.

## Fundamental concepts

### Modular arithmetic

The expression

`a mod m`

means the remainder obtained when `a` is divided by `m`.

For example:

`17 mod 5 = 2`

Two integers are congruent modulo `m` when they have the same remainder:

`17 ≡ 2 (mod 5)`

because both have remainder `2` after division by `5`.

Congruence can also be defined as divisibility:

`a ≡ b (mod m)`

if and only if

`m | (a - b)`.

This means that the difference between the two numbers is an integer multiple of the modulus.

### Residue classes

Modulo `m`, infinitely many integers correspond to the same residue class.

For example, modulo `5`:

`..., -8, -3, 2, 7, 12, 17, ...`

all belong to the same residue class because they are congruent to `2` modulo `5`.

The standard representatives are usually selected from:

`0, 1, 2, ..., m - 1`.

Python's remainder operation with a positive modulus provides these non-negative representatives.

## Multiplicative inverses

An ordinary multiplicative inverse of a nonzero real number `a` is `1/a`.

Modular arithmetic does not define division in exactly the same way. Instead, division by `a` is represented by multiplication by its modular inverse.

If

`a × a⁻¹ ≡ 1 (mod m)`,

then

`b / a (mod m)`

can be interpreted as

`b × a⁻¹ (mod m)`.

This only works when `a` has an inverse modulo `m`.

## The fundamental existence theorem

The most important rule in modular inversion is:

`a⁻¹ mod m exists ⇔ gcd(a, m) = 1`.

For example:

`gcd(3, 7) = 1`

so `3` has an inverse modulo `7`.

By contrast:

`gcd(6, 15) = 3`

so `6` has no inverse modulo `15`.

The reason is that if

`6x ≡ 1 (mod 15)`

then the left side is always divisible by `3`, while the right side is not. Therefore the congruence cannot hold.

## Greatest common divisor

The greatest common divisor, or GCD, of two integers is the largest positive integer that divides both.

The script implements the Euclidean Algorithm.

The central identity is:

`gcd(a, b) = gcd(b, a mod b)`.

The algorithm repeatedly replaces the larger problem with a smaller equivalent problem until the remainder becomes zero.

For example:

`gcd(48, 18)`

becomes

`gcd(18, 12)`

then

`gcd(12, 6)`

then

`gcd(6, 0)`.

Therefore:

`gcd(48, 18) = 6`.

The Euclidean Algorithm runs in logarithmic time with respect to the magnitude of its inputs and is therefore substantially more efficient than checking every possible divisor.

## Brute-force inverse

The simplest conceptual algorithm is to test every possible residue.

For a candidate `x`, check:

`(a × x) mod m = 1`.

The script implements this approach in `modular_inverse_bruteforce`.

It is useful for learning because it directly expresses the definition of an inverse.

Its major weakness is performance. In the worst case, it may inspect almost every value below the modulus.

This makes brute force inappropriate for large moduli.

## Extended Euclidean Algorithm

The Extended Euclidean Algorithm is the standard general-purpose mathematical method for finding modular inverses.

It computes integers `x` and `y` such that:

`ax + by = gcd(a, b)`.

The integers `x` and `y` are called Bézout coefficients.

Suppose:

`gcd(a, m) = 1`.

The Extended Euclidean Algorithm then produces:

`ax + my = 1`.

Taking both sides modulo `m` gives:

`ax ≡ 1 (mod m)`.

Therefore:

`x ≡ a⁻¹ (mod m)`.

This directly explains why the algorithm computes the inverse.

### Example

Consider the inverse of `3` modulo `7`.

The Extended Euclidean Algorithm produces coefficients satisfying:

`3x + 7y = 1`.

One solution is:

`3(-2) + 7(1) = 1`.

Therefore:

`x = -2`.

Modulo `7`:

`-2 ≡ 5 (mod 7)`.

Thus:

`3⁻¹ ≡ 5 (mod 7)`.

Verification:

`3 × 5 = 15`

and

`15 mod 7 = 1`.

## Python's built-in modular inverse

Modern Python provides a direct modular inverse operation:

`pow(a, -1, m)`

when the arguments satisfy the requirements for modular inversion.

For example, the script demonstrates that the inverse of `3` modulo `7` can be obtained directly.

The built-in implementation is generally preferable in production Python code when the application does not require a custom educational implementation.

The Extended Euclidean implementation remains important because it explains the underlying mathematics and is useful when implementing the operation in other environments.

## Negative values

Modular arithmetic naturally supports negative integers.

For example:

`-3 ≡ 8 (mod 11)`.

Therefore, the inverse of `-3` modulo `11` is the same residue as the inverse of `8` modulo `11`.

The script normalizes results using the modulus so that modular inverses are normally represented between `0` and `m - 1`.

The inverse of `-1` modulo `m` is:

`m - 1`.

This follows because:

`(-1)(m - 1) ≡ 1 (mod m)`.

## Important edge cases

### Zero

Zero has no multiplicative inverse.

There is no value `x` for which:

`0 × x ≡ 1 (mod m)`.

The left side is always zero.

### One

One is its own inverse:

`1⁻¹ ≡ 1 (mod m)`.

### A value divisible by the modulus

If:

`a ≡ 0 (mod m)`

then `a` is not invertible.

### Non-coprime values

A value sharing a factor with the modulus has no modular inverse.

For example:

`gcd(10, 20) = 10`.

Therefore `10` is not invertible modulo `20`.

## Uniqueness of the inverse

When an inverse exists, it is unique modulo the modulus.

If both `x` and `y` satisfy:

`ax ≡ 1 (mod m)`

and

`ay ≡ 1 (mod m)`,

then:

`ax ≡ ay (mod m)`.

Because `a` is invertible, it can be cancelled in modular arithmetic, giving:

`x ≡ y (mod m)`.

The inverse may have infinitely many integer representations, but all such representations belong to the same residue class.

## Properties of modular inverses

If `a` is invertible modulo `m`, then:

`(a⁻¹)⁻¹ ≡ a (mod m)`.

If both `a` and `b` are invertible modulo `m`, then:

`(ab)⁻¹ ≡ a⁻¹b⁻¹ (mod m)`.

If:

`a ≡ b (mod m)`

and both are invertible, then:

`a⁻¹ ≡ b⁻¹ (mod m)`.

These properties are important when simplifying modular expressions.

## Modular division

Suppose we want to solve:

`10 / 3 (mod 7)`.

Since:

`3⁻¹ ≡ 5 (mod 7)`,

we calculate:

`10 × 5 mod 7`.

Since:

`50 mod 7 = 1`,

the modular result is:

`1`.

The script implements this operation using the general formula:

`numerator × denominator⁻¹ mod modulus`.

Ordinary floating-point division must not be substituted for modular division.

## Linear congruences

A modular inverse provides a direct method for solving equations such as:

`ax ≡ b (mod m)`.

If:

`gcd(a, m) = 1`,

then:

`x ≡ a⁻¹b (mod m)`.

For example:

`7x ≡ 5 (mod 19)`.

The inverse of `7` modulo `19` is `11` because:

`7 × 11 = 77 ≡ 1 (mod 19)`.

Therefore:

`x ≡ 11 × 5 (mod 19)`.

This gives:

`x ≡ 17 (mod 19)`.

The script also handles the more general case in which `gcd(a, m)` is greater than one.

For

`ax ≡ b (mod m)`,

let:

`d = gcd(a, m)`.

A solution exists exactly when:

`d | b`.

When this condition holds, the equation can be reduced by dividing `a`, `b`, and `m` by `d`.

The reduced coefficient is then invertible modulo the reduced modulus.

## Prime modulus

When the modulus is prime, every nonzero residue has a modular inverse.

If `p` is prime and:

`1 ≤ a < p`,

then:

`gcd(a, p) = 1`.

Therefore every nonzero residue modulo `p` belongs to the multiplicative group of units modulo `p`.

This makes prime moduli especially useful in number theory, combinatorics, finite fields, and cryptography.

## Fermat's little theorem

For a prime `p` and an integer `a` not divisible by `p`:

`a^(p-1) ≡ 1 (mod p)`.

Multiplying conceptually by the inverse of `a` gives:

`a^(p-2) ≡ a⁻¹ (mod p)`.

Therefore, for prime modulus `p`:

`a⁻¹ ≡ a^(p-2) (mod p)`.

The script implements this using modular exponentiation.

For example, the inverse of `3` modulo `7` is:

`3^5 mod 7 = 5`.

### Limitation of Fermat's method

The prime-modulus condition matters.

The formula:

`a^(m-2) mod m`

is not a general modular inverse algorithm for arbitrary composite `m`.

Using it blindly for composite moduli can produce an incorrect result.

## Euler's theorem

Euler's theorem generalizes the prime-modulus result.

If:

`gcd(a, m) = 1`,

then:

`a^φ(m) ≡ 1 (mod m)`,

where `φ(m)` is Euler's totient function.

Therefore:

`a^(φ(m)-1) ≡ a⁻¹ (mod m)`.

The script implements Euler's totient function and demonstrates inverse computation using Euler's theorem.

For a prime `p`:

`φ(p) = p - 1`.

Euler's theorem therefore reduces to Fermat's little theorem.

## Euler's totient function

Euler's totient function `φ(n)` counts the integers from `1` through `n` that are relatively prime to `n`.

For a prime `p`:

`φ(p) = p - 1`.

For a prime power:

`φ(p^k) = p^k - p^(k-1)`.

For general `n` with distinct prime factors:

`φ(n) = n × ∏(1 - 1/p)`.

The script computes the totient using prime-factorization logic.

## Modular exponentiation

Modular inverses frequently appear together with modular exponentiation.

Instead of calculating a potentially enormous value such as:

`a^100000000`

and then taking the remainder, modular exponentiation repeatedly reduces intermediate values modulo the modulus.

Python's three-argument `pow` operation is designed for efficient modular exponentiation.

The script also supports negative exponents by interpreting them through modular inversion.

For an invertible `a`:

`a^(-k) mod m`

can be evaluated as:

`(a⁻¹)^k mod m`.

## Inverse tables

For a fixed modulus, the script can construct a table of all invertible residues.

For modulus `11`, every nonzero residue is invertible because `11` is prime.

For modulus `15`, only values relatively prime to `15` are invertible.

The invertible residues modulo `15` are those not divisible by `3` or `5`.

An inverse table is useful for learning the structure of the multiplicative group modulo a small modulus.

It is not an efficient strategy for large moduli because storing or calculating all inverses requires substantial work and memory.

## Multiplicative group of units

The set of invertible residue classes modulo `m` forms the multiplicative group commonly written as:

`(Z/mZ)×`.

Its elements are exactly the residue classes relatively prime to `m`.

The number of elements in this group is:

`φ(m)`.

The modular inverse is the group inverse.

This group-theoretic interpretation explains why coprimality is the defining condition for invertibility.

## Affine cipher

The script demonstrates a classical affine substitution cipher.

Encryption uses:

`E(x) = ax + b (mod 26)`.

For decryption, the multiplicative key must have an inverse modulo `26`.

Decryption uses:

`D(y) = a⁻¹(y - b) (mod 26)`.

The condition:

`gcd(a, 26) = 1`

is essential.

If `a` is not coprime with `26`, the encryption mapping is not one-to-one and cannot be uniquely reversed.

This provides a practical example of why modular inverses are required for reversible modular transformations.

## RSA and modular inverses

RSA provides one of the most important real-world relationships involving modular inverses.

For educational RSA construction:

`n = pq`

where `p` and `q` are distinct primes.

Euler's totient for this special case is:

`φ(n) = (p - 1)(q - 1)`.

A public exponent `e` is selected such that:

`gcd(e, φ(n)) = 1`.

The private exponent `d` is then defined by:

`ed ≡ 1 (mod φ(n))`.

Therefore:

`d = e⁻¹ mod φ(n)`.

The modular inverse is the mathematical mechanism connecting the public exponent and private exponent.

The Python script demonstrates this using small educational values.

The RSA implementation is deliberately not cryptographically secure. Real RSA requires large parameters, secure prime generation, padding schemes, side-channel protections, secure randomness, and carefully reviewed cryptographic implementations.

The example is intended to demonstrate the mathematical role of modular inversion rather than provide a security implementation.

## Chinese Remainder Theorem

The Chinese Remainder Theorem, or CRT, combines several modular equations into one solution.

For pairwise-coprime moduli:

`x ≡ r1 (mod m1)`

`x ≡ r2 (mod m2)`

and so on,

there is exactly one solution modulo:

`M = m1m2...mk`.

A standard construction uses:

`Mi = M / mi`.

Because `mi` and `Mi` are coprime, `Mi` has a modular inverse modulo `mi`.

The script calculates these inverses and constructs the CRT solution.

For example:

`x ≡ 2 (mod 3)`

`x ≡ 3 (mod 5)`

`x ≡ 2 (mod 7)`.

The solution returned in the range `[0, 105)` is:

`x = 23`.

The result can be verified independently against every congruence.

Modular inverses are therefore an essential component of the standard constructive form of the Chinese Remainder Theorem.

## Combinatorics modulo a prime

Modular inverses are widely used to calculate combinations modulo a prime.

The ordinary formula is:

`C(n,k) = n! / (k!(n-k)!)`.

Modulo a prime `p`, division can be replaced by multiplication by the denominator's inverse:

`C(n,k) ≡ n! × (k!(n-k)!)⁻¹ (mod p)`.

The simple implementation in the script assumes:

`n < p`.

This ensures the relevant factorials do not contain a factor of `p`, so their residues remain invertible modulo `p`.

For larger values of `n`, especially when `n ≥ p`, more sophisticated methods are required.

## Batch modular inverses

Computing many modular inverses independently can be unnecessarily expensive.

The script implements a batch inversion technique for nonzero values modulo a prime.

For values:

`a1, a2, ..., an`

it constructs prefix products and computes the inverse of the total product once.

Individual inverses can then be recovered using multiplication and prefix information.

This reduces the number of expensive inverse operations from one per element to one total inverse, with the remaining work performed using modular multiplication.

This technique is useful in algorithms where many elements must be inverted under the same modulus.

## Performance considerations

### Brute force

Brute-force inversion can require up to approximately `m` candidate checks.

Its running time is therefore proportional to the modulus in the worst case.

It is appropriate for tiny educational examples.

### Extended Euclidean Algorithm

The Euclidean Algorithm has logarithmic behavior with respect to the magnitude of its inputs.

This makes it vastly more scalable than brute force.

It also works for composite moduli as long as the value and modulus are coprime.

### Fermat's theorem

For a prime modulus, the inverse can be computed using modular exponentiation:

`a^(p-2) mod p`.

Fast exponentiation requires logarithmic numbers of multiplication steps relative to the exponent.

This is mathematically elegant and useful in prime-modulus algorithms.

### Euler's theorem

Euler-based inversion also relies on modular exponentiation but requires computing `φ(m)`.

For arbitrary large composite moduli, efficiently determining the totient can itself require knowledge of the modulus's factorization.

### Built-in Python implementation

For ordinary Python applications, `pow(a, -1, m)` is usually the simplest implementation.

The custom Extended Euclidean Algorithm remains valuable when the algorithm itself is part of the learning objective or when implementing equivalent functionality in another language.

## Security considerations

Modular inversion is a mathematical operation used by cryptographic systems, but a mathematically correct inverse function is not automatically a secure cryptographic implementation.

Cryptographic software must consider:

- Side-channel resistance
- Timing behavior
- Secure random number generation
- Key sizes
- Input validation
- Fault attacks
- Memory handling
- Constant-time requirements where applicable
- Secure key storage
- Correct cryptographic protocols
- Padding and encoding requirements

The small RSA example in the script is not suitable for protecting real information.

For cryptographic production systems, cryptographic primitives should be implemented and reviewed as part of established cryptographic libraries and protocols rather than reconstructed from a small educational implementation.

## Common mistakes

### Assuming every nonzero number has an inverse

This is true in fields such as arithmetic modulo a prime, except for zero.

It is not true for arbitrary composite moduli.

For example, `6` is nonzero modulo `15`, but:

`gcd(6,15) = 3`.

Therefore it is not invertible.

### Forgetting the coprimality condition

Before computing an inverse using the Extended Euclidean Algorithm, the key condition is:

`gcd(a,m) = 1`.

### Confusing modular inverse with reciprocal

The modular inverse of `3` modulo `7` is `5`.

It is not the real-number value `1/3`.

The inverse is defined by modular multiplication.

### Using ordinary division

Expressions involving modular division must be transformed using an inverse.

Ordinary floating-point division does not preserve modular arithmetic.

### Applying Fermat's formula to composite moduli

The expression:

`a^(m-2) mod m`

is not a universal inverse formula.

Its standard justification depends on a prime modulus.

### Forgetting normalization

The Extended Euclidean Algorithm can return a negative Bézout coefficient.

That coefficient can still represent the correct inverse, but it should normally be reduced modulo `m` to obtain the canonical representative.

### Ignoring zero

Zero has no modular inverse.

### Ignoring invalid modulus values

A modulus used for standard modular arithmetic should be positive. The script requires a modulus greater than `1` for modular inversion because modulo `1` contains only one residue class and no multiplicative identity distinct from zero.

## Implementation considerations

A robust modular inverse implementation should:

1. Validate the modulus.
2. Compute the GCD of the value and modulus.
3. Reject the input when the GCD is not `1`.
4. Use an appropriate inversion algorithm.
5. Normalize the resulting coefficient.
6. Verify the result when correctness checking is important.

The script's main `modular_inverse` function follows this structure.

The returned inverse is normalized using:

`coefficient % modulus`.

This ensures a standard result in the range:

`0 ≤ inverse < modulus`.

## Testing and verification

A modular inverse should satisfy:

`(a × inverse) % modulus == 1`.

The script repeatedly uses this property to verify results.

It also compares the custom Extended Euclidean implementation with Python's built-in modular inverse.

The unit tests cover:

- Positive values
- Negative values
- Zero
- Non-invertible values
- Known inverse pairs
- GCD correctness
- Bézout coefficients
- Fermat-based inversion
- Euler-based inversion
- Linear congruences
- Chinese Remainder Theorem
- Batch inversion
- Affine encryption and decryption
- RSA-style encryption and decryption

The randomized test generates many coprime pairs and verifies the defining inverse equation.

This is important because mathematical implementations can fail not only on ordinary examples but also on boundary and sign-related cases.

## Relationship with fields

When the modulus is prime `p`, the integers modulo `p` form a finite field.

In a field:

- Every nonzero element has a multiplicative inverse.
- Addition, subtraction, multiplication, and division by nonzero elements remain within the field.
- Every nonzero residue has exactly one inverse modulo `p`.

For a composite modulus, the corresponding modular ring generally contains nonzero elements without inverses.

For example, modulo `8`:

`2 × 4 = 8 ≡ 0 (mod 8)`.

The existence of nonzero elements whose product is zero is incompatible with field behavior.

This distinction is important in number theory, algebra, coding theory, cryptography, and algorithms.

## Real-world applications

Modular inverses appear in many areas of computing and mathematics, including:

- Public-key cryptography
- RSA key generation
- Elliptic-curve cryptography
- Finite-field arithmetic
- Digital signatures
- Error-correcting codes
- Hashing and randomized algorithms
- Combinatorial algorithms
- Competitive programming
- Chinese Remainder Theorem implementations
- Classical substitution ciphers
- Polynomial arithmetic over finite fields
- Number-theoretic algorithms
- Modular linear equations

In cryptographic systems, modular inversion is often one component of a much larger mathematical construction.

## Relationship between the main algorithms

| Method | Main requirement | General modulus | Main idea |
|---|---|---:|---|
| Brute force | Inverse must exist | Yes | Test possible residues |
| Extended Euclid | `gcd(a,m)=1` | Yes | Find Bézout coefficient |
| Fermat | Prime modulus | No | `a^(p-2) mod p` |
| Euler | `gcd(a,m)=1` | Yes | `a^(φ(m)-1) mod m` |
| Python `pow` | Valid inverse | Yes | Built-in modular inversion |

The Extended Euclidean Algorithm is the most direct general mathematical method among these approaches.

Fermat's method is particularly convenient when the modulus is prime.

Euler's theorem generalizes the exponentiation approach but may require knowledge of the totient.

Python's built-in operation is generally the most concise implementation in Python itself.

## Conceptual structure of the Python script

The script is organized progressively.

It begins with:

- Modular arithmetic
- Congruence
- GCD
- Inverse existence

It then develops:

- Brute-force inversion
- Extended Euclidean Algorithm
- Bézout coefficients
- Efficient modular inversion
- Built-in Python inversion

The middle sections apply modular inverses to:

- Negative values
- Modular division
- Linear congruences
- Prime-modulus arithmetic
- Fermat's little theorem
- Euler's theorem
- Modular exponentiation
- Inverse tables
- Affine ciphers

The advanced sections demonstrate:

- RSA-style arithmetic
- Chinese Remainder Theorem
- Batch modular inversion
- Combinatorics modulo a prime
- Algebraic inverse properties
- Performance comparisons
- Randomized correctness testing
- Unit testing

This structure connects the basic definition of an inverse to the algorithms and applications that depend on it.

## Mathematical definition to retain

The central statement is:

`a⁻¹ mod m exists if and only if gcd(a,m)=1`.

When the inverse exists:

`a × a⁻¹ ≡ 1 (mod m)`.

The Extended Euclidean Algorithm finds integers `x` and `y` satisfying:

`ax + my = gcd(a,m)`.

When the GCD is `1`:

`ax + my = 1`.

Reducing modulo `m` gives:

`ax ≡ 1 (mod m)`.

Therefore:

`x ≡ a⁻¹ (mod m)`.

This connection between Bézout's identity and modular inversion is the central algorithmic principle demonstrated throughout the script.
