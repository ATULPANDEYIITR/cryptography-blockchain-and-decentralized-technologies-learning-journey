# Extended Euclidean Algorithm

## 1. Introduction

The Extended Euclidean Algorithm is an extension of the Euclidean Algorithm for computing the greatest common divisor of two integers. While the ordinary Euclidean Algorithm determines only the greatest common divisor, the Extended Euclidean Algorithm also computes integers that satisfy Bézout's identity.

For integers `a` and `b`, it finds integers `x` and `y` such that

`ax + by = gcd(a, b)`

These additional coefficients make the algorithm important throughout number theory and computer science. They provide a direct method for computing modular multiplicative inverses, solving linear Diophantine equations, solving linear congruences, constructing generalized Chinese Remainder Theorem solutions, and understanding important mathematical operations used in public-key cryptography.

The Python script develops these ideas from basic GCD computation through practical modular-arithmetic applications.

---

## 2. Greatest Common Divisor

The greatest common divisor of two integers is the largest positive integer that divides both numbers.

For example:

`gcd(48, 18) = 6`

because the positive divisors common to both numbers include `1`, `2`, `3`, and `6`, with `6` being the largest.

Important properties include:

- `gcd(a, b) = gcd(b, a)`
- `gcd(a, b) = gcd(|a|, |b|)`
- `gcd(a, 0) = |a|`
- `gcd(0, 0)` is conventionally treated as `0` by Python's `math.gcd`

The script first introduces GCD conceptually and then implements the Euclidean Algorithm rather than relying exclusively on the standard library.

---

## 3. The Euclidean Algorithm

The Euclidean Algorithm is based on the identity

`gcd(a, b) = gcd(b, a mod b)`

when `b` is nonzero.

For example:

`48 = 18 × 2 + 12`

`18 = 12 × 1 + 6`

`12 = 6 × 2 + 0`

The last nonzero remainder is `6`, so

`gcd(48, 18) = 6`

The script implements both recursive and iterative forms.

### Recursive structure

The mathematical recurrence is:

`gcd(a, b) = gcd(b, a mod b)`

until `b = 0`.

The base case returns the absolute value of `a`.

### Iterative structure

The iterative implementation repeatedly performs the transformation

`(a, b) → (b, a mod b)`

until the second value becomes zero.

The iterative approach is particularly useful in production code because it does not consume the Python call stack for each Euclidean step.

---

## 4. Why the Euclidean Algorithm Terminates

For positive `b`, the remainder produced by division satisfies

`0 ≤ a mod b < b`

Therefore, every nonzero iteration replaces the second value with a strictly smaller nonnegative integer.

Eventually the remainder becomes zero.

The final nonzero remainder is the GCD.

This decreasing-remainder property is the fundamental termination argument for the algorithm.

---

## 5. Bézout's Identity

Bézout's Identity states that for integers `a` and `b`, there exist integers `x` and `y` such that

`ax + by = gcd(a, b)`

For example:

`48(-1) + 18(3) = 6`

Therefore `x = -1` and `y = 3` are Bézout coefficients for `48` and `18`.

The ordinary Euclidean Algorithm determines the GCD, but it does not explicitly produce these coefficients.

The Extended Euclidean Algorithm maintains additional coefficient information so that the final remainder is accompanied by a valid linear representation.

---

## 6. Extended Euclidean Algorithm

The key output is a triple

`(g, x, y)`

where

`g = gcd(a, b)`

and

`ax + by = g`

The Python script represents this result using the `ExtendedGCDResult` data class.

For example, an execution with `a = 48` and `b = 18` produces a result satisfying

`48x + 18y = 6`

The coefficients are not necessarily unique.

---

## 7. Derivation of the Coefficient Recurrence

Suppose the recursive call has established

`b x1 + (a mod b) y1 = g`

Let

`q = floor(a / b)`

Then

`a mod b = a - qb`

Substituting this into the Bézout expression gives

`b x1 + (a - qb)y1 = g`

Expanding:

`b x1 + ay1 - qby1 = g`

Grouping the coefficients of `a` and `b`:

`ay1 + b(x1 - qy1) = g`

Therefore the coefficients for the original pair are

`x = y1`

and

`y = x1 - qy1`

This recurrence is implemented directly in the recursive Extended Euclidean Algorithm.

---

## 8. Iterative Extended Euclidean Algorithm

The iterative implementation maintains three parallel pairs:

- remainder values
- coefficients associated with the first input
- coefficients associated with the second input

Initially:

`old_r = a`

`r = b`

and

`old_s = 1`

`s = 0`

and

`old_t = 0`

`t = 1`

The coefficient relationships are

`old_r = a × old_s + b × old_t`

and

`r = a × s + b × t`

At each iteration, the same quotient used by the Euclidean Algorithm is applied to the coefficient sequences.

When `r` becomes zero, `old_r` is the GCD and `old_s`, `old_t` are Bézout coefficients.

The script explicitly checks this invariant during execution.

---

## 9. The Central Invariant

The most important implementation invariant is

`old_r = a × old_s + b × old_t`

and

`r = a × s + b × t`

The update

`new_value = old_value - quotient × current_value`

preserves the fact that every remainder is an integer linear combination of the original inputs.

Since the final nonzero remainder is the GCD, its associated coefficients automatically provide Bézout's identity.

This invariant explains why the Extended Euclidean Algorithm is more powerful than the ordinary Euclidean Algorithm.

---

## 10. Negative Integers

The GCD is conventionally represented as a nonnegative integer.

For example:

`gcd(-48, 18) = 6`

and

`gcd(48, -18) = 6`

The Extended Euclidean Algorithm must still satisfy

`ax + by = g`

even when either input is negative.

The script normalizes the final GCD to be nonnegative and adjusts the coefficients when necessary.

This distinction is important because an implementation that simply returns a signed final remainder may produce a mathematically valid linear combination but an incorrectly normalized GCD.

---

## 11. Zero Inputs

The script explicitly tests:

`gcd(0, 7) = 7`

`gcd(7, 0) = 7`

and

`gcd(0, 0) = 0`

The case `(0, 0)` deserves special attention.

The equation

`0x + 0y = 0`

is true for every pair of integers `x` and `y`, so Bézout coefficients are not unique.

The GCD convention used by Python's `math.gcd` is `gcd(0, 0) = 0`.

Applications that impose a different mathematical convention should document that choice explicitly.

---

## 12. Modular Arithmetic

Two integers `a` and `b` are congruent modulo `n` when

`a ≡ b (mod n)`

which means

`n` divides `a - b`.

For example:

`29 ≡ 1 (mod 7)`

because

`29 - 1 = 28`

and `7` divides `28`.

Congruence allows arithmetic to be performed while treating values that differ by multiples of a modulus as equivalent.

The script demonstrates addition and multiplication under modular arithmetic.

---

## 13. Modular Multiplicative Inverse

A modular multiplicative inverse of `a` modulo `n` is an integer `x` satisfying

`ax ≡ 1 (mod n)`

Such an inverse exists exactly when

`gcd(a, n) = 1`

This condition follows immediately from Bézout's Identity.

If

`gcd(a, n) = 1`

then the Extended Euclidean Algorithm gives

`ax + ny = 1`

Reducing both sides modulo `n` produces

`ax ≡ 1 (mod n)`

Therefore `x` is a modular inverse.

---

## 14. Example of a Modular Inverse

Consider finding the inverse of `3` modulo `11`.

The Extended Euclidean Algorithm can produce

`3(4) + 11(-1) = 1`

Therefore

`3 × 4 ≡ 1 (mod 11)`

so

`3⁻¹ ≡ 4 (mod 11)`

The script verifies the result by evaluating

`(3 × 4) mod 11`

which equals `1`.

---

## 15. When a Modular Inverse Does Not Exist

Consider `6` modulo `15`.

Since

`gcd(6, 15) = 3`

there cannot be integers `x` and `y` satisfying

`6x + 15y = 1`

because every integer linear combination of `6` and `15` is divisible by `3`.

Therefore

`6x ≡ 1 (mod 15)`

has no solution.

The script raises a `ValueError` when an inverse is requested for a non-coprime pair.

---

## 16. Normalizing a Modular Inverse

The Extended Euclidean Algorithm may return a negative Bézout coefficient.

For example, an inverse could be represented by `-7`.

Modulo `n`, this can be normalized using

`x mod n`

Python's `%` operator provides the nonnegative representative for a positive modulus.

Thus several integer values can represent the same modular inverse, but the conventional canonical representation is usually chosen from

`0, 1, ..., n - 1`

---

## 17. Invertible Residues

A residue modulo `n` is invertible exactly when it is relatively prime to `n`.

The script constructs an inverse table by testing

`gcd(a, n) = 1`

for each residue.

For modulus `12`, the invertible residues are

`1, 5, 7, 11`

Each of these has a multiplicative inverse modulo `12`.

The number of invertible residues modulo `n` is Euler's totient function `φ(n)`.

---

## 18. Linear Diophantine Equations

A linear Diophantine equation has the form

`ax + by = c`

where `a`, `b`, `c`, `x`, and `y` are integers.

The equation has an integer solution exactly when

`gcd(a, b)` divides `c`.

Suppose

`ax0 + by0 = g`

where

`g = gcd(a, b)`

If `g` divides `c`, define

`k = c/g`

Then

`a(x0k) + b(y0k) = c`

Therefore one solution is

`x = x0(c/g)`

`y = y0(c/g)`

The script implements this construction.

---

## 19. General Solution of a Linear Diophantine Equation

If `(x0, y0)` is one solution to

`ax + by = c`

and

`g = gcd(a, b)`

then every integer solution has the form

`x = x0 + k(b/g)`

`y = y0 - k(a/g)`

for any integer `k`.

The script generates multiple solutions using this parameterization and verifies each one.

This follows because the changes in the left side cancel:

`a(b/g) + b(-a/g) = 0`

---

## 20. Linear Congruences

The script also solves equations of the form

`ax ≡ b (mod n)`

Let

`g = gcd(a, n)`

A solution exists exactly when

`g | b`.

If this condition is satisfied, divide the congruence by `g`:

`(a/g)x ≡ b/g (mod n/g)`

Now

`gcd(a/g, n/g) = 1`

so `(a/g)` has a modular inverse.

The reduced equation can therefore be solved using the Extended Euclidean Algorithm.

There are exactly `g` distinct solutions modulo `n` when a solution exists.

---

## 21. Difference Between Diophantine Equations and Congruences

The equation

`ax + by = c`

asks for exact equality over integers.

The congruence

`ax ≡ b (mod n)`

asks whether the difference

`ax - b`

is divisible by `n`.

These problems are closely related but are not interchangeable.

The Extended Euclidean Algorithm provides the underlying GCD and Bézout information needed for both.

---

## 22. Chinese Remainder Theorem

The Chinese Remainder Theorem concerns systems such as

`x ≡ a1 (mod n1)`

`x ≡ a2 (mod n2)`

When the moduli are pairwise coprime, a solution exists and is unique modulo their product.

The script implements a generalized version that also handles compatible non-coprime moduli.

For two congruences, the combination can be written as

`x = x0 + M k`

where the first congruence has already been represented by `x0 mod M`.

The second congruence then becomes a linear congruence in `k`.

The Extended Euclidean Algorithm is used to determine whether the necessary inverse exists and to calculate it.

---

## 23. Compatible and Incompatible Non-Coprime CRT Systems

Non-coprime moduli do not automatically make a CRT system invalid.

For example,

`x ≡ 2 (mod 6)`

and

`x ≡ 5 (mod 9)`

are compatible because the difference between the remainders is divisible by

`gcd(6, 9) = 3`.

By contrast,

`x ≡ 1 (mod 4)`

and

`x ≡ 2 (mod 6)`

are incompatible because

`1 - 2 = -1`

is not divisible by

`gcd(4, 6) = 2`.

The script explicitly demonstrates both cases.

---

## 24. RSA Connection

The Extended Euclidean Algorithm has a fundamental role in RSA mathematics.

For RSA-style parameters:

`n = pq`

and

`φ(n) = (p - 1)(q - 1)`

A public exponent `e` must satisfy

`gcd(e, φ(n)) = 1`

The private exponent `d` is defined by

`ed ≡ 1 (mod φ(n))`

Therefore `d` is the modular inverse of `e` modulo `φ(n)`.

The script computes this inverse using the Extended Euclidean Algorithm.

For educational parameters such as

`p = 61`

`q = 53`

and

`e = 17`

the script calculates the corresponding `n`, Euler totient, and private exponent and verifies the modular relationship.

The RSA section is mathematical and educational. Production cryptographic systems require carefully implemented cryptographic libraries, secure key generation, appropriate padding schemes, side-channel protections, and other security controls.

---

## 25. Modular Exponentiation in the RSA Example

The script uses Python's three-argument `pow` function to demonstrate

`c = m^e mod n`

and

`m = c^d mod n`

The three-argument form performs modular exponentiation efficiently without constructing the complete enormous integer `m^e`.

The Extended Euclidean Algorithm is responsible for finding the modular inverse used to derive `d`; modular exponentiation itself is a separate operation.

---

## 26. GCD and Fraction Reduction

The script includes a small immutable `Fraction` implementation to demonstrate another practical role of GCD.

A fraction such as

`12/18`

can be reduced using

`gcd(12, 18) = 6`

giving

`2/3`.

The denominator is normalized to be positive, and both numerator and denominator are divided by their common divisor.

This example illustrates how GCD appears in ordinary arithmetic data structures even when Extended GCD is not directly required.

---

## 27. Multiple Bézout Coefficient Pairs

Bézout coefficients are generally not unique.

If

`ax0 + by0 = g`

then every pair

`x = x0 + k(b/g)`

`y = y0 - k(a/g)`

also satisfies

`ax + by = g`.

Thus the Extended Euclidean Algorithm returns one valid pair, not necessarily a unique pair.

This distinction is important when interpreting the output.

---

## 28. GCD of More Than Two Integers

The two-number Extended Euclidean Algorithm can be applied repeatedly to a list.

For numbers

`a1, a2, ..., an`

one can compute

`gcd(a1, a2)`

then combine that result with `a3`, and so forth.

The script extends this idea to construct coefficients satisfying

`c1a1 + c2a2 + ... + cnan = gcd(a1, ..., an)`

This demonstrates that Bézout-style linear combinations are not restricted to exactly two integers.

---

## 29. Performance

The Euclidean Algorithm has logarithmic complexity with respect to the magnitude of its inputs.

More precisely, the number of divisions is `O(log(min(|a|, |b|)))` in the standard bit-operation-independent iteration analysis.

The actual cost for very large integers also depends on the cost of integer arithmetic itself.

Consecutive Fibonacci numbers provide a classic near-worst-case example for the number of Euclidean divisions. The script generates Fibonacci pairs and counts their Euclidean steps.

This does not mean every large pair is slow. The quotient sequence strongly affects the number of iterations.

---

## 30. Recursion Versus Iteration

The recursive implementation mirrors the mathematical recurrence closely and is useful for understanding the algorithm.

Advantages of recursion:

- Direct correspondence with the mathematical definition
- Concise implementation
- Easy conceptual derivation

Disadvantages:

- Consumes call-stack frames
- Can encounter recursion-depth limitations in general recursive algorithms
- Less convenient for some production environments

The iterative implementation avoids these concerns and is normally preferable when building a reusable low-level arithmetic function.

For Python specifically, arbitrary recursion depth is limited, although the Euclidean Algorithm itself normally requires only logarithmically many iterations.

---

## 31. Arbitrary-Precision Integers

Python integers have arbitrary precision.

Consequently, the Extended Euclidean Algorithm can operate on integers far beyond the range of typical fixed-width 32-bit or 64-bit integers without ordinary machine-integer overflow.

The limitation becomes computational cost rather than fixed-width overflow.

For very large integers, multiplication, division, modulo, and other operations become more expensive as the number of bits increases.

The script includes a large-integer example to demonstrate this behavior.

---

## 32. Security Considerations

The Extended Euclidean Algorithm is mathematically deterministic, but its use inside cryptographic systems requires security-aware implementation.

Important considerations include:

- Avoid implementing production cryptographic protocols from scratch.
- Use established cryptographic libraries for real cryptographic operations.
- Consider timing and other side-channel behavior in security-sensitive arithmetic.
- Protect private keys and intermediate secrets.
- Use secure random number generation for cryptographic key material.
- Use modern RSA padding and protocol standards rather than textbook RSA.
- Validate key parameters carefully.
- Avoid treating educational small-prime examples as secure cryptographic keys.

The script's RSA section is intended to demonstrate mathematical dependence on modular inverses, not to provide a production cryptosystem.

---

## 33. Common Implementation Mistakes

### Assuming every number has a modular inverse

An inverse exists only when the number and modulus are coprime.

Incorrect assumption:

`a⁻¹ exists for every a`

Correct condition:

`gcd(a, n) = 1`

### Forgetting normalization

A Bézout coefficient may be negative. When an inverse is needed in the conventional residue range, normalize it with the modulus.

### Mishandling negative inputs

The GCD should normally be returned as nonnegative even when inputs are negative.

### Dividing a congruence incorrectly

For

`ax ≡ b (mod n)`

division is not automatically valid. The common divisor must be handled carefully.

### Assuming non-coprime CRT moduli always fail

Non-coprime systems can be solvable when their remainders satisfy the necessary compatibility condition.

### Confusing GCD output with Bézout coefficients

The ordinary Euclidean Algorithm returns the GCD. The Extended Euclidean Algorithm additionally returns coefficients.

---

## 34. Validation and Testing

The script includes several layers of verification.

### Direct identity checks

Every Extended GCD result is checked using

`ax + by == gcd(a, b)`

### GCD comparison

The custom implementation is compared against Python's `math.gcd`.

### Modular inverse verification

Every inverse is checked using

`a × inverse mod n == 1`

### Diophantine verification

Generated solutions are substituted back into

`ax + by = c`

### Congruence verification

Every returned solution is checked against the original congruence.

### CRT verification

The final CRT result is checked against every original congruence.

### Randomized testing

The script generates many random integer pairs and verifies both the GCD and Bézout identity.

This is particularly useful for detecting errors involving negative values, zeros, coefficient updates, and quotient handling.

---

## 35. Python Implementation Considerations

The script uses only the Python standard library.

Important implementation components include:

- `math.gcd` for reference validation
- `divmod` for quotient and remainder calculation
- `pow(value, exponent, modulus)` for efficient modular exponentiation
- `dataclasses.dataclass` for a structured Extended GCD result
- `typing` annotations for clearer interfaces
- `assert` statements for mathematical invariants and regression tests
- `random.Random` with a fixed seed for reproducible randomized testing

The custom Extended GCD implementation remains independent of `math.gcd` so that its internal coefficient computation can be studied directly.

---

## 36. Relationship Between the Main Algorithms

The major concepts in the script form a chain:

`Euclidean Algorithm`

leads to

`GCD`

and the Extended version adds

`Bézout coefficients`

which provide

`modular inverses`

which enable

`modular division`

and help solve

`linear congruences`

which can be combined to solve

`Chinese Remainder Theorem systems`.

The same modular inverse operation is used in the mathematical construction of an RSA private exponent.

This relationship is the central reason the Extended Euclidean Algorithm is an important foundational algorithm in computational number theory.

---

## 37. Euclidean Algorithm Versus Extended Euclidean Algorithm

| Feature | Euclidean Algorithm | Extended Euclidean Algorithm |
|---|---|---|
| Computes GCD | Yes | Yes |
| Computes Bézout coefficients | No | Yes |
| Solves `ax + by = c` | Indirectly | Directly |
| Computes modular inverse | No | Yes |
| Helps solve linear congruences | Indirectly | Directly |
| Supports CRT construction | Indirectly | Directly useful |
| Used in RSA inverse calculation | No direct coefficient output | Yes |
| Complexity class | Logarithmic iterations | Logarithmic iterations |

The Extended Euclidean Algorithm preserves the efficiency of the Euclidean Algorithm while producing additional information.

---

## 38. Built-in Operations Versus Educational Implementations

Python provides optimized arithmetic functionality such as `math.gcd`.

Python versions that support modular inversion through the three-argument `pow` interface can also calculate inverses conveniently.

The custom implementations in the script serve a different purpose: they expose the mathematical mechanics.

For production software, a standard-library or established-library implementation is usually preferable when it provides the required semantics and performance.

For algorithm study, implementing the algorithm directly is valuable because it exposes:

- quotient calculation
- remainder reduction
- coefficient propagation
- Bézout invariants
- termination behavior
- edge cases

---

## 39. Important Mathematical Conditions

Several conditions recur throughout the applications.

### GCD

`gcd(a, b)` is the largest positive common divisor.

### Bézout Identity

`ax + by = gcd(a, b)`

always has integer solutions for integers `a` and `b`.

### Modular inverse

`a⁻¹ mod n` exists exactly when

`gcd(a, n) = 1`.

### Linear Diophantine equation

`ax + by = c` has an integer solution exactly when

`gcd(a, b) | c`.

### Linear congruence

`ax ≡ b mod n` has a solution exactly when

`gcd(a, n) | b`.

### Generalized CRT

Two congruences with moduli `m` and `n` are compatible when the difference of their remainders is divisible by

`gcd(m, n)`.

These conditions provide a practical decision framework before applying the relevant algorithm.

---

## 40. End-to-End Example

The script concludes with a complete modular equation:

`37x ≡ 12 (mod 101)`

The procedure is:

1. Compute `gcd(37, 101)`.
2. Confirm that the GCD is `1`.
3. Use Extended GCD to obtain the inverse of `37` modulo `101`.
4. Multiply the inverse by `12`.
5. Reduce the result modulo `101`.
6. Substitute the result back into the original congruence.

The example demonstrates the full path from GCD computation to modular equation solving.

---

## 41. Edge Cases Covered by the Script

The implementation explicitly exercises:

- both inputs positive
- one input zero
- both inputs zero
- negative first input
- negative second input
- both inputs negative
- equal inputs
- coprime inputs
- non-coprime inputs
- modulus equal to one
- modular inverses that have negative raw coefficients
- equations with no Diophantine solution
- congruences with no solution
- compatible non-coprime CRT systems
- incompatible CRT systems
- very large Python integers

These cases are important because number-theoretic algorithms often appear simple under positive inputs but require careful handling at boundaries.

---

## 42. Design Principles Demonstrated

The Python implementation follows several useful algorithm-design principles:

1. Separate mathematical primitives from applications.
2. Keep GCD computation independent from modular inverse computation.
3. Validate mathematical invariants explicitly.
4. Normalize values where a canonical representation is useful.
5. Raise meaningful exceptions for invalid operations.
6. Keep recursive and iterative implementations distinct.
7. Reuse the Extended GCD primitive rather than duplicating its mathematics.
8. Verify application-level results against their original equations.
9. Use standard-library implementations as reference points when available.
10. Distinguish educational implementations from production cryptographic software.

These principles make mathematical code easier to test and reason about.

---

## 43. Practical Applications

The Extended Euclidean Algorithm is relevant to:

- modular inverse computation
- modular division
- linear Diophantine equations
- linear congruences
- Chinese Remainder Theorem computations
- RSA key mathematics
- computational number theory
- fraction reduction through GCD
- cryptographic arithmetic
- algorithmic programming
- symbolic integer computations
- solving integer constraint systems

Its importance comes less from the size of the algorithm itself and more from how many other operations can be reduced to GCD and Bézout computations.

---

## 44. Limitations

The algorithm computes integer GCDs and associated integer linear combinations. It is not itself a general-purpose solver for arbitrary algebraic equations.

A modular inverse does not exist for every pair of integers.

A linear congruence may have no solution.

A CRT system may be incompatible.

Large integer inputs are supported by Python's arbitrary-precision arithmetic, but very large operands still require computational resources.

The algorithm also does not automatically address cryptographic implementation concerns such as secure key storage, side-channel resistance, secure random generation, or protocol-level security.

---

## 45. Script Organization

The Python script is organized in increasing conceptual complexity:

1. GCD fundamentals
2. Euclidean Algorithm
3. Bézout's Identity
4. Recursive Extended GCD
5. Iterative Extended GCD
6. Algorithmic invariants
7. Modular arithmetic
8. Modular inverses
9. Invertible residues
10. Diophantine equations
11. Linear congruences
12. Chinese Remainder Theorem
13. RSA mathematical connection
14. Fraction reduction
15. Edge cases
16. Performance
17. Mathematical property verification
18. Randomized testing
19. Multiple Bézout representations
20. Modular division
21. Multi-integer Bézout combinations
22. Common implementation mistakes
23. Large integer behavior
24. Algorithm comparison
25. End-to-end modular equation solving

Each major concept is demonstrated through executable Python rather than being presented solely as theoretical text.
