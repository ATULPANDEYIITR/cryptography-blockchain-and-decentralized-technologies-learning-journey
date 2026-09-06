# Euclidean Algorithm

## Topic Introduction

The Euclidean algorithm is a fundamental algorithm for computing the greatest common divisor, or GCD, of two integers. The GCD of two integers is the largest positive integer that divides both numbers without leaving a remainder.

The algorithm is one of the oldest known efficient algorithms. Its importance extends far beyond calculating GCDs. The same mathematical ideas support the extended Euclidean algorithm, Bézout's identity, modular multiplicative inverses, linear Diophantine equations, fraction reduction, modular arithmetic, continued fractions, and important parts of public-key cryptography.

The accompanying Python script develops the subject progressively. It begins with integer division and the definition of the GCD, then implements the Euclidean algorithm iteratively and recursively. It proceeds to edge cases, multiple-number GCDs, LCM calculation, correctness, termination, the extended Euclidean algorithm, modular inverses, Diophantine equations, continued fractions, modular arithmetic, testing, and practical number-theoretic applications.

---

## Fundamental Terminology

### Divisibility

An integer `d` divides an integer `a` if there exists an integer `k` such that:

`a = dk`

This is written mathematically as:

`d | a`

For example:

`6 | 42`

because:

`42 = 6 × 7`

If no integer `k` satisfies the equation, then `d` does not divide `a`.

### Divisor

A divisor of an integer is a number that divides it exactly.

The positive divisors of 12 are:

`1, 2, 3, 4, 6, 12`

### Remainder

When an integer is divided by another nonzero integer, the division algorithm gives:

`a = bq + r`

where:

- `a` is the dividend
- `b` is the divisor
- `q` is the quotient
- `r` is the remainder
- `0 <= r < |b|`

Python's `divmod(a, b)` returns the quotient and remainder together.

### Greatest Common Divisor

The GCD of integers `a` and `b`, written as `gcd(a, b)`, is the greatest positive integer that divides both.

For example:

`gcd(252, 105) = 21`

because 21 divides both numbers and no larger positive integer does.

---

## The Key Euclidean Identity

The entire algorithm depends on the identity:

`gcd(a, b) = gcd(b, a mod b)`

Suppose:

`a = bq + r`

Every common divisor of `a` and `b` also divides:

`a - bq = r`

Therefore, the common divisors of `a` and `b` are exactly the common divisors of `b` and `r`.

This allows a large GCD problem to be transformed into a smaller one without changing its answer.

For example:

`1071 = 462 × 2 + 147`

Therefore:

`gcd(1071, 462) = gcd(462, 147)`

The process continues:

`462 = 147 × 3 + 21`

and:

`147 = 21 × 7 + 0`

The last nonzero remainder is 21, so:

`gcd(1071, 462) = 21`

---

## Classical Euclidean Algorithm

The iterative form repeatedly replaces the pair `(a, b)` with `(b, a mod b)`.

Conceptually:

1. Start with two integers.
2. Compute the remainder of the first divided by the second.
3. Replace the first number with the second.
4. Replace the second number with the remainder.
5. Continue until the second number becomes zero.
6. The first number is the GCD.

The Python implementation follows this structure:

    while b != 0:
        a, b = b, a % b

    return a

The use of `abs()` makes the returned GCD nonnegative for negative inputs.

---

## Recursive Form

The same mathematical recurrence can be expressed recursively:

`gcd(a, b) = gcd(b, a mod b)`

with the base case:

`gcd(a, 0) = |a|`

The recursive implementation therefore follows the mathematical definition closely.

Recursion is elegant and useful for demonstrating the recurrence, while iteration avoids recursive-call overhead and avoids recursion-depth concerns in general-purpose implementations.

---

## Correctness

The correctness of the Euclidean algorithm follows from the common-divisor argument.

If:

`a = bq + r`

then any common divisor of `a` and `b` divides `r`.

Conversely, any common divisor of `b` and `r` divides:

`bq + r = a`

Therefore, the common divisors are identical, which means their greatest common divisor is identical.

The algorithm does not merely produce a plausible result. Every transformation preserves the GCD.

---

## Termination

At every step, the remainder satisfies:

`0 <= r < |b|`

Therefore, the sequence of nonnegative remainders strictly decreases whenever the algorithm continues.

A strictly decreasing sequence of nonnegative integers cannot continue indefinitely.

Eventually the remainder becomes zero.

The algorithm then stops, and the previous nonzero divisor is the GCD.

---

## Edge Cases

### One argument is zero

For a nonzero integer `a`:

`gcd(a, 0) = |a|`

Therefore:

`gcd(15, 0) = 15`

and:

`gcd(0, 15) = 15`

### Both arguments are zero

`gcd(0, 0)` does not have a uniquely defined greatest positive common divisor.

The custom educational implementation returns zero because the loop naturally terminates at zero, while the script explicitly explains that the mathematical pair `(0, 0)` is conventionally treated as undefined.

Python's `math.gcd(0, 0)` returns zero as a programming convention.

### Negative integers

The standard mathematical GCD is nonnegative. Therefore:

`gcd(-48, 18) = 6`

and:

`gcd(-48, -18) = 6`

The script normalizes inputs using absolute values.

---

## GCD of Multiple Integers

The GCD operation can be applied repeatedly:

`gcd(a, b, c) = gcd(gcd(a, b), c)`

This works because GCD is associative.

For example:

`gcd(84, 126, 210)`

can be computed as:

`gcd(gcd(84, 126), 210)`

The script implements this behavior through `gcd_many()`.

An important optimization is early termination. Once the intermediate GCD becomes 1, the GCD of all remaining numbers must also be 1.

---

## Coprime Integers

Two integers are coprime if their GCD is 1.

For example:

`gcd(8, 15) = 1`

so 8 and 15 are coprime.

Coprimality is particularly important in modular arithmetic. A modular multiplicative inverse exists exactly when the number and the modulus are coprime.

---

## Least Common Multiple

The GCD provides an efficient way to compute the LCM.

For nonzero integers:

`lcm(a, b) = |ab| / gcd(a, b)`

A practical implementation should avoid multiplying before dividing when possible.

The script therefore uses:

`abs((a // gcd(a, b)) * b)`

This reduces unnecessary intermediate integer growth.

If either input is zero:

`lcm(a, 0) = 0`

The script also implements LCM for multiple integers by repeatedly applying the two-number operation.

---

## Important GCD Identities

Several identities are useful both theoretically and computationally.

### Symmetry

`gcd(a, b) = gcd(b, a)`

### Remainder identity

`gcd(a, b) = gcd(b, a mod b)`

### Linear transformation

For any integer `k`:

`gcd(a, b) = gcd(a, b + ka)`

### Scaling

For an integer `k`:

`gcd(ka, kb) = |k| gcd(a, b)`

### GCD and LCM

For nonzero integers:

`gcd(a, b) × lcm(a, b) = |ab|`

These identities are demonstrated directly by executable assertions and examples in the script.

---

## Extended Euclidean Algorithm

The ordinary Euclidean algorithm calculates:

`gcd(a, b)`

The extended Euclidean algorithm additionally calculates integers `x` and `y` satisfying:

`ax + by = gcd(a, b)`

This equation is known as Bézout's identity.

For example, if:

`gcd(240, 46) = 2`

the extended algorithm produces coefficients such that:

`240x + 46y = 2`

The coefficients are obtained by propagating information through the same quotient sequence used by Euclid's algorithm.

The script represents the result with an `ExtendedGCDResult` data class containing:

- `gcd`
- `x`
- `y`

This makes the result explicit and easy to verify.

---

## Bézout's Identity

Bézout's identity states that for integers `a` and `b`, there exist integers `x` and `y` such that:

`ax + by = gcd(a, b)`

This is stronger than simply knowing the GCD.

If:

`gcd(a, b) = 1`

then:

`ax + by = 1`

Such a relationship is central to modular inverses and several results in elementary number theory.

---

## Modular Multiplicative Inverse

A number `x` is a modular inverse of `a` modulo `m` if:

`ax ≡ 1 (mod m)`

Equivalently:

`ax = 1 + km`

for some integer `k`.

Rearranging gives:

`ax - km = 1`

This is a Bézout equation.

Therefore, a modular inverse exists precisely when:

`gcd(a, m) = 1`

The extended Euclidean algorithm provides the coefficient `x`.

For example, the inverse of 17 modulo 3120 exists because:

`gcd(17, 3120) = 1`

The returned coefficient can be reduced modulo 3120 to obtain the standard representative of the inverse.

If the GCD is greater than 1, the script raises an error because an inverse does not exist.

---

## Linear Diophantine Equations

A linear Diophantine equation has the form:

`ax + by = c`

where the desired values of `x` and `y` are integers.

A fundamental solvability condition is:

`gcd(a, b) | c`

In other words, the GCD of the coefficients must divide the right-hand side.

If:

`gcd(a, b) = g`

and the extended Euclidean algorithm gives:

`ax0 + by0 = g`

then multiplying both sides by `c/g` produces:

`a(x0c/g) + b(y0c/g) = c`

This gives one integer solution.

---

## General Diophantine Solution

If `(x0, y0)` is one solution of:

`ax + by = c`

and:

`g = gcd(a, b)`

then all integer solutions can be written as:

`x = x0 + k(b/g)`

`y = y0 - k(a/g)`

where `k` is any integer.

The script generates several values of `k` and verifies that every resulting pair satisfies the original equation.

---

## Linear Congruences

A linear congruence has the form:

`ax ≡ b (mod m)`

A solution exists if and only if:

`gcd(a, m) | b`

This condition follows from the fact that the congruence can be rewritten as a Diophantine equation:

`ax - my = b`

The Euclidean algorithm therefore provides the fundamental solvability test.

---

## Fraction Reduction

A fraction can be reduced using the GCD of its numerator and denominator.

For:

`150/210`

the GCD is:

`gcd(150, 210) = 30`

Dividing both terms by 30 gives:

`5/7`

The script also handles a negative denominator by moving the sign to the numerator, producing a normalized representation.

A zero denominator is rejected because it does not represent a valid fraction.

---

## GCD of Polynomial Coefficients

For an integer polynomial such as:

`12x³ + 18x² + 30x`

the GCD of its coefficients is:

`gcd(12, 18, 30) = 6`

The number 6 is the integer content of the coefficient list.

This illustrates that the Euclidean GCD technique can be applied to structured collections of integers, not only isolated pairs.

---

## Continued Fractions

The Euclidean algorithm and simple continued fractions are closely connected.

When applying Euclid's algorithm to a rational number:

`a/b`

the successive quotient values form the coefficients of its simple continued fraction.

For example, the quotient sequence obtained while reducing `415/93` is also its continued-fraction coefficient sequence.

This connection is mathematically significant because continued fractions provide unusually good rational approximations and appear in number theory, approximation theory, and algorithmic mathematics.

---

## Fibonacci Numbers and Worst-Case Behavior

Consecutive Fibonacci numbers produce particularly long Euclidean division sequences relative to the size of their inputs.

For consecutive Fibonacci numbers:

`F(n+1)` and `F(n)`

the Euclidean algorithm repeatedly reduces the pair through the Fibonacci sequence.

Because Fibonacci numbers grow exponentially with their index, the number of Euclidean iterations is logarithmic in the numerical magnitude of the inputs.

This gives an important intuition for the efficiency of the algorithm.

---

## Complexity

For integers `a` and `b`, the classical Euclidean algorithm performs a logarithmic number of division steps relative to the magnitude of the inputs.

A common high-level characterization is:

`O(log(min(|a|, |b|)))`

division steps.

For fixed-width machine integers, this is extremely efficient.

For arbitrary-precision integers, the cost of arithmetic operations themselves also matters. Large-integer division is not a constant-time operation, so a more detailed bit-complexity analysis considers the number of bits and the complexity of large-number arithmetic.

The Python implementation benefits from Python's arbitrary-precision integer representation, but extremely large integers still require more computational resources.

---

## Brute Force Versus Euclid

A definition-based approach can check every possible candidate divisor up to the smaller input.

That approach is easy to understand but can require a number of checks proportional to the magnitude of the smaller number.

The Euclidean algorithm instead repeatedly reduces the problem through remainders.

The practical difference becomes enormous as the input values grow.

The script includes a timing comparison to make this distinction observable.

Timing results are hardware- and interpreter-dependent and should not be treated as universal benchmarks.

---

## Recursive Versus Iterative Implementation

### Recursive implementation

Advantages:

- Closely matches the mathematical recurrence.
- Concise.
- Easy to relate to the proof.

Disadvantages:

- Creates function-call overhead.
- Depends on recursion depth.
- Less suitable when a simple loop is sufficient.

### Iterative implementation

Advantages:

- No recursion-depth issue.
- Low overhead.
- Direct control over the algorithm's state.
- Well suited to production code.

For a basic GCD implementation, iteration is generally the more practical choice.

---

## Python's `math.gcd`

Python's standard library provides `math.gcd`.

The script compares the custom Euclidean implementation with `math.gcd` across positive, negative, and zero inputs.

For production Python programs, the standard-library implementation should normally be preferred unless the purpose is educational or a specialized algorithm is required.

A custom implementation is valuable for understanding the mathematics, testing, and algorithmic study.

---

## Input Validation

Mathematical functions often assume integer inputs.

The script includes `validate_integer()` to reject inappropriate values.

Python's `bool` type is a subclass of `int`, meaning:

`isinstance(True, int)`

is true.

This can produce surprising behavior if boolean values are silently accepted by a mathematical API.

The validation function explicitly rejects booleans.

---

## Common Implementation Mistakes

### Forgetting normalization

A GCD should conventionally be nonnegative.

Failing to normalize negative inputs can produce inconsistent behavior.

### Mishandling zero

The base case:

`gcd(a, 0) = |a|`

must be handled correctly.

### Treating `(0, 0)` as an ordinary GCD

The mathematical interpretation differs from the programming convention used by Python's `math.gcd`.

### Dividing by zero

The algorithm must stop when the second value is zero rather than attempting another remainder operation.

### Implementing LCM carelessly

Directly computing:

`abs(a * b) // gcd(a, b)`

can create a larger intermediate product than necessary.

### Assuming a modular inverse always exists

An inverse modulo `m` exists only if:

`gcd(a, m) = 1`

### Ignoring denominator validation

Fraction utilities must reject a zero denominator.

### Using recursion unnecessarily

A recursive GCD is mathematically elegant, but iteration is generally simpler for production code.

---

## Testing Strategy

The script uses several forms of testing.

### Deterministic tests

Known input-output pairs verify ordinary and edge-case behavior.

Examples include:

- positive inputs
- reversed inputs
- negative inputs
- zero inputs
- coprime numbers
- known GCD values

### Identity tests

The script verifies mathematical identities such as:

`gcd(a, b) = gcd(b, a)`

and:

`gcd(a, b) = gcd(a, b + ka)`

### Cross-checking

The custom implementation is compared against Python's `math.gcd`.

### Randomized property testing

Random integer pairs are generated and tested against mathematical properties.

Property testing is particularly useful for algorithms whose correctness can be described through invariants rather than a small collection of expected outputs.

---

## Large Integers

Python integers support arbitrary precision.

The Euclidean algorithm can therefore operate on integers much larger than standard 32-bit or 64-bit machine integers without integer overflow in ordinary Python integer arithmetic.

This does not mean large integers are free to process. Memory consumption and arithmetic cost increase as the number of bits increases.

The algorithm remains attractive because its number of remainder steps grows slowly relative to the numerical size of the inputs.

---

## Euclidean Algorithm in Cryptography

The Euclidean algorithm is an important mathematical component of public-key cryptography.

A simplified RSA key-generation process requires selecting an exponent `e` such that:

`gcd(e, φ(n)) = 1`

The private exponent is then the modular inverse of `e` modulo `φ(n)`:

`ed ≡ 1 (mod φ(n))`

The extended Euclidean algorithm can calculate that inverse.

The script includes a small RSA mathematical demonstration using small parameters purely to illustrate the number-theoretic relationships.

The demonstration is not a secure cryptographic implementation. Real cryptographic systems require carefully designed algorithms, large parameters, secure randomness, side-channel considerations, standardized padding, and established cryptographic libraries.

---

## Security Considerations

The Euclidean algorithm itself is a mathematical algorithm and does not inherently provide security.

When used as part of cryptographic software, implementation details matter.

Potential considerations include:

- side-channel leakage
- timing behavior
- secret-dependent branches
- secure handling of private values
- parameter validation
- use of standardized cryptographic primitives
- avoidance of toy-size cryptographic parameters

A mathematically correct GCD implementation should not automatically be considered a secure cryptographic implementation.

For ordinary non-secret numerical computation, the classical algorithm is usually sufficient.

---

## Production Considerations

For production Python applications:

- Prefer `math.gcd` for ordinary GCD operations.
- Validate input types when an API requires strict integer semantics.
- Define the expected behavior for zero and negative values.
- Avoid unnecessary recursion.
- Use arbitrary-precision integers when required by the application.
- Avoid reimplementing cryptographic primitives unless there is a compelling, expert-level reason.
- Use established cryptographic libraries for real cryptographic systems.
- Test edge cases explicitly.
- Use property-based testing when mathematical invariants are available.
- Keep mathematical utility functions small and deterministic.

---

## Performance Considerations

The dominant operation in the classical algorithm is integer remainder or division.

The number of iterations is logarithmic in the magnitude of the smaller input.

Performance can nevertheless depend on:

- number of bits in the operands
- cost of arbitrary-precision division
- interpreter overhead
- recursion overhead
- memory allocation
- implementation details of the integer arithmetic library

For ordinary Python integers, `math.gcd` is preferable when performance matters because it is implemented as optimized standard-library functionality.

The custom implementation in the script is designed primarily for transparency and learning.

---

## Design Considerations

A good GCD utility should have a clear contract.

Important questions include:

- Are negative integers accepted?
- Is zero accepted?
- What happens for `(0, 0)`?
- Are booleans considered valid integers?
- Should invalid types raise `TypeError`?
- Should a collection-based function reject an empty collection?
- Should the implementation expose intermediate Euclidean steps?
- Is the function intended for education, production numerical work, or cryptographic use?

Separating the simple GCD operation from extended-GCD functionality makes APIs easier to understand.

The script uses separate functions for:

- ordinary GCD
- extended GCD
- modular inverse
- Diophantine equations
- LCM
- multi-number GCD
- fraction reduction
- testing

This reflects the mathematical relationships while keeping individual operations focused.

---

## Relationship Between the Main Concepts

The major concepts form a connected chain:

`Integer Division`
  
leads to:

`Remainders`

which lead to:

`Euclidean Algorithm`

which computes:

`GCD`

The extended version computes:

`Bézout Coefficients`

which enable:

`Modular Inverses`

and help solve:

`Linear Diophantine Equations`

The GCD also supports:

`LCM`

`Coprimality`

`Fraction Reduction`

`Linear Congruence Solvability`

and mathematical components of:

`RSA`

The quotient sequence connects the Euclidean algorithm with:

`Continued Fractions`

This network of relationships is one reason the Euclidean algorithm is foundational in computational number theory.

---

## Executable Examples Covered by the Script

The Python file contains complete implementations and demonstrations for:

- division with quotient and remainder
- definition-based GCD
- iterative Euclidean GCD
- recursive Euclidean GCD
- explicit Euclidean division steps
- negative and zero inputs
- GCD of multiple integers
- coprimality
- LCM
- GCD correctness invariants
- termination behavior
- extended Euclidean algorithm
- Bézout coefficients
- modular multiplicative inverses
- linear Diophantine equations
- complete Diophantine solution families
- fraction reduction
- coefficient GCD
- continued fractions
- linear congruence solvability
- RSA-related number theory
- modular exponentiation
- Fibonacci complexity behavior
- brute-force and Euclidean performance comparison
- randomized property testing
- input validation
- deterministic unit tests
- arbitrary-precision integers
- integer-list normalization
- Euclidean step counting
- comparison with `math.gcd`
- combined number-theory workflows
- GCD-LCM identities
- Euclid's lemma context

---

## Important Mathematical Distinctions

### GCD versus LCM

The GCD identifies the largest shared divisor.

The LCM identifies the smallest positive common multiple.

### GCD versus extended GCD

The ordinary Euclidean algorithm returns only the GCD.

The extended algorithm additionally returns coefficients satisfying Bézout's identity.

### Coprime versus prime

Two numbers are coprime when their GCD is 1.

A prime number is an integer greater than 1 with exactly two positive divisors.

A composite number can be coprime with another composite number.

For example:

`8` and `15` are both composite but are coprime.

### Modular inverse versus division

Ordinary division is not the same as modular inversion.

An inverse of `a` modulo `m` exists only when `a` and `m` are coprime.

### Mathematical GCD versus library behavior

Mathematical conventions and programming-library conventions can differ in special cases such as `gcd(0, 0)`.

A software interface should document its behavior explicitly.

---

## Limitations

The classical Euclidean algorithm is excellent for integer GCD computation, but it does not solve every number-theoretic problem.

It does not by itself:

- factor arbitrary integers
- determine whether an arbitrary integer is prime
- provide secure cryptographic key generation
- solve nonlinear Diophantine equations
- compute arbitrary polynomial GCDs over every possible coefficient domain

Specialized problems require additional algorithms and mathematical structures.

The script intentionally focuses on integer Euclidean algorithms and their direct applications.

---

## Real-World Relevance

The Euclidean algorithm appears in many areas of computing and mathematics.

Examples include:

- simplifying ratios and fractions
- rational arithmetic
- modular arithmetic
- cryptographic key mathematics
- solving integer equations
- checking coprimality
- computing LCM values
- algorithm design
- continued fractions
- symbolic and numerical computation
- discrete mathematics
- computational number theory

Its practical importance comes from an unusually strong combination of mathematical simplicity, correctness, and efficiency.

---

## Script Structure

The script is organized so that the concepts progress from elementary operations toward more advanced number theory.

The early functions establish division, remainders, and ordinary GCD computation.

The middle portion develops the extended Euclidean algorithm and its consequences.

The later sections connect the algorithm with modular arithmetic, continued fractions, RSA mathematics, testing, performance, and production considerations.

Every major mathematical claim that can reasonably be demonstrated computationally is supported by executable Python code, verification, assertions, or concrete examples.
