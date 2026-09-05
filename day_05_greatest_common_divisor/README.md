# Greatest Common Divisor (GCD)

## Introduction

The Greatest Common Divisor, commonly abbreviated as **GCD**, is the largest positive integer that divides two or more integers without leaving a remainder.

For two integers \(a\) and \(b\), the GCD is written as:

\[
\gcd(a,b)
\]

For example:

\[
\gcd(48,180)=12
\]

because 12 divides both 48 and 180, and no larger positive integer divides both numbers.

The GCD is a fundamental concept in number theory and has practical applications in fraction simplification, ratio reduction, modular arithmetic, cryptography, integer equations, scheduling, algorithms, and computational mathematics.

---

# Fundamental Concepts

## Divisibility

An integer \(d\) divides an integer \(n\) when:

\[
n \bmod d = 0
\]

This is written mathematically as:

\[
d \mid n
\]

For example:

\[
4 \mid 20
\]

because:

\[
20 \bmod 4 = 0
\]

The positive divisors of 12 are:

\[
1,2,3,4,6,12
\]

---

## Common Divisors

A common divisor of two integers is an integer that divides both numbers.

For example, consider 24 and 36.

The positive divisors of 24 are:

\[
1,2,3,4,6,8,12,24
\]

The positive divisors of 36 are:

\[
1,2,3,4,6,9,12,18,36
\]

Their common divisors are:

\[
1,2,3,4,6,12
\]

Therefore:

\[
\gcd(24,36)=12
\]

---

# Formal Definition

For integers \(a\) and \(b\), not both zero, the Greatest Common Divisor is the largest positive integer \(d\) such that:

\[
d\mid a
\]

and:

\[
d\mid b
\]

The Python script includes a definition-based implementation that determines the GCD by identifying common divisors.

This approach is useful for understanding the mathematical meaning of GCD but is inefficient for large numbers.

---

# Important GCD Rules

## Non-Negative Result

The GCD is conventionally non-negative:

\[
\gcd(a,b)\geq0
\]

Therefore:

\[
\gcd(-12,18)=6
\]

\[
\gcd(12,-18)=6
\]

\[
\gcd(-12,-18)=6
\]

Negative signs do not affect the positive divisors of an integer.

---

## GCD With Zero

Important identities are:

\[
\gcd(a,0)=|a|
\]

and:

\[
\gcd(0,b)=|b|
\]

Examples:

\[
\gcd(10,0)=10
\]

\[
\gcd(0,15)=15
\]

Most programming libraries define:

\[
\gcd(0,0)=0
\]

Python's `math.gcd` follows this convention.

Mathematically, \((0,0)\) is a special case because every non-zero integer divides zero, meaning there is no largest positive common divisor under the ordinary definition.

---

# Brute-Force GCD

A brute-force algorithm starts from the smaller number and searches downward.

The process is:

1. Find the smaller absolute value.
2. Check whether it divides both numbers.
3. If it does not, decrease the candidate.
4. Return the first value that divides both numbers.

The approximate worst-case complexity is:

\[
O(\min(|a|,|b|))
\]

The Python script implements this approach in `gcd_brute_force`.

Brute force is useful for demonstrating the definition of GCD but is not suitable for large integers.

---

# Euclidean Algorithm

The Euclidean algorithm is the most important classical method for calculating the GCD.

Its central identity is:

\[
\gcd(a,b)=\gcd(b,a\bmod b)
\]

Suppose:

\[
a=bq+r
\]

where:

- \(q\) is the quotient
- \(r\) is the remainder

Then:

\[
\gcd(a,b)=\gcd(b,r)
\]

The process continues until the remainder becomes zero.

The last non-zero remainder is the GCD.

---

## Euclidean Algorithm Example

Calculate:

\[
\gcd(252,105)
\]

First:

\[
252=105\times2+42
\]

Therefore:

\[
\gcd(252,105)=\gcd(105,42)
\]

Next:

\[
105=42\times2+21
\]

Therefore:

\[
\gcd(105,42)=\gcd(42,21)
\]

Finally:

\[
42=21\times2+0
\]

Therefore:

\[
\gcd(252,105)=21
\]

The Python script displays these calculations through the `show_euclidean_steps` function.

---

# Iterative Euclidean Algorithm

The iterative algorithm repeatedly performs the logical transformation:

`a, b = b, a % b`

until the second value becomes zero.

When:

`b == 0`

the first value contains the GCD.

The implementation is provided through `gcd_euclidean`.

This is the preferred fundamental algorithm because it is efficient and avoids recursion overhead.

---

# Recursive Euclidean Algorithm

The recursive mathematical definition is:

\[
\gcd(a,b)=
\begin{cases}
|a| & \text{if } b=0\\
\gcd(b,a\bmod b) & \text{otherwise}
\end{cases}
\]

The Python implementation is provided through `gcd_recursive`.

The recursive approach closely follows the mathematical definition.

The iterative version is usually preferable in production Python code because function calls introduce overhead and Python has recursion-depth limits.

---

# Subtraction-Based GCD

The Euclidean principle can also be expressed using subtraction.

When:

\[
a\geq b
\]

then:

\[
\gcd(a,b)=\gcd(a-b,b)
\]

For example:

\[
\gcd(48,18)
\]

can be transformed into:

\[
\gcd(30,18)
\]

then:

\[
\gcd(12,18)
\]

then:

\[
\gcd(12,6)
\]

and finally:

\[
6
\]

The script implements this method through `gcd_subtraction`.

This method is significantly slower than the modulo-based Euclidean algorithm when the two numbers are highly unequal.

---

# Binary GCD

Binary GCD is also called **Stein's algorithm**.

It uses:

- subtraction
- comparisons
- binary shifts

The algorithm uses the following properties.

If both numbers are even:

\[
\gcd(a,b)=2\gcd(a/2,b/2)
\]

If only one number is even:

\[
\gcd(a,b)=\gcd(a/2,b)
\]

for an even \(a\) and odd \(b\).

If both numbers are odd:

\[
\gcd(a,b)=\gcd(|a-b|/2,\min(a,b))
\]

The Python implementation uses bitwise operations and is provided through `gcd_binary`.

Binary GCD can be useful in low-level systems where division is relatively expensive.

---

# Complexity

The Euclidean algorithm has logarithmic complexity:

\[
O(\log(\min(|a|,|b|)))
\]

This makes it much more efficient than checking every possible divisor.

The exact performance for very large arbitrary-precision integers also depends on the cost of operations such as division and modulo.

Python integers can grow beyond fixed machine-word sizes, so operations on extremely large values are not constant-time operations.

---

# Prime Factorization Method

The GCD can also be found through prime factorization.

Consider:

\[
360=2^3\times3^2\times5
\]

and:

\[
840=2^3\times3\times5\times7
\]

The GCD uses common prime factors with their minimum exponents:

\[
\gcd(360,840)=2^3\times3\times5
\]

Therefore:

\[
\gcd(360,840)=120
\]

The script implements prime factorization through `prime_factorization` and GCD calculation through `gcd_prime_factorization`.

Prime factorization is useful for mathematical understanding but is generally inefficient compared with the Euclidean algorithm for large inputs.

---

# Extended Euclidean Algorithm

The Extended Euclidean Algorithm calculates:

\[
g=\gcd(a,b)
\]

and integers \(x\) and \(y\) such that:

\[
ax+by=g
\]

This equation is called **Bézout's identity**.

For example:

\[
\gcd(30,18)=6
\]

One possible representation is:

\[
30(-1)+18(2)=6
\]

Therefore:

\[
x=-1
\]

and:

\[
y=2
\]

are Bézout coefficients.

The script contains both recursive and iterative implementations through:

- `extended_gcd`
- `extended_gcd_iterative`

---

# Bézout's Identity

Bézout's identity states that for integers \(a\) and \(b\), not both zero, there exist integers \(x\) and \(y\) satisfying:

\[
ax+by=\gcd(a,b)
\]

This identity is important because it connects GCD calculations with modular arithmetic.

If:

\[
\gcd(a,m)=1
\]

then:

\[
ax+my=1
\]

Taking the equation modulo \(m\):

\[
ax\equiv1\pmod m
\]

Therefore \(x\) is a multiplicative inverse of \(a\) modulo \(m\).

---

# Coprime Numbers

Two integers are coprime when:

\[
\gcd(a,b)=1
\]

For example:

\[
\gcd(8,15)=1
\]

Therefore 8 and 15 are coprime.

Coprime numbers do not need to be prime.

Both 8 and 15 are composite numbers.

The script implements coprimality testing through `are_coprime`.

---

# GCD of Multiple Numbers

The GCD can be extended to multiple integers.

For example:

\[
\gcd(a,b,c)
\]

can be calculated as:

\[
\gcd(\gcd(a,b),c)
\]

For:

\[
84,126,210
\]

first calculate:

\[
\gcd(84,126)=42
\]

Then:

\[
\gcd(42,210)=42
\]

Therefore:

\[
\gcd(84,126,210)=42
\]

The script implements this through:

- `gcd_many`
- `gcd_many_reduce`

---

# Relationship Between GCD and LCM

For non-zero integers:

\[
\gcd(a,b)\times\operatorname{lcm}(a,b)=|ab|
\]

Therefore:

\[
\operatorname{lcm}(a,b)=\frac{|ab|}{\gcd(a,b)}
\]

For example:

\[
\gcd(12,18)=6
\]

Therefore:

\[
\operatorname{lcm}(12,18)=\frac{12\times18}{6}=36
\]

The script implements:

- `lcm`
- `lcm_many`

The implementation divides before multiplying where possible to reduce intermediate integer sizes.

---

# Fraction Simplification

A fraction:

\[
\frac{p}{q}
\]

can be simplified by dividing both values by:

\[
\gcd(p,q)
\]

For example:

\[
\frac{42}{56}
\]

has:

\[
\gcd(42,56)=14
\]

Therefore:

\[
\frac{42}{56}=\frac{3}{4}
\]

The script implements fraction simplification through `simplify_fraction`.

It also normalizes fractions so that denominators remain positive.

---

# Rational Number Implementation

The `Rational` class demonstrates a practical use of GCD.

Each rational number is automatically reduced to its simplest form.

The class supports:

- normalized storage
- string representation
- addition
- multiplication
- automatic fraction reduction

Multiplication performs cross-cancellation using GCD before multiplication.

This can reduce intermediate integer sizes.

---

# Modular Multiplicative Inverse

A modular inverse of \(a\) modulo \(m\) is an integer \(x\) satisfying:

\[
ax\equiv1\pmod m
\]

An inverse exists if and only if:

\[
\gcd(a,m)=1
\]

The Extended Euclidean Algorithm can calculate the inverse.

The script implements this through `modular_inverse`.

If the GCD is not 1, the function raises `ValueError`.

---

# Linear Diophantine Equations

A linear Diophantine equation has the form:

\[
ax+by=c
\]

where \(x\) and \(y\) must be integers.

A solution exists if and only if:

\[
\gcd(a,b)\mid c
\]

For example:

\[
15x+25y=5
\]

Since:

\[
\gcd(15,25)=5
\]

and:

\[
5\mid5
\]

integer solutions exist.

The script implements this through `solve_linear_diophantine`.

---

# Families of Diophantine Solutions

If:

\[
(x_0,y_0)
\]

is one solution and:

\[
g=\gcd(a,b)
\]

then all integer solutions are:

\[
x=x_0+\frac{b}{g}t
\]

\[
y=y_0-\frac{a}{g}t
\]

where:

\[
t\in\mathbb{Z}
\]

The script exposes this structure through `diophantine_solution_family`.

---

# Modular Linear Equations

A modular linear equation has the form:

\[
ax\equiv b\pmod m
\]

Let:

\[
g=\gcd(a,m)
\]

A solution exists if and only if:

\[
g\mid b
\]

The script implements modular equation solving through `solve_modular_linear_equation`.

The function returns all solutions within the canonical range:

\[
0\leq x<m
\]

This demonstrates how GCD determines whether modular equations can be solved.

---

# Chinese Remainder Theorem

The script includes a solver for two congruences:

\[
x\equiv r_1\pmod{m_1}
\]

and:

\[
x\equiv r_2\pmod{m_2}
\]

When the moduli are coprime:

\[
\gcd(m_1,m_2)=1
\]

a unique solution exists modulo:

\[
m_1m_2
\]

The implementation also handles compatible non-coprime moduli.

The compatibility condition is:

\[
\gcd(m_1,m_2)\mid(r_2-r_1)
\]

The combined modulus is:

\[
\operatorname{lcm}(m_1,m_2)
\]

The implementation is provided through `chinese_remainder_two`.

---

# Mathematical Properties

## Symmetry

\[
\gcd(a,b)=\gcd(b,a)
\]

---

## Identity With Zero

\[
\gcd(a,0)=|a|
\]

---

## Divisibility

If:

\[
g=\gcd(a,b)
\]

then:

\[
g\mid a
\]

and:

\[
g\mid b
\]

---

## Euclidean Invariance

\[
\gcd(a,b)=\gcd(b,a\bmod b)
\]

---

## Scaling

For an integer \(k\):

\[
\gcd(ka,kb)=|k|\gcd(a,b)
\]

---

## GCD and LCM Identity

For non-zero integers:

\[
\gcd(a,b)\operatorname{lcm}(a,b)=|ab|
\]

---

# Practical Applications

## Simplifying Fractions

GCD removes common factors from the numerator and denominator.

---

## Simplifying Ratios

The ratio:

\[
150:100
\]

has:

\[
\gcd(150,100)=50
\]

Therefore:

\[
150:100=3:2
\]

---

## Equal Grouping

Suppose 24 objects and 36 objects must be divided into the maximum possible number of equal groups.

The answer is:

\[
\gcd(24,36)=12
\]

Each group contains:

\[
24/12=2
\]

objects of the first type and:

\[
36/12=3
\]

objects of the second type.

The script demonstrates this through `largest_equal_group_size`.

---

## Periodic Events

If two events repeat after different intervals, their common repetition time is determined by their LCM.

For intervals:

\[
12
\]

and:

\[
18
\]

the next simultaneous event occurs after:

\[
\operatorname{lcm}(12,18)=36
\]

GCD is used internally to calculate LCM efficiently.

---

# Edge Cases

The script explicitly handles:

## Both Inputs Equal to Zero

\[
\gcd(0,0)=0
\]

according to common programming convention.

## One Input Equal to Zero

\[
\gcd(a,0)=|a|
\]

## Negative Numbers

The result remains non-negative.

## Equal Numbers

\[
\gcd(n,n)=|n|
\]

## Coprime Numbers

\[
\gcd(a,b)=1
\]

---

# Common Mistakes

## Confusing GCD With LCM

GCD is the largest common divisor.

LCM is the smallest positive common multiple.

---

## Assuming Coprime Numbers Must Be Prime

Composite numbers can be coprime.

For example:

\[
8
\]

and:

\[
15
\]

are coprime.

---

## Using Prime Factorization for Large Inputs

Factoring large numbers is generally much slower than using the Euclidean algorithm.

---

## Using Repeated Subtraction

Repeated subtraction can require a large number of operations for highly unequal inputs.

Modulo-based Euclid's algorithm is usually much more efficient.

---

## Ignoring Zero Cases

Correct implementations must explicitly define behavior for:

\[
\gcd(a,0)
\]

\[
\gcd(0,b)
\]

and:

\[
\gcd(0,0)
\]

---

## Assuming Every Number Has a Modular Inverse

A modular inverse exists only when:

\[
\gcd(a,m)=1
\]

---

## Using Floating-Point Values

GCD is an integer operation.

Floating-point arithmetic can introduce rounding errors and should not be used for exact divisibility calculations.

---

# Performance Considerations

The Euclidean algorithm is the preferred general-purpose mathematical method.

For production Python programs, the standard library function:

`math.gcd`

is usually the best choice.

Python also provides:

`math.lcm`

for least common multiple calculations.

Brute-force and subtraction-based algorithms are primarily useful for educational comparison.

Prime factorization should not normally be used as the primary method for calculating GCD.

---

# Testing and Validation

The Python script includes several testing strategies.

## Known Test Cases

Algorithms are tested against expected values.

The tested implementations include:

- definition-based GCD
- brute-force GCD
- Euclidean GCD
- recursive Euclidean GCD
- subtraction-based GCD
- binary GCD
- prime-factorization GCD

---

## Randomized Testing

Random integer pairs are compared with Python's standard:

`math.gcd`

This helps validate behavior across:

- positive integers
- negative integers
- zero
- coprime pairs
- numbers with large common factors

---

## Extended GCD Validation

The script verifies:

\[
ax+by=\gcd(a,b)
\]

for computed Bézout coefficients.

---

## Modular Inverse Validation

For every computed inverse:

\[
(a\times a^{-1})\bmod m=1
\]

is verified.

Invalid inverse requests are also tested.

---

# Exceptions and Input Validation

## Zero Fraction Denominator

A denominator equal to zero raises:

`ZeroDivisionError`

---

## Prime Factorization of Zero

Zero does not have a finite prime factorization.

The implementation raises:

`ValueError`

---

## Empty Collections

The multiple-number GCD functions reject empty collections with:

`ValueError`

---

## Invalid Modulus

Modular arithmetic functions validate modulus values.

A modular inverse requires a modulus greater than 1.

---

## Missing Modular Inverse

When:

\[
\gcd(a,m)\neq1
\]

a modular inverse does not exist and the implementation raises `ValueError`.

---

# Security Considerations

GCD calculations are important in security-related mathematics because modular inverses depend on coprimality.

Important implementation considerations include:

- arbitrary-precision arithmetic can have input-dependent execution time
- ordinary educational implementations are not guaranteed to be constant-time
- cryptographic code may require protection against timing side channels
- number-theoretic correctness does not automatically imply cryptographic security

The implementations demonstrate mathematical principles and should not automatically be considered hardened cryptographic primitives.

---

# Implementation Design

The Python script uses integer arithmetic throughout.

Important design decisions include:

- converting GCD inputs to absolute values
- returning non-negative results
- explicitly handling zero
- using the modulo-based Euclidean algorithm for efficiency
- validating exceptional mathematical conditions
- comparing custom implementations with `math.gcd`
- using assertions for correctness testing
- normalizing rational numbers
- reducing intermediate multiplication through GCD-based cancellation

The script progresses from the direct mathematical definition of GCD to efficient algorithms and advanced number-theoretic applications, demonstrating why the Greatest Common Divisor is a foundational operation in both mathematics and computer science.
