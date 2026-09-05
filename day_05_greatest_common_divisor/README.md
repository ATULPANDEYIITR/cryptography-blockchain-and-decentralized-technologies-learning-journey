# Greatest Common Divisor (GCD)

## Introduction

The Greatest Common Divisor, commonly abbreviated as **GCD**, is one of the fundamental concepts of elementary number theory. It describes the largest positive integer that divides two or more integers without leaving a remainder.

For two integers \(a\) and \(b\), the GCD is written as:

\[
\gcd(a,b)
\]

For example:

\[
\gcd(48,180)=12
\]

because the positive divisors of 48 are:

\[
1,2,3,4,6,8,12,16,24,48
\]

and the positive divisors of 180 include:

\[
1,2,3,4,5,6,9,10,12,\ldots
\]

The largest divisor common to both numbers is 12.

The GCD is important in arithmetic, fractions, ratios, modular arithmetic, cryptography, algorithms, scheduling, integer equations, and many computational problems.

This study implementation progresses from the mathematical definition of divisibility to efficient algorithms and advanced applications such as Bézout's identity, modular inverses, linear Diophantine equations, modular equations, and the Chinese Remainder Theorem.

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

Every non-zero integer has at least two positive divisors, 1 and its absolute value, unless its absolute value is 1.

---

## Common Divisors

A common divisor of two integers divides both integers.

For example, consider:

\[
24
\]

and:

\[
36
\]

Their common positive divisors are:

\[
1,2,3,4,6,12
\]

The largest is:

\[
12
\]

Therefore:

\[
\gcd(24,36)=12
\]

---

# Formal Definition of GCD

For integers \(a\) and \(b\), not both zero, the GCD is the largest positive integer \(d\) such that:

\[
d\mid a
\]

and:

\[
d\mid b
\]

The Python script includes `gcd_definition`, which calculates the GCD directly from the mathematical definition by finding the common divisors.

This approach is useful for understanding the concept but is not the preferred algorithm for large integers.

---

# Important GCD Conventions

## GCD Is Non-Negative

The standard programming and mathematical convention is:

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

The sign of an integer does not affect its positive divisors.

---

## GCD With Zero

The following identities are important:

\[
\gcd(a,0)=|a|
\]

and:

\[
\gcd(0,b)=|b|
\]

For example:

\[
\gcd(15,0)=15
\]

because every non-zero divisor of 15 also divides zero.

Most programming libraries define:

\[
\gcd(0,0)=0
\]

Python's `math.gcd` follows this convention, and the implementations in the script also return zero for this case.

Mathematically, the pair \((0,0)\) is special because every non-zero integer divides zero, so there is no largest positive common divisor in the ordinary divisibility sense.

---

# Brute-Force GCD

A direct algorithm starts with the smaller absolute value and checks possible divisors in descending order.

For positive integers:

1. Start with `min(a, b)`.
2. Check whether it divides both numbers.
3. Decrease the candidate.
4. Return the first common divisor found.

The algorithm has worst-case complexity approximately:

\[
O(\min(|a|,|b|))
\]

This is simple but inefficient for large values.

The script implements this approach in:

```text
gcd_brute_force
