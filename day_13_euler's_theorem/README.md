# Euler's theorem in number theory

## Introduction

Euler's theorem is a fundamental result in elementary number theory and modular arithmetic. It describes the behavior of powers of an integer when the base and modulus are relatively prime.

For positive integer `n`, Euler's totient function, written as `φ(n)`, counts the positive integers up to `n` that are relatively prime to `n`.

Euler's theorem states:

**If gcd(a, n) = 1, then**

`a^φ(n) ≡ 1 (mod n)`

The condition `gcd(a, n) = 1` is essential. Euler's theorem cannot be applied blindly to every base and modulus.

The Python script develops the theorem from its prerequisites through modular exponentiation, modular inverses, multiplicative order, the Chinese remainder theorem, Carmichael's function, and RSA-style modular arithmetic.

## Modular arithmetic

A congruence

`a ≡ b (mod n)`

means that `a` and `b` have the same remainder when divided by `n`. Equivalently,

`n | (a - b)`

where the vertical notation means that `n` divides `a - b`.

For example,

`17 ≡ 5 (mod 6)`

because

`17 - 5 = 12`

and `12` is divisible by `6`.

Congruences behave well under addition and multiplication. If

`a ≡ b (mod n)`

then for any integer `c`,

`a + c ≡ b + c (mod n)`

and

`ac ≡ bc (mod n)`.

This algebraic behavior makes modular arithmetic useful for studying powers and divisibility.

## Greatest common divisor and coprimality

The greatest common divisor of two integers `a` and `b`, written `gcd(a, b)`, is the largest positive integer that divides both.

Two integers are **coprime** or **relatively prime** when

`gcd(a, b) = 1`.

For example,

`gcd(8, 15) = 1`

so `8` and `15` are coprime.

By contrast,

`gcd(14, 21) = 7`

so `14` and `21` are not coprime.

The script implements the extended Euclidean algorithm as well. It finds integers `x` and `y` satisfying

`ax + by = gcd(a, b)`.

When `gcd(a, b) = 1`, this becomes

`ax + by = 1`.

That identity is central to computing modular multiplicative inverses.

## Euler's totient function

Euler's totient function `φ(n)` counts the positive integers from `1` through `n` that are coprime to `n`.

For example:

`φ(1) = 1`

`φ(2) = 1`

`φ(5) = 4`

`φ(10) = 4`

The integers between `1` and `10` that are coprime to `10` are:

`1, 3, 7, 9`

so `φ(10) = 4`.

The script calculates the totient function in two ways. The first method directly tests every candidate. The second method uses the prime factorization formula.

## Totient formula from prime factorization

If the distinct prime factors of `n` are `p1, p2, ..., pk`, then

`φ(n) = n(1 - 1/p1)(1 - 1/p2)...(1 - 1/pk)`.

The formula depends only on the distinct prime factors, not on their exponents inside the product.

For example,

`12 = 2^2 × 3`.

Therefore,

`φ(12) = 12(1 - 1/2)(1 - 1/3)`

which gives

`φ(12) = 4`.

Another useful special case occurs when `p` is prime:

`φ(p) = p - 1`.

For a prime power,

`φ(p^k) = p^k - p^(k-1)`

or equivalently,

`φ(p^k) = p^(k-1)(p - 1)`.

## Multiplicativity of the totient function

Euler's totient function is multiplicative for coprime arguments.

If

`gcd(m, n) = 1`

then

`φ(mn) = φ(m)φ(n)`.

For example, `3` and `4` are coprime, so

`φ(12) = φ(3)φ(4)`

and

`4 = 2 × 2`.

This property makes prime factorization particularly useful when calculating `φ(n)`.

It is important not to assume that `φ(mn) = φ(m)φ(n)` for arbitrary `m` and `n`. The coprimality condition is required.

## Statement of Euler's theorem

Euler's theorem is:

`gcd(a, n) = 1  =>  a^φ(n) ≡ 1 (mod n)`.

For example, take

`a = 7`

and

`n = 40`.

Since

`gcd(7, 40) = 1`

Euler's theorem applies.

The prime factorization of `40` is

`40 = 2^3 × 5`.

Therefore,

`φ(40) = 40(1 - 1/2)(1 - 1/5) = 16`.

Euler's theorem gives

`7^16 ≡ 1 (mod 40)`.

The Python script verifies this computationally using modular exponentiation.

## Why the coprimality condition matters

The theorem does not say that

`a^φ(n) ≡ 1 (mod n)`

for every `a`.

For example, consider

`a = 2`

and

`n = 4`.

We have

`gcd(2, 4) = 2`.

Therefore, Euler's theorem does not apply.

Although

`φ(4) = 2`,

we obtain

`2^2 ≡ 0 (mod 4)`

rather than `1`.

The failure is not a contradiction. The theorem's hypothesis was not satisfied.

This is one of the most important details to check before reducing an exponent with Euler's theorem.

## Conceptual proof

A standard proof uses the reduced residue system modulo `n`.

The reduced residue system consists of the residue classes that are coprime to `n`. There are exactly `φ(n)` such classes.

Suppose

`gcd(a, n) = 1`.

Multiplying every member of the reduced residue system by `a` produces another reduced residue system. Multiplication by `a` merely permutes the invertible residue classes.

Therefore, the product of all the transformed residues is congruent to the product of all the original residues.

The transformed product contains the factor

`a^φ(n)`.

After cancellation in the multiplicative group of invertible residues modulo `n`, the result is

`a^φ(n) ≡ 1 (mod n)`.

This proof explains why coprimality is fundamental: multiplication by `a` must preserve the set of invertible residue classes.

## Reducing large exponents

Euler's theorem is particularly useful for expressions involving very large powers.

Suppose

`gcd(a, n) = 1`.

Write an exponent `k` as

`k = qφ(n) + r`.

Then

`a^k = a^(qφ(n)+r)`

which can be written as

`a^k = (a^φ(n))^q a^r`.

Euler's theorem gives

`a^φ(n) ≡ 1 (mod n)`.

Therefore,

`a^k ≡ a^r (mod n)`,

where

`r = k mod φ(n)`.

Thus, for a coprime base, the exponent can be reduced modulo `φ(n)`.

For example, if the modulus is `40`, then `φ(40) = 16`. An exponent such as `123456789` can therefore be reduced modulo `16` before modular exponentiation.

The reduction is mathematically valid because the base is coprime to the modulus.

## Modular exponentiation

Directly calculating a number such as

`7^1,000,000`

is unnecessary when only its remainder modulo some modulus is required.

The script demonstrates binary exponentiation, also called exponentiation by squaring.

The basic idea is to repeatedly square the base while examining the binary representation of the exponent.

For example,

`a^13 = a^8 × a^4 × a`.

The algorithm therefore requires approximately logarithmic rather than linear numbers of multiplication steps.

The complexity changes from approximately

`O(k)`

for repeated multiplication to

`O(log k)`

for binary exponentiation.

Python's three-argument `pow()` function performs modular exponentiation directly:

`pow(base, exponent, modulus)`

This avoids constructing the complete enormous value of `base^exponent`.

## Euler's theorem and Fermat's little theorem

Fermat's little theorem is a special case of Euler's theorem.

If `p` is prime, then

`φ(p) = p - 1`.

Euler's theorem therefore becomes

`a^(p-1) ≡ 1 (mod p)`

when `gcd(a, p) = 1`.

For a prime `p`, every integer not divisible by `p` is automatically coprime to `p`.

Fermat's little theorem is therefore more specialized:

- Fermat's little theorem uses a prime modulus.
- Euler's theorem works for any positive modulus when the base is coprime to that modulus.
- For a prime modulus, Euler's theorem reduces directly to Fermat's result.

## Multiplicative inverses

A number `a` has a multiplicative inverse modulo `n` if there exists an integer `x` such that

`ax ≡ 1 (mod n)`.

The inverse is commonly written

`a^(-1) mod n`.

An inverse exists exactly when

`gcd(a, n) = 1`.

The extended Euclidean algorithm provides one method for finding the inverse.

Euler's theorem provides another method. Since

`a^φ(n) ≡ 1 (mod n)`,

the multiplicative inverse is

`a^(φ(n)-1) mod n`.

Thus,

`a^(-1) ≡ a^(φ(n)-1) (mod n)`.

This is mathematically valid under the same coprimality condition.

The extended Euclidean algorithm is often more direct in practical implementations because it can calculate the inverse without first computing the complete value of `φ(n)`.

## Solving linear congruences

Consider an equation

`ax ≡ b (mod n)`.

When

`gcd(a, n) = 1`,

`a` has a modular inverse. Multiplying both sides by that inverse gives

`x ≡ ba^(-1) (mod n)`.

For example,

`7x ≡ 11 (mod 40)`.

Since

`gcd(7, 40) = 1`,

the inverse of `7` modulo `40` exists.

The script computes the inverse and then obtains the unique residue class for `x` modulo `40`.

If `a` and `n` are not coprime, the problem requires a different analysis. Depending on `gcd(a,n)`, there may be no solutions or multiple solutions.

## Multiplicative groups

The invertible residue classes modulo `n` form the multiplicative group usually denoted

`(Z/nZ)^*`.

Its number of elements is

`φ(n)`.

Euler's theorem can therefore be interpreted using group theory:

Every element of this finite group satisfies

`a^φ(n) = 1`

within the modular group.

This perspective explains why the theorem concerns only numbers coprime to the modulus. Non-coprime residues are not units and therefore do not belong to the multiplicative group of invertible residue classes.

## Multiplicative order

The multiplicative order of `a` modulo `n` is the smallest positive integer `k` satisfying

`a^k ≡ 1 (mod n)`.

The order exists when

`gcd(a,n) = 1`.

Euler's theorem guarantees that

`a^φ(n) ≡ 1 (mod n)`.

Therefore, the multiplicative order divides `φ(n)`.

This is an important refinement. Euler's theorem provides a valid exponent, but it does not necessarily provide the smallest exponent.

For example, the order of an element can be much smaller than the corresponding totient value.

The script calculates multiplicative orders and verifies the divisibility relationship.

## Exponent reduction using multiplicative order

If the exact multiplicative order `ord_n(a)` is known, an exponent can be reduced modulo that order:

`a^k ≡ a^(k mod ord_n(a)) (mod n)`.

This can produce a smaller exponent than reducing modulo `φ(n)`.

The relationship is:

`ord_n(a) | φ(n)`.

Therefore,

`ord_n(a) <= φ(n)`.

The important distinction is that the order depends on both the base and the modulus, while `φ(n)` depends only on the modulus.

## Carmichael's function

Carmichael's function, written `λ(n)`, gives another exponent with an important universal property.

For every `a` satisfying

`gcd(a,n) = 1`,

we have

`a^λ(n) ≡ 1 (mod n)`.

In general,

`λ(n) | φ(n)`.

Therefore, Carmichael's function can provide a smaller exponent bound than Euler's totient.

For example, some moduli have a significant difference between `φ(n)` and `λ(n)`.

For powers of two:

`λ(2) = 1`

`λ(4) = 2`

and for `k >= 3`,

`λ(2^k) = 2^(k-2)`.

For an odd prime power,

`λ(p^k) = φ(p^k)`.

For relatively prime components, the corresponding Carmichael values combine through the least common multiple.

The script implements these rules for educational purposes.

## Chinese remainder theorem

The Chinese remainder theorem concerns systems such as

`x ≡ a1 (mod n1)`

and

`x ≡ a2 (mod n2)`,

where the moduli are coprime.

For coprime `n1` and `n2`, the system has a unique solution modulo

`n1n2`.

Modular inverses are essential when constructing the solution.

Euler's theorem and the Chinese remainder theorem solve different problems, but they are closely connected in computational number theory. Euler's theorem describes powers of invertible residues, while CRT decomposes modular problems into smaller congruence systems.

## RSA-style modular arithmetic

RSA is built on modular arithmetic, prime factorization, modular inverses, and exponentiation.

For two distinct primes `p` and `q`,

`n = pq`

and

`φ(n) = (p-1)(q-1)`.

An exponent `e` can be selected such that

`gcd(e, φ(n)) = 1`.

A corresponding inverse `d` satisfies

`ed ≡ 1 (mod φ(n))`.

The script uses small illustrative primes to demonstrate the structure:

- Construct `n = pq`.
- Compute `φ(n)`.
- Select a suitable exponent `e`.
- Compute its modular inverse `d`.
- Apply modular exponentiation.
- Recover the original message.

The numerical example is intentionally small for educational clarity. Real cryptographic systems require much larger parameters and carefully designed cryptographic padding and implementation techniques.

## Edge case: modulus 1

The case `n = 1` is mathematically degenerate.

By the standard convention,

`φ(1) = 1`.

Modulo `1`, every integer is congruent to `0`, so it does not behave like the ordinary modular systems used for most applications.

This case is useful when implementing general-purpose number-theoretic functions because algorithms should define their behavior explicitly for boundary inputs.

## Negative bases

Euler's theorem also applies to negative bases when the base and modulus are coprime.

For example, if

`gcd(-3, 4) = 1`,

then Euler's theorem applies to `-3` modulo `4`.

Python's modular arithmetic normalizes the result into the conventional non-negative remainder range for a positive modulus.

The mathematical condition remains unchanged:

`gcd(a,n) = 1`.

## Non-coprime bases

For a non-coprime base, Euler's exponent reduction cannot be applied directly.

For example,

`2^k mod 8`

cannot be simplified by saying that the exponent may be reduced modulo `φ(8)` merely because `φ(8) = 4`.

The reason is that

`gcd(2,8) = 2`.

There are other techniques for analyzing powers when the base and modulus share factors. Prime-power decomposition, valuations, CRT, and direct modular reasoning can become relevant.

This distinction is important in programming because blindly applying Euler exponent reduction can produce incorrect results.

## Negative exponents

Euler's theorem is fundamentally a statement about positive powers.

A negative exponent modulo `n` requires a modular inverse:

`a^(-k) ≡ (a^(-1))^k (mod n)`.

This is possible only when `a` is invertible modulo `n`, which means

`gcd(a,n) = 1`.

Therefore, negative modular exponents should not be handled by simply passing a negative exponent into a general-purpose Euler reduction function.

## Performance considerations

There are two separate computational tasks in Euler-based modular calculations:

1. Computing `φ(n)`.
2. Computing a modular power.

Binary modular exponentiation is highly efficient because it runs in logarithmic time with respect to the exponent.

Computing `φ(n)` from the prime factorization of `n` is also straightforward once the factorization is known.

For very large arbitrary integers, factoring `n` can be the difficult part. This is a major practical limitation of methods that depend explicitly on Euler's totient function.

When only a modular power is required, Python's built-in three-argument `pow()` is generally preferable to constructing the full integer power first.

For example, calculating the complete value of `a^k` and then applying `% n` can require substantially more memory and computation than performing modular multiplication throughout the exponentiation.

## Security considerations

Euler's theorem itself is a mathematical theorem rather than a cryptographic algorithm.

Its role in cryptography comes from properties of modular arithmetic and multiplicative groups.

RSA relies on relationships involving Euler's totient function, modular inverses, and exponentiation. The security of RSA does not come simply from the fact that Euler's theorem exists. Practical security depends on sufficiently large parameters, secure key generation, appropriate padding, resistant implementations, and correct protocol design.

Small numerical RSA examples are therefore demonstrations of mathematics, not secure cryptographic configurations.

## Common mistakes

### Forgetting the coprimality condition

Incorrect:

`a^φ(n) ≡ 1 (mod n)` for every `a`.

Correct:

`gcd(a,n) = 1` must hold.

### Assuming φ(n) = n - 1 for every n

The equality

`φ(n) = n - 1`

holds when `n` is prime.

It does not generally hold for composite numbers.

For example,

`φ(8) = 4`

rather than `7`.

### Reducing an exponent without checking the base

The transformation

`a^k mod n`

to

`a^(k mod φ(n)) mod n`

requires `gcd(a,n) = 1`.

### Confusing Euler's theorem with Fermat's little theorem

Fermat's little theorem is the prime-modulus case. Euler's theorem generalizes the exponent from `p - 1` to `φ(n)` and permits composite moduli when the base is coprime to the modulus.

### Computing enormous powers unnecessarily

When only a remainder is required, direct construction of the full power is usually inefficient.

Modular exponentiation should keep intermediate values reduced modulo `n`.

### Assuming φ(mn) = φ(m)φ(n) without checking

The multiplicative identity requires

`gcd(m,n) = 1`.

## Limitations

Euler's theorem is powerful but does not solve every modular exponentiation problem by itself.

The main limitations are:

- The base must be coprime to the modulus for direct application.
- Computing `φ(n)` efficiently can depend on knowing the prime factorization of `n`.
- Factoring large arbitrary integers can be computationally difficult.
- `φ(n)` is not always the smallest exponent that returns a residue to `1`.
- The multiplicative order may be smaller than `φ(n)`.
- Carmichael's function may provide a smaller universal exponent.
- Non-coprime modular powers require different reasoning.

These limitations explain why Euler's theorem should be treated as one component of a broader toolkit for modular arithmetic.

## Implementation considerations

The Python script separates the mathematical concepts into functions so that each algorithm can be inspected and tested independently.

The main implementations include:

- `extended_gcd()` for Bézout coefficients.
- `prime_factorization()` for trial-division factorization.
- `totient_brute_force()` for direct totient calculation.
- `totient_from_prime_factorization()` for efficient totient calculation once factors are available.
- `modular_power_naive()` for the straightforward exponentiation algorithm.
- `modular_power_fast()` for exponentiation by squaring.
- `modular_inverse_extended_gcd()` for modular inverses.
- `modular_inverse_euler()` for Euler-based inverse computation.
- `multiplicative_order()` for finding the smallest exponent producing `1`.
- `carmichael_function()` for a sharper universal exponent.
- `chinese_remainder_two()` for a two-congruence CRT system.
- `euler_theorem_workflow()` for a compact theorem-application workflow.

The implementation deliberately favors transparency over specialized high-performance factorization algorithms.

## Testing and validation

The script contains unit tests for:

- Known values of `φ(n)`.
- Euler's theorem over many small moduli.
- Binary modular exponentiation.
- The extended Euclidean algorithm.
- Modular inverses.
- Multiplicative orders.

It also performs randomized verification of Euler's theorem for many randomly selected coprime pairs.

Randomized testing is useful for identifying implementation errors that may not appear in a small set of manually selected examples.

The mathematical property being tested is always restricted to the correct domain:

`gcd(a,n) = 1`.

## Real-world relevance

Euler's theorem is an important building block in computational number theory and modular arithmetic.

Its concepts appear in:

- Modular inverse computation.
- Congruence solving.
- Public-key cryptography.
- RSA-related mathematics.
- Multiplicative group theory.
- Periodicity of modular powers.
- Number-theoretic algorithms.
- Chinese remainder theorem based computations.
- Analysis of modular exponentiation.

Its most important practical lesson is the relationship between coprimality, invertibility, and periodicity in modular arithmetic.

The central theorem remains:

`gcd(a,n) = 1  =>  a^φ(n) ≡ 1 (mod n)`.# Euler's theorem in number theory

## Introduction

Euler's theorem is a fundamental result in elementary number theory and modular arithmetic. It describes the behavior of powers of an integer when the base and modulus are relatively prime.

For positive integer `n`, Euler's totient function, written as `φ(n)`, counts the positive integers up to `n` that are relatively prime to `n`.

Euler's theorem states:

**If gcd(a, n) = 1, then**

`a^φ(n) ≡ 1 (mod n)`

The condition `gcd(a, n) = 1` is essential. Euler's theorem cannot be applied blindly to every base and modulus.

The Python script develops the theorem from its prerequisites through modular exponentiation, modular inverses, multiplicative order, the Chinese remainder theorem, Carmichael's function, and RSA-style modular arithmetic.

## Modular arithmetic

A congruence

`a ≡ b (mod n)`

means that `a` and `b` have the same remainder when divided by `n`. Equivalently,

`n | (a - b)`

where the vertical notation means that `n` divides `a - b`.

For example,

`17 ≡ 5 (mod 6)`

because

`17 - 5 = 12`

and `12` is divisible by `6`.

Congruences behave well under addition and multiplication. If

`a ≡ b (mod n)`

then for any integer `c`,

`a + c ≡ b + c (mod n)`

and

`ac ≡ bc (mod n)`.

This algebraic behavior makes modular arithmetic useful for studying powers and divisibility.

## Greatest common divisor and coprimality

The greatest common divisor of two integers `a` and `b`, written `gcd(a, b)`, is the largest positive integer that divides both.

Two integers are **coprime** or **relatively prime** when

`gcd(a, b) = 1`.

For example,

`gcd(8, 15) = 1`

so `8` and `15` are coprime.

By contrast,

`gcd(14, 21) = 7`

so `14` and `21` are not coprime.

The script implements the extended Euclidean algorithm as well. It finds integers `x` and `y` satisfying

`ax + by = gcd(a, b)`.

When `gcd(a, b) = 1`, this becomes

`ax + by = 1`.

That identity is central to computing modular multiplicative inverses.

## Euler's totient function

Euler's totient function `φ(n)` counts the positive integers from `1` through `n` that are coprime to `n`.

For example:

`φ(1) = 1`

`φ(2) = 1`

`φ(5) = 4`

`φ(10) = 4`

The integers between `1` and `10` that are coprime to `10` are:

`1, 3, 7, 9`

so `φ(10) = 4`.

The script calculates the totient function in two ways. The first method directly tests every candidate. The second method uses the prime factorization formula.

## Totient formula from prime factorization

If the distinct prime factors of `n` are `p1, p2, ..., pk`, then

`φ(n) = n(1 - 1/p1)(1 - 1/p2)...(1 - 1/pk)`.

The formula depends only on the distinct prime factors, not on their exponents inside the product.

For example,

`12 = 2^2 × 3`.

Therefore,

`φ(12) = 12(1 - 1/2)(1 - 1/3)`

which gives

`φ(12) = 4`.

Another useful special case occurs when `p` is prime:

`φ(p) = p - 1`.

For a prime power,

`φ(p^k) = p^k - p^(k-1)`

or equivalently,

`φ(p^k) = p^(k-1)(p - 1)`.

## Multiplicativity of the totient function

Euler's totient function is multiplicative for coprime arguments.

If

`gcd(m, n) = 1`

then

`φ(mn) = φ(m)φ(n)`.

For example, `3` and `4` are coprime, so

`φ(12) = φ(3)φ(4)`

and

`4 = 2 × 2`.

This property makes prime factorization particularly useful when calculating `φ(n)`.

It is important not to assume that `φ(mn) = φ(m)φ(n)` for arbitrary `m` and `n`. The coprimality condition is required.

## Statement of Euler's theorem

Euler's theorem is:

`gcd(a, n) = 1  =>  a^φ(n) ≡ 1 (mod n)`.

For example, take

`a = 7`

and

`n = 40`.

Since

`gcd(7, 40) = 1`

Euler's theorem applies.

The prime factorization of `40` is

`40 = 2^3 × 5`.

Therefore,

`φ(40) = 40(1 - 1/2)(1 - 1/5) = 16`.

Euler's theorem gives

`7^16 ≡ 1 (mod 40)`.

The Python script verifies this computationally using modular exponentiation.

## Why the coprimality condition matters

The theorem does not say that

`a^φ(n) ≡ 1 (mod n)`

for every `a`.

For example, consider

`a = 2`

and

`n = 4`.

We have

`gcd(2, 4) = 2`.

Therefore, Euler's theorem does not apply.

Although

`φ(4) = 2`,

we obtain

`2^2 ≡ 0 (mod 4)`

rather than `1`.

The failure is not a contradiction. The theorem's hypothesis was not satisfied.

This is one of the most important details to check before reducing an exponent with Euler's theorem.

## Conceptual proof

A standard proof uses the reduced residue system modulo `n`.

The reduced residue system consists of the residue classes that are coprime to `n`. There are exactly `φ(n)` such classes.

Suppose

`gcd(a, n) = 1`.

Multiplying every member of the reduced residue system by `a` produces another reduced residue system. Multiplication by `a` merely permutes the invertible residue classes.

Therefore, the product of all the transformed residues is congruent to the product of all the original residues.

The transformed product contains the factor

`a^φ(n)`.

After cancellation in the multiplicative group of invertible residues modulo `n`, the result is

`a^φ(n) ≡ 1 (mod n)`.

This proof explains why coprimality is fundamental: multiplication by `a` must preserve the set of invertible residue classes.

## Reducing large exponents

Euler's theorem is particularly useful for expressions involving very large powers.

Suppose

`gcd(a, n) = 1`.

Write an exponent `k` as

`k = qφ(n) + r`.

Then

`a^k = a^(qφ(n)+r)`

which can be written as

`a^k = (a^φ(n))^q a^r`.

Euler's theorem gives

`a^φ(n) ≡ 1 (mod n)`.

Therefore,

`a^k ≡ a^r (mod n)`,

where

`r = k mod φ(n)`.

Thus, for a coprime base, the exponent can be reduced modulo `φ(n)`.

For example, if the modulus is `40`, then `φ(40) = 16`. An exponent such as `123456789` can therefore be reduced modulo `16` before modular exponentiation.

The reduction is mathematically valid because the base is coprime to the modulus.

## Modular exponentiation

Directly calculating a number such as

`7^1,000,000`

is unnecessary when only its remainder modulo some modulus is required.

The script demonstrates binary exponentiation, also called exponentiation by squaring.

The basic idea is to repeatedly square the base while examining the binary representation of the exponent.

For example,

`a^13 = a^8 × a^4 × a`.

The algorithm therefore requires approximately logarithmic rather than linear numbers of multiplication steps.

The complexity changes from approximately

`O(k)`

for repeated multiplication to

`O(log k)`

for binary exponentiation.

Python's three-argument `pow()` function performs modular exponentiation directly:

`pow(base, exponent, modulus)`

This avoids constructing the complete enormous value of `base^exponent`.

## Euler's theorem and Fermat's little theorem

Fermat's little theorem is a special case of Euler's theorem.

If `p` is prime, then

`φ(p) = p - 1`.

Euler's theorem therefore becomes

`a^(p-1) ≡ 1 (mod p)`

when `gcd(a, p) = 1`.

For a prime `p`, every integer not divisible by `p` is automatically coprime to `p`.

Fermat's little theorem is therefore more specialized:

- Fermat's little theorem uses a prime modulus.
- Euler's theorem works for any positive modulus when the base is coprime to that modulus.
- For a prime modulus, Euler's theorem reduces directly to Fermat's result.

## Multiplicative inverses

A number `a` has a multiplicative inverse modulo `n` if there exists an integer `x` such that

`ax ≡ 1 (mod n)`.

The inverse is commonly written

`a^(-1) mod n`.

An inverse exists exactly when

`gcd(a, n) = 1`.

The extended Euclidean algorithm provides one method for finding the inverse.

Euler's theorem provides another method. Since

`a^φ(n) ≡ 1 (mod n)`,

the multiplicative inverse is

`a^(φ(n)-1) mod n`.

Thus,

`a^(-1) ≡ a^(φ(n)-1) (mod n)`.

This is mathematically valid under the same coprimality condition.

The extended Euclidean algorithm is often more direct in practical implementations because it can calculate the inverse without first computing the complete value of `φ(n)`.

## Solving linear congruences

Consider an equation

`ax ≡ b (mod n)`.

When

`gcd(a, n) = 1`,

`a` has a modular inverse. Multiplying both sides by that inverse gives

`x ≡ ba^(-1) (mod n)`.

For example,

`7x ≡ 11 (mod 40)`.

Since

`gcd(7, 40) = 1`,

the inverse of `7` modulo `40` exists.

The script computes the inverse and then obtains the unique residue class for `x` modulo `40`.

If `a` and `n` are not coprime, the problem requires a different analysis. Depending on `gcd(a,n)`, there may be no solutions or multiple solutions.

## Multiplicative groups

The invertible residue classes modulo `n` form the multiplicative group usually denoted

`(Z/nZ)^*`.

Its number of elements is

`φ(n)`.

Euler's theorem can therefore be interpreted using group theory:

Every element of this finite group satisfies

`a^φ(n) = 1`

within the modular group.

This perspective explains why the theorem concerns only numbers coprime to the modulus. Non-coprime residues are not units and therefore do not belong to the multiplicative group of invertible residue classes.

## Multiplicative order

The multiplicative order of `a` modulo `n` is the smallest positive integer `k` satisfying

`a^k ≡ 1 (mod n)`.

The order exists when

`gcd(a,n) = 1`.

Euler's theorem guarantees that

`a^φ(n) ≡ 1 (mod n)`.

Therefore, the multiplicative order divides `φ(n)`.

This is an important refinement. Euler's theorem provides a valid exponent, but it does not necessarily provide the smallest exponent.

For example, the order of an element can be much smaller than the corresponding totient value.

The script calculates multiplicative orders and verifies the divisibility relationship.

## Exponent reduction using multiplicative order

If the exact multiplicative order `ord_n(a)` is known, an exponent can be reduced modulo that order:

`a^k ≡ a^(k mod ord_n(a)) (mod n)`.

This can produce a smaller exponent than reducing modulo `φ(n)`.

The relationship is:

`ord_n(a) | φ(n)`.

Therefore,

`ord_n(a) <= φ(n)`.

The important distinction is that the order depends on both the base and the modulus, while `φ(n)` depends only on the modulus.

## Carmichael's function

Carmichael's function, written `λ(n)`, gives another exponent with an important universal property.

For every `a` satisfying

`gcd(a,n) = 1`,

we have

`a^λ(n) ≡ 1 (mod n)`.

In general,

`λ(n) | φ(n)`.

Therefore, Carmichael's function can provide a smaller exponent bound than Euler's totient.

For example, some moduli have a significant difference between `φ(n)` and `λ(n)`.

For powers of two:

`λ(2) = 1`

`λ(4) = 2`

and for `k >= 3`,

`λ(2^k) = 2^(k-2)`.

For an odd prime power,

`λ(p^k) = φ(p^k)`.

For relatively prime components, the corresponding Carmichael values combine through the least common multiple.

The script implements these rules for educational purposes.

## Chinese remainder theorem

The Chinese remainder theorem concerns systems such as

`x ≡ a1 (mod n1)`

and

`x ≡ a2 (mod n2)`,

where the moduli are coprime.

For coprime `n1` and `n2`, the system has a unique solution modulo

`n1n2`.

Modular inverses are essential when constructing the solution.

Euler's theorem and the Chinese remainder theorem solve different problems, but they are closely connected in computational number theory. Euler's theorem describes powers of invertible residues, while CRT decomposes modular problems into smaller congruence systems.

## RSA-style modular arithmetic

RSA is built on modular arithmetic, prime factorization, modular inverses, and exponentiation.

For two distinct primes `p` and `q`,

`n = pq`

and

`φ(n) = (p-1)(q-1)`.

An exponent `e` can be selected such that

`gcd(e, φ(n)) = 1`.

A corresponding inverse `d` satisfies

`ed ≡ 1 (mod φ(n))`.

The script uses small illustrative primes to demonstrate the structure:

- Construct `n = pq`.
- Compute `φ(n)`.
- Select a suitable exponent `e`.
- Compute its modular inverse `d`.
- Apply modular exponentiation.
- Recover the original message.

The numerical example is intentionally small for educational clarity. Real cryptographic systems require much larger parameters and carefully designed cryptographic padding and implementation techniques.

## Edge case: modulus 1

The case `n = 1` is mathematically degenerate.

By the standard convention,

`φ(1) = 1`.

Modulo `1`, every integer is congruent to `0`, so it does not behave like the ordinary modular systems used for most applications.

This case is useful when implementing general-purpose number-theoretic functions because algorithms should define their behavior explicitly for boundary inputs.

## Negative bases

Euler's theorem also applies to negative bases when the base and modulus are coprime.

For example, if

`gcd(-3, 4) = 1`,

then Euler's theorem applies to `-3` modulo `4`.

Python's modular arithmetic normalizes the result into the conventional non-negative remainder range for a positive modulus.

The mathematical condition remains unchanged:

`gcd(a,n) = 1`.

## Non-coprime bases

For a non-coprime base, Euler's exponent reduction cannot be applied directly.

For example,

`2^k mod 8`

cannot be simplified by saying that the exponent may be reduced modulo `φ(8)` merely because `φ(8) = 4`.

The reason is that

`gcd(2,8) = 2`.

There are other techniques for analyzing powers when the base and modulus share factors. Prime-power decomposition, valuations, CRT, and direct modular reasoning can become relevant.

This distinction is important in programming because blindly applying Euler exponent reduction can produce incorrect results.

## Negative exponents

Euler's theorem is fundamentally a statement about positive powers.

A negative exponent modulo `n` requires a modular inverse:

`a^(-k) ≡ (a^(-1))^k (mod n)`.

This is possible only when `a` is invertible modulo `n`, which means

`gcd(a,n) = 1`.

Therefore, negative modular exponents should not be handled by simply passing a negative exponent into a general-purpose Euler reduction function.

## Performance considerations

There are two separate computational tasks in Euler-based modular calculations:

1. Computing `φ(n)`.
2. Computing a modular power.

Binary modular exponentiation is highly efficient because it runs in logarithmic time with respect to the exponent.

Computing `φ(n)` from the prime factorization of `n` is also straightforward once the factorization is known.

For very large arbitrary integers, factoring `n` can be the difficult part. This is a major practical limitation of methods that depend explicitly on Euler's totient function.

When only a modular power is required, Python's built-in three-argument `pow()` is generally preferable to constructing the full integer power first.

For example, calculating the complete value of `a^k` and then applying `% n` can require substantially more memory and computation than performing modular multiplication throughout the exponentiation.

## Security considerations

Euler's theorem itself is a mathematical theorem rather than a cryptographic algorithm.

Its role in cryptography comes from properties of modular arithmetic and multiplicative groups.

RSA relies on relationships involving Euler's totient function, modular inverses, and exponentiation. The security of RSA does not come simply from the fact that Euler's theorem exists. Practical security depends on sufficiently large parameters, secure key generation, appropriate padding, resistant implementations, and correct protocol design.

Small numerical RSA examples are therefore demonstrations of mathematics, not secure cryptographic configurations.

## Common mistakes

### Forgetting the coprimality condition

Incorrect:

`a^φ(n) ≡ 1 (mod n)` for every `a`.

Correct:

`gcd(a,n) = 1` must hold.

### Assuming φ(n) = n - 1 for every n

The equality

`φ(n) = n - 1`

holds when `n` is prime.

It does not generally hold for composite numbers.

For example,

`φ(8) = 4`

rather than `7`.

### Reducing an exponent without checking the base

The transformation

`a^k mod n`

to

`a^(k mod φ(n)) mod n`

requires `gcd(a,n) = 1`.

### Confusing Euler's theorem with Fermat's little theorem

Fermat's little theorem is the prime-modulus case. Euler's theorem generalizes the exponent from `p - 1` to `φ(n)` and permits composite moduli when the base is coprime to the modulus.

### Computing enormous powers unnecessarily

When only a remainder is required, direct construction of the full power is usually inefficient.

Modular exponentiation should keep intermediate values reduced modulo `n`.

### Assuming φ(mn) = φ(m)φ(n) without checking

The multiplicative identity requires

`gcd(m,n) = 1`.

## Limitations

Euler's theorem is powerful but does not solve every modular exponentiation problem by itself.

The main limitations are:

- The base must be coprime to the modulus for direct application.
- Computing `φ(n)` efficiently can depend on knowing the prime factorization of `n`.
- Factoring large arbitrary integers can be computationally difficult.
- `φ(n)` is not always the smallest exponent that returns a residue to `1`.
- The multiplicative order may be smaller than `φ(n)`.
- Carmichael's function may provide a smaller universal exponent.
- Non-coprime modular powers require different reasoning.

These limitations explain why Euler's theorem should be treated as one component of a broader toolkit for modular arithmetic.

## Implementation considerations

The Python script separates the mathematical concepts into functions so that each algorithm can be inspected and tested independently.

The main implementations include:

- `extended_gcd()` for Bézout coefficients.
- `prime_factorization()` for trial-division factorization.
- `totient_brute_force()` for direct totient calculation.
- `totient_from_prime_factorization()` for efficient totient calculation once factors are available.
- `modular_power_naive()` for the straightforward exponentiation algorithm.
- `modular_power_fast()` for exponentiation by squaring.
- `modular_inverse_extended_gcd()` for modular inverses.
- `modular_inverse_euler()` for Euler-based inverse computation.
- `multiplicative_order()` for finding the smallest exponent producing `1`.
- `carmichael_function()` for a sharper universal exponent.
- `chinese_remainder_two()` for a two-congruence CRT system.
- `euler_theorem_workflow()` for a compact theorem-application workflow.

The implementation deliberately favors transparency over specialized high-performance factorization algorithms.

## Testing and validation

The script contains unit tests for:

- Known values of `φ(n)`.
- Euler's theorem over many small moduli.
- Binary modular exponentiation.
- The extended Euclidean algorithm.
- Modular inverses.
- Multiplicative orders.

It also performs randomized verification of Euler's theorem for many randomly selected coprime pairs.

Randomized testing is useful for identifying implementation errors that may not appear in a small set of manually selected examples.

The mathematical property being tested is always restricted to the correct domain:

`gcd(a,n) = 1`.

## Real-world relevance

Euler's theorem is an important building block in computational number theory and modular arithmetic.

Its concepts appear in:

- Modular inverse computation.
- Congruence solving.
- Public-key cryptography.
- RSA-related mathematics.
- Multiplicative group theory.
- Periodicity of modular powers.
- Number-theoretic algorithms.
- Chinese remainder theorem based computations.
- Analysis of modular exponentiation.

Its most important practical lesson is the relationship between coprimality, invertibility, and periodicity in modular arithmetic.

The central theorem remains:

`gcd(a,n) = 1  =>  a^φ(n) ≡ 1 (mod n)`.
