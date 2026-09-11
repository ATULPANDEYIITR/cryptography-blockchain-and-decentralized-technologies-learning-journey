# Fermat's Little Theorem

## Introduction

Fermat's Little Theorem is a fundamental result in number theory concerning powers of integers modulo a prime number. It provides a powerful relationship between prime numbers, modular arithmetic, multiplicative inverses, exponentiation, finite fields, and primality testing.

The Python script accompanying this README develops the theorem from basic modular arithmetic through more advanced applications. It contains executable demonstrations, implementations, verification routines, edge cases, performance comparisons, and automated tests.

The central result is:

For a prime number `p` and an integer `a` that is not divisible by `p`,

`a^(p-1) ≡ 1 (mod p)`

An equivalent form is:

`a^p ≡ a (mod p)`

The distinction between these two forms is important because the first form requires `a` and `p` to be coprime, while the second form is valid for every integer `a` when `p` is prime.

## Modular arithmetic

Modular arithmetic studies numbers according to their remainders after division by a positive modulus.

For example:

`17 mod 5 = 2`

because dividing 17 by 5 leaves remainder 2.

The notation

`a ≡ b (mod m)`

means that `a` and `b` have the same remainder modulo `m`.

An equivalent definition is:

`m | (a - b)`

where the vertical bar means "divides."

For example:

`29 ≡ 5 (mod 12)`

because:

`29 - 5 = 24`

and 12 divides 24.

Modular arithmetic is particularly useful when dealing with very large integers because calculations can repeatedly be reduced to a small remainder.

## Operations with congruences

Congruences preserve several ordinary arithmetic operations.

If:

`a ≡ b (mod m)`

and:

`c ≡ d (mod m)`

then:

`a + c ≡ b + d (mod m)`

`a - c ≡ b - d (mod m)`

and:

`ac ≡ bd (mod m)`

The multiplication rule is especially important for exponentiation.

Repeated multiplication gives:

`a^2 ≡ b^2 (mod m)`

and more generally:

`a^k ≡ b^k (mod m)`

for positive integer `k`.

The Python script demonstrates these rules using concrete numerical examples.

## Prime numbers

A prime number is an integer greater than 1 whose only positive divisors are 1 and itself.

Examples include:

`2, 3, 5, 7, 11, 13, 17, 19`

Numbers such as 4, 6, 8, 9, 10, and 15 are composite because they have factors other than 1 and themselves.

The script includes a basic trial-division primality test. It only checks possible divisors up to the square root of the candidate because if a number has a factor larger than its square root, it must have a corresponding factor smaller than the square root.

This simple approach is suitable for educational examples but is not designed for extremely large integers.

## Coprimality

Two integers are coprime if their greatest common divisor is 1.

For example:

`gcd(8, 15) = 1`

so 8 and 15 are coprime.

In contrast:

`gcd(12, 18) = 6`

so 12 and 18 are not coprime.

The greatest common divisor is crucial to Fermat's Little Theorem because the first form requires:

`gcd(a, p) = 1`

For a prime `p`, every integer from 1 through `p - 1` is automatically coprime to `p`.

## Statement of Fermat's Little Theorem

The first standard form states:

If `p` is prime and `p` does not divide `a`, then:

`a^(p-1) ≡ 1 (mod p)`

For example, let:

`a = 3`

and:

`p = 7`

Then:

`3^6 = 729`

and:

`729 mod 7 = 1`.

Therefore:

`3^6 ≡ 1 (mod 7)`

The exponent is one less than the prime modulus.

## The second form

The second standard form is:

`a^p ≡ a (mod p)`

for every integer `a` when `p` is prime.

This form also works when `a` is divisible by `p`.

For example, with `p = 7` and `a = 14`:

`14^7 ≡ 14 (mod 7)`

Both sides are congruent to zero modulo 7.

This is why the condition that `a` must be coprime to `p` applies to the first form but not to the second.

## Relationship between the two forms

Starting with:

`a^(p-1) ≡ 1 (mod p)`

and multiplying both sides by `a` gives:

`a^p ≡ a (mod p)`

This establishes the second form for values of `a` that are not divisible by `p`.

If `p` divides `a`, then both sides of:

`a^p ≡ a (mod p)`

are zero modulo `p`.

Therefore the second form covers all integers.

## Permutation proof

One of the most important proofs of Fermat's Little Theorem uses the nonzero residues modulo a prime.

Consider:

`1, 2, 3, ..., p - 1`

Let `a` be coprime to `p`.

Multiply every element by `a`:

`a, 2a, 3a, ..., (p - 1)a`

and reduce each result modulo `p`.

These residues form a permutation of:

`1, 2, 3, ..., p - 1`

They cannot contain zero because `a` is not divisible by `p`.

They also cannot contain duplicate residues. Suppose:

`ai ≡ aj (mod p)`

Then:

`a(i - j) ≡ 0 (mod p)`

Since `a` is invertible modulo `p`, this implies:

`i ≡ j (mod p)`

For `i` and `j` between 1 and `p - 1`, this means `i = j`.

Therefore multiplication by `a` merely rearranges the nonzero residues.

Multiplying all the residues gives:

`a^(p-1)(p-1)! ≡ (p-1)! (mod p)`

Because none of the factors in `(p-1)!` is divisible by `p`, the factorial is invertible modulo `p`. Cancellation is therefore valid, producing:

`a^(p-1) ≡ 1 (mod p)`

## Binomial coefficient proof

Another proof uses the binomial theorem:

`(a + 1)^p = C(p,0)a^p + C(p,1)a^(p-1) + ... + C(p,p)`

When `p` is prime, every intermediate binomial coefficient

`C(p,k)`

for:

`1 <= k <= p - 1`

is divisible by `p`.

Consequently, modulo `p`, all intermediate terms disappear:

`(a + 1)^p ≡ a^p + 1 (mod p)`

Starting from the base case and applying this relationship inductively produces:

`a^p ≡ a (mod p)`

This provides a different perspective on why prime moduli have the property described by Fermat's theorem.

## Efficient modular exponentiation

A common computational task is:

`a^b mod m`

Computing `a^b` first and then taking the remainder can be inefficient because the intermediate integer can become enormous.

The script demonstrates modular exponentiation through repeated reduction:

`result = (result * base) mod m`

It also implements exponentiation by squaring.

Instead of performing one multiplication for every unit of the exponent, exponentiation by squaring repeatedly squares the base and halves the exponent.

Its time complexity is:

`O(log b)`

rather than:

`O(b)`

This makes it practical for very large exponents.

Python's three-argument `pow` function:

`pow(a, b, m)`

is the preferred built-in operation for modular exponentiation in Python.

## Reducing exponents with Fermat's theorem

Suppose `p` is prime and:

`gcd(a,p) = 1`

Fermat's Little Theorem gives:

`a^(p-1) ≡ 1 (mod p)`

Therefore an exponent can be reduced modulo `p - 1`:

`a^k ≡ a^(k mod (p-1)) (mod p)`

provided the exponent-reduction conditions are satisfied.

For example, to calculate:

`3^k mod 17`

the exponent can be reduced modulo:

`17 - 1 = 16`

because:

`3^16 ≡ 1 (mod 17)`

This is particularly useful when `k` is extremely large.

The condition on the base must not be ignored. Exponent reduction modulo `p - 1` using Fermat's theorem requires the base to be coprime to `p`.

## Modular multiplicative inverse

A modular inverse of `a` modulo `m` is a number `x` satisfying:

`ax ≡ 1 (mod m)`

For a prime modulus `p` and a nonzero `a` modulo `p`, Fermat's theorem gives:

`a^(p-1) ≡ 1 (mod p)`

Therefore:

`a * a^(p-2) ≡ 1 (mod p)`

so:

`a^(-1) ≡ a^(p-2) (mod p)`

This means the modular inverse can be calculated as:

`pow(a, p - 2, p)`

when `p` is prime and `a` is not divisible by `p`.

For example, modulo 11:

`7^9 ≡ 8 (mod 11)`

so 8 is the inverse of 7:

`7 × 8 ≡ 1 (mod 11)`

## Modular division

Ordinary division is not directly defined in modular arithmetic.

Instead, division by an invertible value means multiplication by its modular inverse.

To calculate:

`a / b (mod p)`

we calculate:

`a × b^(-1) (mod p)`

For example, modulo 13:

`8 / 3`

requires the inverse of 3.

Since:

`3 × 9 = 27 ≡ 1 (mod 13)`

the inverse of 3 is 9.

Therefore:

`8 / 3 ≡ 8 × 9 ≡ 7 (mod 13)`

The script implements this process using Fermat's theorem.

## Modular cancellation

Cancellation requires special care.

In ordinary arithmetic, if:

`ax = ay`

and `a` is nonzero, we can cancel `a`.

In modular arithmetic, this is only valid when the cancelled factor is invertible modulo the modulus.

For example, modulo 6:

`2 × 1 ≡ 2 × 4 (mod 6)`

because both products are congruent to 2.

But cancelling 2 would incorrectly produce:

`1 ≡ 4 (mod 6)`

which is false.

The problem is that 2 has no multiplicative inverse modulo 6.

For a prime modulus `p`, every nonzero residue has an inverse, which makes cancellation much simpler.

## Combinatorics and binomial coefficients

Fermat's theorem can be used to calculate modular binomial coefficients when the modulus is prime and the relevant factorials are nonzero modulo that prime.

The binomial coefficient is:

`C(n,r) = n! / (r!(n-r)!)`

Modulo a prime `p`, division can be replaced with modular inverses:

`C(n,r) mod p`

`= n! × (r!)^(-1) × ((n-r)!)^(-1) mod p`

The script implements this method under the important condition:

`n < p`

If `n >= p`, a simple factorial-based implementation can fail because `p` divides `n!`, making the factorial non-invertible modulo `p`.

More advanced methods are required for those cases.

## Fermat primality testing

Fermat's theorem gives a simple way to detect some composite numbers.

For a prime `p` and a suitable base `a`:

`a^(p-1) ≡ 1 (mod p)`

Therefore, if a candidate `n` has:

`a^(n-1) not ≡ 1 (mod n)`

then `n` is definitely composite.

This produces a one-sided test:

- Failure proves compositeness.
- Passing does not necessarily prove primality.

The second point is fundamental.

A number that passes a particular Fermat test is better described as a probable prime with respect to that test.

## Fermat pseudoprimes

Some composite numbers satisfy:

`a^(n-1) ≡ 1 (mod n)`

for particular bases `a`.

Such a composite number can fool a Fermat primality test for that base.

These numbers are called Fermat pseudoprimes to the corresponding base.

Testing several bases reduces the probability of a false positive for many numbers, but it does not eliminate the structural weakness of the test.

## Carmichael numbers

Carmichael numbers are a particularly important limitation.

A Carmichael number is a composite integer that satisfies the Fermat congruence for every integer relatively prime to it:

`a^(n-1) ≡ 1 (mod n)`

The smallest Carmichael number is:

`561`

with factorization:

`561 = 3 × 11 × 17`

Thus a Fermat-based primality test can incorrectly classify 561 as a probable prime even when multiple bases are tested.

This is why Fermat testing alone is unsuitable for reliable primality determination, particularly in security-sensitive applications.

## Fermat's theorem and Euler's theorem

Euler's theorem generalizes Fermat's Little Theorem.

Euler's theorem states that if:

`gcd(a,n) = 1`

then:

`a^phi(n) ≡ 1 (mod n)`

where `phi(n)` is Euler's totient function.

Euler's totient function counts the positive integers up to `n` that are coprime to `n`.

For a prime `p`:

`phi(p) = p - 1`

Therefore Euler's theorem becomes:

`a^(p-1) ≡ 1 (mod p)`

which is exactly Fermat's Little Theorem.

Thus Fermat's theorem can be viewed as the prime-modulus special case of Euler's theorem.

## Multiplicative group interpretation

For a prime `p`, the nonzero residue classes:

`1, 2, ..., p-1`

form a multiplicative group modulo `p`.

This group has:

`p - 1`

elements.

Every nonzero element has a multiplicative inverse.

Fermat's Little Theorem states that every element raised to the number of elements in this group produces the identity:

`a^(p-1) ≡ 1 (mod p)`

This interpretation connects elementary modular arithmetic to abstract algebra and finite-field mathematics.

## Multiplicative order

For an integer `a` coprime to `m`, the multiplicative order of `a` modulo `m` is the smallest positive integer `k` such that:

`a^k ≡ 1 (mod m)`

For prime `p`, Fermat's theorem guarantees:

`a^(p-1) ≡ 1 (mod p)`

Therefore the multiplicative order of `a` modulo `p` divides `p - 1`.

For example, modulo 13, the possible multiplicative orders of nonzero elements must divide:

`12`

so possible orders include divisors such as:

`1, 2, 3, 4, 6, 12`

This concept is important when studying cyclic groups and finite fields.

## Edge cases

Several edge cases must be distinguished carefully.

### Base equal to zero

The first form of Fermat's theorem does not apply when:

`a = 0`

because:

`gcd(0,p) = p`

rather than 1.

The second form still works:

`0^p ≡ 0 (mod p)`

### Base divisible by the prime

If:

`p | a`

then the first form cannot be applied.

The second form remains valid:

`a^p ≡ a (mod p)`

because both sides are congruent to zero.

### Composite modulus

Fermat's Little Theorem is a prime-modulus theorem.

For a composite modulus, one should not automatically assume:

`a^(n-1) ≡ 1 (mod n)`

Euler's theorem provides a more general result when the base is coprime to the modulus.

### Modulus equal to 2

The theorem includes the prime `p = 2`.

For every odd `a`:

`a^(2-1) = a ≡ 1 (mod 2)`

so the first form holds.

## Negative integers

Modular arithmetic naturally handles negative integers.

For example, modulo 5:

`-3 ≡ 2 (mod 5)`

because:

`-3 - 2 = -5`

and -5 is divisible by 5.

The Python remainder operation also provides a nonnegative remainder for a positive modulus.

Fermat's theorem therefore extends naturally to negative bases when the required coprimality condition is satisfied.

## Negative exponents

A negative exponent requires a modular inverse.

For example:

`a^(-1)`

means the modular inverse of `a`, provided that the inverse exists.

For a prime modulus `p` and `a` not divisible by `p`:

`a^(-1) ≡ a^(p-2) (mod p)`

The script demonstrates modular powers with negative exponents by explicitly calculating the inverse first.

## Performance considerations

There are several levels of computational efficiency.

A straightforward repeated-multiplication algorithm takes approximately:

`O(n)`

iterations for an exponent `n`.

Exponentiation by squaring requires:

`O(log n)`

multiplications.

Python's built-in modular exponentiation:

`pow(a, b, m)`

is highly optimized and should normally be preferred for practical Python programs.

The three-argument form is preferable to:

`pow(a,b) % m`

because the former performs modular reduction during exponentiation instead of constructing the full enormous value first.

## Numerical considerations

Python integers have arbitrary precision, so ordinary integer overflow is not an issue in Python's integer arithmetic.

Nevertheless, intermediate values can become extremely large when modular reduction is postponed.

Using modular exponentiation keeps the intermediate values bounded relative to the modulus and is significantly more efficient.

The algorithmic complexity of modular exponentiation therefore matters even in languages with arbitrary-precision integers.

## Security considerations

Fermat's Little Theorem has important connections to cryptographic mathematics, including modular inverses, finite fields, and prime-modulus operations.

The theorem itself is not an encryption algorithm.

A simple Fermat primality test should not be treated as a reliable cryptographic primality proof because pseudoprimes and Carmichael numbers exist.

Security-sensitive implementations also require considerations beyond mathematical correctness, including:

- secure random number generation
- appropriate prime-generation algorithms
- resistance to timing attacks
- constant-time implementations where required
- careful parameter selection
- side-channel protection
- extensive implementation testing
- established cryptographic libraries

Educational implementations are useful for understanding the mathematics but should not replace reviewed cryptographic implementations.

## Common mistakes

### Forgetting the coprimality condition

The statement:

`a^(p-1) ≡ 1 (mod p)`

requires:

`gcd(a,p) = 1`

when `p` is prime.

### Treating a composite modulus as a prime

The theorem cannot simply be applied with an arbitrary composite modulus.

### Assuming a Fermat test proves primality

Passing a Fermat test establishes only that the candidate survived that particular test.

Carmichael numbers demonstrate why this is insufficient.

### Reducing every exponent modulo p - 1

The reduction:

`a^k ≡ a^(k mod (p-1)) (mod p)`

requires `a` to be coprime to the prime modulus.

### Cancelling arbitrary modular factors

Cancellation is valid only when the cancelled factor has a modular inverse.

### Performing ordinary modular division

Division must be converted into multiplication by a modular inverse.

## Implementation considerations

The Python script separates the mathematical demonstrations into functions so that each concept can be tested independently.

Important implementations include:

- `is_prime_basic`
- `verify_fermat_form_1`
- `verify_fermat_form_2`
- `modular_power_slow`
- `modular_power_fast`
- `reduce_exponent_using_fermat`
- `modular_inverse_fermat`
- `divide_mod_prime`
- `binomial_mod_prime`
- `fermat_primality_test`
- `multiplicative_order`

The implementation uses Python's `math.gcd` for greatest common divisors and `math.comb` for exact binomial coefficients used during verification.

The script does not require third-party packages.

## Testing and validation

The script includes an automated test suite covering:

- primality detection
- modular exponentiation
- Fermat's first form
- Fermat's second form
- modular inverses
- binomial coefficients
- multiple prime moduli
- negative and positive bases
- randomized-style systematic verification over many small primes

The tests compare custom implementations against Python's built-in modular exponentiation where appropriate.

Assertions are used to detect incorrect results immediately.

## Practical problem-solving method

For a problem such as:

`a^k mod p`

where `p` is prime, a useful workflow is:

1. Confirm that `p` is prime.
2. Check whether `gcd(a,p) = 1`.
3. If the base is coprime to `p`, recognize that `a^(p-1) ≡ 1 (mod p)`.
4. Reduce the exponent modulo `p - 1` when appropriate.
5. Compute the resulting modular power efficiently.
6. Verify the result when practical.

For very large exponents, this approach can turn an apparently enormous calculation into a small modular exponentiation problem.

## Applications

Fermat's Little Theorem appears in several areas of mathematics and computing.

### Modular inverses

For a prime modulus:

`a^(-1) ≡ a^(p-2) (mod p)`

This provides an efficient inverse calculation.

### Modular division

A modular inverse converts division into multiplication.

### Combinatorics

Binomial coefficients can be calculated modulo primes using factorials and modular inverses when the relevant values are invertible.

### Primality testing

Fermat congruences can identify many composite numbers, although the test has important weaknesses.

### Finite fields

Arithmetic modulo a prime forms the foundation of a finite field:

`F_p`

where every nonzero element has a multiplicative inverse.

### Cryptographic mathematics

Prime-modulus arithmetic and modular inverses are fundamental components of many public-key cryptographic constructions.

## Important distinction: theorem versus algorithm

Fermat's Little Theorem is a mathematical theorem.

A Fermat primality test is an algorithm inspired by that theorem.

These should not be confused.

The theorem is exact:

If the required conditions hold, the congruence is guaranteed.

The primality test works in the opposite direction:

If the congruence fails, the candidate is definitely composite.

If the congruence passes, compositeness is not ruled out.

This asymmetry is the central limitation of Fermat-based primality testing.

## Relationship to broader number theory

Fermat's Little Theorem connects several major ideas:

- divisibility
- congruences
- prime numbers
- greatest common divisors
- multiplicative inverses
- modular exponentiation
- Euler's totient function
- finite groups
- multiplicative order
- finite fields
- primality testing
- cryptographic arithmetic

The theorem is therefore much more than a formula for simplifying powers. It describes a structural property of multiplication modulo a prime.
