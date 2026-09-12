# Euler's totient function

## Introduction

Euler's totient function is one of the central arithmetic functions in elementary and computational number theory. It is usually written as φ(n), pronounced "phi of n".

For a positive integer n, Euler's totient function counts how many positive integers from 1 through n are relatively prime to n.

The defining expression is

φ(n) = |{k : 1 ≤ k ≤ n and gcd(k,n) = 1}|

For n > 1, the value n itself is never counted because gcd(n,n) = n. The conventional value φ(1) = 1 follows from the fact that 1 is relatively prime to itself under the standard number-theoretic convention.

The Python script develops the subject in the same order in which the mathematics becomes useful. It begins with greatest common divisors and coprimality, then implements direct counting, derives efficient formulas from prime factorization, examines multiplicativity and divisor identities, and finally connects the function to modular arithmetic, modular inverses, RSA, sieves, Farey sequences, Jordan's totient function, and Carmichael's function.

## Greatest common divisor and coprimality

The greatest common divisor of two integers a and b, written gcd(a,b), is the largest positive integer that divides both numbers.

For example,

gcd(18,12) = 6

Two integers are called coprime when their greatest common divisor is 1.

Examples include:

- 8 and 15 are coprime because gcd(8,15) = 1.
- 14 and 21 are not coprime because gcd(14,21) = 7.
- Every integer is coprime to 1.

The script implements the Euclidean algorithm through the function `gcd_euclidean`.

The key identity is

gcd(a,b) = gcd(b, a mod b)

The process repeatedly replaces the pair with the smaller remainder until the remainder becomes zero. The last nonzero remainder is the greatest common divisor.

The Euclidean algorithm is important because the definition of Euler's totient function is expressed directly in terms of gcd.

## Direct definition of φ(n)

The most literal way to calculate φ(n) is to test every integer from 1 through n.

For example, consider n = 12.

The integers from 1 through 12 are

1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12

The integers relatively prime to 12 are

1, 5, 7, 11

Therefore,

φ(12) = 4

The function `phi_bruteforce` performs exactly this calculation.

This implementation is valuable for understanding the definition and for testing more efficient implementations. It is not appropriate for very large n because the number of gcd computations grows linearly with n.

The script also provides `coprime_numbers_up_to`, which explicitly returns the integers counted by φ(n).

## Basic values

Several values are particularly important.

For 1,

φ(1) = 1

For a prime p,

φ(p) = p - 1

For example,

φ(2) = 1  
φ(3) = 2  
φ(5) = 4  
φ(11) = 10

Every integer from 1 through p - 1 is coprime to a prime p because a prime has no positive divisors other than 1 and itself.

The prime case provides the foundation for the prime-power formula.

## Prime powers

Consider n = p^k where p is prime and k ≥ 1.

The formula is

φ(p^k) = p^k - p^(k-1)

The reason is that the numbers that are not relatively prime to p^k are precisely the multiples of p.

There are p^(k-1) multiples of p between 1 and p^k.

Consequently,

φ(p^k) = p^k - p^(k-1)

This can also be written as

φ(p^k) = p^k(1 - 1/p)

For example,

φ(3^4) = 81 - 27 = 54

The function `prime_power_totient` implements this formula.

## Prime factorization

The efficient calculation of φ(n) depends on the distinct prime divisors of n.

Suppose

n = p1^a1 p2^a2 ... pk^ak

where p1, p2, ..., pk are distinct primes.

The function `prime_factorization` represents this structure as a Python dictionary.

For example,

360 = 2^3 × 3^2 × 5

is represented as

2 → 3  
3 → 2  
5 → 1

The exponents matter when reconstructing n, but the totient product formula uses each distinct prime only once.

The script uses trial division for factorization because it makes the algorithm transparent. Trial division is sufficient for educational examples and moderate-sized integers but is not the preferred method for factoring very large integers.

## Euler's product formula

The central computational formula is

φ(n) = n ∏(1 - 1/p)

where the product runs over the distinct prime divisors p of n.

If

n = 360 = 2^3 × 3^2 × 5

then

φ(360) = 360(1 - 1/2)(1 - 1/3)(1 - 1/5)

Therefore,

φ(360) = 96

The implementation `phi` first factorizes n and then applies the product formula.

The function `phi_from_factorization` performs the calculation using integer arithmetic:

result = n

For each distinct prime p,

result = result - result // p

This form is preferable to floating-point arithmetic because exact integer calculations avoid rounding issues.

## Why the product formula works

The product formula follows from inclusion-exclusion.

An integer fails to be coprime to n exactly when it is divisible by at least one prime divisor of n.

Suppose the distinct prime divisors are p1, p2, ..., pk.

Among the first n positive integers:

- n/p1 are divisible by p1.
- n/p2 are divisible by p2.
- n/(p1p2) are divisible by both p1 and p2.
- Similar terms apply to larger subsets.

Inclusion-exclusion therefore gives

φ(n) = n
       - Σ n/pi
       + Σ n/(pipj)
       - ...
       + (-1)^k n/(p1p2...pk)

Factoring out n produces

φ(n) = n ∏(1 - 1/pi)

The function `phi_by_inclusion_exclusion` implements the inclusion-exclusion form explicitly.

This implementation is primarily useful for understanding the derivation. The direct product formula is generally simpler and more efficient.

## Multiplicativity

Euler's totient function is a multiplicative arithmetic function.

If gcd(a,b) = 1, then

φ(ab) = φ(a)φ(b)

For example, 8 and 9 are coprime.

φ(8) = 4  
φ(9) = 6

Therefore,

φ(72) = φ(8)φ(9) = 24

The script demonstrates this property with `demonstrate_coprime_multiplicativity` and verifies it through `verify_multiplicativity`.

### Multiplicative does not mean completely multiplicative

A common mistake is to assume

φ(ab) = φ(a)φ(b)

for every pair a and b.

That is false.

For example,

φ(2) = 1

but

φ(2 × 2) = φ(4) = 2

while

φ(2)φ(2) = 1

The condition gcd(a,b) = 1 is essential.

This distinction is fundamental when working with arithmetic functions.

## A useful equivalent formula

If

n = p1^a1 p2^a2 ... pk^ak

then

φ(n) = p1^(a1-1)(p1-1)
       × p2^(a2-1)(p2-1)
       × ...
       × pk^(ak-1)(pk-1)

This follows directly from the prime-power formula and multiplicativity.

It is mathematically equivalent to the product formula.

For computational purposes, the form

φ(n) = n ∏(1 - 1/p)

is particularly convenient because only the distinct prime factors need to be processed.

## Divisor-sum identity

One of the most important identities involving Euler's totient function is

∑_{d|n} φ(d) = n

The sum is taken over every positive divisor d of n.

For n = 12, the divisors are

1, 2, 3, 4, 6, 12

Their totients are

1, 1, 2, 2, 2, 4

and therefore

1 + 1 + 2 + 2 + 2 + 4 = 12

The function `divisor_sum_totient` demonstrates this identity.

A conceptual interpretation comes from grouping the integers 1 through n according to their gcd with n. Every integer k has some gcd(k,n) that is a divisor of n. The numbers belonging to each gcd class can be counted using a corresponding totient value.

This identity also explains why φ is closely connected to divisor sums and Möbius inversion.

## Möbius function

The Möbius function μ(n) is defined by

μ(1) = 1

If n contains a squared prime factor, then

μ(n) = 0

If n is a product of k distinct primes, then

μ(n) = (-1)^k

Examples include

μ(1) = 1  
μ(2) = -1  
μ(6) = 1  
μ(30) = -1  
μ(12) = 0

because 12 contains the squared prime factor 2^2.

The script implements μ(n) through `mobius`.

## Totient and Möbius inversion

Euler's totient function has the identity

φ(n) = ∑_{d|n} μ(d)(n/d)

Equivalently,

φ(n) = n ∑_{d|n} μ(d)/d

The function `phi_by_mobius` implements the integer form.

This identity follows from Möbius inversion applied to the divisor-sum identity

∑_{d|n} φ(d) = n

The relationship is important because it places Euler's totient inside the broader theory of arithmetic functions and convolution.

## Reduced residue systems

A reduced residue system modulo n is a complete collection of residue classes represented by integers that are relatively prime to n.

For n > 1, the integers in the interval 1 ≤ a < n that satisfy

gcd(a,n) = 1

form a reduced residue system modulo n.

There are exactly

φ(n)

such values.

For n = 10, the reduced residue system is

1, 3, 7, 9

and therefore

φ(10) = 4

The function `reduced_residue_system` produces these values.

Reduced residue systems are central to Euler's theorem because multiplication by a number coprime to n permutes the reduced residue classes modulo n.

## Euler's theorem

Euler's theorem states that if

gcd(a,n) = 1

then

a^φ(n) ≡ 1 mod n

For example, with a = 5 and n = 12,

gcd(5,12) = 1

and

φ(12) = 4

Therefore,

5^4 ≡ 1 mod 12

The function `verify_euler_theorem` checks this property computationally.

The coprimality condition cannot be omitted.

For example, if a shares a factor with n, Euler's theorem does not guarantee that

a^φ(n) ≡ 1 mod n

The script explicitly treats this condition as part of the theorem.

## Modular exponentiation

Expressions such as

a^e mod n

can involve enormous intermediate values.

Binary exponentiation reduces the number of multiplication steps from a quantity proportional to e to a quantity proportional to log(e).

Python's built-in

`pow(a, e, n)`

performs modular exponentiation efficiently without constructing the full value of a^e.

The function `modular_power` exposes this operation in a teaching-oriented interface.

Efficient modular exponentiation is fundamental in cryptography, number theory, primality testing, and modular arithmetic.

## Modular inverses

A modular inverse of a modulo n is an integer x satisfying

ax ≡ 1 mod n

An inverse exists exactly when

gcd(a,n) = 1

The extended Euclidean algorithm provides the most direct general-purpose method.

If

ax + ny = 1

then reducing both sides modulo n gives

ax ≡ 1 mod n

so x is an inverse of a modulo n.

The function `extended_gcd` returns the coefficients of Bézout's identity.

The function `modular_inverse` uses those coefficients to compute the inverse.

## Euler's theorem and modular inverses

Euler's theorem also gives a formula for the modular inverse when gcd(a,n) = 1:

a^φ(n) ≡ 1 mod n

Multiplying conceptually by a^(-1) gives

a^(φ(n)-1) ≡ a^(-1) mod n

Therefore,

a^(-1) ≡ a^(φ(n)-1) mod n

The function `inverse_using_euler` demonstrates this identity.

Although mathematically valid, this is not always the best computational method. Extended Euclid is usually more direct for obtaining an inverse because it does not require computing φ(n) first.

For a prime modulus p, Fermat's little theorem gives the specialized relation

a^(p-1) ≡ 1 mod p

for a not divisible by p, so

a^(-1) ≡ a^(p-2) mod p

## RSA connection

Euler's totient function has a major role in the mathematical foundation of RSA.

For educational RSA parameters, choose distinct primes p and q and define

n = pq

Then

φ(n) = (p-1)(q-1)

Choose a public exponent e such that

gcd(e,φ(n)) = 1

The private exponent d satisfies

ed ≡ 1 mod φ(n)

so

d ≡ e^(-1) mod φ(n)

The public key is based on e and n, while the private key uses d and n.

Encryption is represented mathematically by

c ≡ m^e mod n

and decryption by

m ≡ c^d mod n

The script uses the small educational example

p = 61  
q = 53  
e = 17

It calculates n, φ(n), the modular inverse d, and demonstrates encryption and decryption of a small integer.

This implementation is deliberately not a production cryptosystem. Secure RSA requires cryptographically secure key generation, sufficiently large primes, standardized padding schemes, secure randomness, protected private keys, side-channel considerations, and carefully implemented cryptographic libraries. Raw textbook RSA is not appropriate for real-world encryption.

## Totient sieve

When φ(n) is required for a single number, prime factorization is a natural method.

When φ(1), φ(2), ..., φ(N) are all required, repeatedly factoring every integer is inefficient.

A totient sieve solves the multiple-value problem efficiently.

The classical sieve begins with

phi[i] = i

For every prime p, every multiple m of p is updated by

phi[m] = phi[m] - phi[m]/p

In integer Python notation this is

`phi[m] -= phi[m] // p`

The final values are exactly the Euler totients.

The function `totient_sieve` implements this method.

Its approximate complexity is

O(N log log N)

with

O(N)

memory usage.

The approach is analogous to the Sieve of Eratosthenes but modifies totient values rather than simply marking composite numbers.

## Linear totient sieve

The script also contains `linear_totient_sieve`.

The linear sieve calculates all totient values from 1 through N in

O(N)

time.

It maintains a list of primes and uses the smallest-prime-factor relationship to construct composite numbers exactly once under the relevant transition.

For a prime p,

φ(p) = p - 1

If p divides i,

φ(ip) = pφ(i)

If p does not divide i,

φ(ip) = φ(i)(p - 1)

These two cases are sufficient to build the complete table.

The linear sieve is particularly useful in algorithms where many arithmetic functions or prime-related quantities must be computed up to a fixed bound.

Its main cost is additional bookkeeping compared with the classical totient sieve.

## Choosing a computation method

For a single small n, direct counting is conceptually simplest.

For a single moderate-sized n, prime factorization followed by the product formula is generally preferable.

For all values up to N, a totient sieve is usually much more appropriate.

The main comparison is:

| Method | Main idea | Typical use |
|---|---|---|
| Brute force | Count gcd(k,n) = 1 | Teaching and validation |
| Factorization | Factor n and apply product formula | Single-value computation |
| Inclusion-exclusion | Count numbers avoiding prime divisors | Mathematical derivation |
| Möbius identity | Sum μ(d)n/d over divisors | Arithmetic-function theory |
| Classical sieve | Update multiples of each prime | Many values up to N |
| Linear sieve | Generate each composite through controlled prime transitions | Large batches of values |

The quality of an implementation depends on whether the problem asks for one value or a complete range of values.

## Summatory totient function

The summatory totient function is

Φ(N) = φ(1) + φ(2) + ... + φ(N)

This should not be confused with Euler's totient function itself.

The script implements `summatory_totient`.

The summatory function appears naturally when counting reduced fractions and analyzing Farey sequences.

It also has important asymptotic behavior:

Φ(N) is approximately

3N² / π²

for large N.

Equivalently, the average value of φ(n) up to N grows proportionally to n with the constant related to 1/ζ(2), where

ζ(2) = π²/6

This gives the classical average-order relationship

∑_{n≤N} φ(n) ~ 3N²/π²

The script does not rely on this approximation for exact computation. It computes exact integer values using sieving.

## Totient density

The ratio

φ(n)/n

measures the fraction of integers from 1 through n that are coprime to n.

From Euler's product formula,

φ(n)/n = ∏(1 - 1/p)

over the distinct prime divisors p of n.

This means the ratio is determined by the distinct prime factors rather than their exponents.

For example,

φ(12)/12 = 4/12 = 1/3

because the distinct prime divisors of 12 are 2 and 3:

(1 - 1/2)(1 - 1/3)
= 1/2 × 2/3
= 1/3

A number containing many small distinct prime factors tends to have a smaller φ(n)/n ratio.

## Farey sequence connection

For a fixed denominator b, the number of integers a satisfying

1 ≤ a < b

and

gcd(a,b) = 1

is exactly φ(b).

These values correspond to fractions

a/b

that are already in lowest terms.

Therefore, the number of positive reduced fractions with denominator at most N and numerator strictly smaller than the denominator is

φ(1) + φ(2) + ... + φ(N)

The script's `farey_reduced_fraction_count` uses this identity.

This connects Euler's totient function with rational-number enumeration and the structure of Farey sequences.

## Jordan's totient function

Euler's totient function has a higher-dimensional generalization called Jordan's totient function.

For a positive integer k,

J_k(n) = n^k ∏(1 - 1/p^k)

where the product is taken over distinct prime divisors p of n.

Euler's function is the special case

J_1(n) = φ(n)

The script implements `jordan_totient`.

Jordan's totient function counts k-tuples of residue classes modulo n that satisfy the appropriate collective coprimality condition.

For k = 1, the problem reduces exactly to counting integers coprime to n.

## Carmichael's function

Euler's totient function is closely related to Carmichael's function, but they are not identical.

Carmichael's function λ(n) is the smallest positive integer m such that

a^m ≡ 1 mod n

for every a coprime to n.

Euler's theorem guarantees that

a^φ(n) ≡ 1 mod n

for every such a, so λ(n) always divides φ(n).

In some cases they are equal. In others, λ(n) is smaller.

For example,

φ(8) = 4

but

λ(8) = 2

because every odd integer satisfies

a² ≡ 1 mod 8

The script implements `carmichael_lambda` using its prime-power rules and the least common multiple of the component values.

This distinction is important when studying the exponent of the multiplicative group of units modulo n.

## Common mistakes

### Forgetting that φ(1) = 1

A common informal approach starts with n > 1 and therefore overlooks the conventional value

φ(1) = 1

The script explicitly handles n = 1.

### Treating φ as completely multiplicative

The correct statement is

φ(ab) = φ(a)φ(b)

only when

gcd(a,b) = 1

The identity cannot be applied blindly when a and b share a factor.

### Using all prime factors repeatedly

The product formula uses distinct prime divisors.

For

n = 2^5 × 3^2

the formula is

φ(n) = n(1 - 1/2)(1 - 1/3)

It does not multiply the factor associated with 2 five times or the factor associated with 3 twice.

### Using floating-point arithmetic unnecessarily

The expression

n × (1 - 1/p)

can be represented exactly using rational arithmetic, but floating-point calculations may introduce rounding.

The implementation instead uses

n - n//p

which remains exact.

### Applying Euler's theorem without checking coprimality

Euler's theorem requires

gcd(a,n) = 1

The condition is part of the theorem, not an optional assumption.

### Confusing φ(n) with n - 1

The equality

φ(n) = n - 1

holds when n is prime.

It does not hold for general composite n.

For example,

φ(10) = 4

rather than 9.

### Assuming factorization is always cheap

The product formula is efficient after factorization, but factorization itself can become difficult for very large integers.

The arithmetic operation

n ∏(1 - 1/p)

is not the main bottleneck when the prime factors are unknown. Discovering those factors can be the computationally difficult part.

## Edge cases

The script explicitly considers several boundary cases.

### n = 1

φ(1) = 1

### n = p

For prime p,

φ(p) = p - 1

### n = p^k

For a prime power,

φ(p^k) = p^(k-1)(p-1)

### Composite n with repeated prime factors

The exponent of a prime does not change the corresponding factor in

φ(n)/n

beyond its contribution to n itself.

### Negative or zero input

Euler's totient function in this script is defined only for positive integers.

Functions therefore reject zero and negative values using `ValueError`.

### Modular inverse that does not exist

A modular inverse of a modulo n exists only when

gcd(a,n) = 1

For example, 6 has no inverse modulo 15 because

gcd(6,15) = 3

The script raises an exception rather than returning an invalid result.

## Validation and testing

The script includes `run_assertion_tests`.

The tests compare several independent implementations:

- Direct brute-force counting
- Prime-factorization formula
- Inclusion-exclusion
- Möbius-function identity
- Classical totient sieve
- Linear totient sieve

Known values such as

φ(1) = 1  
φ(5) = 4  
φ(10) = 4  
φ(12) = 4  
φ(36) = 12  
φ(100) = 40

are checked.

The script also checks Euler's theorem across many coprime pairs and verifies modular inverses.

A randomized cross-check compares the efficient implementation with brute force for randomly selected small integers. Independent implementations are useful because an implementation can appear correct for selected examples while containing a systematic error.

## Performance considerations

For direct counting, there are n candidate integers to examine. Each gcd operation is logarithmic in the size of the operands, so this approach quickly becomes unsuitable as n grows.

For a single value, factorization is the main computational consideration.

The trial-division factorization used in the script is intentionally simple. It can require approximately square-root-scale trial work in unfavorable cases.

For computing all totients up to N, the classical sieve avoids repeated factorization and runs in approximately

O(N log log N)

time.

The linear sieve improves the asymptotic time to

O(N)

while using O(N) additional storage.

For very large cryptographic integers, ordinary trial division is not sufficient. Specialized factorization algorithms and highly optimized implementations are required, depending on the mathematical and computational setting.

## Memory considerations

Single-value factorization requires relatively little memory.

A complete totient table requires O(N) memory because each integer from 1 through N has a stored totient value.

The classical sieve stores the totient array.

The linear sieve stores the totient array, a composite marker array, and a list of primes.

The choice between methods therefore depends not only on execution time but also on the available memory and whether all intermediate values are needed.

## Implementation considerations

The script intentionally uses Python's arbitrary-precision integers. This prevents the fixed-width overflow problems that occur in languages where integer sizes are bounded.

Exact integer arithmetic is particularly useful for totient calculations because the mathematical results are integers.

The script also uses type annotations such as

`dict[int, int]`

and

`list[int]`

to make data structures explicit.

The functions are separated by mathematical responsibility. Factorization, gcd calculation, totient computation, sieving, modular arithmetic, RSA demonstration, and testing are implemented independently so that individual components can be inspected and verified.

## Security considerations

Euler's totient function is an important mathematical component of RSA, but knowledge of the function alone does not make an implementation cryptographically secure.

A production RSA implementation must address:

- Secure prime generation
- Sufficient key sizes
- Cryptographically secure randomness
- Secure private-key storage
- Standardized padding such as OAEP for encryption
- Side-channel resistance
- Correct message encoding
- Key validation
- Protection against implementation errors

The toy RSA implementation in the script deliberately demonstrates only the mathematical relationship between p, q, φ(n), e, d, encryption, and decryption.

Textbook RSA without appropriate padding is not secure for production use.

## Important mathematical relationships

Several formulas from the script form a connected chain of ideas.

### Definition

φ(n) counts integers coprime to n.

### Prime

If p is prime,

φ(p) = p - 1

### Prime power

If p is prime,

φ(p^k) = p^k - p^(k-1)

### Product formula

For distinct prime divisors p of n,

φ(n) = n ∏(1 - 1/p)

### Multiplicativity

If gcd(a,b) = 1,

φ(ab) = φ(a)φ(b)

### Divisor sum

∑_{d|n} φ(d) = n

### Möbius representation

φ(n) = ∑_{d|n} μ(d)(n/d)

### Euler's theorem

If gcd(a,n) = 1,

a^φ(n) ≡ 1 mod n

### Modular inverse

If gcd(a,n) = 1,

a^(-1) ≡ a^(φ(n)-1) mod n

These are not isolated formulas. Each arises naturally from the preceding structure.

## Real-world relevance

Euler's totient function is relevant whenever modular arithmetic and the multiplicative structure of integers are important.

Its applications and connections include:

- Public-key cryptography
- RSA key mathematics
- Modular inverses
- Modular exponentiation
- Reduced residue systems
- Arithmetic-function theory
- Divisor sums
- Möbius inversion
- Computational number theory
- Farey sequences
- Counting reduced fractions
- Generalizations such as Jordan's totient function

Its practical significance comes from the relationship between coprimality, modular multiplication, and the finite multiplicative group of units modulo n.

For cryptographic systems, the mathematical properties of φ(n) are combined with computational assumptions about factoring and with carefully engineered algorithms and protocols.

## Structure of the Python implementation

The script is organized into independent sections.

The foundational section implements divisors, the Euclidean algorithm, and coprimality.

The introductory totient section implements direct counting.

The formula section introduces prime testing, prime powers, prime factorization, and the efficient product formula.

The theoretical section demonstrates inclusion-exclusion, multiplicativity, the divisor-sum identity, and Möbius inversion.

The modular-arithmetic section implements Euler's theorem, modular exponentiation, extended Euclid, and modular inverses.

The algorithmic section implements both the classical and linear totient sieves.

The advanced section examines summatory totients, density, Farey-related counting, Jordan's totient function, and Carmichael's function.

The cryptographic section provides a small RSA arithmetic demonstration and clearly separates mathematical illustration from secure production cryptography.

The testing section validates the implementations against known values, mathematical identities, independent methods, and randomized examples.

The complete script can therefore be used both as an executable reference and as a collection of independently inspectable implementations.
