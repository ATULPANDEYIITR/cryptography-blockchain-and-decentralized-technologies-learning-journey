# Modular Addition, Subtraction and Multiplication

## 1. Topic Introduction

Modular arithmetic is arithmetic performed with respect to a fixed positive integer called the **modulus**. Instead of allowing numerical values to grow without bound, calculations are reduced to their remainder after division by the modulus.

For a positive modulus \(m\), every integer belongs to exactly one canonical residue:

\[
0,1,2,\ldots,m-1
\]

For example, modulo 5:

\[
17 \equiv 2 \pmod 5
\]

because 17 leaves remainder 2 when divided by 5.

The Python script develops modular arithmetic from basic remainder calculations through modular addition, subtraction, multiplication, inverses, modular division, linear congruences, binary modular exponentiation, the Extended Euclidean Algorithm, the Chinese Remainder Theorem, and practical applications.

---

## 2. Fundamental Terminology

### Integer

An integer is a whole number that may be positive, negative, or zero.

Examples include:

\[
-10,-3,0,4,17
\]

Modular arithmetic operates primarily on integers.

### Modulus

The **modulus** is the positive integer with respect to which calculations are performed.

For:

\[
17 \mod 5
\]

the modulus is 5.

The script requires the modulus to be positive. This gives a canonical residue range from 0 through \(m-1\).

### Remainder

The remainder is the value left after integer division.

For example:

\[
17 = 3(5)+2
\]

Therefore:

\[
17 \mod 5 = 2
\]

### Congruence

Two integers \(a\) and \(b\) are congruent modulo \(m\) when their difference is divisible by \(m\):

\[
a \equiv b \pmod m
\]

if and only if:

\[
m \mid (a-b)
\]

For example:

\[
17 \equiv 2 \pmod 5
\]

because:

\[
17-2=15
\]

and 15 is divisible by 5.

Congruence is more fundamental than simply thinking about the remainder operation. It defines an equivalence relation on the integers.

---

## 3. Residue Classes

All integers that differ by a multiple of the modulus belong to the same residue class.

Modulo 5, the numbers

\[
\ldots,-13,-8,-3,2,7,12,17,\ldots
\]

all represent the same modular value.

Their canonical representative is 2.

Thus:

\[
-3 \equiv 2 \equiv 7 \equiv 12 \pmod 5
\]

The script uses Python's `%` operator to convert arbitrary integers to canonical representatives.

For a positive modulus \(m\):

\[
0 \leq a\bmod m < m
\]

---

## 4. Modular Addition

Modular addition is defined as:

\[
(a+b)\bmod m
\]

For example:

\[
(17+25)\bmod 12
\]

gives:

\[
42\bmod 12=6
\]

The operands can also be reduced before addition:

\[
(a+b)\bmod m
=
((a\bmod m)+(b\bmod m))\bmod m
\]

For example:

\[
17\bmod 12=5
\]

and:

\[
25\bmod 12=1
\]

Therefore:

\[
(17+25)\bmod12
=
(5+1)\bmod12
=
6
\]

This property is particularly useful when the original operands are extremely large.

The Python script implements this operation with `modular_add()` and `modular_add_reduced()`.

---

## 5. Modular Subtraction

Modular subtraction is:

\[
(a-b)\bmod m
\]

For example:

\[
(3-8)\bmod5
\]

First calculate:

\[
3-8=-5
\]

Then reduce:

\[
-5\bmod5=0
\]

Another example is:

\[
(4-9)\bmod7
\]

which gives:

\[
-5\bmod7=2
\]

Negative intermediate results are not a problem. The final result is represented by its canonical residue.

The script demonstrates negative modular subtraction explicitly.

---

## 6. Modular Multiplication

Modular multiplication is:

\[
(a\times b)\bmod m
\]

For example:

\[
(17\times25)\bmod12
\]

Since:

\[
17\times25=425
\]

and:

\[
425\bmod12=5
\]

the result is 5.

Operands may be reduced before multiplication:

\[
(ab)\bmod m
=
((a\bmod m)(b\bmod m))\bmod m
\]

For the previous example:

\[
17\bmod12=5
\]

and:

\[
25\bmod12=1
\]

so:

\[
(5\times1)\bmod12=5
\]

The script implements both direct and explicitly reduced modular multiplication.

---

## 7. The Three Core Operations

The fundamental operations covered by the script are:

| Operation | Modular form |
|---|---|
| Addition | \((a+b)\bmod m\) |
| Subtraction | \((a-b)\bmod m\) |
| Multiplication | \((ab)\bmod m\) |

All three are closed over the residue set:

\[
\{0,1,\ldots,m-1\}
\]

That means applying any of these operations to two residues produces another residue modulo \(m\).

---

## 8. Python's `%` Operator

Python's modulo operator is particularly useful for modular arithmetic.

For a positive modulus:

\[
a\%m
\]

produces a result satisfying:

\[
0\leq a\%m<m
\]

This includes negative values of \(a\).

For example:

\[
-1\%5=4
\]

and:

\[
-3\%5=2
\]

Python maintains the division identity:

\[
a=(a//m)m+(a\%m)
\]

This behavior is useful when canonical nonnegative residues are required.

---

## 9. Modulus 1

Modulus 1 is mathematically valid.

Every integer is congruent to 0 modulo 1:

\[
a\equiv0\pmod1
\]

because every integer is divisible by 1.

Therefore:

\[
a\bmod1=0
\]

This is an important edge case because it demonstrates that a valid modulus does not necessarily produce multiple distinct residues.

---

## 10. Modulus Zero

Modulo zero is undefined.

Expressions such as:

\[
a\bmod0
\]

do not represent ordinary modular arithmetic.

The script therefore rejects zero as a modulus.

Negative moduli can be discussed under alternative conventions, but the script deliberately requires a positive modulus so that every value has a unique canonical representative in:

\[
0,\ldots,m-1
\]

---

## 11. Algebraic Properties

Modular addition and multiplication preserve the familiar algebraic structure of integer arithmetic.

### Closure

If \(a\) and \(b\) are residues modulo \(m\), then:

\[
(a+b)\bmod m
\]

and:

\[
(a-b)\bmod m
\]

and:

\[
(ab)\bmod m
\]

are also residues modulo \(m\).

### Commutativity

Addition:

\[
a+b\equiv b+a\pmod m
\]

Multiplication:

\[
ab\equiv ba\pmod m
\]

### Associativity

Addition:

\[
(a+b)+c\equiv a+(b+c)\pmod m
\]

Multiplication:

\[
(ab)c\equiv a(bc)\pmod m
\]

### Distributivity

Multiplication distributes over addition:

\[
a(b+c)\equiv ab+ac\pmod m
\]

The script verifies these properties computationally.

---

## 12. Reducing Before or After an Operation

A central rule of modular arithmetic is that reduction may be performed at intermediate stages.

For addition:

\[
(a+b)\bmod m
=
((a\bmod m)+(b\bmod m))\bmod m
\]

For subtraction:

\[
(a-b)\bmod m
=
((a\bmod m)-(b\bmod m))\bmod m
\]

For multiplication:

\[
(ab)\bmod m
=
((a\bmod m)(b\bmod m))\bmod m
\]

This allows calculations involving very large values to remain manageable.

---

## 13. Clock Arithmetic

A clock provides an intuitive example of modular arithmetic.

A 12-hour clock effectively operates modulo 12.

After 10 o'clock, adding 5 hours gives:

\[
10+5=15
\]

and:

\[
15\bmod12=3
\]

so the result is 3 o'clock.

Similarly, moving backward can be handled through modular subtraction.

The script contains a `clock_addition()` function that demonstrates this cyclic behavior.

---

## 14. Modular Integer Abstraction

The `ModularInteger` class represents an integer together with its modulus.

For example, the values:

\[
17\pmod5
\]

and:

\[
-3\pmod5
\]

both have canonical residue 2.

The class normalizes values through its `residue` property.

It implements:

- addition
- subtraction
- multiplication
- equality
- modulus compatibility checking

Two modular integers with different moduli are not automatically compatible.

For example, an element of arithmetic modulo 5 should not be silently added to an element of arithmetic modulo 7.

---

## 15. Modular Exponentiation

Modular exponentiation calculates:

\[
a^n\bmod m
\]

A naive implementation may first calculate:

\[
a^n
\]

and only then reduce the result.

For large \(n\), this creates unnecessarily large intermediate integers.

The script implements **binary exponentiation**, also called exponentiation by squaring.

The key identities are:

\[
a^{2k}=(a^k)^2
\]

and:

\[
a^{2k+1}=a(a^k)^2
\]

By repeatedly halving the exponent, the number of multiplications becomes:

\[
O(\log n)
\]

rather than:

\[
O(n)
\]

The algorithm also reduces after every multiplication and squaring.

Python's built-in:

`pow(base, exponent, modulus)`

is an optimized implementation for modular exponentiation and is generally preferable in production Python code.

---

## 16. Extended Euclidean Algorithm

The Extended Euclidean Algorithm calculates integers \(x\) and \(y\) satisfying:

\[
ax+by=\gcd(a,b)
\]

This is known as a **Bézout identity**.

For example, if:

\[
a=30,\qquad b=12
\]

then:

\[
\gcd(30,12)=6
\]

and there exist integers \(x,y\) such that:

\[
30x+12y=6
\]

The Extended Euclidean Algorithm is especially important because it provides the coefficient required to compute modular inverses.

Its time complexity is logarithmic in the magnitude of the input values.

---

## 17. Modular Multiplicative Inverse

The modular inverse of \(a\) modulo \(m\) is a number \(x\) satisfying:

\[
ax\equiv1\pmod m
\]

An inverse exists exactly when:

\[
\gcd(a,m)=1
\]

For example:

\[
3^{-1}\equiv5\pmod7
\]

because:

\[
3\times5=15
\]

and:

\[
15\bmod7=1
\]

The Extended Euclidean Algorithm can find the inverse efficiently.

The script's `modular_inverse()` function rejects non-invertible values.

For example, 6 has no inverse modulo 15 because:

\[
\gcd(6,15)=3
\]

rather than 1.

---

## 18. Modular Division

Division is fundamentally different from addition, subtraction, and multiplication.

In modular arithmetic, dividing by \(b\) means multiplying by the modular inverse of \(b\):

\[
\frac{a}{b}\equiv a b^{-1}\pmod m
\]

This is valid only if:

\[
\gcd(b,m)=1
\]

For example:

\[
10/3\pmod7
\]

Since:

\[
3^{-1}\equiv5\pmod7
\]

we obtain:

\[
10\times5\bmod7
\]

which is:

\[
1
\]

Ordinary division cannot simply be substituted into modular arithmetic.

---

## 19. Cancellation

Cancellation requires care.

In ordinary arithmetic, if:

\[
ac=bc
\]

we can cancel \(c\).

In modular arithmetic, from:

\[
ac\equiv bc\pmod m
\]

we may cancel \(c\) when:

\[
\gcd(c,m)=1
\]

Without this condition, cancellation can fail.

For example:

\[
2(1)\equiv2(4)\pmod6
\]

because both sides are congruent to 2 modulo 6.

But:

\[
1\not\equiv4\pmod6
\]

Therefore the factor 2 cannot be cancelled modulo 6.

The reason is that 2 is not invertible modulo 6.

---

## 20. Linear Congruences

A linear congruence has the form:

\[
ax\equiv b\pmod m
\]

Let:

\[
d=\gcd(a,m)
\]

A solution exists if and only if:

\[
d\mid b
\]

If a solution exists, there are exactly \(d\) distinct solutions modulo \(m\).

The script implements `solve_linear_congruence()` and handles both unique-solution and multiple-solution cases.

For example:

\[
6x\equiv8\pmod{15}
\]

has:

\[
\gcd(6,15)=3
\]

but 3 does not divide 8, so there is no solution.

By contrast:

\[
6x\equiv9\pmod{15}
\]

has solutions because 3 divides 9.

---

## 21. Chinese Remainder Theorem

The Chinese Remainder Theorem concerns systems such as:

\[
x\equiv2\pmod3
\]

\[
x\equiv3\pmod5
\]

\[
x\equiv2\pmod7
\]

When the moduli are pairwise coprime, there is exactly one solution modulo their product:

\[
3\times5\times7=105
\]

The script computes the smallest nonnegative solution.

The standard construction uses:

\[
M=m_1m_2\cdots m_k
\]

and:

\[
M_i=\frac{M}{m_i}
\]

Then an inverse of \(M_i\) modulo \(m_i\) is used to construct the solution.

The implementation requires pairwise-coprime moduli.

More general versions of the Chinese Remainder Theorem can handle non-coprime moduli, but additional compatibility conditions are required.

---

## 22. Repeated-Doubling Modular Multiplication

Python integers have arbitrary precision, so ordinary multiplication is generally safe from fixed-width integer overflow.

Languages using fixed-width integers face a different problem.

Even if the desired result is:

\[
ab\bmod m
\]

the intermediate product \(ab\) may overflow.

The script therefore includes `multiply_mod_by_repeated_doubling()`.

It calculates the product through repeated doubling, similar to binary multiplication:

- inspect the lowest bit of the multiplier
- add the current multiplicand when that bit is set
- double the multiplicand modulo \(m\)
- shift the multiplier right

Its complexity is:

\[
O(\log b)
\]

This technique is useful for understanding overflow-aware arithmetic and algorithms used in lower-level numerical environments.

---

## 23. Addition, Subtraction and Multiplication Tables

For a small modulus, it is useful to visualize the entire operation.

Modulo 5, the residue set is:

\[
\{0,1,2,3,4\}
\]

The script generates:

- addition tables
- subtraction tables
- multiplication tables

These tables make several structural properties visible.

For multiplication, only residues relatively prime to the modulus have multiplicative inverses.

---

## 24. Multiplicative Units

A **unit modulo \(m\)** is a residue having a multiplicative inverse.

A residue \(a\) is a unit exactly when:

\[
\gcd(a,m)=1
\]

For example, modulo 10:

\[
1,3,7,9
\]

are units because each is relatively prime to 10.

Values such as 2, 4, 5, 6, and 8 are not units because they share a nontrivial factor with 10.

The set of units modulo \(m\) forms the multiplicative group commonly denoted:

\[
(\mathbb Z/m\mathbb Z)^\times
\]

---

## 25. Fermat's Little Theorem

If \(p\) is prime and \(p\nmid a\), Fermat's Little Theorem states:

\[
a^{p-1}\equiv1\pmod p
\]

This gives a useful inverse formula:

\[
a^{-1}\equiv a^{p-2}\pmod p
\]

when \(p\) is prime and \(a\) is nonzero modulo \(p\).

For example, modulo 7:

\[
3^{-1}\equiv3^5\pmod7
\]

which evaluates to 5.

The Extended Euclidean Algorithm is more general because it does not require the modulus to be prime.

---

## 26. Important Distinction: Prime Versus Composite Modulus

Many modular properties work for any positive modulus.

For example:

\[
(a+b)\bmod m
\]

and:

\[
(ab)\bmod m
\]

are valid for arbitrary positive \(m\).

Some stronger results require special conditions.

### Modular inverse

Requires:

\[
\gcd(a,m)=1
\]

### Fermat's Little Theorem

Requires a prime modulus \(p\) and \(p\nmid a\).

### Field structure

The integers modulo a prime \(p\) form a field:

\[
\mathbb F_p
\]

For composite \(m\), \(\mathbb Z/m\mathbb Z\) generally contains nonzero zero-divisors and does not form a field.

---

## 27. Zero Divisors

A nonzero residue \(a\) modulo \(m\) is a zero divisor if there exists a nonzero residue \(b\) such that:

\[
ab\equiv0\pmod m
\]

For example, modulo 6:

\[
2\times3=6\equiv0\pmod6
\]

even though neither 2 nor 3 is zero modulo 6.

This explains why ordinary cancellation rules can fail in modular arithmetic over composite moduli.

---

## 28. Common Mistakes

### Mistake 1: Treating modular division as ordinary division

Incorrect reasoning:

\[
a/b\pmod m
\]

does not generally mean dividing the ordinary representatives.

Correct reasoning:

\[
a/b\equiv ab^{-1}\pmod m
\]

provided \(b\) is invertible.

### Mistake 2: Assuming every nonzero residue has an inverse

This is false for composite moduli.

The correct condition is:

\[
\gcd(a,m)=1
\]

### Mistake 3: Ignoring negative values

Negative intermediate results are allowed.

They must simply be normalized to the appropriate residue.

### Mistake 4: Cancelling arbitrary factors

Cancellation requires an invertibility condition.

### Mistake 5: Computing enormous powers before taking the modulus

For large exponents, modular exponentiation should reduce intermediate values continuously.

### Mistake 6: Using an invalid modulus

Zero is not a valid modulus in this framework.

---

## 29. Edge Cases

Important cases covered by the script include:

- zero operands
- negative operands
- negative intermediate subtraction results
- modulus 1
- modulus 0
- negative modulus rejection
- operands larger than the modulus
- operands much smaller than the modulus
- non-invertible divisors
- multiple solutions to linear congruences
- systems with incompatible or non-coprime moduli

Edge-case handling is essential because modular algorithms often depend on divisibility and greatest-common-divisor conditions.

---

## 30. Performance Considerations

### Addition

A basic modular addition requires constant-time arithmetic for fixed-size machine integers.

For arbitrary-precision integers, complexity depends on the number of digits.

### Subtraction

The same general principle applies to subtraction.

### Multiplication

The complexity depends on integer size. For large integers, multiplication is substantially more expensive than addition.

### Modular exponentiation

Naive repeated multiplication requires approximately:

\[
O(n)
\]

multiplications for exponent \(n\).

Binary exponentiation requires:

\[
O(\log n)
\]

modular multiplications.

This difference becomes substantial for large exponents.

### Modular inverse

The Extended Euclidean Algorithm runs in logarithmic time with respect to the magnitude of the inputs.

### Repeated-doubling multiplication

Repeated doubling takes:

\[
O(\log b)
\]

iterations for multiplier \(b\).

In Python, the built-in integer implementation generally makes direct modular multiplication preferable unless there is a specific algorithmic reason to avoid forming the full product.

---

## 31. Security Considerations

Modular arithmetic is fundamental to many cryptographic systems, but implementing a cryptographic algorithm correctly requires more than merely using modular addition or multiplication.

Important considerations include:

- large integer arithmetic
- modular exponentiation
- modular inverses
- prime numbers
- random number generation
- key generation
- side-channel resistance
- constant-time implementations
- secure parameter selection
- protection of secret values

The simple educational algorithms in this script are intended to explain mathematical mechanisms. They should not automatically be treated as cryptographic implementations.

In particular, timing behavior can matter when secret values influence the execution path. Cryptographic libraries often provide specialized implementations designed to reduce such leakage.

---

## 32. Implementation Considerations

A production implementation should:

1. Validate the modulus.
2. Clearly define whether negative moduli are allowed.
3. Normalize residues consistently.
4. Check invertibility before modular division.
5. Use efficient modular exponentiation for large powers.
6. Avoid unnecessary conversion between different numeric representations.
7. Test boundary conditions.
8. Verify algebraic invariants.
9. Distinguish mathematical requirements from programming-language behavior.

Python's arbitrary-precision integers eliminate many fixed-width overflow concerns, but they do not eliminate performance costs associated with extremely large integers.

---

## 33. Testing Strategy

The script includes automated tests covering:

- addition
- subtraction
- multiplication
- congruence preservation
- modular exponentiation
- modular inverses
- repeated-doubling multiplication

The tests use many small values, including negative operands.

A useful invariant for modular operations is:

\[
0\leq r<m
\]

for a positive modulus \(m\).

For modular inverses, the verification condition is:

\[
(a\cdot a^{-1})\bmod m=1
\]

For a solution \(x\) to a linear congruence:

\[
ax\equiv b\pmod m
\]

the implementation verifies:

\[
(ax-b)\bmod m=0
\]

---

## 34. Practical Application: Cyclic Indexing

Modular arithmetic is useful whenever data wraps around.

For a collection containing \(n\) elements, the index:

\[
(i+k)\bmod n
\]

always maps back into the valid index range.

This is useful for:

- circular buffers
- ring queues
- cyclic schedules
- rotating arrays
- periodic state machines

The script demonstrates cyclic indexing with a five-element sequence.

---

## 35. Practical Application: Checksums

A simple checksum can be constructed as:

\[
C=\sum_i x_i\bmod m
\]

Changing an input value may change the checksum.

This illustrates the role of modular arithmetic in lightweight integrity checks.

A simple modular checksum is not a cryptographic integrity mechanism. Stronger systems use algorithms specifically designed to provide stronger detection or cryptographic guarantees.

---

## 36. Practical Application: Rolling Hashes

The script implements a simple polynomial-style rolling hash step:

\[
H_{\text{new}}
=
(H_{\text{old}}\times B+c)\bmod M
\]

where:

- \(H_{\text{old}}\) is the previous hash value
- \(B\) is a chosen base
- \(c\) represents the current character
- \(M\) is the modulus

This illustrates how modular multiplication and addition can be combined to maintain a bounded numerical state.

Rolling hashes are useful in algorithmic string processing and pattern matching.

A rolling hash should not be confused with a cryptographic hash function.

---

## 37. Practical Application: Cryptographic Arithmetic

Many cryptographic algorithms rely heavily on modular arithmetic.

Typical operations include:

\[
a+b\bmod m
\]

\[
ab\bmod m
\]

\[
a^e\bmod m
\]

and modular inversion.

Public-key cryptography commonly involves very large integers, making efficient modular exponentiation and multiplication essential.

The mathematical foundations introduced in the script therefore extend well beyond simple remainder calculations.

---

## 38. Relationship Between Addition, Subtraction and Multiplication

The three requested operations have a particularly important property:

If:

\[
a\equiv a'\pmod m
\]

and:

\[
b\equiv b'\pmod m
\]

then:

\[
a+b\equiv a'+b'\pmod m
\]

\[
a-b\equiv a'-b'\pmod m
\]

and:

\[
ab\equiv a'b'\pmod m
\]

This means modular operations are well-defined on residue classes rather than depending on a particular integer representative.

That property is the algebraic foundation of modular arithmetic.

---

## 39. Conceptual Progression in the Python Script

The script follows a deliberate progression:

1. Remainders
2. Congruence
3. Modular addition
4. Modular subtraction
5. Modular multiplication
6. Negative operands
7. Algebraic properties
8. Reduction rules
9. Clock arithmetic
10. Modular integer abstraction
11. Binary modular exponentiation
12. Extended Euclidean Algorithm
13. Modular inverses
14. Modular division
15. Linear congruences
16. Chinese Remainder Theorem
17. Repeated-doubling multiplication
18. Operation tables
19. Multiplicative units
20. Fermat's Little Theorem
21. Edge cases
22. Cancellation
23. Automated testing
24. Performance
25. Practical applications

The implementations are executable rather than merely presenting formulas, allowing the mathematical rules to be verified directly.

---

## 40. Core Formulas

The most important formulas implemented in the script are:

### Addition

\[
(a+b)\bmod m
\]

### Subtraction

\[
(a-b)\bmod m
\]

### Multiplication

\[
(ab)\bmod m
\]

### Congruence

\[
a\equiv b\pmod m
\iff
m\mid(a-b)
\]

### Modular inverse

\[
aa^{-1}\equiv1\pmod m
\]

with:

\[
\gcd(a,m)=1
\]

### Modular division

\[
a/b\equiv ab^{-1}\pmod m
\]

when \(b\) is invertible.

### Linear congruence

\[
ax\equiv b\pmod m
\]

with a solution exactly when:

\[
\gcd(a,m)\mid b
\]

### Binary modular exponentiation

\[
a^n\bmod m
\]

computed using repeated squaring.

---

## 41. Mathematical Structure

The residue classes modulo \(m\) form the ring:

\[
\mathbb Z/m\mathbb Z
\]

with modular addition and multiplication.

The additive structure contains an identity element:

\[
0
\]

because:

\[
a+0\equiv a\pmod m
\]

Every residue also has an additive inverse:

\[
-a
\]

because:

\[
a+(-a)\equiv0\pmod m
\]

Multiplicative inverses are more restrictive. Only units satisfy the required invertibility condition.

When \(m\) is prime, every nonzero residue is invertible, producing a finite field.

---

## 42. Limitations of Simple Modular Arithmetic

Modular arithmetic preserves many familiar algebraic rules, but not every operation behaves like ordinary arithmetic.

The main limitations are:

- division is conditional
- cancellation is conditional
- nonzero zero-divisors can exist for composite moduli
- modular equality is different from ordinary integer equality
- information about the original integer is discarded after reduction
- some algorithms require coprime or prime moduli

Understanding these distinctions prevents incorrect algebraic manipulation.

---

## 43. File Execution

The Python file is self-contained and requires no external dependencies.

The standard execution path runs the educational demonstrations and automated tests.

The interactive calculator is implemented as a separate function so that importing or executing the script does not unexpectedly wait for keyboard input.

The script can therefore be used both as an executable tutorial and as a module containing reusable functions.
