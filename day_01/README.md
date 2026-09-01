# Day 1: Introduction to Number Theory

Welcome to **Day 1 of Mathematical Foundations for Cybersecurity**.

This lesson introduces the basic concepts of **Number Theory** and implements those concepts using Python.

Number theory is one of the most important mathematical foundations of cybersecurity and cryptography.

It provides the mathematical foundation for technologies such as:

* RSA
* Diffie-Hellman
* Digital signatures
* Elliptic Curve Cryptography
* Hash functions
* Modular arithmetic
* Public-key cryptography
* Zero-knowledge proofs
* Post-quantum cryptography

The goal of this lesson is not only to learn mathematical definitions, but also to understand how these concepts can be implemented programmatically.

---

# 1. Learning objectives

After completing this lesson, you should understand:

1. What number theory is
2. Natural numbers
3. Whole numbers
4. Integers
5. Even and odd numbers
6. Factors
7. Multiples
8. Prime numbers
9. Composite numbers
10. Divisibility
11. Greatest Common Divisor
12. Least Common Multiple
13. Prime factorization
14. Perfect numbers
15. Coprime numbers
16. Modular arithmetic
17. Modular exponentiation
18. Euler's Totient Function
19. Sieve of Eratosthenes
20. Why number theory is important in cryptography

You will also learn how to implement these concepts in Python.

---

# 2. What is number theory?

Number theory is a branch of mathematics that studies **integers and their properties**.

For example:

```text
1, 2, 3, 4, 5, 6, 7, 8, 9, 10...
```

Number theory investigates questions such as:

* Is a number prime?
* What are the factors of a number?
* Can one number be divided by another?
* What is the greatest common divisor?
* What is the least common multiple?
* How can a number be represented as a product of primes?
* What happens when arithmetic is performed using a modulus?

These questions become extremely important in cryptography.

---

# 3. Types of numbers

## 3.1 Natural numbers

Natural numbers are counting numbers.

```text
1, 2, 3, 4, 5, 6, ...
```

Depending on the mathematical convention, some definitions include 0.

---

## 3.2 Whole numbers

Whole numbers include zero and positive integers.

```text
0, 1, 2, 3, 4, 5, ...
```

---

## 3.3 Integers

Integers include positive numbers, negative numbers and zero.

```text
..., -3, -2, -1, 0, 1, 2, 3, ...
```

Python represents integers using the `int` data type.

Example:

```python
x = 25
y = -10
z = 0
```

---

# 4. Even and odd numbers

An integer is **even** if it is divisible by 2.

Examples:

```text
2
4
6
8
10
12
```

An integer is **odd** if it is not divisible by 2.

Examples:

```text
1
3
5
7
9
11
```

Python uses the modulo operator `%`.

```python
number % 2
```

If the result is:

```text
0
```

the number is even.

Example:

```python
10 % 2
```

Result:

```text
0
```

Therefore 10 is even.

---

# 5. Factors

A factor is a number that divides another number without leaving a remainder.

Consider:

```text
12
```

The factors of 12 are:

```text
1, 2, 3, 4, 6, 12
```

Because:

```text
12 ÷ 1 = 12
12 ÷ 2 = 6
12 ÷ 3 = 4
12 ÷ 4 = 3
12 ÷ 6 = 2
12 ÷ 12 = 1
```

In Python:

```python
12 % 3
```

returns:

```text
0
```

Therefore 3 is a factor of 12.

---

# 6. Multiples

Multiples are obtained by multiplying a number by integers.

For example, multiples of 5 are:

```text
5
10
15
20
25
30
35
40
...
```

Mathematically:

```text
5 × 1 = 5
5 × 2 = 10
5 × 3 = 15
...
```

Python:

```python
def find_multiples(number, count):
    multiples = []

    for i in range(1, count + 1):
        multiples.append(number * i)

    return multiples
```

---

# 7. Prime numbers

A prime number is a positive integer greater than 1 that has exactly two positive factors:

```text
1
itself
```

Examples:

```text
2
3
5
7
11
13
17
19
23
29
```

For example:

```text
7
```

has only:

```text
1 × 7
```

Therefore 7 is prime.

But:

```text
12
```

has:

```text
1
2
3
4
6
12
```

Therefore 12 is not prime.

---

# 8. Why is 2 special?

2 is the smallest prime number.

It is also the only even prime number.

Every other even number can be divided by 2.

For example:

```text
4 = 2 × 2
6 = 2 × 3
8 = 2 × 4
10 = 2 × 5
```

Therefore they are composite.

---

# 9. Checking whether a number is prime

A simple approach is to test every number from 2 to `n - 1`.

But that is inefficient.

We can improve the algorithm by checking only up to:

```text
√n
```

Why?

Suppose:

```text
n = a × b
```

If both `a` and `b` were greater than √n, then:

```text
a × b > n
```

which is impossible.

Therefore, if a number has a factor, at least one factor must be less than or equal to √n.

The program uses:

```python
for i in range(2, int(math.sqrt(number)) + 1):
```

---

# 10. Composite numbers

A composite number has more than two positive factors.

Examples:

```text
4
6
8
9
10
12
14
15
```

For example:

```text
9
```

has:

```text
1
3
9
```

Therefore it is composite.

---

# 11. GCD

GCD means:

**Greatest Common Divisor**

It is the largest number that divides two numbers without leaving a remainder.

Example:

```text
48
18
```

Factors of 48:

```text
1, 2, 3, 4, 6, 8, 12, 16, 24, 48
```

Factors of 18:

```text
1, 2, 3, 6, 9, 18
```

Common factors:

```text
1, 2, 3, 6
```

Therefore:

```text
GCD(48, 18) = 6
```

---

# 12. Euclidean algorithm

The program calculates GCD using the **Euclidean Algorithm**.

The fundamental relationship is:

```text
gcd(a, b) = gcd(b, a mod b)
```

Example:

```text
gcd(48, 18)

48 mod 18 = 12

gcd(18, 12)

18 mod 12 = 6

gcd(12, 6)

12 mod 6 = 0
```

Therefore:

```text
GCD = 6
```

Python implementation:

```python
while b != 0:
    a, b = b, a % b
```

This algorithm is extremely important in cryptography.

---

# 13. LCM

LCM means:

**Least Common Multiple**

It is the smallest positive number that is divisible by both numbers.

Example:

```text
12 and 18
```

Multiples of 12:

```text
12, 24, 36, 48, 60...
```

Multiples of 18:

```text
18, 36, 54, 72...
```

Therefore:

```text
LCM(12, 18) = 36
```

There is an important relationship:

```text
LCM(a,b) × GCD(a,b) = |a × b|
```

Therefore:

```text
LCM(a,b) = |a × b| / GCD(a,b)
```

---

# 14. Divisibility

Divisibility asks whether one number can be divided by another without a remainder.

Example:

```text
100 ÷ 10 = 10
```

Therefore:

```text
10 divides 100
```

In Python:

```python
100 % 10 == 0
```

returns:

```text
True
```

---

# 15. Prime factorization

Prime factorization means expressing a number as a product of prime numbers.

Example:

```text
60
```

We can break it down:

```text
60 = 2 × 30

30 = 2 × 15

15 = 3 × 5
```

Therefore:

```text
60 = 2 × 2 × 3 × 5
```

or:

```text
60 = 2² × 3 × 5
```

The Python program returns:

```python
[2, 2, 3, 5]
```

Prime factorization is fundamental to cryptography.

---

# 16. Why prime factorization matters in cryptography

Consider two large prime numbers:

```text
p
q
```

Multiplying them is relatively easy:

```text
n = p × q
```

But if someone only knows:

```text
n
```

finding the original:

```text
p
q
```

can be computationally difficult when the numbers are extremely large.

This idea is related to the security assumptions historically used by **RSA**.

For example:

```text
61 × 53 = 3233
```

If we know:

```text
61
53
```

multiplication is easy.

Given:

```text
3233
```

we can factor it because the numbers are small.

Cryptographic systems use enormously larger numbers.

---

# 17. Coprime numbers

Two numbers are coprime if their GCD is 1.

Example:

```text
8 and 15
```

Factors of 8:

```text
1, 2, 4, 8
```

Factors of 15:

```text
1, 3, 5, 15
```

Their only common factor is:

```text
1
```

Therefore:

```text
GCD(8,15) = 1
```

So they are coprime.

Python:

```python
calculate_gcd(8, 15) == 1
```

---

# 18. Perfect numbers

A perfect number is equal to the sum of its proper divisors.

Consider:

```text
6
```

Proper divisors:

```text
1, 2, 3
```

Sum:

```text
1 + 2 + 3 = 6
```

Therefore:

```text
6
```

is a perfect number.

Another example:

```text
28
```

Proper divisors:

```text
1, 2, 4, 7, 14
```

Sum:

```text
1 + 2 + 4 + 7 + 14 = 28
```

Therefore:

```text
28
```

is also perfect.

---

# 19. Modular arithmetic

Modular arithmetic is one of the most important concepts for cryptography.

It is sometimes described as **clock arithmetic**.

Consider a 12-hour clock.

After:

```text
12 + 1
```

we get:

```text
1
```

Mathematically:

```text
13 mod 12 = 1
```

The notation:

```text
a mod n
```

means the remainder when `a` is divided by `n`.

Example:

```text
17 mod 5 = 2
```

because:

```text
17 = 5 × 3 + 2
```

---

# 20. Modulo operator in Python

Python uses:

```python
%
```

Example:

```python
17 % 5
```

Output:

```text
2
```

Another example:

```python
100 % 10
```

Output:

```text
0
```

---

# 21. Modular addition

Suppose:

```text
a = 17
b = 8
m = 5
```

Then:

```text
(17 + 8) mod 5
```

becomes:

```text
25 mod 5
```

Therefore:

```text
0
```

Python:

```python
(17 + 8) % 5
```

---

# 22. Modular multiplication

Example:

```text
17 × 8 mod 5
```

First:

```text
17 × 8 = 136
```

Then:

```text
136 mod 5 = 1
```

Therefore:

```text
17 × 8 ≡ 1 (mod 5)
```

---

# 23. Modular exponentiation

Modular exponentiation involves calculations such as:

```text
a^b mod n
```

Example:

```text
2^10 mod 1000
```

Since:

```text
2^10 = 1024
```

we get:

```text
1024 mod 1000 = 24
```

Python has an extremely useful built-in function:

```python
pow(base, exponent, modulus)
```

Example:

```python
pow(2, 10, 1000)
```

Output:

```text
24
```

This is much more useful than calculating:

```python
2 ** 10 % 1000
```

for very large values because Python's three-argument `pow()` performs modular exponentiation efficiently.

---

# 24. Euler's Totient Function

Euler's Totient Function is represented as:

```text
φ(n)
```

It counts how many integers from:

```text
1 to n
```

are relatively prime to `n`.

Consider:

```text
n = 8
```

Numbers from 1 to 8:

```text
1
2
3
4
5
6
7
8
```

Numbers coprime with 8:

```text
1
3
5
7
```

Therefore:

```text
φ(8) = 4
```

Euler's Totient Function is extremely important in classical public-key cryptography, especially RSA.

---

# 25. Sieve of Eratosthenes

The Sieve of Eratosthenes is an efficient algorithm for finding prime numbers.

Suppose we want all primes up to:

```text
30
```

Start with:

```text
2, 3, 4, 5, 6, 7, 8, 9, ...
```

Start with 2.

Mark its multiples:

```text
4, 6, 8, 10, 12...
```

Then move to 3.

Mark:

```text
6, 9, 12, 15...
```

Continue until the required limit.

The remaining unmarked numbers are prime.

The Python implementation is:

```python
def sieve_of_eratosthenes(limit):

    is_prime_number = [True] * (limit + 1)

    is_prime_number[0] = False
    is_prime_number[1] = False

    p = 2

    while p * p <= limit:

        if is_prime_number[p]:

            for multiple in range(p * p, limit + 1, p):
                is_prime_number[multiple] = False

        p += 1

    return [
        number
        for number in range(2, limit + 1)
        if is_prime_number[number]
    ]
```

---

# 26. Running the program

Open your terminal in the project directory.

Run:

```bash
python day_001_number_theory.py
```

You should see output similar to:

```text
============================================================
INTRODUCTION TO NUMBER THEORY
============================================================

1. Even/Odd
12 is Even

2. Factors
Factors of 12: [1, 2, 3, 4, 6, 12]

3. Multiples
First 10 multiples of 5: [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]

4. Prime Check
29 is a prime number.

5. Prime Numbers
Primes up to 50: [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
```

---

# 27. Important Python concepts learned

This program also introduces several Python programming concepts.

## Variables

```python
number = 12
```

## Functions

```python
def is_prime(number):
    ...
```

## Conditional statements

```python
if number % 2 == 0:
    print("Even")
```

## Loops

```python
for i in range(1, number + 1):
    ...
```

## While loops

```python
while b != 0:
    ...
```

## Lists

```python
factors = []
```

## List append

```python
factors.append(i)
```

## Exception handling

```python
try:
    ...
except ValueError:
    ...
```

## Modules

```python
import math
```

## Main program entry point

```python
if __name__ == "__main__":
    basic_demo()
```

---

# 28. Complexity awareness

Understanding algorithms also means understanding how efficiently they run.

The basic factor-finding implementation checks:

```text
1 → n
```

so its complexity is approximately:

```text
O(n)
```

The prime-checking implementation only checks up to:

```text
√n
```

so its complexity is approximately:

```text
O(√n)
```

The Sieve of Eratosthenes is significantly more efficient for generating many primes.

Its time complexity is approximately:

```text
O(n log log n)
```

Understanding computational complexity becomes very important when we work with cryptographic algorithms.

---

# 29. Number theory and cybersecurity

Number theory is not just academic mathematics.

It forms part of the foundation of modern cybersecurity.

A simplified relationship is:

```text
Number Theory
      │
      ├── Prime Numbers
      │       │
      │       └── RSA
      │
      ├── Modular Arithmetic
      │       │
      │       ├── RSA
      │       ├── Diffie-Hellman
      │       └── Cryptographic Algorithms
      │
      ├── GCD
      │       │
      │       └── Modular Inverses
      │
      ├── Euler's Totient
      │       │
      │       └── RSA Mathematics
      │
      └── Prime Factorization
              │
              └── RSA Security Assumption
```

The important point is:

```text
Mathematics
     ↓
Algorithms
     ↓
Cryptography
     ↓
Cybersecurity
```

---

# 30. Exercises

Complete these exercises without looking at the solution first.

## Exercise 1

Write a function that determines whether a number is positive, negative, or zero.

Example:

```text
Input: 10
Output: Positive
```

---

## Exercise 2

Write a function that returns the number of factors of a given number.

Example:

```text
Input: 12
Output: 6
```

---

## Exercise 3

Write a function that finds the smallest prime number greater than a given number.

Example:

```text
Input: 10
Output: 11
```

---

## Exercise 4

Write a function that generates all prime numbers between two numbers.

Example:

```text
Input:
10
30

Output:
11, 13, 17, 19, 23, 29
```

---

## Exercise 5

Write your own GCD algorithm without using:

```python
math.gcd()
```

---

## Exercise 6

Write your own LCM algorithm.

---

## Exercise 7

Find the prime factorization of:

```text
100
```

Expected:

```text
2 × 2 × 5 × 5
```

---

## Exercise 8

Find all perfect numbers between:

```text
1 and 10000
```

---

## Exercise 9

Calculate:

```text
7^20 mod 13
```

Use Python's:

```python
pow()
```

---

## Exercise 10

Calculate:

```text
φ(10)
φ(12)
φ(15)
φ(20)
```

---

# 31. Challenge project

Build a **Number Theory Analyzer**.

The program should accept an integer from the user and display:

```text
Number
│
├── Even / Odd
├── Prime / Composite
├── Factors
├── Number of Factors
├── Prime Factorization
├── Perfect Number?
├── Sum of Proper Divisors
└── Euler Totient
```

Example:

```text
Enter number: 60

Number: 60
Type: Composite

Factors:
1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30, 60

Number of factors:
12

Prime factorization:
2 × 2 × 3 × 5

Perfect number:
No

Euler Totient:
16
```

This is your first small mathematical programming project.

---

# 32. Connection to the next lessons

This lesson provides the foundation for the upcoming cryptography topics.

Recommended progression:

```text
Day 001
Number Theory
     ↓
Day 002
Modular Arithmetic
     ↓
Day 003
GCD & Extended Euclidean Algorithm
     ↓
Day 004
Modular Inverses
     ↓
Day 005
Prime Numbers & Primality Testing
     ↓
Day 006
Fermat's Little Theorem
     ↓
Day 007
Euler's Theorem
     ↓
Day 008
Chinese Remainder Theorem
     ↓
Day 009
RSA Mathematics
     ↓
Day 010
RSA Implementation
```

This progression will eventually take you from basic mathematics to practical cryptography.

---

# 33. Key takeaways

Remember these concepts:

```text
Factor
    ↓
A number that divides another number exactly

Prime
    ↓
A number greater than 1 with exactly two factors

GCD
    ↓
Largest common divisor

LCM
    ↓
Smallest common multiple

Coprime
    ↓
Two numbers whose GCD is 1

Modulo
    ↓
Remainder after division

Prime Factorization
    ↓
Representing a number as a product of primes

Euler's Totient
    ↓
Count of integers relatively prime to n

Sieve
    ↓
Efficient method for generating primes
```

Most importantly:

```text
Number Theory
      ↓
Modular Arithmetic
      ↓
Cryptography
      ↓
Cybersecurity
```

---

# 34. Files for this lesson

The Day 1 directory should contain:

```text
day-001-number-theory/
│
├── README.md
│
└── day_001_number_theory.py
```

The `README.md` explains the mathematical concepts.

The `.py` file contains the practical implementation.

This separation is useful because your GitHub repository becomes both:

```text
Learning Documentation
+
Practical Code
```

which makes the project much easier for someone else to understand and follow.

