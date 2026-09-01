# Introduction to Number Theory

This lesson introduces the basic concepts of number theory and implements them using Python.

The Python program covers:

* Even and odd numbers
* Factors
* Multiples
* Prime numbers
* Prime number checking
* Generating prime numbers
* Greatest Common Divisor (GCD)
* Least Common Multiple (LCM)
* Divisibility
* Prime factorization
* Perfect numbers
* Coprime numbers
* Modular arithmetic
* Modular exponentiation
* Euler's Totient Function
* Sum of proper divisors
* Sieve of Eratosthenes

## What is number theory?

Number theory is a branch of mathematics that studies integers and their properties.

Examples of integers include:

```text
..., -3, -2, -1, 0, 1, 2, 3, ...
```

Number theory deals with concepts such as divisibility, factors, prime numbers, GCD, LCM, modular arithmetic and prime factorization.

## Even and odd numbers

An integer is even if it is completely divisible by 2.

Examples:

```text
2, 4, 6, 8, 10, 12
```

An integer is odd if it is not completely divisible by 2.

Examples:

```text
1, 3, 5, 7, 9, 11
```

Python uses the modulo operator `%` to determine whether a number is divisible by another number.

```python
10 % 2
```

Output:

```text
0
```

Therefore, 10 is even.

The program implements this concept using the `check_even_odd()` function.

```python
def check_even_odd(number):
    if number % 2 == 0:
        return "Even"
    else:
        return "Odd"
```

## Factors

A factor is a number that divides another number without leaving a remainder.

For example, the factors of 12 are:

```text
1, 2, 3, 4, 6, 12
```

This is because each of these numbers divides 12 exactly.

The program checks each number from 1 to the given number and uses the modulo operator to determine whether it is a factor.

```python
for i in range(1, number + 1):
    if number % i == 0:
        factors.append(i)
```

For example:

```python
find_factors(12)
```

returns:

```text
[1, 2, 3, 4, 6, 12]
```

## Multiples

Multiples are obtained by multiplying a number by positive integers.

The first 10 multiples of 5 are:

```text
5, 10, 15, 20, 25, 30, 35, 40, 45, 50
```

The program generates multiples using a loop.

```python
def find_multiples(number, count=10):
    multiples = []

    for i in range(1, count + 1):
        multiples.append(number * i)

    return multiples
```

For example:

```python
find_multiples(5)
```

returns:

```text
[5, 10, 15, 20, 25, 30, 35, 40, 45, 50]
```

## Prime numbers

A prime number is an integer greater than 1 that has exactly two positive factors:

```text
1
itself
```

Examples:

```text
2, 3, 5, 7, 11, 13, 17, 19
```

For example, the factors of 7 are:

```text
1, 7
```

Therefore, 7 is prime.

The number 9 is not prime because its factors are:

```text
1, 3, 9
```

A number greater than 1 that is not prime is called a composite number.

Examples of composite numbers:

```text
4, 6, 8, 9, 10, 12
```

## Checking whether a number is prime

The program contains an `is_prime()` function to determine whether a number is prime.

```python
def is_prime(number):
    if number <= 1:
        return False

    for i in range(2, int(math.sqrt(number)) + 1):
        if number % i == 0:
            return False

    return True
```

The program checks possible factors only up to the square root of the number.

For example, to check whether 29 is prime:

```text
√29 ≈ 5.38
```

Therefore, it is sufficient to check possible divisors up to 5.

The program uses:

```python
math.sqrt(number)
```

from Python's `math` module.

## Generating prime numbers

The program can generate all prime numbers up to a specified limit.

For example:

```python
generate_primes(30)
```

returns:

```text
[2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
```

The function uses the `is_prime()` function to test each number.

```python
def generate_primes(limit):
    primes = []

    for number in range(2, limit + 1):
        if is_prime(number):
            primes.append(number)

    return primes
```

## Greatest Common Divisor

GCD stands for Greatest Common Divisor.

The GCD of two numbers is the largest positive number that divides both numbers exactly.

For example:

```text
48 and 18
```

The common factors are:

```text
1, 2, 3, 6
```

Therefore:

```text
GCD(48, 18) = 6
```

## Euclidean Algorithm

The program calculates GCD using the Euclidean Algorithm.

The main relationship is:

```text
gcd(a, b) = gcd(b, a mod b)
```

For example:

```text
48 mod 18 = 12
18 mod 12 = 6
12 mod 6 = 0
```

Therefore:

```text
GCD(48, 18) = 6
```

The Python implementation uses a `while` loop:

```python
def calculate_gcd(a, b):
    a = abs(a)
    b = abs(b)

    while b != 0:
        a, b = b, a % b

    return a
```

The `abs()` function converts negative values into positive values.

## Least Common Multiple

LCM stands for Least Common Multiple.

It is the smallest positive number that is divisible by both numbers.

For example, the multiples of 12 are:

```text
12, 24, 36, 48, 60, ...
```

The multiples of 18 are:

```text
18, 36, 54, 72, ...
```

The first common multiple is 36.

Therefore:

```text
LCM(12, 18) = 36
```

The program uses the relationship:

```text
LCM(a, b) × GCD(a, b) = |a × b|
```

Therefore:

```text
LCM(a, b) = |a × b| / GCD(a, b)
```

The implementation is:

```python
def calculate_lcm(a, b):
    if a == 0 or b == 0:
        return 0

    gcd = calculate_gcd(a, b)

    return abs(a * b) // gcd
```

## Divisibility

A number is divisible by another number when there is no remainder after division.

For example:

```text
100 ÷ 10 = 10
```

Therefore, 100 is divisible by 10.

In Python:

```python
100 % 10 == 0
```

returns:

```text
True
```

The program implements this using:

```python
def check_divisibility(number, divisor):
    if divisor == 0:
        return False

    return number % divisor == 0
```

## Prime factorization

Prime factorization means expressing a number as a product of prime numbers.

For example:

```text
60
```

can be broken down as:

```text
60 = 2 × 30
30 = 2 × 15
15 = 3 × 5
```

Therefore:

```text
60 = 2 × 2 × 3 × 5
```

The program returns:

```text
[2, 2, 3, 5]
```

The function repeatedly divides the number by its prime factors.

```python
def prime_factorization(number):
    if number <= 1:
        return []

    factors = []

    while number % 2 == 0:
        factors.append(2)
        number //= 2

    factor = 3

    while factor * factor <= number:
        while number % factor == 0:
            factors.append(factor)
            number //= factor

        factor += 2

    if number > 1:
        factors.append(number)

    return factors
```

The `//` operator performs integer division.

For example:

```python
60 // 2
```

returns:

```text
30
```

## Perfect numbers

A perfect number is a number that is equal to the sum of its proper positive divisors.

For example:

```text
6
```

The proper divisors of 6 are:

```text
1, 2, 3
```

Their sum is:

```text
1 + 2 + 3 = 6
```

Therefore, 6 is a perfect number.

Another example is 28:

```text
1 + 2 + 4 + 7 + 14 = 28
```

The program uses the `is_perfect_number()` function to determine whether a number is perfect.

## Sum of proper divisors

A proper divisor is a positive divisor of a number excluding the number itself.

For example, the proper divisors of 12 are:

```text
1, 2, 3, 4, 6
```

Their sum is:

```text
1 + 2 + 3 + 4 + 6 = 16
```

The program provides:

```python
sum_proper_divisors(12)
```

which returns:

```text
16
```

## Coprime numbers

Two numbers are coprime if their GCD is 1.

For example:

```text
8 and 15
```

Their GCD is:

```text
GCD(8, 15) = 1
```

Therefore, 8 and 15 are coprime.

The program checks this using:

```python
def are_coprime(a, b):
    return calculate_gcd(a, b) == 1
```

Example:

```python
are_coprime(8, 15)
```

returns:

```text
True
```

## Modular arithmetic

Modular arithmetic deals with the remainder after division.

Python uses the `%` operator for modulo operations.

For example:

```python
17 % 5
```

returns:

```text
2
```

because:

```text
17 = 5 × 3 + 2
```

Therefore:

```text
17 mod 5 = 2
```

## Modular addition

The program provides a function for modular addition:

```python
def modular_addition(a, b, modulus):
    return (a + b) % modulus
```

For example:

```python
modular_addition(17, 8, 5)
```

calculates:

```text
(17 + 8) mod 5
```

which gives:

```text
25 mod 5 = 0
```

## Modular subtraction

The program implements modular subtraction using:

```python
def modular_subtraction(a, b, modulus):
    return (a - b) % modulus
```

For example:

```python
modular_subtraction(17, 8, 5)
```

calculates:

```text
(17 - 8) mod 5
```

which gives:

```text
9 mod 5 = 4
```

## Modular multiplication

The program implements modular multiplication using:

```python
def modular_multiplication(a, b, modulus):
    return (a * b) % modulus
```

For example:

```python
modular_multiplication(17, 8, 5)
```

calculates:

```text
(17 × 8) mod 5
```

Since:

```text
17 × 8 = 136
```

and:

```text
136 mod 5 = 1
```

the result is:

```text
1
```

## Modular exponentiation

Modular exponentiation involves calculations of the form:

```text
a^b mod m
```

For example:

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

Python provides the three-argument `pow()` function for efficient modular exponentiation.

```python
pow(2, 10, 1000)
```

returns:

```text
24
```

The program implements this using:

```python
def modular_power(base, exponent, modulus):
    return pow(base, exponent, modulus)
```

## Euler's Totient Function

Euler's Totient Function is represented by:

```text
φ(n)
```

It counts the positive integers from 1 to `n` that are coprime with `n`.

For example, consider:

```text
n = 8
```

The numbers from 1 to 8 that are coprime with 8 are:

```text
1, 3, 5, 7
```

Therefore:

```text
φ(8) = 4
```

The program calculates the function by checking the GCD of each number with `n`.

```python
def euler_totient(number):
    if number <= 0:
        return 0

    count = 0

    for i in range(1, number + 1):
        if calculate_gcd(i, number) == 1:
            count += 1

    return count
```

## Sieve of Eratosthenes

The Sieve of Eratosthenes is an algorithm used to generate prime numbers up to a given limit.

For example, to find primes up to 20, start with:

```text
2, 3, 4, 5, 6, 7, 8, 9, 10,
11, 12, 13, 14, 15, 16, 17, 18, 19, 20
```

Starting with 2, eliminate its multiples:

```text
4, 6, 8, 10, 12, 14, 16, 18, 20
```

Then consider 3 and eliminate its multiples:

```text
6, 9, 12, 15, 18
```

After continuing the process, the remaining numbers are prime:

```text
2, 3, 5, 7, 11, 13, 17, 19
```

The program implements the algorithm using a Boolean list:

```python
is_prime_number = [True] * (limit + 1)
```

Numbers identified as composite are changed from `True` to `False`.

The function can be used as:

```python
sieve_of_eratosthenes(100)
```

to generate all prime numbers up to 100.

## Python concepts practiced

The program also practices basic Python programming concepts.

### Variables

```python
number = 12
```

### Functions

```python
def is_prime(number):
    ...
```

### Conditional statements

```python
if number % 2 == 0:
    ...
else:
    ...
```

### For loops

```python
for i in range(1, number + 1):
    ...
```

### While loops

```python
while b != 0:
    ...
```

### Lists

```python
factors = []
```

### Adding items to a list

```python
factors.append(i)
```

### Modules

```python
import math
```

### Exception handling

The interactive calculator uses `try` and `except` to handle invalid input.

```python
try:
    ...
except ValueError:
    print("Invalid input.")
```

### Main program

The program uses:

```python
if __name__ == "__main__":
    basic_demo()
```

This allows the demonstration function to run when the file is executed directly.

## Running the program

Open the terminal in the folder containing the Python file and run:

```bash
python day_001_number_theory.py
```

The program will execute the demonstration section and display results for the different number theory operations.

## Interactive calculator

The Python file also contains an interactive number theory calculator.

The calculator can be enabled by uncommenting:

```python
interactive_calculator()
```

at the bottom of the Python file.

It provides options for:

```text
Check Even/Odd
Find Factors
Check Prime
Prime Factorization
Calculate GCD
Calculate LCM
Check Perfect Number
Euler Totient
Check Coprime
Modular Arithmetic
Generate Primes
Exit
```

The calculator accepts integer input from the user and performs the selected operation.

## Practice exercises

Try the following exercises using the functions implemented in the program.

Check whether these numbers are even or odd:

```text
25
48
73
100
```

Find the factors of:

```text
24
36
50
100
```

Check whether these numbers are prime:

```text
17
23
51
97
101
```

Calculate:

```text
GCD(24, 36)
GCD(48, 60)
GCD(81, 27)
GCD(101, 10)
```

Calculate:

```text
LCM(4, 6)
LCM(12, 15)
LCM(8, 20)
```

Find the prime factorization of:

```text
24
36
72
100
120
```

Check whether these are perfect numbers:

```text
6
28
12
100
496
```

Determine whether these pairs are coprime:

```text
(8, 15)
(12, 18)
(17, 20)
(21, 35)
```

Calculate:

```text
17 mod 5
25 mod 7
100 mod 9
123 mod 10
```

Use Python's `pow()` function to calculate:

```text
2^10 mod 100
3^5 mod 7
5^10 mod 13
7^20 mod 11
```

Calculate:

```text
φ(5)
φ(8)
φ(10)
φ(12)
φ(15)
```

Generate all prime numbers up to:

```text
50
100
200
```

using the `sieve_of_eratosthenes()` function.
