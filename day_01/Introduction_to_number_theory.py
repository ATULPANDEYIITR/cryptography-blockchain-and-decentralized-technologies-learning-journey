# Day 1: Introduction to Number Theory

# Python Program: day_001_number_theory.py

"""
Day 1 - Introduction to Number Theory

This program introduces fundamental concepts of number theory
using Python.

Topics covered:

1. Natural numbers
2. Whole numbers
3. Integers
4. Even and odd numbers
5. Positive and negative numbers
6. Factors
7. Multiples
8. Prime numbers
9. Composite numbers
10. Greatest Common Divisor (GCD)
11. Least Common Multiple (LCM)
12. Divisibility
13. Perfect numbers
14. Prime factorization
15. Euler's Totient Function
16. Modular arithmetic
17. Modular exponentiation
18. Simple number-theory demonstrations

This program is intentionally written in a beginner-friendly way.
"""

import math

# ============================================================

# 1. CHECK WHETHER A NUMBER IS EVEN OR ODD

# ============================================================

def check_even_odd(number):
"""
Determine whether a number is even or odd.

```
A number is even if it is completely divisible by 2.
A number is odd if it leaves a remainder of 1 when divided by 2.

Example:
    10 % 2 = 0  -> Even
    11 % 2 = 1  -> Odd
"""

if number % 2 == 0:
    return "Even"
else:
    return "Odd"
```

# ============================================================

# 2. FIND FACTORS OF A NUMBER

# ============================================================

def find_factors(number):
"""
Find all positive factors of a number.

```
A factor is a number that divides another number
without leaving a remainder.

Example:
    Factors of 12:
    1, 2, 3, 4, 6, 12
"""

if number <= 0:
    return []

factors = []

for i in range(1, number + 1):
    if number % i == 0:
        factors.append(i)

return factors
```

# ============================================================

# 3. FIND MULTIPLES OF A NUMBER

# ============================================================

def find_multiples(number, count=10):
"""
Find the first 'count' multiples of a number.

```
Example:
    Multiples of 5:
    5, 10, 15, 20, 25...
"""

multiples = []

for i in range(1, count + 1):
    multiples.append(number * i)

return multiples
```

# ============================================================

# 4. CHECK WHETHER A NUMBER IS PRIME

# ============================================================

def is_prime(number):
"""
Determine whether a number is prime.

```
A prime number:
- is greater than 1
- has exactly two positive factors:
  1 and itself

Examples:
    2 -> Prime
    3 -> Prime
    5 -> Prime
    7 -> Prime
    9 -> Not Prime
"""

if number <= 1:
    return False

# We only need to check up to sqrt(number).
# If a number has a factor larger than sqrt(number),
# it must also have a corresponding factor smaller
# than sqrt(number).

for i in range(2, int(math.sqrt(number)) + 1):
    if number % i == 0:
        return False

return True
```

# ============================================================

# 5. GENERATE PRIME NUMBERS UP TO N

# ============================================================

def generate_primes(limit):
"""
Generate all prime numbers from 2 up to 'limit'.
"""

```
primes = []

for number in range(2, limit + 1):
    if is_prime(number):
        primes.append(number)

return primes
```

# ============================================================

# 6. FIND GREATEST COMMON DIVISOR (GCD)

# ============================================================

def calculate_gcd(a, b):
"""
Calculate the Greatest Common Divisor (GCD).

```
GCD is the largest number that divides both numbers.

Example:
    GCD(12, 18) = 6

Euclidean Algorithm:

    gcd(a, b) = gcd(b, a % b)

until b becomes 0.
"""

a = abs(a)
b = abs(b)

while b != 0:
    a, b = b, a % b

return a
```

# ============================================================

# 7. FIND LEAST COMMON MULTIPLE (LCM)

# ============================================================

def calculate_lcm(a, b):
"""
Calculate the Least Common Multiple (LCM).

```
LCM is the smallest positive number that is
divisible by both numbers.

Relationship:

    LCM(a, b) * GCD(a, b) = |a * b|
"""

if a == 0 or b == 0:
    return 0

gcd = calculate_gcd(a, b)

return abs(a * b) // gcd
```

# ============================================================

# 8. CHECK DIVISIBILITY

# ============================================================

def check_divisibility(number, divisor):
"""
Check whether 'number' is divisible by 'divisor'.
"""

```
if divisor == 0:
    return False

return number % divisor == 0
```

# ============================================================

# 9. PRIME FACTORIZATION

# ============================================================

def prime_factorization(number):
"""
Find the prime factorization of a number.

```
Example:

    60 = 2 × 2 × 3 × 5

Therefore:

    prime_factorization(60)
    -> [2, 2, 3, 5]
"""

if number <= 1:
    return []

factors = []

# First check factor 2
while number % 2 == 0:
    factors.append(2)
    number //= 2

# Check odd factors
factor = 3

while factor * factor <= number:
    while number % factor == 0:
        factors.append(factor)
        number //= factor

    factor += 2

# If remaining number is greater than 1,
# it is itself a prime factor.
if number > 1:
    factors.append(number)

return factors
```

# ============================================================

# 10. CHECK WHETHER A NUMBER IS PERFECT

# ============================================================

def is_perfect_number(number):
"""
Determine whether a number is a perfect number.

```
A perfect number is equal to the sum of its
proper positive divisors.

Example:

    6

    Proper divisors:
    1, 2, 3

    1 + 2 + 3 = 6

    Therefore, 6 is a perfect number.
"""

if number <= 1:
    return False

divisors_sum = 1

for i in range(2, int(math.sqrt(number)) + 1):

    if number % i == 0:
        divisors_sum += i

        other_factor = number // i

        if other_factor != i:
            divisors_sum += other_factor

return divisors_sum == number
```

# ============================================================

# 11. MODULAR ARITHMETIC

# ============================================================

def modular_addition(a, b, modulus):
"""
Calculate:

```
    (a + b) mod m
"""

return (a + b) % modulus
```

def modular_subtraction(a, b, modulus):
"""
Calculate:

```
    (a - b) mod m
"""

return (a - b) % modulus
```

def modular_multiplication(a, b, modulus):
"""
Calculate:

```
    (a × b) mod m
"""

return (a * b) % modulus
```

# ============================================================

# 12. MODULAR EXPONENTIATION

# ============================================================

def modular_power(base, exponent, modulus):
"""
Calculate:

```
    base^exponent mod modulus

Python's built-in pow() can efficiently perform
modular exponentiation.

Example:

    2^10 mod 1000

    = 1024 mod 1000
    = 24
"""

return pow(base, exponent, modulus)
```

# ============================================================

# 13. EULER'S TOTIENT FUNCTION

# ============================================================

def euler_totient(number):
"""
Calculate Euler's Totient Function φ(n).

```
φ(n) counts the positive integers from 1 to n
that are relatively prime to n.

Two numbers are relatively prime if their GCD is 1.

Example:

    φ(8) = 4

    Numbers from 1 to 8 that are coprime with 8:

    1, 3, 5, 7
"""

if number <= 0:
    return 0

count = 0

for i in range(1, number + 1):

    if calculate_gcd(i, number) == 1:
        count += 1

return count
```

# ============================================================

# 14. CHECK WHETHER TWO NUMBERS ARE COPRIME

# ============================================================

def are_coprime(a, b):
"""
Two numbers are coprime if their GCD is 1.
"""

```
return calculate_gcd(a, b) == 1
```

# ============================================================

# 15. SUM OF PROPER DIVISORS

# ============================================================

def sum_proper_divisors(number):
"""
Calculate the sum of all proper divisors.

```
Proper divisors exclude the number itself.

Example:

    Proper divisors of 12:
    1, 2, 3, 4, 6

    Sum = 16
"""

if number <= 1:
    return 0

total = 1

for i in range(2, int(math.sqrt(number)) + 1):

    if number % i == 0:

        total += i

        other_factor = number // i

        if other_factor != i:
            total += other_factor

return total
```

# ============================================================

# 16. GENERATE PRIME NUMBERS USING SIEVE OF ERATOSTHENES

# ============================================================

def sieve_of_eratosthenes(limit):
"""
Generate prime numbers up to 'limit' using the
Sieve of Eratosthenes.

```
This is more efficient than individually checking
every number for primality.
"""

if limit < 2:
    return []

is_prime_number = [True] * (limit + 1)

is_prime_number[0] = False
is_prime_number[1] = False

p = 2

while p * p <= limit:

    if is_prime_number[p]:

        for multiple in range(p * p, limit + 1, p):
            is_prime_number[multiple] = False

    p += 1

primes = []

for number in range(2, limit + 1):

    if is_prime_number[number]:
        primes.append(number)

return primes
```

# ============================================================

# 17. DEMONSTRATE BASIC NUMBER THEORY

# ============================================================

def basic_demo():

```
print("=" * 60)
print("INTRODUCTION TO NUMBER THEORY")
print("=" * 60)

number = 12

print("\n1. Even/Odd")
print(f"{number} is {check_even_odd(number)}")

print("\n2. Factors")
print(f"Factors of {number}: {find_factors(number)}")

print("\n3. Multiples")
print(f"First 10 multiples of 5: {find_multiples(5)}")

print("\n4. Prime Check")

test_number = 29

if is_prime(test_number):
    print(f"{test_number} is a prime number.")
else:
    print(f"{test_number} is not a prime number.")

print("\n5. Prime Numbers")
print(f"Primes up to 50: {generate_primes(50)}")

print("\n6. GCD")

a = 48
b = 18

print(f"GCD({a}, {b}) = {calculate_gcd(a, b)}")

print("\n7. LCM")
print(f"LCM({a}, {b}) = {calculate_lcm(a, b)}")

print("\n8. Divisibility")

print(
    f"Is 100 divisible by 10? "
    f"{check_divisibility(100, 10)}"
)

print("\n9. Prime Factorization")

number = 60

print(
    f"Prime factorization of {number}: "
    f"{prime_factorization(number)}"
)

print("\n10. Perfect Number")

number = 28

print(
    f"Is {number} a perfect number? "
    f"{is_perfect_number(number)}"
)

print("\n11. Modular Arithmetic")

print(
    "17 + 8 mod 5 =",
    modular_addition(17, 8, 5)
)

print(
    "17 - 8 mod 5 =",
    modular_subtraction(17, 8, 5)
)

print(
    "17 × 8 mod 5 =",
    modular_multiplication(17, 8, 5)
)

print("\n12. Modular Exponentiation")

print(
    "2^10 mod 1000 =",
    modular_power(2, 10, 1000)
)

print("\n13. Euler's Totient Function")

number = 8

print(
    f"φ({number}) =",
    euler_totient(number)
)

print("\n14. Coprime Numbers")

a = 8
b = 15

print(
    f"Are {a} and {b} coprime?",
    are_coprime(a, b)
)

print("\n15. Sum of Proper Divisors")

number = 12

print(
    f"Sum of proper divisors of {number} =",
    sum_proper_divisors(number)
)

print("\n16. Sieve of Eratosthenes")

print(
    "Primes up to 100:",
    sieve_of_eratosthenes(100)
)

print("\n" + "=" * 60)
```

# ============================================================

# 18. INTERACTIVE NUMBER THEORY CALCULATOR

# ============================================================

def interactive_calculator():

```
while True:

    print("\n")
    print("=" * 50)
    print("NUMBER THEORY CALCULATOR")
    print("=" * 50)

    print("1. Check Even/Odd")
    print("2. Find Factors")
    print("3. Check Prime")
    print("4. Prime Factorization")
    print("5. Calculate GCD")
    print("6. Calculate LCM")
    print("7. Check Perfect Number")
    print("8. Euler Totient")
    print("9. Check Coprime")
    print("10. Modular Arithmetic")
    print("11. Generate Primes")
    print("12. Exit")

    choice = input("\nEnter your choice: ")

    try:

        if choice == "1":

            number = int(input("Enter number: "))

            print(
                f"{number} is "
                f"{check_even_odd(number)}"
            )

        elif choice == "2":

            number = int(input("Enter number: "))

            print(
                "Factors:",
                find_factors(number)
            )

        elif choice == "3":

            number = int(input("Enter number: "))

            if is_prime(number):
                print(f"{number} is Prime.")
            else:
                print(f"{number} is not Prime.")

        elif choice == "4":

            number = int(input("Enter number: "))

            print(
                "Prime factors:",
                prime_factorization(number)
            )

        elif choice == "5":

            a = int(input("Enter first number: "))
            b = int(input("Enter second number: "))

            print(
                "GCD =",
                calculate_gcd(a, b)
            )

        elif choice == "6":

            a = int(input("Enter first number: "))
            b = int(input("Enter second number: "))

            print(
                "LCM =",
                calculate_lcm(a, b)
            )

        elif choice == "7":

            number = int(input("Enter number: "))

            if is_perfect_number(number):
                print(
                    f"{number} is a perfect number."
                )
            else:
                print(
                    f"{number} is not a perfect number."
                )

        elif choice == "8":

            number = int(input("Enter number: "))

            print(
                f"φ({number}) =",
                euler_totient(number)
            )

        elif choice == "9":

            a = int(input("Enter first number: "))
            b = int(input("Enter second number: "))

            if are_coprime(a, b):
                print(
                    f"{a} and {b} are coprime."
                )
            else:
                print(
                    f"{a} and {b} are not coprime."
                )

        elif choice == "10":

            a = int(input("Enter first number: "))
            b = int(input("Enter second number: "))
            modulus = int(input("Enter modulus: "))

            print(
                f"({a} + {b}) mod {modulus} =",
                modular_addition(a, b, modulus)
            )

            print(
                f"({a} - {b}) mod {modulus} =",
                modular_subtraction(a, b, modulus)
            )

            print(
                f"({a} × {b}) mod {modulus} =",
                modular_multiplication(a, b, modulus)
            )

        elif choice == "11":

            limit = int(input("Generate primes up to: "))

            print(
                "Prime numbers:",
                sieve_of_eratosthenes(limit)
            )

        elif choice == "12":

            print("Exiting program...")
            break

        else:

            print("Invalid choice. Please try again.")

    except ValueError:

        print(
            "Invalid input. Please enter integers only."
        )

    except Exception as error:

        print(
            f"An unexpected error occurred: {error}"
        )
```

# ============================================================

# PROGRAM ENTRY POINT

# ============================================================

if **name** == "**main**":

```
# Run the demonstration first.
basic_demo()

# Uncomment the following line if you want to use
# the interactive calculator.

# interactive_calculator()
```

