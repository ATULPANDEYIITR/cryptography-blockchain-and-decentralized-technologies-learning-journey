"""
====================================================================
                    PRIME NUMBERS: COMPLETE GUIDE
====================================================================

This Python program teaches Prime Numbers from basic to advanced.

Topics covered:
1. What numbers are
2. Natural numbers, whole numbers, integers
3. Factors and multiples
4. Definition of prime numbers
5. Composite numbers
6. Special case: Number 1
7. Prime factorization
8. Methods for checking prime numbers
9. Brute-force primality testing
10. Optimized primality testing
11. Square root optimization
12. Checking only odd divisors
13. Generating prime numbers
14. Sieve of Eratosthenes
15. Prime factorization algorithms
16. Twin primes
17. Cousin primes
18. Sexy primes
19. Mersenne primes
20. Fermat numbers
21. Goldbach's conjecture
22. Prime gaps
23. Fundamental Theorem of Arithmetic
24. Applications in cryptography
25. RSA concept
26. Modular arithmetic
27. Performance comparison
28. Practice problems

Run this script and carefully read every section.

====================================================================
"""


import math
import time


# ================================================================
# SECTION 1: INTRODUCTION
# ================================================================

print("\n" + "=" * 70)
print("SECTION 1: INTRODUCTION TO PRIME NUMBERS")
print("=" * 70)

print("""
A prime number is one of the most important concepts in mathematics.

Prime numbers are often called the building blocks of numbers because
every integer greater than 1 can be represented using prime numbers.

Examples:

2, 3, 5, 7, 11, 13, 17, 19...

Prime numbers have applications in:

- Mathematics
- Computer Science
- Cybersecurity
- Cryptography
- RSA Encryption
- Blockchain
- Digital Signatures
- Random Number Generation
""")


# ================================================================
# SECTION 2: TYPES OF NUMBERS
# ================================================================

print("\n" + "=" * 70)
print("SECTION 2: TYPES OF NUMBERS")
print("=" * 70)

print("""
Natural Numbers:
1, 2, 3, 4, 5, ...

Whole Numbers:
0, 1, 2, 3, 4, 5, ...

Integers:
..., -3, -2, -1, 0, 1, 2, 3, ...

Prime numbers are positive integers greater than 1.
""")


# ================================================================
# SECTION 3: FACTORS
# ================================================================

print("\n" + "=" * 70)
print("SECTION 3: UNDERSTANDING FACTORS")
print("=" * 70)


def find_factors(number):
    """
    Returns all factors of a number.

    Example:
    Factors of 12:
    1, 2, 3, 4, 6, 12
    """

    factors = []

    for i in range(1, number + 1):
        if number % i == 0:
            factors.append(i)

    return factors


numbers_to_test = [2, 3, 4, 5, 6, 12, 15]

for number in numbers_to_test:
    print(f"Factors of {number}: {find_factors(number)}")


print("""
Observation:

A prime number has exactly TWO positive factors:

1. The number 1
2. The number itself

For example:

7 -> Factors: 1, 7

Therefore, 7 is PRIME.

12 -> Factors: 1, 2, 3, 4, 6, 12

Therefore, 12 is COMPOSITE.
""")


# ================================================================
# SECTION 4: PRIME VS COMPOSITE
# ================================================================

print("\n" + "=" * 70)
print("SECTION 4: PRIME VS COMPOSITE NUMBERS")
print("=" * 70)


def classify_number(number):

    if number < 1:
        return "Neither Prime nor Composite"

    if number == 1:
        return "Neither Prime nor Composite"

    factors = find_factors(number)

    if len(factors) == 2:
        return "Prime"

    return "Composite"


for number in range(-2, 16):
    print(f"{number:>3} -> {classify_number(number)}")


# ================================================================
# SECTION 5: WHY 1 IS NOT PRIME
# ================================================================

print("\n" + "=" * 70)
print("SECTION 5: WHY IS 1 NOT A PRIME NUMBER?")
print("=" * 70)

print("""
The number 1 has only ONE positive factor:

1

A prime number must have EXACTLY TWO positive factors.

Therefore:

1 is NOT prime.

1 is also NOT composite.

The number 1 is a special mathematical case.
""")


# ================================================================
# SECTION 6: FIRST PRIME NUMBER
# ================================================================

print("\n" + "=" * 70)
print("SECTION 6: THE FIRST PRIME NUMBER")
print("=" * 70)

print("""
The first prime number is:

2

It is also the ONLY EVEN PRIME NUMBER.

Why?

Every other even number can be divided by 2.

Examples:

4 = 2 × 2
6 = 2 × 3
8 = 2 × 4
10 = 2 × 5

Therefore, all even numbers greater than 2 are composite.
""")


# ================================================================
# SECTION 7: BRUTE FORCE PRIME CHECKING
# ================================================================

print("\n" + "=" * 70)
print("SECTION 7: BRUTE FORCE PRIME CHECKING")
print("=" * 70)


def is_prime_brute_force(number):
    """
    Checks whether a number is prime.

    Method:
    Test every number from 2 to number - 1.

    Time Complexity:
    O(n)
    """

    if number <= 1:
        return False

    for i in range(2, number):

        if number % i == 0:
            return False

    return True


test_numbers = [1, 2, 3, 4, 5, 17, 20, 29]

for number in test_numbers:
    print(f"{number} -> Prime: {is_prime_brute_force(number)}")


# ================================================================
# SECTION 8: OPTIMIZATION USING SQUARE ROOT
# ================================================================

print("\n" + "=" * 70)
print("SECTION 8: SQUARE ROOT OPTIMIZATION")
print("=" * 70)

print("""
Suppose we want to check whether 100 is prime.

Instead of checking every number until 99,
we only need to check divisors until:

sqrt(100) = 10

Why?

Factors usually appear in pairs.

Example:

100 = 2 × 50
100 = 4 × 25
100 = 5 × 20
100 = 10 × 10

If a number has a factor greater than its square root,
the matching factor must be smaller than the square root.

Therefore, checking until sqrt(n) is sufficient.
""")


def is_prime_sqrt(number):
    """
    Optimized prime checking.

    Time Complexity:
    O(sqrt(n))
    """

    if number <= 1:
        return False

    limit = int(math.sqrt(number))

    for i in range(2, limit + 1):

        if number % i == 0:
            return False

    return True


for number in test_numbers:
    print(f"{number} -> Prime: {is_prime_sqrt(number)}")


# ================================================================
# SECTION 9: EVEN MORE OPTIMIZATION
# ================================================================

print("\n" + "=" * 70)
print("SECTION 9: CHECK ONLY ODD NUMBERS")
print("=" * 70)


def is_prime_optimized(number):
    """
    Efficient primality test for normal-sized integers.

    Steps:

    1. Reject numbers <= 1
    2. Accept 2
    3. Reject even numbers
    4. Check only odd divisors
    5. Stop at sqrt(number)

    Time Complexity:
    O(sqrt(n))
    """

    if number <= 1:
        return False

    if number == 2:
        return True

    if number % 2 == 0:
        return False

    limit = int(math.sqrt(number))

    for divisor in range(3, limit + 1, 2):

        if number % divisor == 0:
            return False

    return True


print("\nTesting optimized function:\n")

for number in range(1, 31):

    if is_prime_optimized(number):
        print(number, "is PRIME")


# ================================================================
# SECTION 10: GENERATING PRIME NUMBERS
# ================================================================

print("\n" + "=" * 70)
print("SECTION 10: GENERATING PRIME NUMBERS")
print("=" * 70)


def generate_primes(limit):

    primes = []

    for number in range(2, limit + 1):

        if is_prime_optimized(number):
            primes.append(number)

    return primes


limit = 100

primes = generate_primes(limit)

print(f"\nPrime numbers from 1 to {limit}:\n")
print(primes)

print(f"\nTotal prime numbers: {len(primes)}")


# ================================================================
# SECTION 11: SIEVE OF ERATOSTHENES
# ================================================================

print("\n" + "=" * 70)
print("SECTION 11: SIEVE OF ERATOSTHENES")
print("=" * 70)

print("""
The Sieve of Eratosthenes is an efficient algorithm for finding
all prime numbers up to a given limit.

Basic idea:

1. Assume every number is prime.
2. Start with 2.
3. Mark all multiples of 2 as composite.
4. Move to the next unmarked number.
5. Mark its multiples.
6. Continue until sqrt(limit).

Time Complexity:

Approximately O(n log log n)
""")


def sieve_of_eratosthenes(limit):

    if limit < 2:
        return []

    is_prime = [True] * (limit + 1)

    is_prime[0] = False
    is_prime[1] = False

    for number in range(2, int(math.sqrt(limit)) + 1):

        if is_prime[number]:

            for multiple in range(number * number,
                                  limit + 1,
                                  number):

                is_prime[multiple] = False

    primes = []

    for number in range(limit + 1):

        if is_prime[number]:
            primes.append(number)

    return primes


sieve_primes = sieve_of_eratosthenes(100)

print("\nPrimes using Sieve of Eratosthenes:\n")
print(sieve_primes)


# ================================================================
# SECTION 12: PRIME FACTORIZATION
# ================================================================

print("\n" + "=" * 70)
print("SECTION 12: PRIME FACTORIZATION")
print("=" * 70)

print("""
Prime factorization means representing a number as multiplication
of prime numbers.

Examples:

12 = 2 × 2 × 3

60 = 2 × 2 × 3 × 5

100 = 2 × 2 × 5 × 5
""")


def prime_factorization(number):

    original_number = number

    factors = []

    divisor = 2

    while divisor * divisor <= number:

        while number % divisor == 0:

            factors.append(divisor)

            number = number // divisor

        divisor += 1

    if number > 1:
        factors.append(number)

    return factors


factorization_numbers = [12, 60, 100, 315, 1024]

for number in factorization_numbers:

    factors = prime_factorization(number)

    print(f"{number} = {' × '.join(map(str, factors))}")


# ================================================================
# SECTION 13: FUNDAMENTAL THEOREM OF ARITHMETIC
# ================================================================

print("\n" + "=" * 70)
print("SECTION 13: FUNDAMENTAL THEOREM OF ARITHMETIC")
print("=" * 70)

print("""
The Fundamental Theorem of Arithmetic states:

Every integer greater than 1 can be represented as a product
of prime numbers.

This representation is unique except for the order of the factors.

Example:

60 = 2 × 2 × 3 × 5

We can change the order:

60 = 5 × 3 × 2 × 2

But the prime factors remain the same.

This is one of the reasons prime numbers are considered
the building blocks of integers.
""")


# ================================================================
# SECTION 14: SPECIAL TYPES OF PRIME NUMBERS
# ================================================================

print("\n" + "=" * 70)
print("SECTION 14: SPECIAL TYPES OF PRIME NUMBERS")
print("=" * 70)


# ---------------- TWIN PRIMES ----------------

def twin_primes(limit):

    primes = sieve_of_eratosthenes(limit)

    pairs = []

    for i in range(len(primes) - 1):

        if primes[i + 1] - primes[i] == 2:

            pairs.append(
                (primes[i], primes[i + 1])
            )

    return pairs


print("\nTwin Primes:")
print(twin_primes(100))


# ---------------- COUSIN PRIMES ----------------

def cousin_primes(limit):

    primes = sieve_of_eratosthenes(limit)

    pairs = []

    for i in range(len(primes) - 1):

        if primes[i + 1] - primes[i] == 4:

            pairs.append(
                (primes[i], primes[i + 1])
            )

    return pairs


print("\nCousin Primes:")
print(cousin_primes(100))


# ---------------- SEXY PRIMES ----------------

def sexy_primes(limit):

    primes = sieve_of_eratosthenes(limit)

    pairs = []

    for i in range(len(primes) - 1):

        if primes[i + 1] - primes[i] == 6:

            pairs.append(
                (primes[i], primes[i + 1])
            )

    return pairs


print("\nSexy Primes:")
print(sexy_primes(100))


# ================================================================
# SECTION 15: PRIME GAPS
# ================================================================

print("\n" + "=" * 70)
print("SECTION 15: PRIME GAPS")
print("=" * 70)

print("""
A prime gap is the difference between two consecutive prime numbers.

Examples:

3 and 5 -> Gap = 2

7 and 11 -> Gap = 4

23 and 29 -> Gap = 6
""")


def calculate_prime_gaps(limit):

    primes = sieve_of_eratosthenes(limit)

    gaps = []

    for i in range(len(primes) - 1):

        gap = primes[i + 1] - primes[i]

        gaps.append(
            (primes[i],
             primes[i + 1],
             gap)
        )

    return gaps


print("\nPrime gaps up to 50:\n")

for start, end, gap in calculate_prime_gaps(50):

    print(
        f"{start} -> {end} | Gap = {gap}"
    )


# ================================================================
# SECTION 16: MERSENNE PRIMES
# ================================================================

print("\n" + "=" * 70)
print("SECTION 16: MERSENNE PRIMES")
print("=" * 70)

print("""
A Mersenne number has the form:

2^p - 1

If the resulting number is prime, it is called a Mersenne Prime.

Examples:

p = 2

2^2 - 1 = 3 -> Prime

p = 3

2^3 - 1 = 7 -> Prime

p = 5

2^5 - 1 = 31 -> Prime
""")


def mersenne_primes(max_power):

    results = []

    for p in range(2, max_power + 1):

        number = (2 ** p) - 1

        if is_prime_optimized(number):

            results.append(
                (p, number)
            )

    return results


print("\nMersenne primes:\n")

for exponent, number in mersenne_primes(20):

    print(
        f"2^{exponent} - 1 = {number}"
    )


# ================================================================
# SECTION 17: GOLD BACH'S CONJECTURE
# ================================================================

print("\n" + "=" * 70)
print("SECTION 17: GOLDBACH'S CONJECTURE")
print("=" * 70)

print("""
Goldbach's Conjecture states that every even integer greater than 2
can be represented as the sum of two prime numbers.

Examples:

4 = 2 + 2

10 = 3 + 7

20 = 3 + 17

30 = 7 + 23
""")


def goldbach_pairs(even_number):

    if even_number <= 2 or even_number % 2 != 0:

        return []

    primes = sieve_of_eratosthenes(even_number)

    prime_set = set(primes)

    pairs = []

    for prime in primes:

        second_prime = even_number - prime

        if second_prime in prime_set:

            if prime <= second_prime:

                pairs.append(
                    (prime, second_prime)
                )

    return pairs


number = 50

print(
    f"\nGoldbach pairs for {number}:"
)

print(
    goldbach_pairs(number)
)


# ================================================================
# SECTION 18: MODULAR ARITHMETIC
# ================================================================

print("\n" + "=" * 70)
print("SECTION 18: MODULAR ARITHMETIC")
print("=" * 70)

print("""
Modular arithmetic deals with remainders.

Example:

17 % 5 = 2

This means when 17 is divided by 5,
the remainder is 2.

Prime numbers are extremely important in modular arithmetic,
especially in cryptography.
""")


print("\nExamples:\n")

examples = [
    (17, 5),
    (29, 7),
    (100, 9),
    (53, 11)
]

for a, b in examples:

    print(
        f"{a} % {b} = {a % b}"
    )


# ================================================================
# SECTION 19: RSA CRYPTOGRAPHY CONCEPT
# ================================================================

print("\n" + "=" * 70)
print("SECTION 19: PRIME NUMBERS AND RSA CRYPTOGRAPHY")
print("=" * 70)

print("""
Prime numbers are fundamental to RSA encryption.

Simplified RSA concept:

1. Select two large prime numbers:

p and q

2. Multiply them:

n = p × q

3. The number n can be public.

4. Factoring n back into p and q becomes extremely difficult
   when p and q are very large.

Example:

p = 61
q = 53

n = 61 × 53 = 3233

For small numbers this is easy.

For extremely large primes, factorization becomes computationally
difficult.

This mathematical difficulty provides security.
""")


p = 61
q = 53

n = p * q

print(f"\np = {p}")
print(f"q = {q}")
print(f"n = p × q = {n}")


# ================================================================
# SECTION 20: FERMAT'S LITTLE THEOREM
# ================================================================

print("\n" + "=" * 70)
print("SECTION 20: FERMAT'S LITTLE THEOREM")
print("=" * 70)

print("""
Fermat's Little Theorem is an important theorem involving primes.

If p is prime and a is not divisible by p, then:

a^(p-1) modulo p = 1

Example:

a = 2
p = 7

2^6 = 64

64 % 7 = 1
""")


a = 2
p = 7

result = pow(a, p - 1, p)

print(
    f"pow({a}, {p - 1}, {p}) = {result}"
)


# ================================================================
# SECTION 21: PERFORMANCE COMPARISON
# ================================================================

print("\n" + "=" * 70)
print("SECTION 21: PERFORMANCE COMPARISON")
print("=" * 70)

print("""
We will compare:

1. Brute force prime checking
2. Square root optimization
3. Optimized odd-divisor checking
""")


test_number = 999983


start = time.perf_counter()

result1 = is_prime_brute_force(test_number)

end = time.perf_counter()

brute_time = end - start


start = time.perf_counter()

result2 = is_prime_sqrt(test_number)

end = time.perf_counter()

sqrt_time = end - start


start = time.perf_counter()

result3 = is_prime_optimized(test_number)

end = time.perf_counter()

optimized_time = end - start


print(f"\nTesting number: {test_number}")

print(
    f"\nBrute Force Result: {result1}"
)

print(
    f"Brute Force Time: {brute_time:.8f} seconds"
)

print(
    f"\nSquare Root Result: {result2}"
)

print(
    f"Square Root Time: {sqrt_time:.8f} seconds"
)

print(
    f"\nOptimized Result: {result3}"
)

print(
    f"Optimized Time: {optimized_time:.8f} seconds"
)


# ================================================================
# SECTION 22: INTERACTIVE PRIME CHECKER
# ================================================================

print("\n" + "=" * 70)
print("SECTION 22: INTERACTIVE PRIME CHECKER")
print("=" * 70)

print("""
You can now test your own numbers.

Enter 'q' to quit.
""")


while True:

    user_input = input(
        "\nEnter a number to check: "
    )

    if user_input.lower() == "q":

        print(
            "\nExiting Prime Checker..."
        )

        break

    try:

        number = int(user_input)

        if is_prime_optimized(number):

            print(
                f"{number} is a PRIME NUMBER."
            )

        else:

            if number > 1:

                print(
                    f"{number} is a COMPOSITE NUMBER."
                )

                factors = prime_factorization(number)

                print(
                    "Prime Factorization:",
                    " × ".join(
                        map(str, factors)
                    )
                )

            else:

                print(
                    f"{number} is neither prime nor composite."
                )

    except ValueError:

        print(
            "Please enter a valid integer."
        )
