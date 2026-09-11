"""
Fermat's Little Theorem
=======================

A self-contained tutorial and executable study file covering Fermat's Little
Theorem from beginner to advanced level.

Topics covered:
- Modular arithmetic fundamentals
- Congruence notation
- Prime numbers and coprimality
- Statement of Fermat's Little Theorem
- Two equivalent forms of the theorem
- Step-by-step examples
- Direct verification
- Modular exponentiation
- Efficient exponentiation by squaring
- Why the theorem works
- Proof using multiplication modulo p
- Proof using binomial coefficients
- Applications
- Computing modular inverses
- Solving modular equations
- Large-exponent reduction
- Fast primality testing using Fermat witnesses
- Carmichael numbers and the limitation of Fermat primality testing
- Comparison with Euler's theorem
- Relationship to Euler's totient function
- Edge cases and important exceptions
- Common mistakes
- Performance considerations
- Testing and validation
- Practical cryptographic relevance
- Advanced examples
"""

from math import gcd, comb
import random
import time


# ============================================================================
# 1. BASIC TERMINOLOGY
# ============================================================================

def print_section(title):
    """Print a clearly separated educational section."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_modular_arithmetic():
    """
    Demonstrate the basic idea of modular arithmetic.

    a mod m is the remainder obtained when a is divided by m.

    Examples:
        17 mod 5 = 2
        23 mod 7 = 2
        -3 mod 5 = 2 in Python
    """
    print_section("1. Modular arithmetic fundamentals")

    examples = [
        (17, 5),
        (23, 7),
        (100, 9),
        (-3, 5),
        (42, 1),
    ]

    for number, modulus in examples:
        print(f"{number} mod {modulus} = {number % modulus}")

    print("\nThe notation")
    print("    a ≡ b (mod m)")
    print("means that a and b leave the same remainder when divided by m.")

    print("\nEquivalent definition:")
    print("    a ≡ b (mod m)  exactly when  m divides (a - b).")

    a, b, m = 29, 5, 12
    print(f"\nExample: {a} ≡ {b} (mod {m})")
    print(f"{a} - {b} = {a - b}")
    print(f"{a - b} is divisible by {m}: {(a - b) % m == 0}")


# ============================================================================
# 2. CONGRUENCE OPERATIONS
# ============================================================================

def demonstrate_congruence_operations():
    """
    Congruences behave well under addition, subtraction, and multiplication.

    If:
        a ≡ b (mod m)
        c ≡ d (mod m)

    then:
        a + c ≡ b + d (mod m)
        a - c ≡ b - d (mod m)
        ac ≡ bd (mod m)

    Exponentiation follows naturally from repeated multiplication.
    """
    print_section("2. Operations with congruences")

    m = 7
    a, b = 17, 3
    c, d = 23, 2

    print(f"a = {a}, b = {b}, c = {c}, d = {d}, modulus = {m}")
    print(f"a mod m = {a % m}")
    print(f"b mod m = {b % m}")
    print(f"c mod m = {c % m}")
    print(f"d mod m = {d % m}")

    print("\nAddition:")
    print((a + c) % m, (b + d) % m)

    print("\nSubtraction:")
    print((a - c) % m, (b - d) % m)

    print("\nMultiplication:")
    print((a * c) % m, (b * d) % m)

    print("\nExponentiation:")
    print(pow(a, 5, m), pow(b, 5, m))


# ============================================================================
# 3. PRIME NUMBERS AND COPRIMALITY
# ============================================================================

def is_prime_basic(n):
    """
    Basic trial-division primality test.

    This implementation is intended for teaching rather than very large
    integers. It checks possible divisors only up to sqrt(n).
    """
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2

    return True


def demonstrate_primes_and_coprimality():
    print_section("3. Prime numbers and coprimality")

    numbers = [1, 2, 3, 4, 5, 7, 11, 15, 17, 25, 29]

    for number in numbers:
        print(f"{number:>3} -> prime: {is_prime_basic(number)}")

    print("\nTwo integers are coprime when their greatest common divisor is 1.")

    pairs = [(8, 15), (12, 18), (14, 25), (21, 35)]

    for a, b in pairs:
        print(f"gcd({a}, {b}) = {gcd(a, b)}")


# ============================================================================
# 4. FERMAT'S LITTLE THEOREM
# ============================================================================

def fermat_little_theorem_statement():
    """
    Fermat's Little Theorem has two standard equivalent forms.

    Form 1:
        If p is prime and a is not divisible by p, then

            a^(p-1) ≡ 1 (mod p)

    Form 2:
        If p is prime, then for every integer a,

            a^p ≡ a (mod p)

    Form 1 requires gcd(a, p) = 1.
    Form 2 does not require that restriction.
    """
    print_section("4. Fermat's Little Theorem")

    print("If p is prime and p does not divide a:")
    print("    a^(p-1) ≡ 1 (mod p)")

    print("\nEquivalent form:")
    print("    a^p ≡ a (mod p)")

    print("\nExample:")
    print("Let p = 7 and a = 3.")
    print("3^(7-1) = 3^6")
    print(f"3^6 mod 7 = {pow(3, 6, 7)}")

    print("\nTherefore:")
    print("3^6 ≡ 1 (mod 7)")


# ============================================================================
# 5. DIRECT VERIFICATION
# ============================================================================

def verify_fermat_form_1(a, p):
    """
    Verify the first form of Fermat's Little Theorem.

    Returns True only when p is prime, gcd(a, p) = 1, and the congruence holds.
    """
    if not is_prime_basic(p):
        return False

    if gcd(a, p) != 1:
        return False

    return pow(a, p - 1, p) == 1


def verify_fermat_form_2(a, p):
    """Verify a^p ≡ a (mod p) for a prime p."""
    if not is_prime_basic(p):
        return False

    return pow(a, p, p) == a % p


def demonstrate_fermat_verification():
    print_section("5. Verifying Fermat's Little Theorem")

    p = 13

    for a in range(1, 13):
        result = pow(a, p - 1, p)
        print(f"{a:>2}^12 mod 13 = {result}")

    print("\nSecond form:")
    for a in range(0, 13):
        result = pow(a, p, p)
        print(f"{a:>2}^13 mod 13 = {result:>2} | a mod 13 = {a % 13}")


# ============================================================================
# 6. WHY THE THEOREM WORKS: PERMUTATION PROOF
# ============================================================================

def demonstrate_permutation_proof():
    """
    The classic multiplication-permutation proof.

    Consider:
        1, 2, ..., p-1

    Multiply every member by a, where p is prime and p does not divide a.

    The resulting residues:
        a, 2a, ..., (p-1)a

    are a permutation of:
        1, 2, ..., p-1

    because multiplication by a cannot make two different nonzero residues
    equal modulo p.

    Therefore:

        a * 2a * ... * (p-1)a
        ≡ 1 * 2 * ... * (p-1) (mod p)

    Thus:

        a^(p-1) * (p-1)! ≡ (p-1)! (mod p)

    Since p does not divide any of 1, 2, ..., p-1, it does not divide
    (p-1)!, so cancellation is valid modulo p.

    Hence:

        a^(p-1) ≡ 1 (mod p)
    """
    print_section("6. Proof idea: multiplication creates a permutation")

    p = 7
    a = 3

    original = list(range(1, p))
    multiplied = [(a * x) % p for x in original]

    print(f"Prime p = {p}")
    print(f"Base a = {a}")
    print(f"Original nonzero residues: {original}")
    print(f"After multiplication by {a}: {multiplied}")
    print(f"Sorted multiplied residues: {sorted(multiplied)}")

    print("\nThe multiplied residues are the same set in a different order.")
    print("Therefore their products are congruent modulo p.")

    left = pow(a, p - 1, p)
    right = 1 % p

    print(f"\na^({p}-1) mod {p} = {left}")
    print(f"1 mod {p} = {right}")


# ============================================================================
# 7. SECOND PROOF USING BINOMIAL COEFFICIENTS
# ============================================================================

def demonstrate_binomial_proof_idea():
    """
    A second proof starts from the binomial theorem:

        (a + 1)^p
        = sum C(p,k) a^k

    For prime p, every intermediate binomial coefficient

        C(p,k), 1 <= k <= p-1

    is divisible by p.

    Therefore:

        (a + 1)^p ≡ a^p + 1 (mod p)

    Starting from a = 0 and using induction gives:

        a^p ≡ a (mod p)

    This is the second form of Fermat's Little Theorem.
    """
    print_section("7. Proof idea: binomial coefficients")

    p = 5

    print(f"Binomial coefficients for (a + 1)^{p}:")
    for k in range(p + 1):
        coefficient = comb(p, k)
        print(
            f"C({p}, {k}) = {coefficient}, "
            f"divisible by {p}: {coefficient % p == 0}"
        )

    print("\nThe two middle coefficients are divisible by 5.")
    print("This is what causes the intermediate terms to disappear modulo p.")


# ============================================================================
# 8. MODULAR EXPONENTIATION
# ============================================================================

def modular_power_slow(base, exponent, modulus):
    """
    Simple repeated multiplication.

    Time complexity:
        O(exponent)

    Useful for demonstrating the idea, but inefficient for very large
    exponents.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    result = 1 % modulus

    for _ in range(exponent):
        result = (result * base) % modulus

    return result


def modular_power_fast(base, exponent, modulus):
    """
    Exponentiation by squaring.

    Time complexity:
        O(log exponent)

    This is closely related to the way Python's built-in pow(base, exponent,
    modulus) efficiently computes modular powers.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    if exponent < 0:
        raise ValueError("This function expects a non-negative exponent.")

    result = 1 % modulus
    base %= modulus

    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent //= 2

    return result


def demonstrate_modular_exponentiation():
    print_section("8. Efficient modular exponentiation")

    base = 7
    exponent = 123456
    modulus = 1009

    fast_result = modular_power_fast(base, exponent, modulus)
    builtin_result = pow(base, exponent, modulus)

    print(f"{base}^{exponent} mod {modulus} = {fast_result}")
    print(f"Python pow result = {builtin_result}")
    print(f"Results agree: {fast_result == builtin_result}")

    print("\nExponentiation by squaring repeatedly halves the exponent.")
    print("This changes the exponent-dependent work from O(n) to O(log n).")


# ============================================================================
# 9. REDUCING LARGE EXPONENTS USING FERMAT
# ============================================================================

def reduce_exponent_using_fermat(base, exponent, prime):
    """
    For prime p and gcd(base, p) = 1:

        base^(p-1) ≡ 1 (mod p)

    Therefore the exponent can be reduced modulo p-1:

        base^exponent ≡ base^(exponent mod (p-1)) (mod p)

    Important:
    This reduction is valid only when gcd(base, p) = 1.
    """
    if not is_prime_basic(prime):
        raise ValueError("The modulus must be prime.")

    if gcd(base, prime) != 1:
        raise ValueError(
            "Exponent reduction by p-1 requires base and p to be coprime."
        )

    reduced_exponent = exponent % (prime - 1)
    return reduced_exponent, pow(base, reduced_exponent, prime)


def demonstrate_large_exponent_reduction():
    print_section("9. Reducing huge exponents")

    base = 3
    exponent = 10**18 + 12345
    prime = 17

    reduced_exponent, reduced_result = reduce_exponent_using_fermat(
        base, exponent, prime
    )

    direct_result = pow(base, exponent, prime)

    print(f"Base: {base}")
    print(f"Exponent: {exponent}")
    print(f"Prime modulus: {prime}")
    print(f"Exponent modulo p-1: {reduced_exponent}")
    print(f"Reduced calculation: {reduced_result}")
    print(f"Direct modular power: {direct_result}")
    print(f"Results agree: {reduced_result == direct_result}")


# ============================================================================
# 10. MODULAR INVERSE
# ============================================================================

def modular_inverse_fermat(a, p):
    """
    Compute a^-1 modulo prime p using Fermat's Little Theorem.

    Since:

        a^(p-1) ≡ 1 (mod p)

    multiply both sides by a^-1:

        a^(p-2) ≡ a^-1 (mod p)

    Therefore:

        inverse(a) = a^(p-2) mod p

    Requirement:
        p must be prime and a must not be divisible by p.
    """
    if not is_prime_basic(p):
        raise ValueError("Fermat's inverse method requires a prime modulus.")

    if gcd(a, p) != 1:
        raise ValueError("a must be coprime to p.")

    return pow(a, p - 2, p)


def demonstrate_modular_inverse():
    print_section("10. Modular inverse using Fermat's theorem")

    p = 11
    a = 7

    inverse = modular_inverse_fermat(a, p)

    print(f"a = {a}")
    print(f"p = {p}")
    print(f"a^({p}-2) mod {p} = {inverse}")
    print(f"a * inverse mod p = {(a * inverse) % p}")

    print("\nTherefore:")
    print(f"{a}^(-1) ≡ {inverse} (mod {p})")


# ============================================================================
# 11. SOLVING MODULAR DIVISION
# ============================================================================

def divide_mod_prime(numerator, denominator, prime):
    """
    Solve:

        numerator / denominator (mod prime)

    by multiplying the numerator by the modular inverse of denominator.

    Requirement:
        prime is prime and denominator is not divisible by prime.
    """
    inverse = modular_inverse_fermat(denominator, prime)
    return (numerator * inverse) % prime


def demonstrate_modular_division():
    print_section("11. Modular division")

    numerator = 8
    denominator = 3
    prime = 13

    result = divide_mod_prime(numerator, denominator, prime)

    print(f"{numerator} / {denominator} mod {prime} = {result}")
    print(
        f"Verification: {denominator} * {result} mod {prime} = "
        f"{(denominator * result) % prime}"
    )


# ============================================================================
# 12. COMBINATORICS: BINOMIAL COEFFICIENTS MODULO A PRIME
# ============================================================================

def factorial_mod(n, modulus):
    """Compute n! modulo modulus."""
    result = 1 % modulus

    for value in range(2, n + 1):
        result = (result * value) % modulus

    return result


def binomial_mod_prime(n, r, prime):
    """
    Compute C(n, r) modulo prime using factorials and Fermat inverses.

    This direct factorial method assumes:
        0 <= r <= n
        n < prime

    For n >= prime, additional techniques such as Lucas's theorem may be
    required. That is an important limitation of this simple implementation.
    """
    if not is_prime_basic(prime):
        raise ValueError("The modulus must be prime.")

    if not (0 <= r <= n):
        return 0

    if n >= prime:
        raise ValueError(
            "This simple factorial implementation requires n < prime."
        )

    numerator = factorial_mod(n, prime)
    denominator = (
        factorial_mod(r, prime) * factorial_mod(n - r, prime)
    ) % prime

    inverse_denominator = modular_inverse_fermat(denominator, prime)

    return (numerator * inverse_denominator) % prime


def demonstrate_combinatorics():
    print_section("12. Binomial coefficients modulo a prime")

    n = 10
    r = 4
    prime = 13

    exact = comb(n, r)
    modular_result = binomial_mod_prime(n, r, prime)

    print(f"C({n}, {r}) = {exact}")
    print(f"C({n}, {r}) mod {prime} = {exact % prime}")
    print(f"Computed using Fermat inverses = {modular_result}")


# ============================================================================
# 13. FERMAT-BASED PRIMALITY TEST
# ============================================================================

def fermat_primality_test(n, bases=None):
    """
    A basic Fermat probable-prime test.

    For prime n and any a with gcd(a, n) = 1:

        a^(n-1) ≡ 1 (mod n)

    If the condition fails for a chosen base, n is definitely composite.

    If it passes, n is only a probable prime. This distinction is essential.

    The test is unreliable against Carmichael numbers.
    """
    if n < 2:
        return False

    if n in (2, 3):
        return True

    if bases is None:
        bases = [2, 3, 5, 7, 11]

    for base in bases:
        if base >= n:
            continue

        if gcd(base, n) != 1:
            continue

        if pow(base, n - 1, n) != 1:
            return False

    return True


def demonstrate_fermat_primality_test():
    print_section("13. Fermat primality testing")

    candidates = [2, 3, 5, 7, 11, 13, 15, 17, 21, 25, 29, 31]

    for number in candidates:
        result = fermat_primality_test(number)
        print(f"{number:>3} -> Fermat probable-prime result: {result}")

    print("\nImportant:")
    print("A False result proves compositeness.")
    print("A True result does NOT prove primality.")


# ============================================================================
# 14. CARMICHAEL NUMBERS
# ============================================================================

def demonstrate_carmichael_number():
    """
    561 is the smallest Carmichael number.

    It is composite:

        561 = 3 * 11 * 17

    Yet for every integer a coprime to 561:

        a^560 ≡ 1 (mod 561)

    Therefore a simple Fermat test can incorrectly classify 561 as a
    probable prime.

    This is one of the most important limitations of Fermat primality tests.
    """
    print_section("14. Carmichael numbers: a major limitation")

    n = 561

    print(f"{n} is prime according to the basic trial division test: {is_prime_basic(n)}")
    print(f"Factorization: {n} = 3 × 11 × 17")

    for base in [2, 3, 5, 7, 10]:
        if gcd(base, n) == 1:
            print(
                f"base {base}: {base}^560 mod 561 = "
                f"{pow(base, 560, n)}"
            )

    print("\nThe Fermat test can therefore be fooled by Carmichael numbers.")


# ============================================================================
# 15. WHY CANCELLATION NEEDS CARE
# ============================================================================

def demonstrate_invalid_cancellation():
    """
    Modular arithmetic does not permit arbitrary cancellation.

    For example modulo 6:

        2 * 1 ≡ 2 * 4 (mod 6)

    because:
        2 ≡ 8 (mod 6)

    But after cancelling 2:

        1 ≡ 4 (mod 6)

    which is false.

    Cancellation is safe when the cancelled factor is invertible modulo m.
    For a prime p, every nonzero residue modulo p is invertible.
    """
    print_section("15. Why modular cancellation needs conditions")

    modulus = 6

    left = (2 * 1) % modulus
    right = (2 * 4) % modulus

    print(f"2 × 1 mod 6 = {left}")
    print(f"2 × 4 mod 6 = {right}")
    print(f"The products are congruent: {left == right}")

    print("\nBut:")
    print(f"1 mod 6 = {1 % modulus}")
    print(f"4 mod 6 = {4 % modulus}")
    print("So cancellation of 2 is invalid modulo 6.")


# ============================================================================
# 16. EDGE CASES
# ============================================================================

def demonstrate_edge_cases():
    print_section("16. Edge cases and exceptions")

    print("Case 1: a = 0, p = 7")
    print(f"0^7 mod 7 = {pow(0, 7, 7)}")
    print("The second form a^p ≡ a works.")

    print("\nCase 2: a divisible by p")
    p = 7
    a = 14
    print(f"a = {a}, p = {p}")
    print(f"a^(p-1) mod p = {pow(a, p - 1, p)}")
    print(
        "The first form is not applicable because gcd(a, p) != 1."
    )

    print("\nCase 3: p is not prime")
    n = 8
    a = 3
    print(f"{a}^{n - 1} mod {n} = {pow(a, n - 1, n)}")
    print("The prime-modulus theorem cannot be assumed for n = 8.")

    print("\nCase 4: p = 2")
    print(f"5^(2-1) mod 2 = {pow(5, 1, 2)}")
    print("The theorem still works for the prime p = 2.")


# ============================================================================
# 17. FERMAT'S THEOREM VS EULER'S THEOREM
# ============================================================================

def euler_totient(n):
    """Compute Euler's phi(n), the count of integers from 1 to n coprime to n."""
    count = 0

    for value in range(1, n + 1):
        if gcd(value, n) == 1:
            count += 1

    return count


def demonstrate_euler_connection():
    """
    Euler's theorem states:

        If gcd(a, n) = 1,

        a^phi(n) ≡ 1 (mod n)

    For a prime p:

        phi(p) = p - 1

    Therefore Euler's theorem becomes Fermat's Little Theorem.
    """
    print_section("17. Fermat's theorem and Euler's theorem")

    n = 10
    phi = euler_totient(n)

    print(f"phi({n}) = {phi}")
    print(f"3^phi({n}) mod {n} = {pow(3, phi, n)}")

    print("\nFor prime p:")
    p = 13
    print(f"phi({p}) = {euler_totient(p)}")
    print(f"p - 1 = {p - 1}")
    print("Thus phi(p) = p - 1.")


# ============================================================================
# 18. FERMAT'S THEOREM AND THE MULTIPLICATIVE GROUP
# ============================================================================

def demonstrate_multiplicative_group():
    """
    For prime p, the nonzero residue classes

        {1, 2, ..., p-1}

    form a multiplicative group modulo p.

    Every nonzero element has a multiplicative inverse, and the group has
    exactly p - 1 elements.

    Fermat's Little Theorem says that every element raised to the group order
    becomes the identity:

        a^(p-1) = 1

    modulo p.
    """
    print_section("18. Group-theoretic interpretation")

    p = 11
    print(f"Nonzero residues modulo {p}: {list(range(1, p))}")

    for a in range(1, p):
        inverse = modular_inverse_fermat(a, p)
        product = (a * inverse) % p
        print(f"{a:>2} inverse = {inverse:>2}; product = {product}")

    print("\nEvery nonzero residue has an inverse modulo a prime.")


# ============================================================================
# 19. MULTIPLICATIVE ORDER
# ============================================================================

def multiplicative_order(a, modulus):
    """
    Find the smallest positive k such that:

        a^k ≡ 1 (mod modulus)

    This is called the multiplicative order of a modulo modulus.

    The function requires gcd(a, modulus) = 1.
    """
    if gcd(a, modulus) != 1:
        raise ValueError("a must be coprime to modulus.")

    value = 1

    for k in range(1, modulus + 1):
        value = (value * a) % modulus

        if value == 1:
            return k

    raise RuntimeError("Order not found.")


def demonstrate_multiplicative_order():
    print_section("19. Multiplicative order")

    p = 13

    for a in range(1, p):
        order = multiplicative_order(a, p)
        print(f"ord_{p}({a}) = {order}")

    print("\nFermat's theorem guarantees that every order divides p - 1.")


# ============================================================================
# 20. A COMPLETE LARGE-EXPONENT EXAMPLE
# ============================================================================

def demonstrate_large_power_problem():
    """
    Compute:

        7^123456789012345 mod 19

    Since 19 is prime and gcd(7,19) = 1:

        7^18 ≡ 1 (mod 19)

    So the exponent can be reduced modulo 18.
    """
    print_section("20. Large exponent problem")

    base = 7
    exponent = 123456789012345
    p = 19

    reduced = exponent % (p - 1)

    print(f"Original expression: {base}^{exponent} mod {p}")
    print(f"p - 1 = {p - 1}")
    print(f"Reduced exponent = {reduced}")

    result = pow(base, reduced, p)
    direct = pow(base, exponent, p)

    print(f"Reduced result = {result}")
    print(f"Direct result = {direct}")
    print(f"Results agree = {result == direct}")


# ============================================================================
# 21. NEGATIVE EXPONENTS AND MODULAR INVERSES
# ============================================================================

def modular_power_with_negative_exponent(base, exponent, modulus):
    """
    Extended modular power supporting negative exponents.

    For exponent < 0:

        base^(-k) ≡ (base^-1)^k (mod modulus)

    The inverse must exist.
    """
    if exponent >= 0:
        return pow(base, exponent, modulus)

    inverse = modular_inverse_fermat(base, modulus)
    return pow(inverse, -exponent, modulus)


def demonstrate_negative_exponents():
    print_section("21. Negative modular exponents")

    p = 17
    a = 5

    positive = pow(a, 3, p)
    negative = modular_power_with_negative_exponent(a, -3, p)

    print(f"{a}^3 mod {p} = {positive}")
    print(f"{a}^(-3) mod {p} = {negative}")

    verification = (positive * negative) % p
    print(f"Verification product = {verification}")


# ============================================================================
# 22. RANDOMIZED VERIFICATION
# ============================================================================

def randomized_fermat_verification():
    """
    Test Fermat's theorem across many small primes and valid bases.

    This is useful as a practical consistency check for the implementation.
    """
    print_section("22. Randomized theorem verification")

    primes = [p for p in range(2, 100) if is_prime_basic(p)]

    failures = []

    for p in primes:
        for a in range(1, p):
            if pow(a, p - 1, p) != 1:
                failures.append((a, p))

    print(f"Primes tested: {len(primes)}")
    print(f"Valid base/modulus pairs tested: {sum(p - 1 for p in primes)}")
    print(f"Failures: {len(failures)}")

    if failures:
        print(f"First failure: {failures[0]}")
    else:
        print("All tested cases satisfy Fermat's Little Theorem.")


# ============================================================================
# 23. PERFORMANCE COMPARISON
# ============================================================================

def demonstrate_performance():
    """
    Compare repeated multiplication with exponentiation by squaring.

    Timing values depend on hardware, Python version, and system load.
    """
    print_section("23. Performance considerations")

    base = 37
    exponent = 200_000
    modulus = 1_000_003

    start = time.perf_counter()
    slow = modular_power_slow(base, exponent, modulus)
    slow_time = time.perf_counter() - start

    start = time.perf_counter()
    fast = modular_power_fast(base, exponent, modulus)
    fast_time = time.perf_counter() - start

    builtin = pow(base, exponent, modulus)

    print(f"Repeated multiplication result: {slow}")
    print(f"Exponentiation by squaring result: {fast}")
    print(f"Built-in pow result: {builtin}")

    print(f"\nSlow method time: {slow_time:.6f} seconds")
    print(f"Fast method time: {fast_time:.6f} seconds")

    print("\nThe fast method performs O(log exponent) modular multiplications.")
    print("The repeated method performs O(exponent) iterations.")
    print("Python's three-argument pow is highly optimized for this operation.")


# ============================================================================
# 24. COMMON MISTAKES
# ============================================================================

def demonstrate_common_mistakes():
    print_section("24. Common mistakes")

    print("Mistake 1: Forgetting the coprimality condition.")
    print("Correct first-form condition: gcd(a, p) = 1.")

    print("\nMistake 2: Assuming every modulus is prime.")
    print("Fermat's Little Theorem is specifically about prime moduli.")

    print("\nMistake 3: Treating a Fermat probable-prime result as a proof.")
    print("Carmichael numbers can pass Fermat tests.")

    print("\nMistake 4: Reducing exponents modulo p - 1 when the base is divisible by p.")
    print("The reduction requires gcd(a, p) = 1.")

    print("\nMistake 5: Cancelling arbitrary factors in modular arithmetic.")
    print("Cancellation requires the cancelled factor to be invertible.")

    print("\nMistake 6: Using normal division for modular division.")
    print("Modular division requires multiplication by a modular inverse.")


# ============================================================================
# 25. SECURITY AND CRYPTOGRAPHIC CONTEXT
# ============================================================================

def demonstrate_cryptographic_context():
    """
    Fermat's Little Theorem is foundational to modular arithmetic used in
    cryptography.

    The theorem itself is not a cryptosystem.

    Its concepts contribute to:
    - modular inverses
    - finite-field arithmetic
    - prime-modulus computations
    - public-key cryptographic constructions
    - reasoning about multiplicative groups

    In production cryptography, naive Fermat primality testing should not be
    used as a standalone proof that a large integer is prime.
    """
    print_section("25. Cryptographic relevance")

    p = 101
    a = 37

    inverse = pow(a, p - 2, p)

    print(f"Prime p = {p}")
    print(f"a = {a}")
    print(f"Computed inverse = {inverse}")
    print(f"a * inverse mod p = {(a * inverse) % p}")

    print("\nThis illustrates finite-field arithmetic over a prime modulus.")
    print("Cryptographic implementations require carefully reviewed algorithms,")
    print("secure random generation, constant-time considerations, and tested")
    print("libraries rather than educational implementations such as this one.")


# ============================================================================
# 26. PRODUCTION-ORIENTED IMPLEMENTATION NOTES
# ============================================================================

def production_implementation_notes():
    print_section("26. Implementation and production considerations")

    print("1. Prefer Python's pow(a, b, m) for modular exponentiation.")
    print("2. Validate that assumptions such as primality actually hold.")
    print("3. Do not use Fermat testing alone for cryptographic primality decisions.")
    print("4. Be explicit about whether an exponent-reduction condition is satisfied.")
    print("5. Handle non-invertible values instead of silently producing a result.")
    print("6. Use established cryptographic libraries for security-sensitive systems.")
    print("7. Test boundary cases, especially zero, one, negative values, and")
    print("   values sharing factors with the modulus.")


# ============================================================================
# 27. UNIT TESTS
# ============================================================================

def run_tests():
    """
    Small deterministic test suite.

    Assertions stop execution if an implementation assumption is violated.
    """
    print_section("27. Automated tests")

    # Prime detection.
    assert not is_prime_basic(0)
    assert not is_prime_basic(1)
    assert is_prime_basic(2)
    assert is_prime_basic(97)
    assert not is_prime_basic(100)

    # Fast modular exponentiation.
    for base in range(-10, 11):
        for exponent in range(0, 15):
            assert modular_power_fast(base, exponent, 17) == pow(
                base, exponent, 17
            )

    # Fermat's theorem for valid pairs.
    for p in [2, 3, 5, 7, 11, 13, 17, 19]:
        for a in range(1, p):
            assert verify_fermat_form_1(a, p)

    # Second form.
    for p in [2, 3, 5, 7, 11, 13]:
        for a in range(-10, 20):
            assert verify_fermat_form_2(a, p)

    # Modular inverses.
    for p in [5, 7, 11, 13, 17]:
        for a in range(1, p):
            inverse = modular_inverse_fermat(a, p)
            assert (a * inverse) % p == 1

    # Binomial coefficients for n < p.
    for p in [5, 7, 11, 13]:
        for n in range(p):
            for r in range(n + 1):
                assert binomial_mod_prime(n, r, p) == comb(n, r) % p

    print("All tests passed.")


# ============================================================================
# 28. INTERACTIVE CALCULATOR
# ============================================================================

def interactive_fermat_calculator():
    """
    Optional interactive demonstration.

    The program remains non-interactive by default because the main tutorial
    should execute automatically. This function can be called manually.
    """
    print_section("28. Interactive Fermat calculator")

    print("Enter integers to verify a^(p-1) ≡ 1 (mod p).")
    print("Enter q to quit.")

    while True:
        raw_base = input("Base a: ").strip()

        if raw_base.lower() == "q":
            break

        raw_prime = input("Prime p: ").strip()

        if raw_prime.lower() == "q":
            break

        try:
            a = int(raw_base)
            p = int(raw_prime)

            if not is_prime_basic(p):
                print("The supplied modulus is not prime.")
                continue

            if gcd(a, p) != 1:
                print(
                    "The first form requires a and p to be coprime. "
                    "Try a value not divisible by p."
                )
                continue

            result = pow(a, p - 1, p)

            print(f"{a}^{p - 1} mod {p} = {result}")
            print(f"Theorem verified: {result == 1}")

        except ValueError:
            print("Please enter valid integers.")


# ============================================================================
# 29. COMPLETE PRACTICAL WORKFLOW
# ============================================================================

def practical_workflow():
    """
    Demonstrate a sensible workflow for solving a modular exponentiation
    problem involving a prime modulus.
    """
    print_section("29. Practical problem-solving workflow")

    base = 12
    exponent = 987654321
    prime = 23

    print("Problem:")
    print(f"Compute {base}^{exponent} mod {prime}")

    print("\nStep 1: Check that the modulus is prime.")
    print(f"prime = {is_prime_basic(prime)}")

    print("\nStep 2: Check coprimality.")
    print(f"gcd({base}, {prime}) = {gcd(base, prime)}")

    print("\nStep 3: Apply Fermat's theorem.")
    print(f"{base}^({prime}-1) ≡ 1 (mod {prime})")

    reduced_exponent = exponent % (prime - 1)

    print("\nStep 4: Reduce the exponent.")
    print(f"{exponent} mod {prime - 1} = {reduced_exponent}")

    print("\nStep 5: Compute the smaller modular power.")
    answer = pow(base, reduced_exponent, prime)
    print(f"{base}^{reduced_exponent} mod {prime} = {answer}")

    print("\nStep 6: Direct verification.")
    direct = pow(base, exponent, prime)
    print(f"Direct computation = {direct}")
    print(f"Answers agree = {answer == direct}")


# ============================================================================
# 30. MAIN PROGRAM
# ============================================================================

def main():
    """
    Execute the complete Fermat's Little Theorem tutorial.
    """
    print("=" * 78)
    print("FERMAT'S LITTLE THEOREM")
    print("A comprehensive executable tutorial")
    print("=" * 78)

    explain_modular_arithmetic()
    demonstrate_congruence_operations()
    demonstrate_primes_and_coprimality()
    fermat_little_theorem_statement()
    demonstrate_fermat_verification()
    demonstrate_permutation_proof()
    demonstrate_binomial_proof_idea()
    demonstrate_modular_exponentiation()
    demonstrate_large_exponent_reduction()
    demonstrate_modular_inverse()
    demonstrate_modular_division()
    demonstrate_combinatorics()
    demonstrate_fermat_primality_test()
    demonstrate_carmichael_number()
    demonstrate_invalid_cancellation()
    demonstrate_edge_cases()
    demonstrate_euler_connection()
    demonstrate_multiplicative_group()
    demonstrate_multiplicative_order()
    demonstrate_large_power_problem()
    demonstrate_negative_exponents()
    randomized_fermat_verification()
    demonstrate_performance()
    demonstrate_common_mistakes()
    demonstrate_cryptographic_context()
    production_implementation_notes()
    run_tests()
    practical_workflow()

    print_section("End of tutorial")
    print("All major demonstrations and automated tests have completed.")


if __name__ == "__main__":
    main()
