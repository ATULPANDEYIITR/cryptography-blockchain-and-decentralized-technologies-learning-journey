"""
MODULAR ARITHMETIC
==================

A comprehensive standalone study script covering modular arithmetic from
absolute beginner level through advanced topics.

The script uses only Python's standard library.

Run:
    python modular_arithmetic.py

The examples are organized from fundamentals to advanced number-theoretic
algorithms and applications.
"""

from __future__ import annotations

from math import gcd, isqrt
from random import randrange, SystemRandom
from typing import Iterable, List, Optional, Sequence, Tuple


# =============================================================================
# 1. FUNDAMENTALS: DIVISION ALGORITHM AND REMAINDERS
# =============================================================================

def division_algorithm(a: int, m: int) -> Tuple[int, int]:
    """
    Return q and r such that:

        a = mq + r
        0 <= r < |m|

    Python's // and % already provide a mathematically useful floor-division
    convention, but this function explicitly demonstrates the non-negative
    remainder form.
    """
    if m == 0:
        raise ValueError("The divisor/modulus must not be zero.")

    modulus = abs(m)
    q, r = divmod(a, modulus)
    return q, r


def demonstrate_remainders() -> None:
    print("\n=== 1. Remainders and the Division Algorithm ===")

    examples = [17, 25, -17, -25, 0]
    modulus = 5

    for value in examples:
        q, r = division_algorithm(value, modulus)
        print(f"{value} = {modulus}({q}) + {r}")

    print("Python examples:")
    print("17 % 5 =", 17 % 5)
    print("-17 % 5 =", -17 % 5)
    print("17 // 5 =", 17 // 5)
    print("-17 // 5 =", -17 // 5)


# =============================================================================
# 2. CONGRUENCE
# =============================================================================

def are_congruent(a: int, b: int, m: int) -> bool:
    """
    Test whether:

        a ≡ b (mod m)

    This is equivalent to m dividing (a - b).
    """
    if m == 0:
        raise ValueError("The modulus must not be zero.")
    return (a - b) % abs(m) == 0


def residue(a: int, m: int) -> int:
    """Return the canonical residue in {0, 1, ..., |m|-1}."""
    if m == 0:
        raise ValueError("The modulus must not be zero.")
    return a % abs(m)


def demonstrate_congruence() -> None:
    print("\n=== 2. Congruence ===")

    print("38 ≡ 8 (mod 10):", are_congruent(38, 8, 10))
    print("38 ≡ 9 (mod 10):", are_congruent(38, 9, 10))
    print("Canonical residue of -13 modulo 7:", residue(-13, 7))

    print("\nImportant equivalences:")
    print("38 % 10 =", 38 % 10)
    print("8 % 10  =", 8 % 10)
    print("Therefore 38 and 8 belong to the same residue class modulo 10.")


# =============================================================================
# 3. RESIDUE CLASSES AND MODULAR REPRESENTATION
# =============================================================================

def residue_class(representative: int, modulus: int, radius: int = 2) -> List[int]:
    """
    Display several integers belonging to the residue class of representative.
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")

    target = representative % modulus
    return [
        x
        for x in range(target - radius * modulus, target + (radius + 1) * modulus)
        if x % modulus == target
    ]


def demonstrate_residue_classes() -> None:
    print("\n=== 3. Residue Classes ===")

    print("[2] modulo 5 contains:", residue_class(2, 5))
    print("[0] modulo 4 contains:", residue_class(0, 4))
    print("[3] modulo 7 contains:", residue_class(3, 7))

    print(
        "A residue class modulo m is the set of all integers that have the "
        "same remainder when divided by m."
    )


# =============================================================================
# 4. BASIC MODULAR OPERATIONS
# =============================================================================

def modular_add(a: int, b: int, m: int) -> int:
    return (a + b) % m


def modular_subtract(a: int, b: int, m: int) -> int:
    return (a - b) % m


def modular_multiply(a: int, b: int, m: int) -> int:
    return (a * b) % m


def demonstrate_modular_operations() -> None:
    print("\n=== 4. Modular Addition, Subtraction, and Multiplication ===")

    a, b, m = 27, 19, 7

    print(f"({a} + {b}) mod {m} =", modular_add(a, b, m))
    print(f"({a} - {b}) mod {m} =", modular_subtract(a, b, m))
    print(f"({a} * {b}) mod {m} =", modular_multiply(a, b, m))

    print("\nReduction can be performed before multiplication:")
    print("(123456 * 789012) mod 97 =", (123456 * 789012) % 97)
    print("((123456 % 97) * (789012 % 97)) % 97 =",
          ((123456 % 97) * (789012 % 97)) % 97)


# =============================================================================
# 5. MODULAR EXPONENTIATION
# =============================================================================

def modular_power(base: int, exponent: int, modulus: int) -> int:
    """
    Compute base^exponent mod modulus using binary exponentiation.

    Time complexity: O(log exponent) modular multiplications.

    This is preferable to constructing the enormous integer base**exponent
    before taking the remainder.
    """
    if modulus <= 0:
        raise ValueError("The modulus must be positive.")
    if exponent < 0:
        raise ValueError("This function expects a non-negative exponent.")

    result = 1 % modulus
    base %= modulus

    while exponent:
        if exponent & 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent >>= 1

    return result


def demonstrate_modular_exponentiation() -> None:
    print("\n=== 5. Modular Exponentiation ===")

    print("3^100 mod 7 =", modular_power(3, 100, 7))
    print("123456789^12345 mod 1009 =",
          modular_power(123456789, 12345, 1009))

    # Python's built-in pow(base, exponent, modulus) uses an optimized
    # modular exponentiation implementation.
    print("Python pow(3, 100, 7) =", pow(3, 100, 7))


# =============================================================================
# 6. NEGATIVE VALUES AND MODULAR REDUCTION
# =============================================================================

def demonstrate_negative_numbers() -> None:
    print("\n=== 6. Negative Numbers ===")

    for value in [-20, -13, -8, -1, 0, 1, 8, 13, 20]:
        print(f"{value:>4} mod 7 = {value % 7}")

    print("\nThe expressions -1 and 6 represent the same residue modulo 7:")
    print("-1 ≡ 6 (mod 7):", are_congruent(-1, 6, 7))


# =============================================================================
# 7. MODULAR DIVISION AND INVERSES
# =============================================================================

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.

    Returns (g, x, y) satisfying:

        ax + by = g

    where g = gcd(a, b).
    """
    old_r, r = abs(a), abs(b)
    old_x, x = 1, 0
    old_y, y = 0, 1

    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y

    if a < 0:
        old_x = -old_x
    if b < 0:
        old_y = -old_y

    return old_r, old_x, old_y


def modular_inverse(a: int, m: int) -> int:
    """
    Return x such that:

        ax ≡ 1 (mod m)

    An inverse exists exactly when gcd(a, m) = 1.
    """
    if m <= 1:
        raise ValueError("The modulus must be greater than 1.")

    g, x, _ = extended_gcd(a, m)

    if g != 1:
        raise ValueError(
            f"{a} has no modular inverse modulo {m}; gcd = {g}."
        )

    return x % m


def modular_divide(a: int, b: int, m: int) -> int:
    """
    Solve:

        b*x ≡ a (mod m)

    when b has a modular inverse.
    """
    inverse = modular_inverse(b, m)
    return (a * inverse) % m


def demonstrate_modular_inverse() -> None:
    print("\n=== 7. Modular Inverses and Division ===")

    a, m = 3, 11
    inverse = modular_inverse(a, m)

    print(f"Inverse of {a} modulo {m} =", inverse)
    print(f"{a} * {inverse} mod {m} =", (a * inverse) % m)

    print("7 / 3 modulo 11 =", modular_divide(7, 3, 11))
    print(
        "Verification:",
        "(3 * modular_divide(7, 3, 11)) mod 11 =",
        (3 * modular_divide(7, 3, 11)) % 11,
    )

    try:
        modular_inverse(6, 15)
    except ValueError as error:
        print("Expected failure:", error)


# =============================================================================
# 8. EUCLIDEAN ALGORITHM
# =============================================================================

def gcd_euclidean(a: int, b: int) -> int:
    """Compute gcd using the Euclidean algorithm."""
    a, b = abs(a), abs(b)

    while b:
        a, b = b, a % b

    return a


def lcm(a: int, b: int) -> int:
    """Compute the least common multiple."""
    if a == 0 or b == 0:
        return 0
    return abs(a // gcd_euclidean(a, b) * b)


def demonstrate_gcd_lcm() -> None:
    print("\n=== 8. GCD and LCM ===")

    print("gcd(252, 105) =", gcd_euclidean(252, 105))
    print("lcm(21, 6) =", lcm(21, 6))

    g, x, y = extended_gcd(252, 105)
    print("Extended GCD result:", (g, x, y))
    print("Verification:", 252 * x + 105 * y)


# =============================================================================
# 9. LINEAR CONGRUENCES
# =============================================================================

def solve_linear_congruence(
    a: int,
    b: int,
    m: int,
) -> List[int]:
    """
    Solve:

        ax ≡ b (mod m)

    There are solutions iff gcd(a, m) divides b.

    If d = gcd(a, m), there are exactly d distinct solutions modulo m
    whenever a solution exists.
    """
    if m <= 0:
        raise ValueError("The modulus must be positive.")

    d = gcd_euclidean(a, m)

    if b % d != 0:
        return []

    a_reduced = a // d
    b_reduced = b // d
    m_reduced = m // d

    inverse = modular_inverse(a_reduced % m_reduced, m_reduced)
    x0 = (inverse * b_reduced) % m_reduced

    return sorted(
        (x0 + k * m_reduced) % m
        for k in range(d)
    )


def demonstrate_linear_congruences() -> None:
    print("\n=== 9. Linear Congruences ===")

    equation = "14x ≡ 8 (mod 22)"
    solutions = solve_linear_congruence(14, 8, 22)

    print(equation)
    print("Solutions modulo 22:", solutions)

    for x in solutions:
        print(f"14*{x} mod 22 =", (14 * x) % 22)

    print("\nAn equation with no solution:")
    print("6x ≡ 5 (mod 15)")
    print("Solutions:", solve_linear_congruence(6, 5, 15))


# =============================================================================
# 10. CHINESE REMAINDER THEOREM
# =============================================================================

def chinese_remainder_theorem(
    residues: Sequence[int],
    moduli: Sequence[int],
) -> Tuple[int, int]:
    """
    Solve a system of congruences with pairwise coprime moduli:

        x ≡ a1 (mod m1)
        x ≡ a2 (mod m2)
        ...

    Returns (x0, M), where x0 is the unique solution modulo
    M = m1*m2*... .
    """
    if len(residues) != len(moduli) or not residues:
        raise ValueError("Residues and moduli must have equal non-zero length.")

    for modulus in moduli:
        if modulus <= 0:
            raise ValueError("Moduli must be positive.")

    for i in range(len(moduli)):
        for j in range(i + 1, len(moduli)):
            if gcd_euclidean(moduli[i], moduli[j]) != 1:
                raise ValueError("The moduli must be pairwise coprime.")

    total_modulus = 1
    for modulus in moduli:
        total_modulus *= modulus

    result = 0

    for residue_value, modulus in zip(residues, moduli):
        partial = total_modulus // modulus
        inverse = modular_inverse(partial, modulus)
        result += residue_value * partial * inverse

    return result % total_modulus, total_modulus


def demonstrate_crt() -> None:
    print("\n=== 10. Chinese Remainder Theorem ===")

    residues = [2, 3, 2]
    moduli = [3, 5, 7]

    solution, modulus = chinese_remainder_theorem(residues, moduli)

    print("x ≡ 2 (mod 3)")
    print("x ≡ 3 (mod 5)")
    print("x ≡ 2 (mod 7)")
    print("Solution:", solution)
    print("Unique modulo:", modulus)

    for a, m in zip(residues, moduli):
        print(f"{solution} mod {m} =", solution % m)


# =============================================================================
# 11. GENERALIZED CRT FOR NON-COPRIME MODULI
# =============================================================================

def generalized_crt(
    a1: int,
    m1: int,
    a2: int,
    m2: int,
) -> Optional[Tuple[int, int]]:
    """
    Solve:

        x ≡ a1 (mod m1)
        x ≡ a2 (mod m2)

    even when m1 and m2 are not coprime.

    A solution exists iff:

        a1 ≡ a2 (mod gcd(m1, m2))

    The result is (x0, lcm(m1, m2)).
    """
    if m1 <= 0 or m2 <= 0:
        raise ValueError("Moduli must be positive.")

    g = gcd_euclidean(m1, m2)

    if (a2 - a1) % g != 0:
        return None

    reduced_m1 = m1 // g
    reduced_m2 = m2 // g
    difference = (a2 - a1) // g

    inverse = modular_inverse(reduced_m1 % reduced_m2, reduced_m2)
    k = (difference * inverse) % reduced_m2

    x = a1 + m1 * k
    combined_modulus = m1 * reduced_m2

    return x % combined_modulus, combined_modulus


def demonstrate_generalized_crt() -> None:
    print("\n=== 11. Generalized CRT ===")

    result = generalized_crt(2, 6, 8, 9)
    print("x ≡ 2 (mod 6)")
    print("x ≡ 8 (mod 9)")
    print("Solution:", result)

    no_solution = generalized_crt(2, 6, 7, 9)
    print("x ≡ 2 (mod 6), x ≡ 7 (mod 9)")
    print("Solution:", no_solution)


# =============================================================================
# 12. EULER'S TOTIENT FUNCTION
# =============================================================================

def prime_factorization(n: int) -> List[Tuple[int, int]]:
    """
    Return the prime factorization as (prime, exponent) pairs.

    Trial division is intended for educational use and is not appropriate
    for very large cryptographic integers.
    """
    if n < 1:
        raise ValueError("n must be positive.")

    factors = []
    exponent = 0

    while n % 2 == 0 and n > 1:
        n //= 2
        exponent += 1

    if exponent:
        factors.append((2, exponent))

    p = 3
    while p * p <= n:
        if n % p == 0:
            exponent = 0
            while n % p == 0:
                n //= p
                exponent += 1
            factors.append((p, exponent))
        p += 2

    if n > 1:
        factors.append((n, 1))

    return factors


def euler_totient(n: int) -> int:
    """
    Compute phi(n), the number of integers in {1,...,n} coprime to n.

    Formula:

        phi(n) = n * product(1 - 1/p)

    over distinct prime divisors p of n.
    """
    if n <= 0:
        raise ValueError("n must be positive.")

    result = n

    for prime, _ in prime_factorization(n):
        result -= result // prime

    return result


def demonstrate_totient() -> None:
    print("\n=== 12. Euler's Totient Function ===")

    for n in [1, 2, 5, 8, 9, 10, 12, 36]:
        print(f"phi({n}) =", euler_totient(n))

    print("Factorization of 360:", prime_factorization(360))


# =============================================================================
# 13. EULER'S THEOREM AND FERMAT'S LITTLE THEOREM
# =============================================================================

def demonstrate_euler_and_fermat() -> None:
    print("\n=== 13. Euler's Theorem and Fermat's Little Theorem ===")

    # Euler's theorem:
    # If gcd(a, n) = 1, then a^phi(n) ≡ 1 (mod n).
    a, n = 3, 10
    phi_n = euler_totient(n)

    print(
        f"{a}^{phi_n} mod {n} =",
        modular_power(a, phi_n, n),
    )

    # Fermat's little theorem is the prime-modulus special case:
    # If p is prime and p does not divide a:
    #     a^(p-1) ≡ 1 (mod p)
    a, p = 5, 13

    print(
        f"{a}^{p - 1} mod {p} =",
        modular_power(a, p - 1, p),
    )

    print(
        "For prime p, a^(p-1) ≡ 1 (mod p) whenever p does not divide a."
    )


# =============================================================================
# 14. MULTIPLICATIVE ORDER
# =============================================================================

def multiplicative_order(a: int, m: int) -> int:
    """
    Find the smallest positive k such that:

        a^k ≡ 1 (mod m)

    Requires gcd(a, m) = 1.
    """
    if m <= 1:
        raise ValueError("m must be greater than 1.")

    if gcd_euclidean(a, m) != 1:
        raise ValueError("a must be coprime to m.")

    order = 1
    value = a % m

    while value != 1:
        value = (value * a) % m
        order += 1

        if order > euler_totient(m):
            raise RuntimeError("Unexpected order computation failure.")

    return order


def demonstrate_multiplicative_order() -> None:
    print("\n=== 14. Multiplicative Order ===")

    for a in [2, 3, 4, 5]:
        if gcd_euclidean(a, 7) == 1:
            print(f"ord_7({a}) =", multiplicative_order(a, 7))


# =============================================================================
# 15. MODULAR SQUARE ROOTS BY BRUTE FORCE
# =============================================================================

def modular_square_roots_bruteforce(a: int, p: int) -> List[int]:
    """
    Educational implementation for finding x satisfying:

        x^2 ≡ a (mod p)

    by testing every residue.

    This is intentionally simple and is not efficient for large p.
    """
    if p <= 1:
        raise ValueError("The modulus must be greater than 1.")

    target = a % p
    return [x for x in range(p) if (x * x) % p == target]


def demonstrate_modular_square_roots() -> None:
    print("\n=== 15. Modular Square Roots ===")

    print("Solutions of x^2 ≡ 4 (mod 7):",
          modular_square_roots_bruteforce(4, 7))

    print("Solutions of x^2 ≡ 3 (mod 7):",
          modular_square_roots_bruteforce(3, 7))


# =============================================================================
# 16. JACOBI SYMBOL
# =============================================================================

def jacobi_symbol(a: int, n: int) -> int:
    """
    Compute the Jacobi symbol (a/n) for positive odd n.

    The Jacobi symbol generalizes the Legendre symbol.
    """
    if n <= 0 or n % 2 == 0:
        raise ValueError("n must be a positive odd integer.")

    a %= n
    result = 1

    while a:
        while a % 2 == 0:
            a //= 2
            n_mod_8 = n % 8
            if n_mod_8 in (3, 5):
                result = -result

        a, n = n, a

        if a % 4 == 3 and n % 4 == 3:
            result = -result

        a %= n

    return result if n == 1 else 0


def legendre_symbol(a: int, p: int) -> int:
    """
    For an odd prime p, compute the Legendre symbol (a/p).

    Euler's criterion:
        (a/p) ≡ a^((p-1)/2) mod p

    The returned value is -1, 0, or 1.
    """
    if p <= 2 or p % 2 == 0:
        raise ValueError("p must be an odd prime.")

    a %= p

    if a == 0:
        return 0

    value = modular_power(a, (p - 1) // 2, p)
    return 1 if value == 1 else -1


def demonstrate_symbols() -> None:
    print("\n=== 16. Legendre and Jacobi Symbols ===")

    print("(2/7) Legendre symbol =", legendre_symbol(2, 7))
    print("(3/7) Legendre symbol =", legendre_symbol(3, 7))

    print("(5/21) Jacobi symbol =", jacobi_symbol(5, 21))
    print("(2/15) Jacobi symbol =", jacobi_symbol(2, 15))


# =============================================================================
# 17. FAST MODULAR EXPONENTIATION WITH TRACE
# =============================================================================

def modular_power_trace(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Binary modular exponentiation with a printed trace.

    Useful for understanding exponentiation by squaring.
    """
    if exponent < 0 or modulus <= 0:
        raise ValueError("Exponent must be non-negative and modulus positive.")

    result = 1 % modulus
    base %= modulus
    step = 0

    print("step | exponent | base | result")

    while exponent:
        print(f"{step:>4} | {exponent:>9} | {base:>4} | {result:>6}")

        if exponent & 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent >>= 1
        step += 1

    print(f"{step:>4} | {exponent:>9} | {base:>4} | {result:>6}")

    return result


def demonstrate_power_trace() -> None:
    print("\n=== 17. Exponentiation by Squaring Trace ===")
    result = modular_power_trace(7, 13, 20)
    print("Final result:", result)


# =============================================================================
# 18. MODULAR EXPONENTIATION WITH NEGATIVE EXPONENT
# =============================================================================

def modular_power_signed(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Compute base^exponent modulo modulus for positive or negative exponents.

    For exponent < 0, the modular inverse of base is required.
    """
    if modulus <= 1:
        raise ValueError("The modulus must be greater than 1.")

    if exponent >= 0:
        return modular_power(base, exponent, modulus)

    inverse = modular_inverse(base, modulus)
    return modular_power(inverse, -exponent, modulus)


def demonstrate_negative_exponent() -> None:
    print("\n=== 18. Negative Modular Exponents ===")

    print("3^(-2) mod 11 =", modular_power_signed(3, -2, 11))

    # 3^(-2) = (3^-1)^2.
    # Since 3^-1 ≡ 4 (mod 11), the result is 16 ≡ 5.
    print("Verification:", (5 * 3 * 3) % 11)


# =============================================================================
# 19. POLYNOMIALS OVER A FINITE MODULAR RING
# =============================================================================

def polynomial_evaluate_mod(
    coefficients: Sequence[int],
    x: int,
    modulus: int,
) -> int:
    """
    Evaluate:

        c0 + c1*x + c2*x^2 + ...

    modulo modulus using Horner's method.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive.")

    result = 0

    for coefficient in reversed(coefficients):
        result = (result * x + coefficient) % modulus

    return result


def demonstrate_polynomial_modular_evaluation() -> None:
    print("\n=== 19. Polynomial Evaluation Modulo m ===")

    # f(x) = 2x^3 + 3x^2 + 5x + 7
    coefficients = [7, 5, 3, 2]
    x = 11
    modulus = 13

    print(
        "f(11) mod 13 =",
        polynomial_evaluate_mod(coefficients, x, modulus),
    )


# =============================================================================
# 20. PERIODICITY AND CYCLES
# =============================================================================

def modular_power_cycle(base: int, modulus: int, limit: int = 100) -> List[int]:
    """
    Generate powers:

        base^1 mod m, base^2 mod m, ...

    until 1 appears or the limit is reached.
    """
    if modulus <= 1:
        raise ValueError("Modulus must be greater than 1.")

    values = []
    value = base % modulus

    for _ in range(limit):
        values.append(value)

        if value == 1:
            break

        value = (value * base) % modulus

    return values


def demonstrate_cycles() -> None:
    print("\n=== 20. Cyclic Behavior ===")

    print("Powers of 2 modulo 7:")
    print(modular_power_cycle(2, 7))

    print("Powers of 10 modulo 17:")
    print(modular_power_cycle(10, 17))


# =============================================================================
# 21. CHECKING PRIMALITY
# =============================================================================

def is_prime_trial_division(n: int) -> bool:
    """
    Educational deterministic primality test using trial division.

    Complexity is approximately O(sqrt(n)) divisions.
    """
    if n < 2:
        return False

    if n in (2, 3):
        return True

    if n % 2 == 0:
        return False

    divisor = 3

    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2

    return True


def demonstrate_primality() -> None:
    print("\n=== 21. Primality Testing ===")

    for n in [1, 2, 3, 4, 17, 25, 97, 100]:
        print(f"{n:>3} prime? {is_prime_trial_division(n)}")


# =============================================================================
# 22. SIEVE OF ERATOSTHENES
# =============================================================================

def sieve_primes(limit: int) -> List[int]:
    """Return all primes <= limit using the Sieve of Eratosthenes."""
    if limit < 2:
        return []

    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False

    for p in range(2, isqrt(limit) + 1):
        if is_prime[p]:
            start = p * p
            is_prime[start : limit + 1 : p] = [False] * (
                ((limit - start) // p) + 1
            )

    return [n for n, prime in enumerate(is_prime) if prime]


def demonstrate_sieve() -> None:
    print("\n=== 22. Sieve of Eratosthenes ===")
    print("Primes <= 50:", sieve_primes(50))


# =============================================================================
# 23. TOTIENT SIEVE
# =============================================================================

def totient_sieve(limit: int) -> List[int]:
    """
    Compute phi(n) for every n from 0 through limit.

    Complexity: approximately O(n log log n).
    """
    if limit < 0:
        raise ValueError("limit must be non-negative.")

    phi = list(range(limit + 1))

    for p in range(2, limit + 1):
        if phi[p] == p:
            for multiple in range(p, limit + 1, p):
                phi[multiple] -= phi[multiple] // p

    if limit >= 0:
        phi[0] = 0

    return phi


def demonstrate_totient_sieve() -> None:
    print("\n=== 23. Totient Sieve ===")

    phi = totient_sieve(20)
    print("phi(1)..phi(20):", phi[1:])


# =============================================================================
# 24. DISCRETE LOGARITHM BY BABY-STEP GIANT-STEP
# =============================================================================

def baby_step_giant_step(
    base: int,
    target: int,
    modulus: int,
) -> Optional[int]:
    """
    Find x satisfying:

        base^x ≡ target (mod modulus)

    using the Baby-Step Giant-Step algorithm.

    This implementation assumes gcd(base, modulus) = 1.

    For a group of size approximately n, the algorithm requires O(sqrt(n))
    time and memory.
    """
    if modulus <= 1:
        raise ValueError("Modulus must be greater than 1.")

    if gcd_euclidean(base, modulus) != 1:
        raise ValueError("This implementation requires gcd(base, modulus) = 1.")

    order_bound = modulus
    step = isqrt(order_bound) + 1

    baby_steps = {}
    value = 1

    for j in range(step):
        baby_steps.setdefault(value, j)
        value = (value * base) % modulus

    base_inverse = modular_inverse(base, modulus)
    factor = modular_power(base_inverse, step, modulus)

    gamma = target % modulus

    for i in range(step + 1):
        if gamma in baby_steps:
            candidate = i * step + baby_steps[gamma]

            if modular_power(base, candidate, modulus) == target % modulus:
                return candidate

        gamma = (gamma * factor) % modulus

    return None


def demonstrate_discrete_log() -> None:
    print("\n=== 24. Discrete Logarithm: Baby-Step Giant-Step ===")

    base = 5
    exponent = 7
    modulus = 23
    target = modular_power(base, exponent, modulus)

    found = baby_step_giant_step(base, target, modulus)

    print(f"{base}^{exponent} mod {modulus} =", target)
    print(f"Recovered exponent:", found)


# =============================================================================
# 25. TONELLI-SHANKS MODULAR SQUARE ROOT
# =============================================================================

def tonelli_shanks(n: int, p: int) -> Optional[int]:
    """
    Find x such that:

        x^2 ≡ n (mod p)

    for an odd prime p.

    Returns one root or None if no root exists.

    Tonelli-Shanks runs efficiently for prime moduli.
    """
    if p == 2:
        return n % 2

    if p <= 2 or not is_prime_trial_division(p):
        raise ValueError("p must be an odd prime.")

    n %= p

    if n == 0:
        return 0

    if legendre_symbol(n, p) != 1:
        return None

    # Simple case for p ≡ 3 (mod 4).
    if p % 4 == 3:
        return modular_power(n, (p + 1) // 4, p)

    # Write p - 1 = q * 2^s with q odd.
    q = p - 1
    s = 0

    while q % 2 == 0:
        q //= 2
        s += 1

    # Find a quadratic non-residue z.
    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    c = modular_power(z, q, p)
    x = modular_power(n, (q + 1) // 2, p)
    t = modular_power(n, q, p)
    m = s

    while t != 1:
        i = 1
        t_power = (t * t) % p

        while t_power != 1:
            t_power = (t_power * t_power) % p
            i += 1

            if i >= m:
                raise RuntimeError("Tonelli-Shanks internal failure.")

        b = modular_power(c, 1 << (m - i - 1), p)
        x = (x * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i

    return x


def demonstrate_tonelli_shanks() -> None:
    print("\n=== 25. Tonelli-Shanks ===")

    for n, p in [(10, 13), (56, 101), (5, 11)]:
        root = tonelli_shanks(n, p)
        print(f"x^2 ≡ {n} (mod {p}) -> root =", root)

        if root is not None:
            print("Verification:", (root * root) % p)


# =============================================================================
# 26. RSA-STYLE MODULAR ARITHMETIC
# =============================================================================

def rsa_demo() -> None:
    """
    Small educational RSA demonstration.

    This is NOT secure cryptographic code. The primes are intentionally tiny.
    Real RSA requires large carefully generated primes, secure padding,
    side-channel protections, validated key generation, and established
    cryptographic libraries.
    """
    print("\n=== 26. RSA-Style Modular Arithmetic ===")

    p = 61
    q = 53
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 17
    d = modular_inverse(e, phi)

    message = 65

    ciphertext = modular_power(message, e, n)
    decrypted = modular_power(ciphertext, d, n)

    print("p =", p)
    print("q =", q)
    print("n =", n)
    print("phi(n) =", phi)
    print("public exponent e =", e)
    print("private exponent d =", d)
    print("message =", message)
    print("ciphertext =", ciphertext)
    print("decrypted =", decrypted)


# =============================================================================
# 27. DIFFIE-HELLMAN STYLE MODULAR EXPONENTIATION
# =============================================================================

def diffie_hellman_demo() -> None:
    """
    Demonstrate the arithmetic behind Diffie-Hellman.

    The parameters are intentionally small and insecure.
    """
    print("\n=== 27. Diffie-Hellman-Style Key Agreement ===")

    prime = 23
    generator = 5

    private_a = 6
    private_b = 15

    public_a = modular_power(generator, private_a, prime)
    public_b = modular_power(generator, private_b, prime)

    shared_a = modular_power(public_b, private_a, prime)
    shared_b = modular_power(public_a, private_b, prime)

    print("prime =", prime)
    print("generator =", generator)
    print("Alice public value =", public_a)
    print("Bob public value =", public_b)
    print("Alice shared secret =", shared_a)
    print("Bob shared secret =", shared_b)
    print("Shared secrets match:", shared_a == shared_b)


# =============================================================================
# 28. HASHING / CHECKSUM EXAMPLE USING MODULAR ARITHMETIC
# =============================================================================

def polynomial_rolling_hash(
    text: str,
    base: int = 257,
    modulus: int = 1_000_000_007,
) -> int:
    """
    Educational polynomial rolling hash.

    It is useful for demonstrating modular arithmetic in string algorithms.
    It is not a cryptographic hash.
    """
    hash_value = 0

    for character in text:
        hash_value = (
            hash_value * base + ord(character)
        ) % modulus

    return hash_value


def demonstrate_hashing() -> None:
    print("\n=== 28. Polynomial Rolling Hash ===")

    for text in ["hello", "world", "hello!"]:
        print(
            f"{text!r} ->",
            polynomial_rolling_hash(text),
        )


# =============================================================================
# 29. MODULAR DATE/CLOCK ARITHMETIC
# =============================================================================

def clock_after_hours(start_hour: int, hours: int) -> int:
    """
    A 24-hour clock is naturally modeled modulo 24.
    """
    return (start_hour + hours) % 24


def weekday_after_days(start_day: int, days: int) -> int:
    """
    Model weekdays using residues 0..6.
    """
    return (start_day + days) % 7


def demonstrate_real_world_cycles() -> None:
    print("\n=== 29. Real-World Cyclic Applications ===")

    print("22:00 + 7 hours =", clock_after_hours(22, 7), ":00")
    print("Day 5 + 10 days =", weekday_after_days(5, 10))


# =============================================================================
# 30. MODULAR MATRIX ARITHMETIC
# =============================================================================

Matrix = List[List[int]]


def matrix_mod(matrix: Matrix, modulus: int) -> Matrix:
    return [
        [value % modulus for value in row]
        for row in matrix
    ]


def matrix_multiply_mod(
    a: Matrix,
    b: Matrix,
    modulus: int,
) -> Matrix:
    """Multiply two matrices modulo modulus."""
    if not a or not b or not a[0] or not b[0]:
        raise ValueError("Matrices must be non-empty.")

    a_columns = len(a[0])
    b_rows = len(b)

    if a_columns != b_rows:
        raise ValueError("Incompatible matrix dimensions.")

    if any(len(row) != a_columns for row in a):
        raise ValueError("Matrix A is not rectangular.")

    if any(len(row) != len(b[0]) for row in b):
        raise ValueError("Matrix B is not rectangular.")

    result = [
        [0 for _ in range(len(b[0]))]
        for _ in range(len(a))
    ]

    for i in range(len(a)):
        for j in range(len(b[0])):
            total = 0
            for k in range(a_columns):
                total += a[i][k] * b[k][j]
            result[i][j] = total % modulus

    return result


def matrix_power_mod(
    matrix: Matrix,
    exponent: int,
    modulus: int,
) -> Matrix:
    """
    Compute a square matrix power modulo m using binary exponentiation.
    """
    if exponent < 0:
        raise ValueError("Exponent must be non-negative.")

    n = len(matrix)

    if n == 0 or any(len(row) != n for row in matrix):
        raise ValueError("Matrix must be non-empty and square.")

    result = [
        [1 if i == j else 0 for j in range(n)]
        for i in range(n)
    ]

    base = matrix_mod(matrix, modulus)

    while exponent:
        if exponent & 1:
            result = matrix_multiply_mod(result, base, modulus)

        base = matrix_multiply_mod(base, base, modulus)
        exponent >>= 1

    return result


def demonstrate_matrix_modular_arithmetic() -> None:
    print("\n=== 30. Matrix Arithmetic Modulo m ===")

    matrix = [
        [1, 1],
        [1, 0],
    ]

    result = matrix_power_mod(matrix, 10, 1000)

    print("Fibonacci matrix^10 modulo 1000:")
    for row in result:
        print(row)

    # The upper-left entry is F(11) = 89.
    print("F(11) =", result[0][0])


# =============================================================================
# 31. LINEAR RECURRENCES WITH MATRIX EXPONENTIATION
# =============================================================================

def fibonacci_mod(n: int, modulus: int) -> int:
    """Compute F(n) modulo modulus in O(log n) matrix operations."""
    if n < 0:
        raise ValueError("n must be non-negative.")

    if n == 0:
        return 0

    matrix = [
        [1, 1],
        [1, 0],
    ]

    powered = matrix_power_mod(matrix, n - 1, modulus)
    return powered[0][0] % modulus


def demonstrate_fibonacci_modular() -> None:
    print("\n=== 31. Fibonacci Numbers Modulo m ===")

    print("F(1000) mod 1009 =", fibonacci_mod(1000, 1009))
    print("F(1000000) mod 1000000007 =",
          fibonacci_mod(1_000_000, 1_000_000_007))


# =============================================================================
# 32. MODULAR EXPONENTIATION UNDER A COMPOSITE MODULUS
# =============================================================================

def demonstrate_composite_modulus_behavior() -> None:
    print("\n=== 32. Composite Modulus Behavior ===")

    # Fermat's theorem cannot be applied directly with n = 15 because 15 is
    # composite. Euler's theorem requires gcd(a, n) = 1.
    print("2^4 mod 15 =", modular_power(2, 4, 15))
    print("phi(15) =", euler_totient(15))
    print("2^phi(15) mod 15 =", modular_power(2, euler_totient(15), 15))

    # If gcd(a, n) != 1, Euler's theorem in its standard form does not apply.
    print("gcd(6, 15) =", gcd_euclidean(6, 15))
    print("6^4 mod 15 =", modular_power(6, 4, 15))


# =============================================================================
# 33. CARMICHAEL FUNCTION FOR SMALL VALUES
# =============================================================================

def prime_power_carmichael(p: int, k: int) -> int:
    """
    Compute lambda(p^k) for prime p.

    For odd p:
        lambda(p^k) = phi(p^k)

    For powers of 2:
        lambda(2) = 1
        lambda(4) = 2
        lambda(2^k) = 2^(k-2), k >= 3
    """
    if not is_prime_trial_division(p) or k < 1:
        raise ValueError("p must be prime and k must be positive.")

    if p == 2:
        if k == 1:
            return 1
        if k == 2:
            return 2
        return 2 ** (k - 2)

    return (p - 1) * (p ** (k - 1))


def lcm_many(values: Iterable[int]) -> int:
    result = 1

    for value in values:
        result = lcm(result, value)

    return result


def carmichael_lambda(n: int) -> int:
    """
    Compute Carmichael's lambda function using prime factorization.
    """
    if n <= 0:
        raise ValueError("n must be positive.")

    if n == 1:
        return 1

    factors = prime_factorization(n)

    values = [
        prime_power_carmichael(p, k)
        for p, k in factors
    ]

    return lcm_many(values)


def demonstrate_carmichael() -> None:
    print("\n=== 33. Carmichael Function ===")

    for n in [1, 2, 4, 8, 9, 15, 16, 21]:
        print(f"lambda({n}) =", carmichael_lambda(n))


# =============================================================================
# 34. MODULAR ARITHMETIC EDGE CASES
# =============================================================================

def demonstrate_edge_cases() -> None:
    print("\n=== 34. Important Edge Cases ===")

    print("0 mod 7 =", 0 % 7)
    print("7 mod 7 =", 7 % 7)
    print("-7 mod 7 =", -7 % 7)
    print("1^0 mod 13 =", modular_power(1, 0, 13))
    print("0^0 under this modular-power convention =", modular_power(0, 0, 13))

    cases = [
        ("inverse of 2 modulo 4", lambda: modular_inverse(2, 4)),
        ("inverse modulo 1", lambda: modular_inverse(2, 1)),
        ("zero modulus", lambda: residue(5, 0)),
        ("negative exponent without inverse", lambda: modular_power_signed(6, -1, 15)),
    ]

    for description, operation in cases:
        try:
            print(description, "=", operation())
        except ValueError as error:
            print(description, "-> expected error:", error)


# =============================================================================
# 35. PROPERTY-BASED INTERNAL CHECKS
# =============================================================================

def run_correctness_checks() -> None:
    """
    Small deterministic tests validating important identities.
    """
    print("\n=== 35. Correctness Checks ===")

    # Congruence is preserved by addition and multiplication.
    assert are_congruent(17, 5, 12)
    assert are_congruent(17 + 20, 5 + 20, 12)
    assert are_congruent(17 * 4, 5 * 4, 12)

    # Extended GCD identity.
    for a, b in [(252, 105), (99, 78), (17, 31)]:
        g, x, y = extended_gcd(a, b)
        assert a * x + b * y == g
        assert g == gcd_euclidean(a, b)

    # Inverse identity.
    for a, m in [(3, 11), (7, 20), (17, 3120)]:
        inverse = modular_inverse(a, m)
        assert (a * inverse) % m == 1

    # Fast exponentiation agrees with Python.
    test_values = [
        (2, 0, 7),
        (2, 10, 13),
        (123, 456, 97),
        (9999, 1234, 1009),
    ]

    for base, exponent, modulus in test_values:
        assert modular_power(base, exponent, modulus) == pow(
            base, exponent, modulus
        )

    # Linear congruence solutions really satisfy the equations.
    for a, b, m in [(14, 8, 22), (6, 9, 15), (5, 2, 7)]:
        for x in solve_linear_congruence(a, b, m):
            assert (a * x - b) % m == 0

    # CRT.
    x, modulus = chinese_remainder_theorem([2, 3, 2], [3, 5, 7])
    assert x == 23
    assert modulus == 105

    # Fibonacci.
    assert fibonacci_mod(0, 100) == 0
    assert fibonacci_mod(1, 100) == 1
    assert fibonacci_mod(10, 100) == 55

    # Tonelli-Shanks.
    for n, p in [(10, 13), (56, 101)]:
        root = tonelli_shanks(n, p)
        assert root is not None
        assert root * root % p == n % p

    print("All correctness checks passed.")


# =============================================================================
# 36. PERFORMANCE COMPARISON: NAIVE VS FAST EXPONENTIATION
# =============================================================================

def naive_modular_power(base: int, exponent: int, modulus: int) -> int:
    """
    Naive repeated multiplication.

    This performs O(exponent) multiplications.
    """
    result = 1 % modulus

    for _ in range(exponent):
        result = (result * base) % modulus

    return result


def demonstrate_performance_concept() -> None:
    print("\n=== 36. Performance: Naive vs Binary Exponentiation ===")

    base = 7
    exponent = 1000
    modulus = 1_000_000_007

    naive = naive_modular_power(base, exponent, modulus)
    fast = modular_power(base, exponent, modulus)

    print("Naive result:", naive)
    print("Binary-exponentiation result:", fast)
    print("Results agree:", naive == fast)
    print("Naive performs approximately exponent multiplications.")
    print("Binary exponentiation performs O(log exponent) iterations.")


# =============================================================================
# 37. CONSTANT-TIME CONSIDERATIONS
# =============================================================================

def constant_time_concept_example(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Montgomery-ladder-style conceptual exponentiation.

    The structure performs a similar pair of modular multiplications per
    exponent bit. This reduces some timing variation compared with a simple
    square-and-multiply implementation, although Python itself is NOT suitable
    for claiming constant-time cryptographic behavior.
    """
    if exponent < 0 or modulus <= 0:
        raise ValueError("Invalid exponent or modulus.")

    r0 = 1 % modulus
    r1 = base % modulus

    bits = bin(exponent)[2:] or "0"

    for bit in bits:
        if bit == "0":
            r1 = (r0 * r1) % modulus
            r0 = (r0 * r0) % modulus
        else:
            r0 = (r0 * r1) % modulus
            r1 = (r1 * r1) % modulus

    return r0


def demonstrate_security_concept() -> None:
    print("\n=== 37. Timing and Security Considerations ===")

    base = 7
    exponent = 12345
    modulus = 1_000_003

    normal = modular_power(base, exponent, modulus)
    ladder = constant_time_concept_example(base, exponent, modulus)

    print("Normal modular exponentiation:", normal)
    print("Ladder-style result:", ladder)
    print("Results agree:", normal == ladder)
    print(
        "Important: algorithmic structure alone does not make Python "
        "cryptographic code constant-time."
    )


# =============================================================================
# 38. RANDOMIZED MODULAR ARITHMETIC EXERCISES
# =============================================================================

def generate_practice_questions(
    count: int = 10,
    seed: int = 2026,
) -> List[Tuple[int, int, int, int]]:
    """
    Generate reproducible modular-arithmetic questions.

    Each tuple is (a, b, m, answer) for:

        a*b mod m
    """
    import random

    rng = random.Random(seed)
    questions = []

    for _ in range(count):
        a = rng.randint(-500, 500)
        b = rng.randint(-500, 500)
        m = rng.randint(2, 100)
        answer = (a * b) % m
        questions.append((a, b, m, answer))

    return questions


def demonstrate_practice_generation() -> None:
    print("\n=== 38. Practice Questions ===")

    for a, b, m, answer in generate_practice_questions(5):
        print(f"({a} * {b}) mod {m} = {answer}")


# =============================================================================
# 39. MODULAR ARITHMETIC REFERENCE FUNCTIONS
# =============================================================================

def modular_sum(values: Iterable[int], modulus: int) -> int:
    """Compute the sum of many values modulo m."""
    if modulus <= 0:
        raise ValueError("modulus must be positive.")

    total = 0

    for value in values:
        total = (total + value) % modulus

    return total


def modular_product(values: Iterable[int], modulus: int) -> int:
    """Compute the product of many values modulo m."""
    if modulus <= 0:
        raise ValueError("modulus must be positive.")

    result = 1 % modulus

    for value in values:
        result = (result * value) % modulus

    return result


def demonstrate_aggregate_operations() -> None:
    print("\n=== 39. Modular Aggregation ===")

    values = [10, 20, 30, 40]

    print("Sum modulo 7 =", modular_sum(values, 7))
    print("Product modulo 7 =", modular_product(values, 7))


# =============================================================================
# 40. MODULAR LINEAR EQUATION AS A SYSTEMATIC WORKFLOW
# =============================================================================

def solve_and_explain_linear_equation(
    a: int,
    b: int,
    m: int,
) -> None:
    """
    Explain the decision process for ax ≡ b (mod m).
    """
    print(f"\nSolving {a}x ≡ {b} (mod {m})")

    d = gcd_euclidean(a, m)
    print("gcd(a, m) =", d)

    if b % d != 0:
        print("Since gcd(a,m) does not divide b, no solution exists.")
        return

    print("Since gcd(a,m) divides b, solutions exist.")

    solutions = solve_linear_congruence(a, b, m)
    print("Solutions modulo m:", solutions)

    for solution in solutions:
        print(
            f"Check: ({a} * {solution} - {b}) mod {m} =",
            (a * solution - b) % m,
        )


# =============================================================================
# 41. MODULAR ARITHMETIC WITH LARGE INTEGERS
# =============================================================================

def demonstrate_large_integer_arithmetic() -> None:
    print("\n=== 41. Large Integer Modular Arithmetic ===")

    base = 987654321987654321987654321
    exponent = 123456789
    modulus = 1_000_000_007

    result = modular_power(base, exponent, modulus)

    print("Large modular exponentiation result:", result)
    print(
        "Python integers have arbitrary precision, but the modular algorithm "
        "keeps intermediate values reduced modulo the modulus."
    )


# =============================================================================
# 42. APPLICATION: CHECKING DIVISIBILITY WITH MODULAR ARITHMETIC
# =============================================================================

def divisibility_tests(number: int) -> dict:
    """
    Demonstrate divisibility tests as modular conditions.
    """
    return {
        "divisible_by_2": number % 2 == 0,
        "divisible_by_3": number % 3 == 0,
        "divisible_by_5": number % 5 == 0,
        "divisible_by_9": number % 9 == 0,
        "divisible_by_10": number % 10 == 0,
        "divisible_by_11": number % 11 == 0,
    }


def demonstrate_divisibility() -> None:
    print("\n=== 42. Divisibility Through Modular Arithmetic ===")

    number = 1234567890

    for rule, result in divisibility_tests(number).items():
        print(f"{rule}: {result}")


# =============================================================================
# 43. APPLICATION: CHECK DIGIT STYLE VALIDATION
# =============================================================================

def mod11_check_digit(number_string: str) -> int:
    """
    A simple educational modulus-11 check digit.

    This is not a universal standard and should not be confused with the
    specific algorithms used by every real-world identification system.
    """
    if not number_string.isdigit():
        raise ValueError("Input must contain digits only.")

    weighted_sum = 0
    weight = 2

    for digit in reversed(number_string):
        weighted_sum += int(digit) * weight
        weight += 1

        if weight > 7:
            weight = 2

    return (11 - weighted_sum % 11) % 11


def demonstrate_check_digit() -> None:
    print("\n=== 43. Check-Digit Example ===")

    value = "123456789"
    check_digit = mod11_check_digit(value)

    print("Value:", value)
    print("Educational mod-11 check digit:", check_digit)


# =============================================================================
# 44. MODULAR ARITHMETIC AS AN ALGEBRAIC STRUCTURE
# =============================================================================

def demonstrate_algebraic_structure() -> None:
    print("\n=== 44. Algebraic Structure ===")

    modulus = 6
    residues = list(range(modulus))

    print("Z/6Z representatives:", residues)

    print("\nAddition table modulo 6:")
    for a in residues:
        row = [(a + b) % modulus for b in residues]
        print(row)

    print("\nMultiplication table modulo 6:")
    for a in residues:
        row = [(a * b) % modulus for b in residues]
        print(row)

    print(
        "\nZ/mZ forms a ring under modular addition and multiplication. "
        "Its elements that are coprime to m form the multiplicative group "
        "of units modulo m."
    )


# =============================================================================
# 45. ZERO DIVISORS AND WHY CANCELLATION CAN FAIL
# =============================================================================

def demonstrate_zero_divisors() -> None:
    print("\n=== 45. Zero Divisors and Failed Cancellation ===")

    # Modulo 6:
    # 2 * 3 = 6 ≡ 0 (mod 6), even though neither factor is 0 modulo 6.
    print("2 * 3 mod 6 =", (2 * 3) % 6)

    print(
        "This means 2 and 3 are zero divisors modulo 6."
    )

    # Cancellation is valid only under appropriate conditions.
    # If gcd(c,m)=1, multiplication by c is invertible modulo m.
    print("gcd(5, 6) =", gcd_euclidean(5, 6))
    print(
        "5 has inverse modulo 6:",
        modular_inverse(5, 6),
    )


# =============================================================================
# 46. UNITS MODULO m
# =============================================================================

def units_modulo(m: int) -> List[int]:
    """Return all units modulo m."""
    if m <= 1:
        raise ValueError("m must be greater than 1.")

    return [
        a
        for a in range(m)
        if gcd_euclidean(a, m) == 1
    ]


def demonstrate_units() -> None:
    print("\n=== 46. Units Modulo m ===")

    for m in [5, 8, 10, 12]:
        units = units_modulo(m)
        print(f"Units modulo {m}:", units)
        print(f"Count = {len(units)}, phi({m}) = {euler_totient(m)}")


# =============================================================================
# 47. FAST POWER USING RECURSION
# =============================================================================

def recursive_modular_power(
    base: int,
    exponent: int,
    modulus: int,
) -> int:
    """
    Recursive exponentiation by squaring.

    Iterative binary exponentiation is generally preferable in Python because
    it avoids recursion depth considerations.
    """
    if exponent < 0 or modulus <= 0:
        raise ValueError("Invalid exponent or modulus.")

    if exponent == 0:
        return 1 % modulus

    half = recursive_modular_power(base, exponent // 2, modulus)
    result = (half * half) % modulus

    if exponent % 2:
        result = (result * base) % modulus

    return result


def demonstrate_recursive_power() -> None:
    print("\n=== 47. Recursive Exponentiation by Squaring ===")

    result = recursive_modular_power(7, 20, 13)
    print("7^20 mod 13 =", result)


# =============================================================================
# 48. MODULAR INVERSE USING PYTHON'S BUILT-IN POW
# =============================================================================

def modular_inverse_builtin(a: int, m: int) -> int:
    """
    Python 3.8+ supports pow(a, -1, m) for modular inverses.

    This wrapper provides an explicit educational name.
    """
    if m <= 1:
        raise ValueError("Modulus must be greater than 1.")

    try:
        return pow(a, -1, m)
    except ValueError as error:
        raise ValueError(
            f"{a} has no modular inverse modulo {m}."
        ) from error


def demonstrate_builtin_inverse() -> None:
    print("\n=== 48. Built-in Modular Inverse ===")

    print("Inverse of 3 modulo 11:", modular_inverse_builtin(3, 11))
    print("3^(-1) modulo 11 using pow:", pow(3, -1, 11))


# =============================================================================
# 49. COMMON MISTAKES
# =============================================================================

def demonstrate_common_mistakes() -> None:
    print("\n=== 49. Common Mistakes ===")

    print("Mistake 1: confusing / with modular division.")
    print("Ordinary 7 / 3 =", 7 / 3)
    print("Modular 7 / 3 mod 11 =", modular_divide(7, 3, 11))

    print("\nMistake 2: assuming every non-zero number has an inverse.")
    print("6 modulo 15 has no inverse because gcd(6,15) =", gcd_euclidean(6, 15))

    print("\nMistake 3: using Fermat's theorem for composite moduli.")
    print("15 is composite:", not is_prime_trial_division(15))

    print("\nMistake 4: cancelling factors without checking invertibility.")
    print("Modulo 6, multiplication by 2 is not invertible.")
    print("gcd(2,6) =", gcd_euclidean(2, 6))


# =============================================================================
# 50. MAIN STUDY RUNNER
# =============================================================================

def run_all_demos() -> None:
    """Run the complete modular arithmetic study program."""

    demonstrate_remainders()
    demonstrate_congruence()
    demonstrate_residue_classes()
    demonstrate_modular_operations()
    demonstrate_modular_exponentiation()
    demonstrate_negative_numbers()
    demonstrate_modular_inverse()
    demonstrate_gcd_lcm()
    demonstrate_linear_congruences()
    demonstrate_crt()
    demonstrate_generalized_crt()
    demonstrate_totient()
    demonstrate_euler_and_fermat()
    demonstrate_multiplicative_order()
    demonstrate_modular_square_roots()
    demonstrate_symbols()
    demonstrate_power_trace()
    demonstrate_negative_exponent()
    demonstrate_polynomial_modular_evaluation()
    demonstrate_cycles()
    demonstrate_primality()
    demonstrate_sieve()
    demonstrate_totient_sieve()
    demonstrate_discrete_log()
    demonstrate_tonelli_shanks()
    rsa_demo()
    diffie_hellman_demo()
    demonstrate_hashing()
    demonstrate_real_world_cycles()
    demonstrate_matrix_modular_arithmetic()
    demonstrate_fibonacci_modular()
    demonstrate_composite_modulus_behavior()
    demonstrate_carmichael()
    demonstrate_edge_cases()
    run_correctness_checks()
    demonstrate_performance_concept()
    demonstrate_security_concept()
    demonstrate_practice_generation()
    demonstrate_aggregate_operations()
    solve_and_explain_linear_equation(14, 8, 22)
    demonstrate_large_integer_arithmetic()
    demonstrate_divisibility()
    demonstrate_check_digit()
    demonstrate_algebraic_structure()
    demonstrate_zero_divisors()
    demonstrate_units()
    demonstrate_recursive_power()
    demonstrate_builtin_inverse()
    demonstrate_common_mistakes()


if __name__ == "__main__":
    run_all_demos()
