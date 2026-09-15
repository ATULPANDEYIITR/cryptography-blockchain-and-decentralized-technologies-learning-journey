"""
Discrete Logarithms: From Fundamentals to Cryptographic Applications

This standalone study script develops the theory and practice of discrete
logarithms from elementary modular arithmetic through advanced algorithms
such as baby-step giant-step, Pohlig-Hellman, and a practical view of
Pollard's rho method.

A discrete logarithm asks for x in

    g^x ≡ h (mod p)

or, more generally, in a finite cyclic group.

The examples use small parameters so that the algorithms can be executed
and inspected directly. Cryptographic parameters are intentionally not
implemented with production-sized custom arithmetic; real cryptographic
software should use audited libraries.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import gcd, isqrt
from time import perf_counter
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# 1. Basic modular arithmetic
# ---------------------------------------------------------------------------

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    old_r, r = abs(a), abs(b)
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    if a < 0:
        old_s = -old_s
    if b < 0:
        old_t = -old_t

    return old_r, old_s, old_t


def mod_inverse(a: int, modulus: int) -> int:
    """
    Compute a^(-1) mod modulus.

    An inverse exists exactly when gcd(a, modulus) = 1.
    """
    a %= modulus
    g, x, _ = extended_gcd(a, modulus)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {modulus}")
    return x % modulus


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """
    Binary modular exponentiation.

    Python's built-in pow(base, exponent, modulus) is preferred in ordinary
    Python applications, but this implementation exposes the algorithm.
    """
    if modulus <= 0:
        raise ValueError("Modulus must be positive")
    if exponent < 0:
        return mod_inverse(mod_pow(base, -exponent, modulus), modulus)

    result = 1 % modulus
    base %= modulus

    while exponent:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1

    return result


def multiplicative_order(g: int, modulus: int) -> int:
    """
    Return the multiplicative order of g modulo modulus.

    The function is intended for small educational examples.
    """
    if gcd(g, modulus) != 1:
        raise ValueError("g must be invertible modulo the modulus")

    value = 1
    for order in range(1, modulus + 1):
        value = (value * g) % modulus
        if value == 1:
            return order

    raise ValueError("Order was not found")


def prime_factors(n: int) -> Dict[int, int]:
    """Return the prime factorization of a positive integer."""
    if n <= 0:
        raise ValueError("n must be positive")

    factors: Dict[int, int] = {}
    divisor = 2

    while divisor * divisor <= n:
        while n % divisor == 0:
            factors[divisor] = factors.get(divisor, 0) + 1
            n //= divisor
        divisor = 3 if divisor == 2 else divisor + 2

    if n > 1:
        factors[n] = factors.get(n, 0) + 1

    return factors


# ---------------------------------------------------------------------------
# 2. What a discrete logarithm means
# ---------------------------------------------------------------------------

def brute_force_discrete_log(
    g: int,
    h: int,
    modulus: int,
    order: Optional[int] = None,
) -> Optional[int]:
    """
    Search sequentially for x satisfying g^x = h mod modulus.

    This is useful for understanding the definition but becomes infeasible
    quickly because the search takes O(order) group operations.
    """
    if order is None:
        order = multiplicative_order(g, modulus)

    value = 1
    for x in range(order):
        if value == h % modulus:
            return x
        value = (value * g) % modulus

    return None


def print_discrete_log_example() -> None:
    p = 29
    g = 2
    x = 11
    h = mod_pow(g, x, p)

    print("Basic discrete logarithm")
    print(f"Group: nonzero residues modulo {p}")
    print(f"g = {g}")
    print(f"Secret exponent x = {x}")
    print(f"h = g^x mod p = {h}")

    recovered = brute_force_discrete_log(g, h, p)
    print(f"Recovered x by brute force = {recovered}")
    print(f"Verification: g^x mod p = {mod_pow(g, recovered, p)}")
    print()


# ---------------------------------------------------------------------------
# 3. Groups, orders, generators, and uniqueness
# ---------------------------------------------------------------------------

def demonstrate_group_structure() -> None:
    p = 23
    g = 5
    order = multiplicative_order(g, p)

    print("Group structure")
    print(f"Modulo {p}, order of {g} = {order}")
    print(f"Prime factors of p - 1 = {prime_factors(p - 1)}")

    subgroup = [mod_pow(g, k, p) for k in range(order)]
    print(f"Subgroup generated by {g}: {subgroup}")

    # A generator of the full multiplicative group modulo a prime has
    # order p - 1. Such an element is called a primitive root.
    print(f"Is {g} a primitive root modulo {p}? {order == p - 1}")

    # If g has order n, exponents are periodic modulo n:
    # g^(x+n) = g^x.
    for x in (0, 1, 7, 18):
        print(
            f"g^{x} mod p = {mod_pow(g, x, p)}, "
            f"g^{x + order} mod p = {mod_pow(g, x + order, p)}"
        )

    print()


# ---------------------------------------------------------------------------
# 4. Solvability and subgroup membership
# ---------------------------------------------------------------------------

def explain_solvability() -> None:
    p = 29
    g = 7
    n = multiplicative_order(g, p)

    print("Solvability and subgroup membership")
    print(f"ord({g}) modulo {p} = {n}")

    reachable = {mod_pow(g, x, p) for x in range(n)}
    unreachable = sorted(set(range(1, p)) - reachable)

    print(f"Elements reachable as powers of g: {sorted(reachable)}")
    print(f"Elements outside <g>: {unreachable}")

    # A discrete log with base g exists only when h belongs to <g>.
    for h in (4, 10):
        answer = brute_force_discrete_log(g, h, p, n)
        print(f"log_{g}({h}) mod {p} = {answer}")

    print()


# ---------------------------------------------------------------------------
# 5. Baby-step giant-step
# ---------------------------------------------------------------------------

def baby_step_giant_step(
    g: int,
    h: int,
    modulus: int,
    order: Optional[int] = None,
) -> Optional[int]:
    """
    Solve g^x = h mod modulus using baby-step giant-step.

    Let m = ceil(sqrt(n)), where n is the order of g.

    Write x = i*m + j.

    Then:
        g^(i*m+j) = h
        g^j = h * (g^(-m))^i

    We store baby steps g^j and search giant steps.

    Time: O(sqrt(n))
    Memory: O(sqrt(n))
    """
    if gcd(g, modulus) != 1:
        raise ValueError("g must be invertible modulo modulus")

    if order is None:
        order = multiplicative_order(g, modulus)

    m = isqrt(order) + 1

    baby: Dict[int, int] = {}
    value = 1

    for j in range(m):
        baby.setdefault(value, j)
        value = (value * g) % modulus

    factor = mod_inverse(mod_pow(g, m, modulus), modulus)
    gamma = h % modulus

    for i in range(m + 1):
        if gamma in baby:
            x = i * m + baby[gamma]
            if x < order and mod_pow(g, x, modulus) == h % modulus:
                return x
        gamma = (gamma * factor) % modulus

    return None


def demonstrate_bsgs() -> None:
    p = 1009
    g = 11
    x = 731
    h = mod_pow(g, x, p)
    order = multiplicative_order(g, p)

    print("Baby-step giant-step")
    print(f"p = {p}, g = {g}, order = {order}")
    print(f"h = {h}")

    start = perf_counter()
    recovered = baby_step_giant_step(g, h, p, order)
    elapsed = perf_counter() - start

    print(f"Recovered x modulo order = {recovered}")
    print(f"Verification = {mod_pow(g, recovered, p)}")
    print(f"Runtime for this small example = {elapsed:.6f} seconds")
    print()


# ---------------------------------------------------------------------------
# 6. Multiple discrete logarithms and equivalence classes
# ---------------------------------------------------------------------------

def demonstrate_non_generator() -> None:
    p = 29
    g = 12
    order = multiplicative_order(g, p)
    x = 8
    h = mod_pow(g, x, p)

    print("Non-generator base")
    print(f"g = {g}, p = {p}, ord(g) = {order}")
    print(f"x = {x}, h = {h}")

    recovered = baby_step_giant_step(g, h, p, order)
    print(f"One recovered exponent = {recovered}")

    # All solutions are congruent modulo ord(g), not necessarily modulo p-1.
    if recovered is not None:
        for k in range(3):
            candidate = recovered + k * order
            print(
                f"x + {k}*ord(g) = {candidate}: "
                f"{mod_pow(g, candidate, p)}"
            )

    print()


# ---------------------------------------------------------------------------
# 7. Pohlig-Hellman
# ---------------------------------------------------------------------------

def crt(congruences: Sequence[Tuple[int, int]]) -> Tuple[int, int]:
    """
    Combine x ≡ a_i mod n_i.

    The implementation assumes pairwise-coprime moduli.
    Returns (x, product_of_moduli).
    """
    if not congruences:
        raise ValueError("At least one congruence is required")

    result = 0
    modulus_product = 1

    for residue, modulus in congruences:
        if gcd(modulus_product, modulus) != 1:
            raise ValueError("CRT moduli must be pairwise coprime")

        inverse = mod_inverse(modulus_product, modulus)
        adjustment = ((residue - result) * inverse) % modulus

        result += modulus_product * adjustment
        modulus_product *= modulus
        result %= modulus_product

    return result, modulus_product


def discrete_log_prime_order(
    g: int,
    h: int,
    p: int,
    prime_order: int,
) -> Optional[int]:
    """
    Solve a discrete log in a subgroup whose order is prime.

    For educational clarity, this uses brute force. Pohlig-Hellman reduces
    a large composite-order problem to several smaller prime-order problems.
    """
    value = 1
    for x in range(prime_order):
        if value == h % p:
            return x
        value = (value * g) % p
    return None


def pohlig_hellman(g: int, h: int, p: int) -> Optional[int]:
    """
    Solve g^x = h mod p when the order of g factors into manageable
    prime powers.

    This implementation uses a direct digit-by-digit approach for each
    prime-power factor. It is designed for educational clarity rather than
    optimized cryptographic workloads.
    """
    order = multiplicative_order(g, p)
    factorization = prime_factors(order)

    congruences: List[Tuple[int, int]] = []

    for prime, exponent in factorization.items():
        prime_power = prime ** exponent

        # We recover x modulo q^e one base-q digit at a time.
        recovered = 0

        for digit_position in range(exponent):
            q_power = prime ** digit_position

            # Current residual:
            # h * g^(-recovered)
            residual = (
                h
                * mod_inverse(mod_pow(g, recovered, p), p)
            ) % p

            # Raise by order / q^(digit_position+1).
            reduced_h = mod_pow(
                residual,
                order // (prime ** (digit_position + 1)),
                p,
            )

            reduced_g = mod_pow(
                g,
                order // (prime ** (digit_position + 1)),
                p,
            )

            digit = discrete_log_prime_order(
                reduced_g,
                reduced_h,
                p,
                prime,
            )

            if digit is None:
                return None

            recovered += digit * q_power

        congruences.append((recovered, prime_power))

    answer, combined_modulus = crt(congruences)

    if combined_modulus != order:
        raise ArithmeticError("CRT did not reconstruct the complete exponent space")

    if mod_pow(g, answer, p) != h % p:
        return None

    return answer


def demonstrate_pohlig_hellman() -> None:
    # Here p - 1 = 100 = 2^2 * 5^2.
    # Such smooth factorization is exactly the structure exploited by
    # Pohlig-Hellman.
    p = 101
    g = 2
    order = multiplicative_order(g, p)
    secret = 73
    h = mod_pow(g, secret, p)

    print("Pohlig-Hellman")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"ord(g) = {order}")
    print(f"factorization = {prime_factors(order)}")
    print(f"h = {h}")

    recovered = pohlig_hellman(g, h, p)
    print(f"Recovered x = {recovered}")
    print(f"Verification = {mod_pow(g, recovered, p)}")
    print()


# ---------------------------------------------------------------------------
# 8. Pollard's rho for discrete logarithms
# ---------------------------------------------------------------------------

@dataclass
class RhoState:
    value: int
    alpha: int
    beta: int


def pollard_rho_discrete_log(
    g: int,
    h: int,
    p: int,
    order: Optional[int] = None,
    max_iterations: int = 100_000,
) -> Optional[int]:
    """
    Educational Pollard-rho discrete-log implementation.

    The state is represented as:
        value = g^alpha * h^beta mod p

    A collision gives:
        g^a * h^b = g^A * h^B

    Therefore:
        a - A = x(B - b) mod order

    The modular equation may have multiple solutions if the denominator
    is not invertible. This implementation retries with deterministic
    starting partitions if a collision is unusable.

    Expected generic-group work is approximately O(sqrt(order)) time and
    O(1) state memory, although practical behavior depends on the walk.
    """
    if order is None:
        order = multiplicative_order(g, p)

    if order <= 1:
        return 0 if h % p == 1 else None

    def step(state: RhoState) -> RhoState:
        # Three partitions produce a simple pseudorandom-looking walk.
        bucket = state.value % 3

        if bucket == 0:
            return RhoState(
                value=(state.value * g) % p,
                alpha=(state.alpha + 1) % order,
                beta=state.beta,
            )

        if bucket == 1:
            return RhoState(
                value=(state.value * h) % p,
                alpha=state.alpha,
                beta=(state.beta + 1) % order,
            )

        return RhoState(
            value=(state.value * state.value) % p,
            alpha=(2 * state.alpha) % order,
            beta=(2 * state.beta) % order,
        )

    for seed in range(1, 16):
        start_value = mod_pow(g, seed, p)
        tortoise = RhoState(start_value, seed % order, 0)
        hare = tortoise

        for _ in range(max_iterations):
            tortoise = step(tortoise)
            hare = step(step(hare))

            if tortoise.value == hare.value:
                numerator = (tortoise.alpha - hare.alpha) % order
                denominator = (hare.beta - tortoise.beta) % order

                d = gcd(denominator, order)

                if d == 0:
                    break

                if numerator % d != 0:
                    break

                reduced_order = order // d
                reduced_denominator = denominator // d
                reduced_numerator = numerator // d

                try:
                    inverse = mod_inverse(
                        reduced_denominator,
                        reduced_order,
                    )
                except ValueError:
                    break

                base_solution = (
                    reduced_numerator * inverse
                ) % reduced_order

                # There can be d solutions modulo order. Test them all.
                for offset in range(d):
                    candidate = (
                        base_solution
                        + offset * reduced_order
                    ) % order

                    if mod_pow(g, candidate, p) == h % p:
                        return candidate

                break

    return None


def demonstrate_pollard_rho() -> None:
    p = 1009
    g = 11
    order = multiplicative_order(g, p)
    secret = 427
    h = mod_pow(g, secret, p)

    print("Pollard-rho discrete logarithm")
    print(f"p = {p}, g = {g}, order = {order}")
    print(f"h = {h}")

    recovered = pollard_rho_discrete_log(g, h, p, order)
    print(f"Recovered x = {recovered}")

    if recovered is not None:
        print(f"Verification = {mod_pow(g, recovered, p)}")

    print()


# ---------------------------------------------------------------------------
# 9. Comparing algorithms
# ---------------------------------------------------------------------------

def compare_algorithms() -> None:
    p = 10007
    g = 5
    order = multiplicative_order(g, p)
    secret = 4321
    h = mod_pow(g, secret, p)

    print("Algorithm comparison")
    print(f"p = {p}, order = {order}, target exponent = {secret}")

    start = perf_counter()
    brute = brute_force_discrete_log(g, h, p, order)
    brute_time = perf_counter() - start

    start = perf_counter()
    bsgs = baby_step_giant_step(g, h, p, order)
    bsgs_time = perf_counter() - start

    start = perf_counter()
    rho = pollard_rho_discrete_log(g, h, p, order)
    rho_time = perf_counter() - start

    print(f"Brute force: {brute}, {brute_time:.6f}s")
    print(f"Baby-step giant-step: {bsgs}, {bsgs_time:.6f}s")
    print(f"Pollard rho: {rho}, {rho_time:.6f}s")
    print()

    print("Asymptotic comparison")
    print("Brute force:          O(n) time,       O(1) memory")
    print("Baby-step giant-step: O(sqrt(n)) time, O(sqrt(n)) memory")
    print("Pollard rho:          O(sqrt(n)) expected time, O(1) memory")
    print("Pohlig-Hellman:       depends strongly on factorization of n")
    print()


# ---------------------------------------------------------------------------
# 10. Diffie-Hellman and why discrete logs matter
# ---------------------------------------------------------------------------

def diffie_hellman_demo() -> None:
    """
    Demonstrate the mathematical structure behind Diffie-Hellman.

    Alice chooses a, Bob chooses b.

        A = g^a mod p
        B = g^b mod p

    Both compute:
        g^(ab) mod p

    An observer sees g, p, A, B. Recovering a from A is a discrete-log
    problem. Recovering the shared secret directly is related to the
    computational Diffie-Hellman problem.
    """
    p = 23
    g = 5
    alice_private = 6
    bob_private = 15

    alice_public = mod_pow(g, alice_private, p)
    bob_public = mod_pow(g, bob_private, p)

    alice_shared = mod_pow(bob_public, alice_private, p)
    bob_shared = mod_pow(alice_public, bob_private, p)

    print("Diffie-Hellman structure")
    print(f"p = {p}, g = {g}")
    print(f"Alice public value = {alice_public}")
    print(f"Bob public value = {bob_public}")
    print(f"Alice shared value = {alice_shared}")
    print(f"Bob shared value = {bob_shared}")
    print(f"Shared values match = {alice_shared == bob_shared}")

    # On this tiny group, an attacker can simply solve the discrete log.
    recovered_alice_private = brute_force_discrete_log(
        g,
        alice_public,
        p,
    )
    attacker_shared = mod_pow(
        bob_public,
        recovered_alice_private,
        p,
    )

    print(f"Private exponent recovered in toy group = {recovered_alice_private}")
    print(f"Attacker can compute shared value = {attacker_shared}")
    print()


# ---------------------------------------------------------------------------
# 11. ElGamal encryption structure
# ---------------------------------------------------------------------------

def elgamal_demo() -> None:
    """
    Educational ElGamal demonstration over a small prime field.

    Public key:
        y = g^x mod p

    Encryption:
        c1 = g^k
        c2 = m * y^k

    Decryption:
        m = c2 * (c1^x)^(-1)

    The small parameters are insecure and exist only to expose the algebra.
    """
    p = 467
    g = 2
    private_key = 127
    message = 123
    ephemeral_key = 83

    public_key = mod_pow(g, private_key, p)

    c1 = mod_pow(g, ephemeral_key, p)
    shared = mod_pow(public_key, ephemeral_key, p)
    c2 = (message * shared) % p

    recovered_shared = mod_pow(c1, private_key, p)
    recovered_message = (
        c2 * mod_inverse(recovered_shared, p)
    ) % p

    print("ElGamal structure")
    print(f"Public key y = {public_key}")
    print(f"Ciphertext = ({c1}, {c2})")
    print(f"Recovered message = {recovered_message}")
    print(f"Correct = {recovered_message == message}")
    print()


# ---------------------------------------------------------------------------
# 12. Edge cases
# ---------------------------------------------------------------------------

def edge_cases() -> None:
    print("Edge cases")

    # x = 0 always maps to 1 for a nonzero base.
    print(f"g^0 mod 17 = {mod_pow(3, 0, 17)}")

    # Negative exponents require an inverse.
    print(f"3^(-1) mod 17 = {mod_pow(3, -1, 17)}")

    # A base that is not coprime to the modulus is not in the
    # multiplicative group and does not have a modular inverse.
    try:
        mod_inverse(6, 15)
    except ValueError as error:
        print(f"Expected inverse error: {error}")

    # A target may be outside the subgroup generated by g.
    p = 29
    g = 4
    order = multiplicative_order(g, p)
    target = 2
    result = baby_step_giant_step(g, target, p, order)
    print(f"ord({g}) mod {p} = {order}")
    print(f"log_{g}({target}) mod {p} = {result}")

    print()


# ---------------------------------------------------------------------------
# 13. Complexity and parameter selection
# ---------------------------------------------------------------------------

def parameter_discussion() -> None:
    print("Complexity and security considerations")
    print()
    print("For a group of order n:")
    print("  Naive exhaustive search: approximately n group operations")
    print("  BSGS: approximately sqrt(n) operations and sqrt(n) storage")
    print("  Pollard rho: approximately sqrt(n) expected operations and small memory")
    print()
    print("A group with smooth order is vulnerable to Pohlig-Hellman because")
    print("the discrete logarithm can be reduced to smaller prime-power subgroups.")
    print()
    print("For cryptographic use, parameter selection matters as much as the")
    print("algorithm. Small educational primes such as those in this script")
    print("must never be treated as secure cryptographic parameters.")
    print()


# ---------------------------------------------------------------------------
# 14. Validation helpers
# ---------------------------------------------------------------------------

def validate_discrete_log(
    g: int,
    h: int,
    modulus: int,
    candidate: Optional[int],
) -> bool:
    """Check both existence and correctness of a proposed discrete log."""
    if candidate is None:
        return False

    if gcd(g, modulus) != 1:
        return False

    order = multiplicative_order(g, modulus)
    return 0 <= candidate < order and mod_pow(g, candidate, modulus) == h % modulus


def run_self_tests() -> None:
    """Small deterministic tests covering the major implementations."""
    tests = [
        (5, 7, 23, 12),
        (2, 19, 29, 11),
        (11, 777, 1009, 731),
        (5, 4321, 10007, 4321),
    ]

    for g, target_or_secret, p, expected in tests:
        if p == 23:
            h = mod_pow(g, expected, p)
        elif p == 29:
            h = mod_pow(g, expected, p)
        else:
            h = mod_pow(g, expected, p)

        order = multiplicative_order(g, p)

        bsgs_result = baby_step_giant_step(g, h, p, order)
        assert bsgs_result == expected % order
        assert validate_discrete_log(g, h, p, bsgs_result)

    # Test modular exponentiation against Python's built-in implementation.
    for base in range(-5, 20):
        for exponent in range(0, 20):
            assert mod_pow(base, exponent, 23) == pow(base, exponent, 23)

    # CRT test.
    x, modulus = crt([(2, 3), (3, 5), (2, 7)])
    assert x == 23
    assert modulus == 105

    print("All self-tests passed.")
    print()


# ---------------------------------------------------------------------------
# 15. Main educational sequence
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 72)
    print("DISCRETE LOGARITHMS")
    print("=" * 72)
    print()

    print_discrete_log_example()
    demonstrate_group_structure()
    explain_solvability()
    demonstrate_bsgs()
    demonstrate_non_generator()
    demonstrate_pohlig_hellman()
    demonstrate_pollard_rho()
    compare_algorithms()
    diffie_hellman_demo()
    elgamal_demo()
    edge_cases()
    parameter_discussion()
    run_self_tests()

    print("Key relationships")
    print("  Modular exponentiation: easy to compute")
    print("  Discrete logarithm: generally much harder in suitable groups")
    print("  Diffie-Hellman: uses exponentiation to establish a shared value")
    print("  ElGamal: uses the same algebraic structure for encryption")
    print("  BSGS: time-memory trade-off")
    print("  Pollard rho: low-memory generic attack")
    print("  Pohlig-Hellman: exploits smooth group order")
    print()
    print("The central equation throughout the script is:")
    print("    g^x ≡ h (mod p)")
    print("where x is the unknown discrete logarithm.")


if __name__ == "__main__":
    main()
