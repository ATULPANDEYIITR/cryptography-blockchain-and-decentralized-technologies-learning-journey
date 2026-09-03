"""
=====================================================================
PRIME FACTORIZATION IN CRYPTOGRAPHY, BLOCKCHAIN AND DECENTRALIZED
TECHNOLOGIES
=====================================================================

PURPOSE
-------
This program provides a complete learning journey through:

1. Prime numbers
2. Composite numbers
3. Factors and divisibility
4. Prime factorization
5. Fundamental Theorem of Arithmetic
6. Greatest Common Divisor and Euclidean Algorithm
7. Modular arithmetic
8. Why prime factorization matters in cryptography
9. RSA and the factoring problem
10. Euler's Totient Function
11. Carmichael's function
12. RSA key generation
13. RSA encryption/decryption demonstration
14. RSA signatures
15. Why RSA depends on the difficulty of factoring
16. Trial-division factorization
17. Wheel-style optimization
18. Miller-Rabin primality testing
19. Pollard's Rho factorization
20. Recursive factorization
21. Semiprime numbers
22. Security intuition behind RSA key sizes
23. Blockchain and prime factorization
24. Why Bitcoin does NOT primarily depend on prime factorization
25. Elliptic-curve cryptography and the discrete logarithm problem
26. RSA accumulators
27. Prime-based cryptographic accumulators
28. Merkle trees vs RSA accumulators
29. Zero-knowledge and decentralized technologies
30. Educational security experiments
31. Performance comparison of factorization methods
32. Important limitations of toy cryptography

IMPORTANT
---------
This is an educational program.

The cryptographic implementations below are intentionally designed
to demonstrate mathematical concepts. They are NOT intended to replace
professional cryptographic libraries.

For real applications use established libraries such as:
    cryptography
    PyCryptodome

Do NOT use the educational RSA implementation below for protecting
real-world confidential information.

=====================================================================
SECTION 1: PRIME NUMBERS
=====================================================================

A prime number is an integer greater than 1 that has exactly two
positive divisors:

    1
    itself

Examples:

    2, 3, 5, 7, 11, 13, 17, 19, 23...

A number greater than 1 that is not prime is called composite.

Examples:

    4 = 2 × 2
    6 = 2 × 3
    8 = 2 × 2 × 2
    9 = 3 × 3
    10 = 2 × 5
"""


def is_prime_basic(n):
    """
    Basic primality test.

    This version checks divisibility from 2 through sqrt(n).

    Why sqrt(n)?

    If n = a × b and both a and b were greater than sqrt(n),
    their product would be greater than n.

    Therefore, if n has a factor, at least one factor must be
    less than or equal to sqrt(n).
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


def list_primes(limit):
    """
    Generate all prime numbers up to limit using a simple
    sieve of Eratosthenes.
    """

    if limit < 2:
        return []

    sieve = [True] * (limit + 1)

    sieve[0] = False
    sieve[1] = False

    p = 2

    while p * p <= limit:

        if sieve[p]:

            for multiple in range(p * p, limit + 1, p):
                sieve[multiple] = False

        p += 1

    return [
        number
        for number in range(2, limit + 1)
        if sieve[number]
    ]


"""
=====================================================================
SECTION 2: FACTORS
=====================================================================

A factor of n is a number that divides n without leaving a remainder.

Example:

    12

Factors:

    1, 2, 3, 4, 6, 12

Factor pairs:

    1 × 12
    2 × 6
    3 × 4
"""


def find_factors(n):
    """
    Return all positive factors of n.
    """

    if n <= 0:
        raise ValueError("n must be positive")

    factors = []

    divisor = 1

    while divisor * divisor <= n:

        if n % divisor == 0:

            factors.append(divisor)

            paired_factor = n // divisor

            if paired_factor != divisor:
                factors.append(paired_factor)

        divisor += 1

    return sorted(factors)


"""
=====================================================================
SECTION 3: PRIME FACTORIZATION
=====================================================================

Prime factorization expresses a composite integer as a product of
prime numbers.

Examples:

    12 = 2 × 2 × 3
    18 = 2 × 3 × 3
    60 = 2 × 2 × 3 × 5
    84 = 2 × 2 × 3 × 7

Using exponents:

    60 = 2² × 3 × 5

This is fundamental because every integer greater than 1 has a
unique prime factorization.

This is known as the Fundamental Theorem of Arithmetic.
"""


def prime_factorization_basic(n):
    """
    Prime factorization using trial division.

    Returns a list of prime factors with repetition.

    Example:

        prime_factorization_basic(60)

    returns:

        [2, 2, 3, 5]
    """

    if n < 2:
        raise ValueError("n must be at least 2")

    factors = []

    while n % 2 == 0:
        factors.append(2)
        n //= 2

    divisor = 3

    while divisor * divisor <= n:

        while n % divisor == 0:
            factors.append(divisor)
            n //= divisor

        divisor += 2

    if n > 1:
        factors.append(n)

    return factors


def factorization_as_powers(factors):
    """
    Convert:

        [2, 2, 2, 3, 5, 5]

    into:

        {2: 3, 3: 1, 5: 2}
    """

    result = {}

    for factor in factors:
        result[factor] = result.get(factor, 0) + 1

    return result


def format_factorization(n):
    """
    Return a human-readable prime factorization.
    """

    factors = prime_factorization_basic(n)
    powers = factorization_as_powers(factors)

    parts = []

    for prime, exponent in powers.items():

        if exponent == 1:
            parts.append(str(prime))
        else:
            parts.append(f"{prime}^{exponent}")

    return f"{n} = " + " × ".join(parts)


"""
=====================================================================
SECTION 4: GREATEST COMMON DIVISOR
=====================================================================

The Greatest Common Divisor (GCD) of two numbers is the largest
positive integer that divides both.

Example:

    gcd(48, 18) = 6

The Euclidean Algorithm provides an efficient way to calculate GCD.

The fundamental relationship is:

    gcd(a, b) = gcd(b, a mod b)

until b becomes zero.
"""


def gcd(a, b):
    """
    Euclidean Algorithm.
    """

    a = abs(a)
    b = abs(b)

    while b != 0:
        a, b = b, a % b

    return a


"""
=====================================================================
SECTION 5: EXTENDED EUCLIDEAN ALGORITHM
=====================================================================

The Extended Euclidean Algorithm finds integers x and y such that:

    ax + by = gcd(a, b)

When gcd(a, m) = 1, x can be used to calculate the modular inverse
of a modulo m.

The modular inverse is important in RSA.
"""


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.

    Returns:

        gcd(a,b), x, y

    such that:

        ax + by = gcd(a,b)
    """

    if b == 0:
        return a, 1, 0

    g, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return g, x, y


def modular_inverse(a, modulus):
    """
    Find x such that:

        a*x ≡ 1 (mod modulus)

    if the inverse exists.
    """

    g, x, _ = extended_gcd(a, modulus)

    if g != 1:
        raise ValueError(
            "Modular inverse does not exist because "
            "numbers are not coprime."
        )

    return x % modulus


"""
=====================================================================
SECTION 6: MODULAR ARITHMETIC
=====================================================================

Modular arithmetic deals with remainders.

For example:

    17 mod 5 = 2

because:

    17 = 5 × 3 + 2

The notation:

    a ≡ b (mod n)

means that a and b have the same remainder when divided by n.

Modular exponentiation is extremely important in cryptography.

Example:

    a^e mod n
"""


def modular_power(base, exponent, modulus):
    """
    Fast modular exponentiation.

    Instead of calculating:

        base ** exponent

    directly, we repeatedly square values and reduce modulo modulus.

    This makes modular exponentiation practical even for large
    exponents.
    """

    if modulus <= 0:
        raise ValueError("modulus must be positive")

    result = 1
    base %= modulus

    while exponent > 0:

        if exponent & 1:
            result = (result * base) % modulus

        base = (base * base) % modulus
        exponent >>= 1

    return result


"""
=====================================================================
SECTION 7: EULER'S TOTIENT FUNCTION
=====================================================================

Euler's Totient Function φ(n) counts positive integers less than or
equal to n that are relatively prime to n.

For a prime p:

    φ(p) = p - 1

For two distinct primes p and q:

    φ(pq) = (p - 1)(q - 1)

This formula is central to the mathematical construction of RSA.
"""


def euler_totient_from_factorization(n):
    """
    Calculate Euler's Totient Function using prime factorization.

    If:

        n = p1^a1 × p2^a2 × ...

    then:

        φ(n) = n × Π(1 - 1/p)
    """

    factors = factorization_as_powers(
        prime_factorization_basic(n)
    )

    result = n

    for prime in factors:
        result = result // prime * (prime - 1)

    return result


"""
=====================================================================
SECTION 8: CARMICHAEL'S FUNCTION
=====================================================================

RSA implementations often reason about Euler's totient or
Carmichael's function.

Carmichael's function λ(n) is the smallest positive integer m such
that:

    a^m ≡ 1 (mod n)

for every a relatively prime to n.

For:

    n = p × q

where p and q are distinct odd primes:

    λ(n) = lcm(p - 1, q - 1)
"""


def lcm(a, b):
    """
    Least Common Multiple.
    """

    return abs(a * b) // gcd(a, b)


def carmichael_lambda_for_two_primes(p, q):
    """
    Carmichael lambda for n = p*q where p and q are distinct primes.
    """

    if not is_prime_basic(p) or not is_prime_basic(q):
        raise ValueError("p and q must be prime")

    if p == q:
        raise ValueError("p and q must be distinct")

    return lcm(p - 1, q - 1)


"""
=====================================================================
SECTION 9: WHY PRIME FACTORIZATION MATTERS IN CRYPTOGRAPHY
=====================================================================

A major cryptographic idea is the difference between:

    EASY TO CALCULATE

and

    HARD TO REVERSE

Multiplying two large primes is computationally easy.

For example:

    p = 61
    q = 53

then:

    n = p × q = 3233

Anyone can multiply p and q.

But if someone is given only:

    n = 3233

they need to discover:

    61 and 53

For small numbers this is trivial.

For appropriately chosen large RSA moduli, recovering p and q
from n is computationally difficult using known classical methods.

This asymmetry is the foundation of RSA.

IMPORTANT:

RSA does not assume that factoring is mathematically impossible.

It relies on factoring being computationally infeasible for properly
chosen key sizes and algorithms.
"""


def demonstrate_factorization_asymmetry():
    """
    Demonstrate the basic idea using small numbers.
    """

    p = 61
    q = 53

    n = p * q

    print("Two primes:")
    print("p =", p)
    print("q =", q)

    print("\nPublic-looking product:")
    print("n =", n)

    print("\nFactoring n:")
    print(prime_factorization_basic(n))


"""
=====================================================================
SECTION 10: SEMIPRIMES
=====================================================================

A semiprime is a number that is the product of exactly two primes.

Examples:

    15 = 3 × 5
    21 = 3 × 7
    77 = 7 × 11
    3233 = 61 × 53

RSA uses a modulus:

    n = p × q

where p and q are large primes.

The security objective is to make recovering p and q from n
computationally infeasible.
"""


def is_semiprime(n):
    """
    Check whether n is a product of exactly two primes,
    counting multiplicity.

    Examples:

        15 -> True
        49 -> True
        60 -> False
    """

    if n < 4:
        return False

    factors = prime_factorization_basic(n)

    return len(factors) == 2


"""
=====================================================================
SECTION 11: RSA KEY GENERATION
=====================================================================

RSA conceptually works as follows.

Step 1:
Choose two large primes:

    p
    q

Step 2:
Calculate:

    n = p × q

Step 3:
Calculate:

    φ(n) = (p - 1)(q - 1)

Step 4:
Choose public exponent e such that:

    gcd(e, φ(n)) = 1

A common public exponent is:

    e = 65537

Step 5:
Calculate private exponent d:

    d ≡ e^(-1) mod φ(n)

The public key is:

    (n, e)

The private key is:

    (n, d)

The security intuition is:

Public:
    n and e

Secret:
    p, q and d

If an attacker can efficiently factor n into p and q, they can
calculate φ(n) and derive the private exponent d.
"""


def generate_rsa_keypair_small(p, q, e=65537):
    """
    Educational RSA key generation.

    IMPORTANT:
    This uses small primes and is NOT secure.
    """

    if not is_prime_basic(p):
        raise ValueError("p must be prime")

    if not is_prime_basic(q):
        raise ValueError("q must be prime")

    if p == q:
        raise ValueError("p and q must be different")

    n = p * q

    phi = (p - 1) * (q - 1)

    if gcd(e, phi) != 1:
        raise ValueError(
            "e must be relatively prime to phi(n)"
        )

    d = modular_inverse(e, phi)

    public_key = (n, e)
    private_key = (n, d)

    return public_key, private_key


"""
=====================================================================
SECTION 12: RSA ENCRYPTION AND DECRYPTION
=====================================================================

For a plaintext integer m:

Encryption:

    c = m^e mod n

Decryption:

    m = c^d mod n

where:

    c = ciphertext

The mathematical structure of modular exponentiation and the
relationship between e and d make this possible.
"""


def rsa_encrypt_integer(message, public_key):
    """
    Educational RSA encryption for a single integer.
    """

    n, e = public_key

    if not 0 <= message < n:
        raise ValueError(
            "Message must satisfy 0 <= message < n"
        )

    return modular_power(message, e, n)


def rsa_decrypt_integer(ciphertext, private_key):
    """
    Educational RSA decryption for a single integer.
    """

    n, d = private_key

    return modular_power(ciphertext, d, n)


"""
=====================================================================
SECTION 13: RSA DIGITAL SIGNATURES
=====================================================================

Encryption and signatures are conceptually different.

A simplified RSA signature demonstration:

Signing:

    signature = message^d mod n

Verification:

    recovered = signature^e mod n

If:

    recovered == message

the signature is mathematically consistent.

Real RSA signatures should use secure standardized padding schemes,
such as RSA-PSS, and cryptographic hashes.

Never use raw textbook RSA signatures in production.
"""


def rsa_sign_integer(message, private_key):
    """
    Educational raw RSA signature.
    """

    n, d = private_key

    if not 0 <= message < n:
        raise ValueError(
            "Message must satisfy 0 <= message < n"
        )

    return modular_power(message, d, n)


def rsa_verify_integer(message, signature, public_key):
    """
    Educational raw RSA signature verification.
    """

    n, e = public_key

    recovered = modular_power(signature, e, n)

    return recovered == message


"""
=====================================================================
SECTION 14: FACTORING RSA'S MODULUS
=====================================================================

Suppose an attacker receives:

    n
    e

but does not know:

    p
    q
    d

If the attacker factors:

    n = p × q

then they can calculate:

    φ(n) = (p - 1)(q - 1)

and then:

    d = e^(-1) mod φ(n)

Therefore, factoring the RSA modulus can lead to recovery of
the private key.

This is the core connection between prime factorization and RSA.
"""


def recover_rsa_private_exponent_from_factors(n, e, p, q):
    """
    Demonstrate how knowing p and q allows an attacker to derive d.

    This is intentionally educational.
    """

    if p * q != n:
        raise ValueError("p × q must equal n")

    phi = (p - 1) * (q - 1)

    return modular_inverse(e, phi)


"""
=====================================================================
SECTION 15: TRIAL DIVISION FACTORIZATION
=====================================================================

Trial division repeatedly tests whether a number is divisible by
candidate factors.

It is simple and useful for learning.

Its major weakness is scalability.

For large semiprimes, trial division can become extremely slow.
"""


def trial_division_factorization(n):
    """
    Trial division implementation.
    """

    if n < 2:
        raise ValueError("n must be at least 2")

    factors = []

    divisor = 2

    while divisor * divisor <= n:

        while n % divisor == 0:
            factors.append(divisor)
            n //= divisor

        divisor = 3 if divisor == 2 else divisor + 2

    if n > 1:
        factors.append(n)

    return factors


"""
=====================================================================
SECTION 16: MILLER-RABIN PRIMALITY TEST
=====================================================================

When dealing with large integers, checking primality efficiently
becomes extremely important.

Miller-Rabin is a probabilistic primality test.

For educational purposes, a deterministic set of bases can be used
for integers within a bounded range.

For arbitrary huge integers, production implementations should rely
on carefully designed cryptographic libraries.
"""


def miller_rabin(n, bases=None):
    """
    Miller-Rabin primality test.

    This implementation uses a known deterministic base set for
    64-bit integers.

    For educational use.
    """

    if n < 2:
        return False

    small_primes = [
        2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37
    ]

    if n in small_primes:
        return True

    for prime in small_primes:
        if n % prime == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    if bases is None:

        # Deterministic for unsigned 64-bit integers.
        bases = [
            2,
            325,
            9375,
            28178,
            450775,
            9780504,
            1795265022
        ]

    for a in bases:

        if a % n == 0:
            continue

        x = modular_power(a, d, n)

        if x == 1 or x == n - 1:
            continue

        probably_prime = False

        for _ in range(s - 1):

            x = (x * x) % n

            if x == n - 1:
                probably_prime = True
                break

        if not probably_prime:
            return False

    return True


"""
=====================================================================
SECTION 17: POLLARD'S RHO FACTORIZATION
=====================================================================

Trial division is not the only factorization technique.

Pollard's Rho is a much more sophisticated classical factoring
algorithm.

It can find relatively small factors efficiently compared with
naive trial division.

The algorithm uses:

    pseudorandom-like iteration

and:

    gcd(|x - y|, n)

to discover a non-trivial factor.

The important conceptual point is that cryptographic factorization
is an algorithmic problem, not simply "trying every number".
"""


import math
import random


def pollards_rho(n):
    """
    Educational Pollard's Rho implementation.

    Returns a non-trivial factor when successful.
    """

    if n % 2 == 0:
        return 2

    if n % 3 == 0:
        return 3

    if miller_rabin(n):
        return n

    while True:

        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1

        while d == 1:

            x = (x * x + c) % n

            y = (y * y + c) % n
            y = (y * y + c) % n

            d = math.gcd(abs(x - y), n)

        if d != n:
            return d


def factor_recursive_pollard(n, factors=None):
    """
    Recursively factor an integer using Pollard's Rho.
    """

    if factors is None:
        factors = []

    if n == 1:
        return factors

    if miller_rabin(n):
        factors.append(n)
        return factors

    factor = pollards_rho(n)

    factor_recursive_pollard(factor, factors)
    factor_recursive_pollard(n // factor, factors)

    return sorted(factors)


"""
=====================================================================
SECTION 18: COMPARING FACTORIZATION METHODS
=====================================================================

For small numbers:

    Trial division
        |
        +-- extremely simple
        +-- easy to understand
        +-- slow for large numbers

Pollard's Rho:
        |
        +-- more sophisticated
        +-- probabilistic behavior
        +-- useful for finding smaller factors
        +-- still not a general solution to factoring huge RSA keys

For very large cryptographic integers, advanced algorithms include:

    Pollard's p - 1
    Elliptic Curve Method (ECM)
    Quadratic Sieve
    General Number Field Sieve (GNFS)

GNFS is historically the most powerful general-purpose classical
algorithm known for factoring very large general integers.

RSA security parameters are selected with these attacks in mind.
"""


def compare_factorization_methods(n):
    """
    Compare educational factorization approaches.
    """

    print("Number:", n)

    print("\nTrial division:")
    print(trial_division_factorization(n))

    print("\nPollard's Rho:")
    print(factor_recursive_pollard(n))


"""
=====================================================================
SECTION 19: PRIME GENERATION CONCEPT
=====================================================================

RSA requires large prime numbers.

The basic process is:

    1. Generate a random candidate.
    2. Check whether it is prime.
    3. If not, generate another candidate.
    4. Continue until a prime is found.

For production cryptography, randomness must be cryptographically
secure.

Python's ordinary random module is NOT appropriate for generating
cryptographic keys.

The example below is deliberately educational.
"""


def random_odd_candidate(bits):
    """
    Generate a random odd integer with approximately the requested
    number of bits.

    EDUCATIONAL ONLY.

    The random module should NOT be used for production key generation.
    """

    if bits < 2:
        raise ValueError("bits must be at least 2")

    candidate = random.getrandbits(bits)

    candidate |= (1 << (bits - 1))
    candidate |= 1

    return candidate


def generate_probable_prime(bits):
    """
    Educational probable-prime generator.
    """

    while True:

        candidate = random_odd_candidate(bits)

        if miller_rabin(candidate):
            return candidate


"""
=====================================================================
SECTION 20: WHY RSA USES LARGE PRIMES
=====================================================================

Consider:

    p = 61
    q = 53

Then:

    n = 3233

Factoring 3233 is trivial.

An attacker can simply try:

    2
    3
    5
    7
    ...

until discovering factors.

RSA therefore uses very large primes.

The security does not come from:

    "Nobody knows the primes."

The primes can be known by the key owner.

The security comes from the difficulty of discovering the hidden
factors from the public modulus.
"""


def demonstrate_rsa_factor_recovery():
    """
    Complete educational RSA demonstration.
    """

    p = 61
    q = 53

    public_key, private_key = generate_rsa_keypair_small(
        p,
        q,
        e=17
    )

    print("Public key:", public_key)
    print("Private key:", private_key)

    message = 65

    ciphertext = rsa_encrypt_integer(
        message,
        public_key
    )

    recovered = rsa_decrypt_integer(
        ciphertext,
        private_key
    )

    print("Original message:", message)
    print("Ciphertext:", ciphertext)
    print("Decrypted message:", recovered)

    factors = prime_factorization_basic(public_key[0])

    print("Factors discovered:", factors)

    recovered_p = factors[0]
    recovered_q = factors[1]

    recovered_d = recover_rsa_private_exponent_from_factors(
        public_key[0],
        public_key[1],
        recovered_p,
        recovered_q
    )

    print("Recovered private exponent:", recovered_d)


"""
=====================================================================
SECTION 21: RSA SIGNATURE DEMONSTRATION
=====================================================================
"""


def demonstrate_rsa_signature():
    """
    Educational RSA signature example.
    """

    p = 61
    q = 53

    public_key, private_key = generate_rsa_keypair_small(
        p,
        q,
        e=17
    )

    message = 123

    signature = rsa_sign_integer(
        message,
        private_key
    )

    valid = rsa_verify_integer(
        message,
        signature,
        public_key
    )

    tampered_message = 124

    tampered_valid = rsa_verify_integer(
        tampered_message,
        signature,
        public_key
    )

    print("Message:", message)
    print("Signature:", signature)
    print("Valid signature:", valid)
    print("Tampered message verification:", tampered_valid)


"""
=====================================================================
SECTION 22: HASHING VS PRIME FACTORIZATION
=====================================================================

Hash functions and factoring solve different cryptographic problems.

A cryptographic hash function:

    input
       |
       v
    fixed-size digest

Examples:

    SHA-256
    SHA-3

Hash functions are designed to provide properties such as:

    preimage resistance
    second-preimage resistance
    collision resistance

Hashing does NOT depend on prime factorization in the same way RSA
does.

Blockchain systems rely heavily on hashing.

This distinction is essential:

    RSA security
        |
        +-- closely associated with integer factorization

    SHA-256 security
        |
        +-- associated with hash-function security properties

    ECC security
        |
        +-- associated with elliptic-curve discrete logarithms
"""


"""
=====================================================================
SECTION 23: BLOCKCHAIN AND PRIME FACTORIZATION
=====================================================================

A blockchain is not automatically a "prime factorization system".

Many blockchain systems use several cryptographic primitives:

    Hash functions
    Digital signatures
    Public-key cryptography
    Merkle trees
    Consensus mechanisms

For example, Bitcoin uses:

    SHA-256
    RIPEMD-160 in parts of its address ecosystem
    ECDSA over secp256k1
    Schnorr signatures in newer Taproot-related functionality

The critical point:

Bitcoin's security is NOT primarily based on the difficulty of
prime factorization.

Bitcoin's elliptic-curve signatures rely on the difficulty of the
elliptic-curve discrete logarithm problem.

Bitcoin's proof-of-work relies on hash computation.

Therefore:

    Prime factorization ≠ blockchain security in general.
"""


"""
=====================================================================
SECTION 24: TOY BLOCKCHAIN
=====================================================================

This example demonstrates how hashing is used to connect blocks.

It is NOT a production blockchain.
"""

import hashlib
from dataclasses import dataclass


@dataclass
class Block:
    index: int
    data: str
    previous_hash: str

    def calculate_hash(self):
        """
        Calculate SHA-256 hash of block contents.
        """

        content = (
            f"{self.index}"
            f"{self.data}"
            f"{self.previous_hash}"
        )

        return hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()


def demonstrate_hash_chain():
    """
    Demonstrate a simple blockchain-like hash chain.
    """

    genesis = Block(
        index=0,
        data="Genesis Block",
        previous_hash="0"
    )

    block_1 = Block(
        index=1,
        data="Alice sends 10 coins to Bob",
        previous_hash=genesis.calculate_hash()
    )

    block_2 = Block(
        index=2,
        data="Bob sends 3 coins to Charlie",
        previous_hash=block_1.calculate_hash()
    )

    print("Genesis hash:")
    print(genesis.calculate_hash())

    print("\nBlock 1 hash:")
    print(block_1.calculate_hash())

    print("\nBlock 2 hash:")
    print(block_2.calculate_hash())

    print("\nBlock 2 previous hash:")
    print(block_2.previous_hash)

    print(
        "\nChain linkage valid:",
        block_2.previous_hash == block_1.calculate_hash()
    )


"""
=====================================================================
SECTION 25: MERKLE TREES
=====================================================================

A Merkle tree summarizes many transactions using hashes.

Example:

            Root
           /    \
         H12    H34
        /  \    /  \
       H1  H2  H3  H4

Each leaf represents a transaction hash.

Parents are created by hashing combinations of child hashes.

Prime factorization is not required for this structure.

Merkle trees demonstrate another important distinction:

    Blockchain data integrity
        |
        +-- often hash based

    RSA cryptographic security
        |
        +-- factorization based
"""


def sha256_hex(data):
    """
    Calculate SHA-256 digest.
    """

    return hashlib.sha256(
        data.encode("utf-8")
    ).hexdigest()


def merkle_parent(left, right):
    """
    Create a parent hash from two child hashes.
    """

    return sha256_hex(left + right)


def build_merkle_root(transactions):
    """
    Build a simple Merkle root.

    This is an educational implementation.
    """

    if not transactions:
        raise ValueError("Transactions cannot be empty")

    level = [
        sha256_hex(transaction)
        for transaction in transactions
    ]

    while len(level) > 1:

        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level = []

        for i in range(0, len(level), 2):

            parent = merkle_parent(
                level[i],
                level[i + 1]
            )

            next_level.append(parent)

        level = next_level

    return level[0]


"""
=====================================================================
SECTION 26: RSA ACCUMULATORS
=====================================================================

Prime numbers have another interesting application in
cryptography: RSA accumulators.

An accumulator allows a collection of values to be represented by
a compact cryptographic value.

A simplified conceptual RSA accumulator can use:

    A = g^(product of primes) mod N

where:

    g = generator/base
    N = RSA modulus
    primes = representatives of accumulated elements

For example, if the set is represented by:

    2, 3, 5

then:

    A = g^(2×3×5) mod N

      = g^30 mod N

The accumulator can provide compact membership proofs.

This demonstrates that prime numbers can play a role in advanced
cryptographic constructions beyond RSA encryption.
"""


def rsa_accumulate(base, primes, modulus):
    """
    Simplified RSA-style accumulator.

    IMPORTANT:
    This is an educational mathematical demonstration.

    Production RSA accumulators require careful parameter generation,
    domain separation, prime representatives, trapdoor assumptions,
    and secure proof systems.
    """

    exponent = 1

    for prime in primes:

        if not is_prime_basic(prime):
            raise ValueError(
                f"{prime} is not prime"
            )

        exponent *= prime

    return modular_power(
        base,
        exponent,
        modulus
    )


"""
=====================================================================
SECTION 27: RSA ACCUMULATOR MEMBERSHIP INTUITION
=====================================================================

Suppose:

    A = g^(p1 × p2 × p3) mod N

To prove membership of p1, one can conceptually create:

    W = g^(p2 × p3) mod N

Then:

    W^p1 = A mod N

because:

    (g^(p2×p3))^p1
        =
    g^(p1×p2×p3)

This is the mathematical intuition behind an accumulator witness.

Actual secure constructions are significantly more sophisticated.
"""


def accumulator_membership_check(
    accumulator,
    witness,
    member_prime,
    modulus
):
    """
    Verify the simplified mathematical relationship:

        witness^member_prime mod modulus == accumulator
    """

    return (
        modular_power(
            witness,
            member_prime,
            modulus
        )
        == accumulator
    )


"""
=====================================================================
SECTION 28: MERKLE TREES VS RSA ACCUMULATORS
=====================================================================

Merkle tree:

    Uses hashes
    |
    +-- widely used in blockchains
    +-- membership proof size grows logarithmically
    +-- no trusted RSA setup required
    +-- very practical

RSA accumulator:

    Uses modular exponentiation
    |
    +-- compact accumulator
    +-- can support succinct membership proofs
    +-- relies on number-theoretic assumptions
    +-- requires careful cryptographic construction

Both can provide efficient membership verification, but their
underlying mathematics is different.
"""


"""
=====================================================================
SECTION 29: PRIME FACTORIZATION AND ZERO-KNOWLEDGE SYSTEMS
=====================================================================

Modern decentralized technologies use zero-knowledge proofs.

Examples include:

    zk-SNARKs
    zk-STARKs
    privacy-preserving blockchains
    rollups
    verifiable computation

Not all zero-knowledge systems depend on prime factorization.

Different proof systems rely on different mathematical assumptions.

Some constructions may use:

    elliptic curves
    finite fields
    polynomial commitments
    pairings
    hash functions
    discrete logarithms
    integer arithmetic

Therefore, it is incorrect to say:

    "Blockchain uses prime factorization."

A more accurate statement is:

    "Prime factorization is one important number-theoretic problem
     used in some cryptographic constructions, especially RSA and
     certain accumulator systems, while many decentralized systems
     rely on hashing, elliptic curves, finite fields, and other
     mathematical assumptions."
"""


"""
=====================================================================
SECTION 30: INTEGER FACTORIZATION PROBLEM
=====================================================================

The Integer Factorization Problem can be stated as:

Given a composite integer:

    N

find integers:

    p1, p2, ..., pk

such that:

    N = p1 × p2 × ... × pk

where each pi is prime.

For arbitrary large integers, this can be computationally difficult.

But difficulty depends on:

    size of N
    structure of N
    factor sizes
    available algorithms
    computing resources

This is why cryptography cannot simply say:

    "Factoring is impossible."

The correct concept is:

    "Factoring is believed to be computationally difficult for
     appropriately selected cryptographic parameters against the
     relevant attack model."
"""


"""
=====================================================================
SECTION 31: WHY WE DO NOT USE SMALL RSA KEYS
=====================================================================

Small RSA examples are easy to factor.

For example:

    n = 3233

can be factored almost instantly.

Real RSA uses much larger moduli.

Historically common RSA security levels include:

    1024 bits
    2048 bits
    3072 bits
    4096 bits

Modern security recommendations generally avoid 1024-bit RSA for
new security-sensitive applications.

2048-bit RSA has historically been a common baseline, while larger
sizes provide more security at the cost of performance.

Exact security recommendations depend on application, standards,
and threat model.
"""


"""
=====================================================================
SECTION 32: CLASSICAL FACTORIZATION ALGORITHMS
=====================================================================

Important factorization algorithms include:

1. Trial Division

   Very simple.
   Good for learning and small numbers.

2. Pollard's Rho

   Useful for finding relatively small factors.

3. Pollard's p - 1

   Exploits smoothness of p - 1.

4. Elliptic Curve Method (ECM)

   Particularly effective for finding relatively small factors
   of large integers.

5. Quadratic Sieve

   Powerful general-purpose factoring algorithm.

6. General Number Field Sieve (GNFS)

   The most powerful general-purpose classical factoring method
   for sufficiently large general integers.

The existence of increasingly sophisticated algorithms explains
why cryptographic key sizes must be selected carefully.
"""


"""
=====================================================================
SECTION 33: QUANTUM COMPUTING AND SHOR'S ALGORITHM
=====================================================================

A major future security concern is quantum computing.

Shor's algorithm provides a polynomial-time quantum algorithm for:

    integer factorization

and also for:

    discrete logarithms

If a sufficiently powerful fault-tolerant quantum computer exists,
traditional RSA could become vulnerable.

This means the relationship is:

    RSA
      |
      +-- security related to factoring
      |
      +-- Shor's algorithm threatens factoring assumption

ECC
      |
      +-- security related to discrete logarithm
      |
      +-- Shor's algorithm also threatens it

This is one reason post-quantum cryptography is important.
"""


"""
=====================================================================
SECTION 34: POST-QUANTUM CRYPTOGRAPHY
=====================================================================

Post-quantum cryptography (PQC) aims to provide cryptographic
security against attackers possessing large-scale quantum computers.

Important families include:

    lattice-based cryptography
    hash-based signatures
    code-based cryptography
    multivariate approaches
    isogeny-related research

Modern standardization efforts have focused heavily on lattice-based
and hash-based constructions.

The important lesson for this topic:

    Prime factorization is NOT the only mathematical foundation
    available for cryptography.

Cryptographic systems can be built on different computational
assumptions.
"""


"""
=====================================================================
SECTION 35: FACTORING AS A ONE-WAY-STYLE COMPUTATIONAL PROBLEM
=====================================================================

Cryptographic design often looks for mathematical operations that are:

    easy in one direction
    difficult in the reverse direction

RSA:

    p, q
      |
      v
    n = p × q

Multiplication is easy.

Reverse:

    n
      |
      v
    p, q

Factoring can be difficult for properly chosen large n.

This asymmetry is a core idea in public-key cryptography.
"""


"""
=====================================================================
SECTION 36: PRIME FACTORIZATION IN DECENTRALIZED TECHNOLOGY
=====================================================================

Potential roles include:

    RSA-based identity systems
    RSA signatures
    RSA accumulators
    certain anonymous credential systems
    number-theoretic proof systems
    cryptographic research
    historical decentralized constructions

But many mainstream decentralized systems primarily rely on:

    hash functions
    elliptic curves
    digital signatures
    Merkle trees
    finite fields
    polynomial commitments
    zero-knowledge proof systems

Therefore, prime factorization should be viewed as one component of
the broader mathematical toolkit of cryptography.
"""


"""
=====================================================================
SECTION 37: CRYPTOGRAPHIC ASSUMPTIONS
=====================================================================

A cryptographic scheme is generally built around assumptions.

Examples:

    RSA:
        hardness of factoring / related RSA inversion assumptions

    ECC:
        hardness of elliptic-curve discrete logarithm

    Hash-based cryptography:
        security properties of hash functions

    Lattice cryptography:
        hardness assumptions involving lattice problems

A cryptographic algorithm is therefore not simply "an algorithm".

It is:

    mathematics
        +
    computational assumptions
        +
    parameter selection
        +
    implementation
        +
    protocol design
"""


"""
=====================================================================
SECTION 38: WHY FACTORING THE MODULUS IS SO IMPORTANT TO RSA
=====================================================================

Suppose:

    n = p × q

and:

    φ(n) = (p - 1)(q - 1)

Suppose the public exponent is:

    e

The private exponent satisfies:

    e × d ≡ 1 (mod φ(n))

Therefore:

    d = e^(-1) mod φ(n)

If an attacker learns p and q:

    p, q
      |
      v
    φ(n)
      |
      v
    d
      |
      v
    private key

Therefore:

    factoring n
        |
        v
    recovering p and q
        |
        v
    calculating φ(n)
        |
        v
    calculating d
        |
        v
    compromising RSA private key

This is the central security relationship.
"""


"""
=====================================================================
SECTION 39: DEMONSTRATION OF THE COMPLETE RSA CHAIN
=====================================================================
"""


def complete_rsa_factorization_demo():
    """
    Demonstrate:

        prime selection
        ->
        RSA modulus
        ->
        public/private keys
        ->
        encryption
        ->
        decryption
        ->
        factoring
        ->
        private-key recovery
    """

    p = 61
    q = 53
    e = 17

    public_key, private_key = generate_rsa_keypair_small(
        p,
        q,
        e
    )

    n, public_exponent = public_key
    _, private_exponent = private_key

    print("=" * 70)
    print("RSA EDUCATIONAL DEMONSTRATION")
    print("=" * 70)

    print("\nOriginal primes:")
    print("p =", p)
    print("q =", q)

    print("\nRSA modulus:")
    print("n =", n)

    print("\nEuler totient:")
    phi = (p - 1) * (q - 1)
    print("phi(n) =", phi)

    print("\nPublic exponent:")
    print("e =", public_exponent)

    print("\nPrivate exponent:")
    print("d =", private_exponent)

    message = 65

    print("\nOriginal message:")
    print(message)

    ciphertext = rsa_encrypt_integer(
        message,
        public_key
    )

    print("\nCiphertext:")
    print(ciphertext)

    decrypted = rsa_decrypt_integer(
        ciphertext,
        private_key
    )

    print("\nDecrypted:")
    print(decrypted)

    print("\nAttacker receives n:")
    print(n)

    discovered_factors = factor_recursive_pollard(n)

    print("\nAttacker factors n:")
    print(discovered_factors)

    recovered_p = discovered_factors[0]
    recovered_q = discovered_factors[1]

    recovered_d = recover_rsa_private_exponent_from_factors(
        n,
        e,
        recovered_p,
        recovered_q
    )

    print("\nRecovered private exponent:")
    print(recovered_d)

    print(
        "\nPrivate exponent successfully recovered:",
        recovered_d == private_exponent
    )


"""
=====================================================================
SECTION 40: RSA ACCUMULATOR DEMONSTRATION
=====================================================================
"""


def demonstrate_rsa_accumulator():
    """
    Demonstrate a simplified RSA accumulator.
    """

    modulus = 3233

    base = 2

    members = [
        3,
        5,
        7
    ]

    accumulator = rsa_accumulate(
        base,
        members,
        modulus
    )

    print("=" * 70)
    print("RSA ACCUMULATOR DEMONSTRATION")
    print("=" * 70)

    print("Base:", base)
    print("Prime representatives:", members)
    print("Modulus:", modulus)

    print("\nAccumulator:")
    print(accumulator)

    # To prove that 3 is included, use:
    #
    # witness = g^(5*7) mod N

    witness = modular_power(
        base,
        5 * 7,
        modulus
    )

    valid = accumulator_membership_check(
        accumulator,
        witness,
        3,
        modulus
    )

    print("\nMembership witness for 3:")
    print(witness)

    print("\nMembership verification:")
    print(valid)


"""
=====================================================================
SECTION 41: BLOCKCHAIN CRYPTOGRAPHY SUMMARY
=====================================================================

When studying blockchain security, separate the following concepts:

                    BLOCKCHAIN
                        |
        +---------------+---------------+
        |               |               |
      HASHES         SIGNATURES      CONSENSUS
        |               |               |
    SHA-256          ECDSA/Schnorr   PoW/PoS/etc.
        |
    Merkle trees

Prime factorization is directly relevant only to some cryptographic
components and protocols.

For example:

    RSA-based blockchain-related system
        |
        +-- factorization can matter

Bitcoin:
        |
        +-- hashing
        +-- elliptic-curve cryptography
        +-- consensus
        |
        +-- not primarily factoring
"""


"""
=====================================================================
SECTION 42: IMPORTANT DISTINCTIONS
=====================================================================

DISTINCTION 1

Prime factorization:

    Finding prime factors of an integer.

RSA:

    Public-key cryptosystem whose security is associated with
    difficult number-theoretic problems, especially factoring.

These are related but not identical concepts.

DISTINCTION 2

Encryption:

    Protects confidentiality.

Digital signature:

    Provides authenticity and integrity.

Hash:

    Produces a fixed-size digest and supports integrity-related
    constructions.

Blockchain:

    A distributed protocol/system combining cryptography with
    networking, consensus, data structures and incentives.

DISTINCTION 3

Bitcoin:

    Not based on RSA.

Bitcoin uses elliptic-curve cryptography and hash functions.

DISTINCTION 4

Blockchain:

    Not synonymous with cryptography.

Blockchain systems combine:

    cryptography
    networking
    consensus
    data structures
    distributed systems
    economic incentives
"""


"""
=====================================================================
SECTION 43: SECURITY EXPERIMENT
=====================================================================

Let's compare the difficulty of factoring different educational
numbers.

The following experiment should use moderate values only.

Never use this script to attempt unauthorized attacks against
real cryptographic keys or systems.
"""


def factorization_experiment(numbers):
    """
    Factor a list of moderate-sized integers.
    """

    for number in numbers:

        print("\nNumber:", number)

        if miller_rabin(number):
            print("Status: prime")
            continue

        print("Status: composite")

        factors = factor_recursive_pollard(number)

        print("Prime factors:", factors)


"""
=====================================================================
SECTION 44: FACTORIZATION AND TIME COMPLEXITY INTUITION
=====================================================================

Trial division approximately explores possible divisors.

For a number n, checking all candidates up to sqrt(n) gives a rough
upper-bound intuition around:

    O(sqrt(n))

candidate testing in the naive case.

This becomes enormous as n grows.

Pollard's Rho has substantially better expected behavior for finding
small factors and is often described using roughly:

    O(sqrt(p))

behavior where p is a relatively small prime factor.

Large general semiprimes require much more advanced algorithms.

The important cryptographic lesson:

    Exponential-looking growth in attack effort can create a
    practical security barrier.
"""


"""
=====================================================================
SECTION 45: WHY PYTHON'S BIG INTEGERS ARE USEFUL
=====================================================================

Python integers have arbitrary precision.

This means Python can represent integers much larger than typical
fixed-width machine integers.

Example:

    2 ** 100
    2 ** 1000
    2 ** 10000

can all be represented.

This makes Python useful for learning number theory and
cryptographic mathematics.

But arbitrary-precision integers do not automatically make a
cryptographic implementation secure.

Security also requires:

    secure randomness
    constant-time considerations
    padding
    side-channel resistance
    protocol correctness
    key management
    secure libraries
"""


def demonstrate_big_integers():
    """
    Demonstrate arbitrary-precision integers.
    """

    numbers = [
        2 ** 32,
        2 ** 64,
        2 ** 128,
        2 ** 256
    ]

    for number in numbers:

        print(
            "Number of bits:",
            number.bit_length()
        )


"""
=====================================================================
SECTION 46: PRACTICAL CRYPTOGRAPHIC RULES
=====================================================================

RULE 1

Do not implement production RSA yourself.

Use audited libraries.

RULE 2

Do not use small RSA keys.

RULE 3

Do not use Python's random module for cryptographic key generation.

Use:

    secrets

or an established cryptographic library.

RULE 4

Do not use textbook RSA directly.

Use standardized padding schemes.

For encryption, modern protocols may use hybrid encryption rather
than directly encrypting arbitrary data with RSA.

For signatures, RSA-PSS is a standard modern construction.

RULE 5

Do not confuse hashing with encryption.

RULE 6

Do not assume blockchain automatically means RSA.

RULE 7

Do not assume every zero-knowledge proof depends on factorization.

RULE 8

Do not treat mathematical demonstrations as production security.
"""


"""
=====================================================================
SECTION 47: EDUCATIONAL USE OF THE secrets MODULE
=====================================================================

For cryptographic randomness, Python provides the secrets module.

Example:

    secrets.randbits()

is designed for security-sensitive randomness.

This is still only one part of secure cryptographic implementation.
"""


import secrets


def secure_random_bits_demo(bits=128):
    """
    Demonstrate cryptographically stronger randomness for Python
    application development.

    This does NOT itself create a complete cryptographic key.
    """

    return secrets.randbits(bits)


"""
=====================================================================
SECTION 48: PRIME FACTORIZATION WORKFLOW
=====================================================================

Given:

    N

The learning workflow is:

    1. Check whether N is prime.
    2. If N is prime, factorization is simply N.
    3. If composite, search for a factor.
    4. Divide N by that factor.
    5. Continue recursively.
    6. Stop when every remaining factor is prime.

Example:

    360

First:

    360 / 2 = 180

Again:

    180 / 2 = 90

Again:

    90 / 2 = 45

Then:

    45 / 3 = 15

Then:

    15 / 3 = 5

5 is prime.

Therefore:

    360 = 2 × 2 × 2 × 3 × 3 × 5

or:

    360 = 2³ × 3² × 5
"""


def explain_factorization_step_by_step(n):
    """
    Print the factorization process.
    """

    if n < 2:
        raise ValueError("n must be at least 2")

    original = n

    print("\nStarting number:", original)

    divisor = 2

    while divisor * divisor <= n:

        while n % divisor == 0:

            print(
                f"{n} ÷ {divisor} = {n // divisor}"
            )

            n //= divisor

        divisor = 3 if divisor == 2 else divisor + 2

    if n > 1:

        print(
            f"Remaining prime factor: {n}"
        )

    print(
        "Prime factorization:",
        format_factorization(original)
    )


"""
=====================================================================
SECTION 49: ADVANCED CONCEPT: SMOOTH NUMBERS
=====================================================================

A number is called B-smooth if all of its prime factors are <= B.

For example:

    60 = 2² × 3 × 5

is 5-smooth.

Smoothness plays an important role in several number-theoretic
algorithms.

Examples include:

    Pollard's p - 1
    Quadratic Sieve
    Number Field Sieve

Understanding factorization therefore requires understanding not only
prime numbers but also the structure of composite numbers.
"""


def largest_prime_factor(n):
    """
    Return the largest prime factor using basic factorization.
    """

    factors = prime_factorization_basic(n)

    return max(factors)


"""
=====================================================================
SECTION 50: FINAL KNOWLEDGE MAP
=====================================================================

PRIME NUMBERS
    |
    +-- factors
    |
    +-- prime factorization
    |
    +-- modular arithmetic
    |
    +-- GCD
    |
    +-- Euler's totient
    |
    +-- modular inverse
    |
    +-- RSA
          |
          +-- p × q = n
          |
          +-- public key
          |
          +-- private key
          |
          +-- encryption
          |
          +-- signatures
          |
          +-- factoring attacks

PRIME NUMBERS
    |
    +-- RSA accumulators
    |
    +-- number-theoretic cryptography

BLOCKCHAIN
    |
    +-- hash functions
    |
    +-- Merkle trees
    |
    +-- digital signatures
    |
    +-- consensus
    |
    +-- zero-knowledge systems
    |
    +-- decentralized applications

CRITICAL DISTINCTION:

Prime factorization
        |
        +-- important to RSA and some number-theoretic constructions

Blockchain
        |
        +-- broader system
        +-- often hash + signature + consensus based

Bitcoin
        |
        +-- SHA-256
        +-- elliptic-curve cryptography
        +-- consensus
        +-- NOT RSA / NOT primarily factorization based


=====================================================================
SECTION 51: MAIN EXECUTION
=====================================================================
"""


def main():

    print("=" * 70)
    print("PRIME FACTORIZATION IN CRYPTOGRAPHY, BLOCKCHAIN")
    print("AND DECENTRALIZED TECHNOLOGIES")
    print("=" * 70)

    print("\n1. PRIME CHECKING")
    print("-" * 70)

    test_numbers = [
        2,
        3,
        4,
        17,
        19,
        25,
        97
    ]

    for number in test_numbers:

        print(
            number,
            "is prime:",
            is_prime_basic(number)
        )

    print("\n2. PRIMES UP TO 50")
    print("-" * 70)

    print(list_primes(50))

    print("\n3. FACTORS")
    print("-" * 70)

    print("Factors of 60:")
    print(find_factors(60))

    print("\n4. PRIME FACTORIZATION")
    print("-" * 70)

    numbers = [
        12,
        18,
        60,
        84,
        360,
        1001
    ]

    for number in numbers:

        print(
            format_factorization(number)
        )

    print("\n5. GCD")
    print("-" * 70)

    print(
        "gcd(48, 18) =",
        gcd(48, 18)
    )

    print("\n6. EXTENDED GCD")
    print("-" * 70)

    g, x, y = extended_gcd(240, 46)

    print("gcd =", g)
    print("x =", x)
    print("y =", y)

    print(
        "Verification:",
        240 * x + 46 * y
    )

    print("\n7. MODULAR INVERSE")
    print("-" * 70)

    inverse = modular_inverse(17, 3120)

    print(
        "17^-1 mod 3120 =",
        inverse
    )

    print("\n8. MODULAR EXPONENTIATION")
    print("-" * 70)

    print(
        "5^117 mod 19 =",
        modular_power(5, 117, 19)
    )

    print("\n9. EULER TOTIENT")
    print("-" * 70)

    print(
        "phi(60) =",
        euler_totient_from_factorization(60)
    )

    print("\n10. RSA DEMONSTRATION")
    print("-" * 70)

    demonstrate_rsa_factorization()

    print("\n11. RSA SIGNATURE")
    print("-" * 70)

    demonstrate_rsa_signature()

    print("\n12. POLLARD'S RHO")
    print("-" * 70)

    number = 8051

    print(
        "Number:",
        number
    )

    print(
        "Factors:",
        factor_recursive_pollard(number)
    )

    print("\n13. BLOCKCHAIN HASH CHAIN")
    print("-" * 70)

    demonstrate_hash_chain()

    print("\n14. MERKLE ROOT")
    print("-" * 70)

    transactions = [
        "Alice pays Bob 10",
        "Bob pays Charlie 5",
        "Charlie pays David 2",
        "David pays Eve 1"
    ]

    root = build_merkle_root(transactions)

    print("Merkle root:")
    print(root)

    print("\n15. RSA ACCUMULATOR")
    print("-" * 70)

    demonstrate_rsa_accumulator()

    print("\n16. BIG INTEGER DEMONSTRATION")
    print("-" * 70)

    demonstrate_big_integers()

    print("\n17. FACTORIZATION WALKTHROUGH")
    print("-" * 70)

    explain_factorization_step_by_step(360)

    print("\n18. LARGEST PRIME FACTOR")
    print("-" * 70)

    number = 7560

    print(
        "Number:",
        number
    )

    print(
        "Largest prime factor:",
        largest_prime_factor(number)
    )

    print("\n19. SEMIPRIME TEST")
    print("-" * 70)

    for number in [15, 21, 49, 60, 77, 3233]:

        print(
            number,
            "is semiprime:",
            is_semiprime(number)
        )

    print("\n20. SECURE RANDOMNESS DEMONSTRATION")
    print("-" * 70)

    print(
        "Random 128-bit value:",
        secure_random_bits_demo(128)
    )

    print("\n" + "=" * 70)
    print("LEARNING PROGRAM COMPLETED")
    print("=" * 70)

    print(
        """
CORE LESSON:

Prime factorization is one of the fundamental mathematical ideas
behind classical public-key cryptography.

RSA demonstrates the connection most directly:

    p × q = n
       |
       v
    public modulus
       |
       v
    factoring n is computationally difficult
       |
       v
    private-key security

Blockchain technology is broader.

Many blockchain systems rely primarily on:

    hashing
    digital signatures
    Merkle trees
    elliptic curves
    consensus
    zero-knowledge proofs

Prime factorization remains important in RSA and selected
number-theoretic cryptographic constructions such as RSA accumulators.

Never confuse:

    RSA security
    blockchain security
    hash security
    elliptic-curve security
    zero-knowledge proof security

They can depend on different mathematical assumptions.
"""
    )


if __name__ == "__main__":
    main()
