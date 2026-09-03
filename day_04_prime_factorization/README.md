# Prime factorization in cryptography, blockchain and decentralized technologies

## Overview

Prime factorization is one of the fundamental concepts of number theory and has an important relationship with modern cryptography.

Prime factorization means expressing a composite number as a product of prime numbers.

For example:

60 = 2 × 2 × 3 × 5

or:

60 = 2³ × 3 × 5

The Python program studied prime numbers, factors, prime factorization, modular arithmetic, RSA, factorization algorithms, blockchain cryptography, RSA accumulators and the relationship between classical number theory and decentralized technologies.

## Prime numbers

A prime number is an integer greater than 1 that has exactly two positive divisors:

- 1
- itself

Examples include:

2, 3, 5, 7, 11, 13, 17, 19 and 23.

A composite number is an integer greater than 1 that is not prime.

Examples:

4 = 2 × 2

6 = 2 × 3

8 = 2 × 2 × 2

9 = 3 × 3

10 = 2 × 5

A basic primality-testing function was implemented in Python.

The program also implemented the Sieve of Eratosthenes for generating prime numbers up to a specified limit.

## Factors

A factor is a number that divides another number without leaving a remainder.

For example, the factors of 12 are:

1, 2, 3, 4, 6 and 12.

Factor pairs include:

1 × 12

2 × 6

3 × 4

The Python program implemented a function for finding all positive factors of a number.

## Prime factorization

Prime factorization expresses a number as a product of prime numbers.

Examples:

12 = 2 × 2 × 3

18 = 2 × 3 × 3

60 = 2 × 2 × 3 × 5

84 = 2 × 2 × 3 × 7

360 = 2³ × 3² × 5

The Python program implemented prime factorization using trial division.

The factors were also converted into a power representation such as:

2³ × 3² × 5

## Fundamental Theorem of Arithmetic

The Fundamental Theorem of Arithmetic states that every integer greater than 1 can be represented uniquely as a product of prime numbers, apart from the order of those factors.

For example:

60 = 2² × 3 × 5

There is no different set of prime factors that can produce 60.

This unique representation is fundamental to number theory and important to cryptographic constructions based on integer factorization.

## Greatest Common Divisor

The Greatest Common Divisor, or GCD, is the largest positive integer that divides two numbers.

For example:

gcd(48, 18) = 6

The Euclidean Algorithm was implemented to calculate the GCD efficiently.

The main relationship used by the algorithm is:

gcd(a, b) = gcd(b, a mod b)

The algorithm repeatedly replaces the pair of numbers until the second number becomes zero.

## Extended Euclidean Algorithm

The Extended Euclidean Algorithm extends the GCD calculation.

It finds integers x and y satisfying:

ax + by = gcd(a, b)

This is important in modular arithmetic because when:

gcd(a, m) = 1

the value x can be used to calculate the modular inverse of a modulo m.

The Python program implemented both the Extended Euclidean Algorithm and modular inverse calculation.

## Modular arithmetic

Modular arithmetic works with remainders.

For example:

17 mod 5 = 2

because:

17 = 5 × 3 + 2

The notation:

a ≡ b (mod n)

means that a and b have the same remainder when divided by n.

Modular arithmetic is fundamental to many cryptographic algorithms.

The Python program implemented fast modular exponentiation.

Instead of calculating a very large value such as:

a^e

directly, repeated squaring is used to calculate:

a^e mod n

efficiently.

## Euler's Totient Function

Euler's Totient Function is represented by:

φ(n)

It counts the positive integers up to n that are relatively prime to n.

For a prime p:

φ(p) = p - 1

For two distinct primes p and q:

φ(pq) = (p - 1)(q - 1)

This relationship is particularly important in RSA.

The Python program implemented Euler's Totient Function using prime factorization.

## Carmichael's function

Carmichael's function is represented by:

λ(n)

It is related to the smallest exponent that causes modular powers of numbers relatively prime to n to return to 1.

For two distinct odd primes:

n = p × q

the function is:

λ(n) = lcm(p - 1, q - 1)

The Python program implemented the least common multiple and the Carmichael function for a product of two distinct primes.

## Why prime factorization matters in cryptography

One of the most important ideas in public-key cryptography is computational asymmetry.

Some mathematical operations are easy to perform in one direction but difficult to reverse.

Multiplication of two large primes is easy:

p × q = n

The reverse operation is factorization:

n → p and q

For small values, factorization is easy.

For appropriately selected large RSA moduli, factorization is computationally difficult using known classical techniques.

This computational difficulty is closely connected to the security of RSA.

## Semiprimes

A semiprime is an integer that is the product of exactly two prime numbers, counting multiplicity.

Examples:

15 = 3 × 5

21 = 3 × 7

49 = 7 × 7

77 = 7 × 11

RSA uses a modulus constructed from two large primes:

n = p × q

The resulting number is a large semiprime.

The security objective is to make it computationally infeasible for an attacker to recover p and q from n.

## RSA

RSA is a classical public-key cryptographic system whose mathematics is strongly connected to integer factorization.

The basic RSA key-generation process is:

Choose two prime numbers:

p and q

Calculate:

n = p × q

Calculate:

φ(n) = (p - 1)(q - 1)

Choose a public exponent e such that:

gcd(e, φ(n)) = 1

Calculate the private exponent:

d = e⁻¹ mod φ(n)

The public key is:

(n, e)

The private key is:

(n, d)

The Python program demonstrated this complete mathematical process using intentionally small educational primes.

## RSA encryption

For an integer message m, simplified RSA encryption is:

c = m^e mod n

where c is the ciphertext.

Decryption is:

m = c^d mod n

The Python program implemented educational RSA encryption and decryption for integer messages.

The implementation is intentionally small and is not suitable for real-world cryptographic use.

## RSA and prime factorization

The central relationship between RSA and factorization can be represented as:

p × q = n

If an attacker can factor the public modulus n and discover:

p and q

then they can calculate:

φ(n) = (p - 1)(q - 1)

and then calculate:

d = e⁻¹ mod φ(n)

Therefore:

factor n

→ recover p and q

→ calculate φ(n)

→ calculate d

→ recover the RSA private exponent

This explains why the difficulty of factoring a properly generated RSA modulus is important to RSA security.

RSA security should not be described as "factoring is impossible."

The correct idea is that factoring sufficiently large appropriately structured RSA moduli is computationally difficult for known classical attacks under the relevant assumptions.

## RSA digital signatures

Digital signatures are different from encryption.

Encryption primarily addresses confidentiality.

Digital signatures provide properties such as:

- authenticity
- integrity
- proof of possession of a signing key

The Python program demonstrated the mathematical concept of an RSA signature using:

signature = message^d mod n

and verification using:

signature^e mod n

This was a mathematical demonstration of raw RSA.

Production RSA signatures should use standardized secure schemes such as RSA-PSS and should be implemented using established cryptographic libraries.

## Recovering an RSA private exponent from known factors

The Python program demonstrated what happens if the factors of an RSA modulus become known.

Given:

n = p × q

and:

e

the program calculates:

φ(n) = (p - 1)(q - 1)

and then:

d = e⁻¹ mod φ(n)

This demonstrates why compromise of the RSA modulus's secret factors can lead to compromise of the corresponding private key.

## Trial division

Trial division is one of the simplest factorization algorithms.

It repeatedly tests candidate divisors.

For example, to factor 60:

60 ÷ 2 = 30

30 ÷ 2 = 15

15 ÷ 3 = 5

5 is prime.

Therefore:

60 = 2² × 3 × 5

Trial division is excellent for understanding factorization but becomes inefficient for large numbers.

The program implemented trial-division factorization.

## Miller-Rabin primality testing

When numbers become large, efficient primality testing becomes important.

Miller-Rabin is a probabilistic primality-testing algorithm.

It determines whether a number is composite or whether it passes a set of tests indicating that it is probably prime.

The program implemented a Miller-Rabin test using a deterministic set of bases appropriate for a bounded integer range.

The important distinction is that primality testing and factorization are different problems.

Primality testing asks:

"Is this number prime?"

Factorization asks:

"What are the prime factors of this composite number?"

## Pollard's Rho

Pollard's Rho is a more advanced classical factorization algorithm.

Unlike trial division, it uses pseudorandom-like sequences and GCD calculations to search for non-trivial factors.

The important mathematical operation is based around:

gcd(|x - y|, n)

The Python program implemented Pollard's Rho and recursive factorization.

This provides a practical introduction to the fact that integer factorization involves sophisticated algorithms rather than simply testing every possible divisor.

## Advanced factorization algorithms

The program introduced several increasingly advanced approaches:

- Trial division
- Pollard's Rho
- Pollard's p - 1
- Elliptic Curve Method
- Quadratic Sieve
- General Number Field Sieve

The General Number Field Sieve is historically the most powerful general-purpose classical algorithm for factoring sufficiently large general integers.

This explains why RSA key sizes must be selected with known factorization algorithms and available computational resources in mind.

## Smooth numbers

A number is called B-smooth when all of its prime factors are less than or equal to B.

For example:

60 = 2² × 3 × 5

is 5-smooth.

Smoothness is important in several number-theoretic algorithms, including:

- Pollard's p - 1
- Quadratic Sieve
- Number Field Sieve

Understanding the structure of composite numbers therefore goes beyond simply finding their factors.

## Big integers in Python

Python integers support arbitrary precision.

This makes Python particularly useful for learning number theory and cryptographic mathematics.

Examples include:

2³²

2⁶⁴

2¹²⁸

2²⁵⁶

Arbitrary-precision arithmetic allows Python to represent very large integers without the fixed-width limitations found in many programming environments.

Arbitrary precision does not automatically make a cryptographic implementation secure.

Security also depends on secure randomness, implementation techniques, padding, side-channel resistance, key management and protocol design.

## Hashing and factorization

Hash functions and integer factorization represent different cryptographic concepts.

Cryptographic hash functions such as SHA-256 produce fixed-size digests.

Hash security involves properties such as:

- preimage resistance
- second-preimage resistance
- collision resistance

Hash functions are not based on the RSA factorization problem.

This distinction is particularly important when studying blockchain systems.

## Blockchain and prime factorization

Blockchain technology should not be described as being based on prime factorization.

A blockchain system can combine:

- cryptographic hash functions
- digital signatures
- public-key cryptography
- Merkle trees
- consensus mechanisms
- distributed networking
- incentive mechanisms
- zero-knowledge proofs

Prime factorization is relevant to some cryptographic systems used in or around decentralized technologies, but it is not the universal mathematical foundation of blockchain.

## Bitcoin and prime factorization

Bitcoin does not primarily depend on RSA or integer factorization.

Bitcoin's cryptographic architecture uses technologies including:

- SHA-256 hashing
- elliptic-curve cryptography
- digital signatures
- Merkle trees
- proof-of-work

Bitcoin's elliptic-curve cryptography is based on the difficulty of the elliptic-curve discrete logarithm problem rather than the integer factorization problem.

Bitcoin's proof-of-work is based on hash computations rather than prime factorization.

This distinction is essential when connecting number theory with blockchain technology.

## Hash chains

The Python program implemented a simple educational hash chain.

Each block contained:

- an index
- data
- the previous block's hash

A block hash was calculated using SHA-256.

The next block stored the previous block's hash.

This creates a cryptographic linkage:

Block 1

→ hash

Block 2

→ hash

Block 3

→ hash

If earlier block data is modified, the corresponding hash changes and the linkage can be detected.

This demonstrates how hashing can provide tamper-evident data structures.

## Merkle trees

A Merkle tree summarizes multiple pieces of data using cryptographic hashes.

A simplified structure is:

        Root
       /    \
     H12    H34
    /  \    /  \
   H1  H2  H3  H4

Transactions are hashed at the leaves.

Pairs of hashes are combined to create parent hashes.

The process continues until one root hash remains.

The Python program implemented a simple Merkle root calculation.

Merkle trees are important in blockchain systems because they allow large collections of transactions to be represented by a compact root hash.

## Merkle trees versus RSA accumulators

Merkle trees and RSA accumulators provide different approaches to representing collections of data.

Merkle trees use:

cryptographic hashes

RSA accumulators use:

modular arithmetic and exponentiation

A simplified RSA accumulator can be represented as:

A = g^(p1 × p2 × p3) mod N

where the values are represented by prime numbers.

Merkle trees are widely used in blockchain systems.

RSA accumulators demonstrate another way that prime numbers and number theory can support compact cryptographic representations.

## RSA accumulators

An RSA accumulator can represent a collection of values using a single accumulator value.

For prime representatives:

p1, p2, p3

a simplified accumulator can be expressed as:

A = g^(p1 × p2 × p3) mod N

For example:

A = g^(2 × 3 × 5) mod N

which becomes:

A = g³⁰ mod N

A membership witness for a member can demonstrate that the member is part of the accumulated set.

The Python program implemented a simplified mathematical RSA accumulator and a basic membership verification relationship.

The implementation is educational and does not represent a production-secure RSA accumulator.

## RSA accumulator membership intuition

Suppose:

A = g^(p1 × p2 × p3) mod N

For member p1, a witness can conceptually be:

W = g^(p2 × p3) mod N

Then:

W^p1 mod N = A

because:

(g^(p2 × p3))^p1

=

g^(p1 × p2 × p3)

This illustrates the mathematical intuition behind accumulator membership proofs.

Actual secure constructions require considerably more careful parameter generation and proof design.

## Zero-knowledge systems

Modern decentralized technologies increasingly use zero-knowledge proofs.

Examples include:

- zk-SNARKs
- zk-STARKs
- privacy-preserving blockchains
- rollups
- verifiable computation

Not every zero-knowledge system depends on prime factorization.

Different systems can depend on different mathematical assumptions, including:

- elliptic curves
- finite fields
- polynomial commitments
- pairings
- hash functions
- discrete logarithms
- lattice problems
- other algebraic structures

Therefore, prime factorization is one component of the larger mathematical foundation of cryptography rather than the foundation of every cryptographic system.

## Cryptographic assumptions

Different cryptographic systems depend on different computational assumptions.

RSA:

factorization-related and RSA inversion assumptions

Elliptic-curve cryptography:

elliptic-curve discrete logarithm assumptions

Hash-based cryptography:

security properties of cryptographic hash functions

Lattice-based cryptography:

hardness assumptions involving lattice problems

Understanding the underlying assumption is important when evaluating a cryptographic system.

## Quantum computing and Shor's algorithm

Quantum computing introduces an important challenge for classical public-key cryptography.

Shor's algorithm provides a quantum algorithm for integer factorization and discrete logarithms.

This has important implications:

RSA:

factorization-based security assumption

Elliptic-curve cryptography:

discrete-logarithm-based security assumption

Shor's algorithm:

threatens both types of assumptions when sufficiently powerful fault-tolerant quantum computers become available.

This is one of the major reasons post-quantum cryptography is being developed and standardized.

## Post-quantum cryptography

Post-quantum cryptography aims to create cryptographic systems that remain secure against attackers with sufficiently powerful quantum computers.

Important research and construction families include:

- lattice-based cryptography
- hash-based signatures
- code-based cryptography
- other post-quantum approaches

The major lesson is that cryptography does not have to depend on prime factorization.

Different cryptographic systems can be based on different mathematical problems.

## Security lessons

The Python program demonstrated several important security principles.

### Do not use small RSA keys

Small educational RSA moduli can be factored easily.

They are useful for learning but provide no meaningful modern security.

### Do not implement production RSA yourself

The mathematical demonstration is useful for understanding RSA.

Production systems require carefully reviewed and audited cryptographic implementations.

### Do not use Python's normal random module for cryptographic keys

The program demonstrated the difference between ordinary pseudo-random generation and security-oriented randomness.

For security-sensitive randomness, Python provides the `secrets` module, while established cryptographic libraries should generally be preferred for complete cryptographic operations.

### Do not use textbook RSA in production

The raw mathematical RSA implementation in the program is for learning.

Production RSA encryption and signatures require standardized secure constructions and appropriate padding.

### Do not confuse encryption and hashing

Encryption is designed to provide confidentiality.

Hashing produces a digest and supports integrity and other cryptographic constructions.

### Do not confuse RSA with blockchain

RSA and blockchain are not synonymous.

RSA is a public-key cryptographic system.

Blockchain is a broader distributed-system architecture that can combine cryptography, networking, consensus, data structures and economic mechanisms.

## Complete relationship between prime factorization and RSA

The complete mathematical relationship studied was:

p × q = n

↓

RSA public modulus

↓

Difficulty of recovering p and q

↓

Difficulty of calculating φ(n)

↓

Difficulty of calculating the private exponent d

↓

Security of RSA

The important point is that multiplication is easy while reversing the multiplication through factorization can be computationally difficult for appropriately selected large parameters.

## Complete relationship between cryptography and blockchain

The broader relationship can be represented as:

Cryptography

├── Hash functions
│   ├── SHA-256
│   └── Merkle trees
│
├── Public-key cryptography
│   ├── RSA
│   └── Elliptic-curve cryptography
│
├── Digital signatures
│   ├── RSA signatures
│   ├── ECDSA
│   └── Schnorr signatures
│
├── Number-theoretic constructions
│   ├── RSA
│   └── RSA accumulators
│
└── Zero-knowledge systems
    ├── zk-SNARKs
    └── zk-STARKs

Blockchain technologies can use several of these components depending on the specific protocol.

## Important distinctions learned

Prime factorization is not the same thing as RSA.

RSA is a public-key cryptographic system that is closely associated with difficult number-theoretic problems including integer factorization.

Prime factorization is not the same thing as blockchain security.

Blockchain systems can rely on hashes, signatures, consensus, elliptic curves, Merkle trees and zero-knowledge technologies.

Bitcoin is not an RSA-based system.

Bitcoin relies heavily on hashing and elliptic-curve cryptography.

Hashing is not encryption.

Digital signatures are not the same as encryption.

Primality testing is not factorization.

Quantum computing does not simply make all cryptography useless. It threatens particular mathematical assumptions and motivates migration toward post-quantum cryptographic systems.

## Practical Python concepts practiced

The program practiced:

- Functions
- Conditional statements
- Loops
- Lists
- Dictionaries
- Exceptions
- Recursion
- Imports
- Classes and dataclasses
- String formatting
- Integer arithmetic
- Modular arithmetic
- Arbitrary-precision integers
- Hashing with SHA-256
- Random number generation
- Security-oriented randomness using `secrets`

## Algorithms implemented

The Python program implemented:

- Basic primality testing
- Sieve of Eratosthenes
- Factor enumeration
- Trial-division factorization
- Prime factorization
- Factorization represented using powers
- Euclidean Algorithm
- Extended Euclidean Algorithm
- Modular inverse
- Fast modular exponentiation
- Euler's Totient Function
- Least Common Multiple
- Carmichael's function for two primes
- Semiprime detection
- Miller-Rabin primality testing
- Pollard's Rho factorization
- Recursive factorization
- Educational RSA key generation
- Educational RSA encryption
- Educational RSA decryption
- Educational RSA signatures
- RSA signature verification
- RSA private-exponent recovery from known factors
- SHA-256 hashing
- Hash-chain construction
- Merkle root construction
- Simplified RSA accumulator
- Simplified RSA accumulator membership verification
- Cryptographic-randomness demonstration

## Overall learning outcome

After completing this topic, the relationship between number theory and cryptography can be understood as:

Prime numbers

→ factors

→ prime factorization

→ modular arithmetic

→ GCD and modular inverse

→ Euler's Totient Function

→ RSA

→ public-key cryptography

→ factorization as a security assumption

The connection with decentralized technologies can then be understood as:

Cryptography

→ hashing

→ digital signatures

→ Merkle trees

→ elliptic curves

→ RSA accumulators

→ zero-knowledge proofs

→ blockchain and decentralized systems

The central lesson is that prime factorization is an important part of the history and mathematics of cryptography, especially RSA and certain number-theoretic constructions, but it is not the universal security foundation of blockchain or decentralized technologies.

Different cryptographic systems depend on different mathematical assumptions, and understanding those assumptions is essential for understanding modern cybersecurity, cryptography, blockchain and decentralized technology.
