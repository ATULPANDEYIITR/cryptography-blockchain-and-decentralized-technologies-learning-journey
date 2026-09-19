"""
Introduction to Cryptography
============================

A self-contained study program covering cryptography from absolute beginner
concepts through practical and advanced foundations.

The examples are educational. Cryptographic systems used in production should
use well-reviewed, maintained libraries and carefully designed protocols rather
than custom cryptographic primitives.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets
import string
from collections import Counter
from dataclasses import dataclass
from typing import Iterable


# ---------------------------------------------------------------------------
# 1. FOUNDATIONS: WHAT CRYPTOGRAPHY PROVIDES
# ---------------------------------------------------------------------------

def print_section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def demonstrate_security_goals() -> None:
    print_section("1. Cryptography and its security goals")

    goals = {
        "Confidentiality": "Only authorized parties can read protected data.",
        "Integrity": "Unauthorized modification can be detected.",
        "Authentication": "A system can establish who or what it is communicating with.",
        "Non-repudiation": "Digital signatures can provide evidence of authorship under "
                           "appropriate legal and technical assumptions.",
    }

    for name, description in goals.items():
        print(f"{name}: {description}")

    print("\nImportant distinction:")
    print("Encryption mainly addresses confidentiality.")
    print("Hashes address integrity-related and fingerprinting use cases.")
    print("MACs provide integrity and authentication with a shared secret.")
    print("Digital signatures provide integrity and origin authentication using asymmetric keys.")


# ---------------------------------------------------------------------------
# 2. CLASSICAL CRYPTOGRAPHY
# ---------------------------------------------------------------------------

def caesar_encrypt(text: str, shift: int) -> str:
    """
    Caesar cipher: every alphabetic character is shifted by the same amount.

    This is historically useful but cryptographically insecure because its
    key space is tiny and its structure is easy to analyze.
    """
    result = []

    for character in text:
        if "A" <= character <= "Z":
            result.append(chr((ord(character) - ord("A") + shift) % 26 + ord("A")))
        elif "a" <= character <= "z":
            result.append(chr((ord(character) - ord("a") + shift) % 26 + ord("a")))
        else:
            result.append(character)

    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    return caesar_encrypt(ciphertext, -shift)


def demonstrate_caesar_cipher() -> None:
    print_section("2. Classical cryptography: Caesar cipher")

    plaintext = "Attack at dawn"
    ciphertext = caesar_encrypt(plaintext, 3)
    recovered = caesar_decrypt(ciphertext, 3)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)

    print("\nWhy it is insecure:")
    print("- Only 26 possible shifts exist for English letters.")
    print("- Letter frequencies remain recognizable.")
    print("- An attacker can simply try every key.")


# ---------------------------------------------------------------------------
# 3. SUBSTITUTION AND FREQUENCY ANALYSIS
# ---------------------------------------------------------------------------

def letter_frequency(text: str) -> Counter:
    return Counter(
        character.lower()
        for character in text
        if character.isalpha()
    )


def demonstrate_frequency_analysis() -> None:
    print_section("3. Frequency analysis")

    sample = (
        "Cryptography protects information, but weak substitution ciphers "
        "often preserve statistical properties of the original language."
    )

    frequencies = letter_frequency(sample)

    print("Letter frequencies:")
    for character, count in frequencies.most_common():
        print(f"{character}: {count}")

    print("\nFrequency analysis illustrates why simple substitution systems")
    print("are generally unsuitable for modern security.")


# ---------------------------------------------------------------------------
# 4. ONE-TIME PAD
# ---------------------------------------------------------------------------

def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("XOR operands must have equal length.")
    return bytes(a ^ b for a, b in zip(left, right))


def one_time_pad_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Educational one-time-pad implementation.

    Perfect secrecy requires:
    1. A truly random key.
    2. Key length equal to plaintext length.
    3. Key secrecy.
    4. The key must never be reused.
    """
    if len(plaintext) != len(key):
        raise ValueError("One-time-pad key must equal plaintext length.")
    return xor_bytes(plaintext, key)


def demonstrate_one_time_pad() -> None:
    print_section("4. One-time pad")

    plaintext = b"HELLO CRYPTO"
    key = secrets.token_bytes(len(plaintext))
    ciphertext = one_time_pad_encrypt(plaintext, key)
    recovered = one_time_pad_encrypt(ciphertext, key)

    print("Plaintext :", plaintext)
    print("Random key:", key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered)

    print("\nCritical rule: never reuse a one-time-pad key.")


# ---------------------------------------------------------------------------
# 5. RANDOMNESS
# ---------------------------------------------------------------------------

def demonstrate_randomness() -> None:
    print_section("5. Cryptographically secure randomness")

    insecure_example = __import__("random").randint(0, 999999)
    secure_example = secrets.randbelow(1_000_000)

    print("Non-cryptographic random value:", insecure_example)
    print("Cryptographically secure value :", secure_example)

    print("\nUse secrets for security-sensitive random values in Python.")
    print("The ordinary random module is designed for simulation and general-purpose randomness.")


# ---------------------------------------------------------------------------
# 6. ENCODING IS NOT ENCRYPTION
# ---------------------------------------------------------------------------

def demonstrate_encoding() -> None:
    print_section("6. Encoding is not encryption")

    message = b"Confidential message"
    encoded = base64.b64encode(message)
    decoded = base64.b64decode(encoded)

    print("Original :", message)
    print("Base64   :", encoded)
    print("Decoded  :", decoded)

    print("\nBase64 changes representation but provides no secrecy.")
    print("Anyone can decode Base64 without a key.")


# ---------------------------------------------------------------------------
# 7. HASH FUNCTIONS
# ---------------------------------------------------------------------------

def demonstrate_hash_functions() -> None:
    print_section("7. Cryptographic hash functions")

    message = b"Cryptographic hashing"

    algorithms = {
        "SHA-256": hashlib.sha256,
        "SHA-512": hashlib.sha512,
        "SHA3-256": hashlib.sha3_256,
    }

    for name, algorithm in algorithms.items():
        digest = algorithm(message).hexdigest()
        print(f"{name:10}: {digest}")

    print("\nA cryptographic hash maps arbitrary-length input to a fixed-size digest.")
    print("Important properties include preimage resistance, second-preimage resistance,")
    print("and collision resistance.")


def demonstrate_avalanche_effect() -> None:
    print_section("8. Avalanche effect")

    first = hashlib.sha256(b"Hello").hexdigest()
    second = hashlib.sha256(b"hello").hexdigest()

    print("SHA-256('Hello'):", first)
    print("SHA-256('hello'):", second)
    print("A tiny input change produces a substantially different digest.")


# ---------------------------------------------------------------------------
# 8. PASSWORD HASHING AND SALTING
# ---------------------------------------------------------------------------

def password_digest(password: str, salt: bytes) -> str:
    """
    PBKDF2 is included in Python's standard library.

    Password hashing intentionally performs many computational operations,
    making large-scale password guessing more expensive.
    """
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000,
        dklen=32,
    )
    return derived_key.hex()


def verify_password(password: str, salt: bytes, expected_digest: str) -> bool:
    actual_digest = password_digest(password, salt)
    return hmac.compare_digest(actual_digest, expected_digest)


def demonstrate_password_hashing() -> None:
    print_section("9. Password hashing and salts")

    password = "correct horse battery staple"
    salt = secrets.token_bytes(16)

    stored_digest = password_digest(password, salt)

    print("Salt  :", salt.hex())
    print("Digest:", stored_digest)
    print("Correct password:", verify_password(password, salt, stored_digest))
    print("Wrong password  :", verify_password("wrong password", salt, stored_digest))

    print("\nPasswords should not be stored as plaintext.")
    print("A unique salt prevents identical passwords from having identical stored hashes.")
    print("Production password storage should normally use a password-specific KDF such as")
    print("Argon2id, scrypt, or bcrypt, selected according to the deployment environment.")


# ---------------------------------------------------------------------------
# 10. MESSAGE AUTHENTICATION CODES
# ---------------------------------------------------------------------------

def create_hmac(secret_key: bytes, message: bytes) -> bytes:
    return hmac.new(secret_key, message, hashlib.sha256).digest()


def verify_hmac(secret_key: bytes, message: bytes, tag: bytes) -> bool:
    expected = create_hmac(secret_key, message)
    return hmac.compare_digest(expected, tag)


def demonstrate_hmac() -> None:
    print_section("10. HMAC")

    key = secrets.token_bytes(32)
    message = b"Transfer amount=500"

    tag = create_hmac(key, message)

    print("Message:", message)
    print("HMAC   :", tag.hex())
    print("Valid  :", verify_hmac(key, message, tag))
    print("Tampered:", verify_hmac(key, b"Transfer amount=900", tag))

    print("\nHMAC combines a secret key with a cryptographic hash.")
    print("Unlike a plain hash, an attacker without the key cannot normally create a valid tag.")


# ---------------------------------------------------------------------------
# 11. SYMMETRIC ENCRYPTION
# ---------------------------------------------------------------------------

def xor_stream_demo(message: bytes, key_stream: bytes) -> bytes:
    """
    This is an educational XOR demonstration, not a secure encryption algorithm.

    Real applications should use authenticated encryption such as AES-GCM or
    ChaCha20-Poly1305 through a trusted cryptographic library.
    """
    return xor_bytes(message, key_stream)


def demonstrate_symmetric_concept() -> None:
    print_section("11. Symmetric encryption concept")

    plaintext = b"Symmetric encryption"
    keystream = secrets.token_bytes(len(plaintext))

    ciphertext = xor_stream_demo(plaintext, keystream)
    recovered = xor_stream_demo(ciphertext, keystream)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered)

    print("\nSymmetric systems use shared secret material for encryption and decryption.")
    print("The practical challenge is secure key establishment and key management.")


# ---------------------------------------------------------------------------
# 12. AUTHENTICATED ENCRYPTION MODEL
# ---------------------------------------------------------------------------

@dataclass
class AuthenticatedMessage:
    ciphertext: bytes
    authentication_tag: bytes


def educational_authenticated_encryption(
    plaintext: bytes,
    encryption_key: bytes,
    authentication_key: bytes,
) -> AuthenticatedMessage:
    """
    Educational composition showing encryption + authentication.

    This intentionally does NOT claim to be a production AEAD construction.
    The XOR stream is only a teaching mechanism.
    """
    keystream = hashlib.sha256(encryption_key).digest()

    if len(plaintext) > len(keystream):
        # Extend the teaching keystream deterministically for demonstration.
        stream = bytearray()
        counter = 0
        while len(stream) < len(plaintext):
            stream.extend(
                hashlib.sha256(
                    encryption_key + counter.to_bytes(8, "big")
                ).digest()
            )
            counter += 1
        keystream = bytes(stream[:len(plaintext)])

    ciphertext = xor_bytes(plaintext, keystream[:len(plaintext)])
    tag = create_hmac(authentication_key, ciphertext)

    return AuthenticatedMessage(ciphertext, tag)


def demonstrate_authenticated_encryption_model() -> None:
    print_section("12. Encryption plus authentication")

    plaintext = b"Authenticated encryption protects secrecy and integrity."
    encryption_key = secrets.token_bytes(32)
    authentication_key = secrets.token_bytes(32)

    protected = educational_authenticated_encryption(
        plaintext,
        encryption_key,
        authentication_key,
    )

    print("Ciphertext:", protected.ciphertext.hex())
    print("Tag       :", protected.authentication_tag.hex())
    print(
        "Valid tag :",
        verify_hmac(
            authentication_key,
            protected.ciphertext,
            protected.authentication_tag,
        ),
    )

    print("\nModern applications normally use standardized AEAD constructions")
    print("rather than assembling encryption and authentication manually.")


# ---------------------------------------------------------------------------
# 13. MODULAR ARITHMETIC
# ---------------------------------------------------------------------------

def demonstrate_modular_arithmetic() -> None:
    print_section("13. Modular arithmetic")

    values = [
        ("17 mod 5", 17 % 5),
        ("-3 mod 5", -3 % 5),
        ("7^4 mod 13", pow(7, 4, 13)),
    ]

    for expression, result in values:
        print(f"{expression} = {result}")

    print("\nModular arithmetic is fundamental to many public-key algorithms.")


# ---------------------------------------------------------------------------
# 14. GREATEST COMMON DIVISOR AND MODULAR INVERSE
# ---------------------------------------------------------------------------

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Returns (g, x, y) satisfying:
        a*x + b*y = g
    where g = gcd(a, b).
    """
    if b == 0:
        return abs(a), 1 if a >= 0 else -1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1

    return gcd_value, x, y


def modular_inverse(value: int, modulus: int) -> int:
    gcd_value, x, _ = extended_gcd(value, modulus)

    if gcd_value != 1:
        raise ValueError("A modular inverse exists only when gcd(value, modulus) = 1.")

    return x % modulus


def demonstrate_modular_inverse() -> None:
    print_section("14. Modular inverses")

    value = 7
    modulus = 26
    inverse = modular_inverse(value, modulus)

    print(f"Inverse of {value} modulo {modulus}: {inverse}")
    print(f"({value} * {inverse}) mod {modulus} =", (value * inverse) % modulus)


# ---------------------------------------------------------------------------
# 15. PRIME TESTING
# ---------------------------------------------------------------------------

def is_probable_prime(number: int, rounds: int = 16) -> bool:
    """
    Miller-Rabin probable-prime test.

    This is useful educational code. Cryptographic key generation should use
    carefully reviewed implementations and appropriate parameter choices.
    """
    if number < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    if number in small_primes:
        return True

    for prime in small_primes:
        if number % prime == 0:
            return False

    d = number - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        base = secrets.randbelow(number - 3) + 2
        x = pow(base, d, number)

        if x in (1, number - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, number)
            if x == number - 1:
                break
        else:
            return False

    return True


def demonstrate_prime_testing() -> None:
    print_section("15. Prime numbers and probabilistic testing")

    for candidate in [2, 17, 97, 221, 1_000_000_007]:
        print(f"{candidate}: {'probably prime' if is_probable_prime(candidate) else 'composite'}")


# ---------------------------------------------------------------------------
# 16. DIFFIE-HELLMAN CONCEPT
# ---------------------------------------------------------------------------

def demonstrate_diffie_hellman() -> None:
    print_section("16. Diffie-Hellman key agreement")

    # Small public parameters are intentionally used so the mathematics is easy
    # to inspect. Real systems use standardized, much larger parameters.
    prime = 23
    generator = 5

    alice_private = 6
    bob_private = 15

    alice_public = pow(generator, alice_private, prime)
    bob_public = pow(generator, bob_private, prime)

    alice_shared = pow(bob_public, alice_private, prime)
    bob_shared = pow(alice_public, bob_private, prime)

    print("Public prime:", prime)
    print("Generator   :", generator)
    print("Alice public:", alice_public)
    print("Bob public  :", bob_public)
    print("Alice shared:", alice_shared)
    print("Bob shared  :", bob_shared)

    assert alice_shared == bob_shared

    print("\nThe protocol establishes shared key material without sending")
    print("the private values across the network.")
    print("Unauthenticated Diffie-Hellman is vulnerable to man-in-the-middle attacks.")


# ---------------------------------------------------------------------------
# 17. RSA CONCEPT
# ---------------------------------------------------------------------------

@dataclass
class RSAKeyPair:
    public_key: tuple[int, int]
    private_key: tuple[int, int]


def generate_toy_rsa(p: int, q: int, e: int = 65537) -> RSAKeyPair:
    """
    Tiny RSA implementation for mathematical education only.

    It is not secure because the example uses small primes and textbook RSA.
    """
    if not is_probable_prime(p) or not is_probable_prime(q):
        raise ValueError("p and q must be prime.")
    if p == q:
        raise ValueError("p and q should be distinct.")

    modulus = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        raise ValueError("Public exponent must be coprime to phi(n).")

    private_exponent = modular_inverse(e, phi)

    return RSAKeyPair(
        public_key=(e, modulus),
        private_key=(private_exponent, modulus),
    )


def rsa_encrypt_integer(message: int, public_key: tuple[int, int]) -> int:
    exponent, modulus = public_key

    if not 0 <= message < modulus:
        raise ValueError("Message must be in the range [0, n).")

    return pow(message, exponent, modulus)


def rsa_decrypt_integer(ciphertext: int, private_key: tuple[int, int]) -> int:
    exponent, modulus = private_key
    return pow(ciphertext, exponent, modulus)


def demonstrate_rsa() -> None:
    print_section("17. RSA fundamentals")

    keys = generate_toy_rsa(61, 53)

    message = 65
    ciphertext = rsa_encrypt_integer(message, keys.public_key)
    recovered = rsa_decrypt_integer(ciphertext, keys.private_key)

    print("Public key :", keys.public_key)
    print("Private key:", keys.private_key)
    print("Message    :", message)
    print("Ciphertext :", ciphertext)
    print("Recovered  :", recovered)

    print("\nProduction RSA requires secure key sizes, randomized padding")
    print("such as OAEP for encryption, and careful implementation.")


# ---------------------------------------------------------------------------
# 18. DIGITAL SIGNATURE CONCEPT
# ---------------------------------------------------------------------------

def toy_rsa_signature(message: int, private_key: tuple[int, int]) -> int:
    return rsa_decrypt_integer(message, private_key)


def verify_toy_rsa_signature(
    message: int,
    signature: int,
    public_key: tuple[int, int],
) -> bool:
    return rsa_encrypt_integer(signature, public_key) == message


def demonstrate_digital_signature() -> None:
    print_section("18. Digital signatures")

    keys = generate_toy_rsa(61, 53)
    message = 42

    signature = toy_rsa_signature(message, keys.private_key)
    valid = verify_toy_rsa_signature(message, signature, keys.public_key)
    tampered = verify_toy_rsa_signature(43, signature, keys.public_key)

    print("Message signature:", signature)
    print("Valid signature   :", valid)
    print("After modification:", tampered)

    print("\nA real signature scheme signs a structured digest using a standardized")
    print("signature algorithm and secure padding or encoding.")


# ---------------------------------------------------------------------------
# 19. CRYPTOGRAPHIC PROTOCOL THINKING
# ---------------------------------------------------------------------------

@dataclass
class MessageEnvelope:
    sender: str
    receiver: str
    sequence_number: int
    payload: bytes


def demonstrate_replay_protection_model() -> None:
    print_section("19. Replay protection")

    key = secrets.token_bytes(32)

    envelope = MessageEnvelope(
        sender="Alice",
        receiver="Bob",
        sequence_number=10,
        payload=b"PAY 100",
    )

    authenticated_data = (
        envelope.sender.encode()
        + b"|"
        + envelope.receiver.encode()
        + b"|"
        + envelope.sequence_number.to_bytes(8, "big")
        + b"|"
        + envelope.payload
    )

    tag = create_hmac(key, authenticated_data)

    received_sequence = 10
    received_data = authenticated_data

    accepted = (
        received_sequence >= 11
        and verify_hmac(key, received_data, tag)
    )

    print("Message sequence:", envelope.sequence_number)
    print("MAC valid:", verify_hmac(key, received_data, tag))
    print("Accepted without prior sequence state:", accepted)

    print("\nCryptographic authentication alone does not automatically prevent replay.")
    print("Protocols often combine authentication with nonces, sequence numbers,")
    print("timestamps, counters, or state tracking.")


# ---------------------------------------------------------------------------
# 20. DOMAIN SEPARATION
# ---------------------------------------------------------------------------

def derive_domain_hash(domain: str, message: bytes) -> bytes:
    """
    Domain separation prevents the same raw input from unintentionally sharing
    identical cryptographic meanings across different protocol contexts.
    """
    prefix = domain.encode("utf-8") + b"\x00"
    return hashlib.sha256(prefix + message).digest()


def demonstrate_domain_separation() -> None:
    print_section("20. Domain separation")

    message = b"transaction"

    payment_digest = derive_domain_hash("PAYMENT", message)
    login_digest = derive_domain_hash("LOGIN", message)

    print("Payment context:", payment_digest.hex())
    print("Login context  :", login_digest.hex())
    print("Equal:", payment_digest == login_digest)


# ---------------------------------------------------------------------------
# 21. CONSTANT-TIME COMPARISON
# ---------------------------------------------------------------------------

def demonstrate_constant_time_comparison() -> None:
    print_section("21. Timing-sensitive comparisons")

    expected = create_hmac(b"secret", b"message")
    actual = create_hmac(b"secret", b"message")

    print("compare_digest:", hmac.compare_digest(expected, actual))
    print(
        "\nFor authentication tags, use constant-time comparison functions "
        "such as hmac.compare_digest rather than ordinary string comparison."
    )


# ---------------------------------------------------------------------------
# 22. HASH CHAINS
# ---------------------------------------------------------------------------

def demonstrate_hash_chain() -> None:
    print_section("22. Hash chains")

    previous = b"GENESIS"

    for index in range(1, 6):
        current = hashlib.sha256(previous).digest()
        print(f"Block {index}: {current.hex()}")
        previous = current

    print("\nChanging an earlier value changes every subsequent hash.")


# ---------------------------------------------------------------------------
# 23. MERKLE TREE
# ---------------------------------------------------------------------------

def merkle_parent(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def merkle_root(data_items: Iterable[bytes]) -> bytes:
    nodes = [hashlib.sha256(item).digest() for item in data_items]

    if not nodes:
        raise ValueError("A Merkle tree needs at least one item.")

    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        nodes = [
            merkle_parent(nodes[index], nodes[index + 1])
            for index in range(0, len(nodes), 2)
        ]

    return nodes[0]


def demonstrate_merkle_tree() -> None:
    print_section("23. Merkle trees")

    transactions = [
        b"Alice pays Bob 10",
        b"Bob pays Carol 5",
        b"Carol pays Dave 2",
        b"Dave pays Erin 1",
        b"Erin pays Frank 3",
    ]

    root = merkle_root(transactions)

    print("Merkle root:", root.hex())
    print("The root commits to all transactions beneath it.")


# ---------------------------------------------------------------------------
# 24. KEY DERIVATION
# ---------------------------------------------------------------------------

def demonstrate_key_derivation() -> None:
    print_section("24. Key derivation")

    master_secret = secrets.token_bytes(32)

    encryption_key = hmac.new(
        master_secret,
        b"encryption-key",
        hashlib.sha256,
    ).digest()

    authentication_key = hmac.new(
        master_secret,
        b"authentication-key",
        hashlib.sha256,
    ).digest()

    print("Encryption key     :", encryption_key.hex())
    print("Authentication key :", authentication_key.hex())
    print("Keys equal:", encryption_key == authentication_key)

    print("\nDomain-separated derivation allows independent keys to be derived")
    print("from a master secret.")


# ---------------------------------------------------------------------------
# 25. KEY ROTATION
# ---------------------------------------------------------------------------

@dataclass
class VersionedKey:
    version: int
    key: bytes


class KeyRing:
    def __init__(self) -> None:
        self._keys: dict[int, VersionedKey] = {}

    def add_key(self, version: int, key: bytes) -> None:
        if version <= 0:
            raise ValueError("Key version must be positive.")
        self._keys[version] = VersionedKey(version, key)

    def get_key(self, version: int) -> bytes:
        try:
            return self._keys[version].key
        except KeyError as exc:
            raise KeyError(f"Unknown key version: {version}") from exc

    def latest_version(self) -> int:
        if not self._keys:
            raise ValueError("No keys available.")
        return max(self._keys)


def demonstrate_key_rotation() -> None:
    print_section("25. Key rotation")

    key_ring = KeyRing()
    key_ring.add_key(1, secrets.token_bytes(32))
    key_ring.add_key(2, secrets.token_bytes(32))

    print("Current key version:", key_ring.latest_version())
    print("Version 1 length:", len(key_ring.get_key(1)))
    print("Version 2 length:", len(key_ring.get_key(2)))

    print("\nKey rotation limits the lifetime of individual keys and can support")
    print("incident response and cryptographic agility.")


# ---------------------------------------------------------------------------
# 26. CERTIFICATES AND TRUST
# ---------------------------------------------------------------------------

def demonstrate_certificate_model() -> None:
    print_section("26. Certificates and public-key trust")

    certificate_fields = {
        "subject": "server.example",
        "issuer": "Example Root CA",
        "public_key": "server public key",
        "valid_from": "2026-01-01",
        "valid_to": "2027-01-01",
        "signature": "CA signature over certificate data",
    }

    for field, value in certificate_fields.items():
        print(f"{field:12}: {value}")

    print("\nA certificate binds an identity or name to a public key through")
    print("a signature from a certificate authority within a trust model.")
    print("TLS uses certificates as part of server authentication.")


# ---------------------------------------------------------------------------
# 27. TLS CONCEPT
# ---------------------------------------------------------------------------

def demonstrate_tls_concept() -> None:
    print_section("27. TLS protocol model")

    steps = [
        "Client and server negotiate protocol parameters.",
        "The server proves possession of a private key associated with a certificate.",
        "Ephemeral key agreement establishes shared session secrets.",
        "Traffic keys provide authenticated encryption.",
        "Sequence/state mechanisms help detect tampering and replay.",
    ]

    for number, step in enumerate(steps, start=1):
        print(f"{number}. {step}")

    print("\nTLS is a protocol rather than a single encryption algorithm.")


# ---------------------------------------------------------------------------
# 28. CRYPTOGRAPHIC FAILURE MODES
# ---------------------------------------------------------------------------

def demonstrate_common_failures() -> None:
    print_section("28. Common cryptographic failures")

    failures = [
        ("Hard-coded secrets", "Secrets can leak through source code or repositories."),
        ("Weak randomness", "Predictable keys or tokens may become guessable."),
        ("Nonce reuse", "Some AEAD and stream constructions can catastrophically fail."),
        ("Plaintext passwords", "A database compromise immediately exposes credentials."),
        ("Unsalted password hashes", "Identical passwords become trivially linkable."),
        ("Textbook RSA", "Deterministic encryption can leak message relationships."),
        ("Custom cryptography", "Design and implementation errors are difficult to detect."),
        ("Bad certificate validation", "Attackers may impersonate servers."),
        ("Improper error handling", "Different errors can reveal sensitive information."),
        ("Key leakage", "Strong algorithms cannot compensate for compromised keys."),
    ]

    for failure, consequence in failures:
        print(f"{failure}: {consequence}")


# ---------------------------------------------------------------------------
# 29. EDGE CASES AND VALIDATION
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    print_section("29. Edge cases")

    test_cases = [
        b"",
        b"a",
        b"\x00\xff\x00",
        "Unicode π密码".encode("utf-8"),
    ]

    for data in test_cases:
        digest = hashlib.sha256(data).hexdigest()
        print(f"Input {data!r} -> {digest}")

    print("\nCryptographic APIs must define behavior for empty input, binary data,")
    print("Unicode encoding, malformed input, incorrect key lengths, and invalid parameters.")


# ---------------------------------------------------------------------------
# 30. SECURITY DESIGN CHECKLIST
# ---------------------------------------------------------------------------

def security_checklist() -> None:
    print_section("30. Practical cryptographic design checklist")

    checklist = [
        "Define the security property before choosing an algorithm.",
        "Use standardized algorithms and protocol constructions.",
        "Use cryptographically secure randomness.",
        "Use authenticated encryption for protected application data.",
        "Use dedicated password-hashing algorithms for passwords.",
        "Never reuse nonces where an algorithm forbids reuse.",
        "Protect private keys and secret keys with appropriate access controls.",
        "Validate certificates and identities correctly.",
        "Use constant-time comparison for authentication values.",
        "Plan key rotation and revocation.",
        "Separate keys by purpose.",
        "Log security events without logging secrets.",
        "Test malformed, adversarial, and boundary inputs.",
        "Prefer established libraries over custom cryptographic implementations.",
        "Document algorithm, parameter, key version, and protocol assumptions.",
    ]

    for item in checklist:
        print(f"- {item}")


# ---------------------------------------------------------------------------
# 31. PERFORMANCE CONSIDERATIONS
# ---------------------------------------------------------------------------

def benchmark_hashing() -> None:
    print_section("31. Performance considerations")

    data = b"A" * (1024 * 1024)

    digest = hashlib.sha256(data).hexdigest()

    print("Processed bytes:", len(data))
    print("SHA-256 digest :", digest)

    print("\nHashing is generally fast for large data streams.")
    print("Password hashing intentionally uses much more computation than ordinary hashing.")
    print("Asymmetric cryptography is generally more expensive than symmetric cryptography.")
    print("Modern systems therefore commonly use public-key mechanisms for key establishment")
    print("and symmetric authenticated encryption for bulk data.")


# ---------------------------------------------------------------------------
# 32. CRYPTOGRAPHIC AGILITY
# ---------------------------------------------------------------------------

def demonstrate_algorithm_agility() -> None:
    print_section("32. Cryptographic agility")

    algorithms = {
        "integrity_v1": hashlib.sha256,
        "integrity_v2": hashlib.sha3_256,
    }

    message = b"versioned cryptographic design"

    for name, algorithm in algorithms.items():
        print(name, algorithm(message).hexdigest())

    print("\nSystems should avoid embedding assumptions about one algorithm so deeply")
    print("that migration becomes impossible when standards or threat models change.")


# ---------------------------------------------------------------------------
# 33. POST-QUANTUM CONTEXT
# ---------------------------------------------------------------------------

def demonstrate_post_quantum_context() -> None:
    print_section("33. Post-quantum cryptography context")

    vulnerable_families = {
        "RSA": "Large-scale quantum algorithms threaten the underlying integer-factorization problem.",
        "Finite-field Diffie-Hellman": "Large-scale quantum algorithms threaten the discrete-logarithm problem.",
        "Elliptic-curve cryptography": "Large-scale quantum algorithms threaten elliptic-curve discrete logarithms.",
    }

    for family, reason in vulnerable_families.items():
        print(f"{family}: {reason}")

    print("\nPost-quantum cryptography studies algorithms designed to resist known")
    print("large-scale quantum attacks while remaining practical on classical computers.")


# ---------------------------------------------------------------------------
# 34. TESTING
# ---------------------------------------------------------------------------

def run_assertion_tests() -> None:
    print_section("34. Built-in correctness tests")

    assert caesar_decrypt(caesar_encrypt("Hello World", 13), 13) == "Hello World"

    sample = b"test message"
    key = secrets.token_bytes(len(sample))
    assert one_time_pad_encrypt(one_time_pad_encrypt(sample, key), key) == sample

    secret = b"key"
    message = b"message"
    tag = create_hmac(secret, message)

    assert verify_hmac(secret, message, tag)
    assert not verify_hmac(secret, b"modified", tag)

    assert modular_inverse(7, 26) == 15
    assert (7 * modular_inverse(7, 26)) % 26 == 1

    rsa_keys = generate_toy_rsa(61, 53)
    number = 42
    encrypted = rsa_encrypt_integer(number, rsa_keys.public_key)
    assert rsa_decrypt_integer(encrypted, rsa_keys.private_key) == number

    assert merkle_root([b"a", b"b"]) != merkle_root([b"a", b"c"])

    print("All educational tests passed.")


# ---------------------------------------------------------------------------
# 35. MINI CASE STUDY
# ---------------------------------------------------------------------------

class SecureTokenService:
    """
    A small demonstration of authenticated tokens.

    The token format is:
        version.payload.signature

    This is an educational protocol. It is not a replacement for established
    token standards or mature authentication libraries.
    """

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("Use at least 32 bytes for this demonstration.")
        self.signing_key = signing_key

    def issue(self, user_id: str, expiration: int) -> str:
        if not user_id:
            raise ValueError("user_id cannot be empty.")

        payload = f"{user_id}|{expiration}".encode("utf-8")
        encoded_payload = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

        signing_input = f"v1.{encoded_payload}".encode("ascii")
        signature = create_hmac(self.signing_key, signing_input)

        encoded_signature = (
            base64.urlsafe_b64encode(signature)
            .decode("ascii")
            .rstrip("=")
        )

        return f"v1.{encoded_payload}.{encoded_signature}"

    def verify(self, token: str, current_time: int) -> str:
        parts = token.split(".")

        if len(parts) != 3 or parts[0] != "v1":
            raise ValueError("Malformed token.")

        _, encoded_payload, encoded_signature = parts

        signing_input = f"v1.{encoded_payload}".encode("ascii")

        try:
            supplied_signature = base64.urlsafe_b64decode(
                encoded_signature + "=" * (-len(encoded_signature) % 4)
            )
            payload = base64.urlsafe_b64decode(
                encoded_payload + "=" * (-len(encoded_payload) % 4)
            )
        except Exception as exc:
            raise ValueError("Malformed Base64 data.") from exc

        if not hmac.compare_digest(
            create_hmac(self.signing_key, signing_input),
            supplied_signature,
        ):
            raise ValueError("Invalid signature.")

        try:
            user_id, expiration_text = payload.decode("utf-8").split("|", 1)
            expiration = int(expiration_text)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("Malformed token payload.") from exc

        if expiration < current_time:
            raise ValueError("Token has expired.")

        return user_id


def demonstrate_token_case_study() -> None:
    print_section("35. Mini case study: authenticated token")

    service = SecureTokenService(secrets.token_bytes(32))

    token = service.issue("alice", expiration=2_000_000_000)

    print("Token:", token)
    print("Verified user:", service.verify(token, current_time=1_900_000_000))

    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")

    try:
        service.verify(tampered, current_time=1_900_000_000)
    except ValueError as error:
        print("Tampering rejected:", error)

    try:
        service.verify(token, current_time=2_100_000_000)
    except ValueError as error:
        print("Expired token rejected:", error)


# ---------------------------------------------------------------------------
# 36. MAIN PROGRAM
# ---------------------------------------------------------------------------

def main() -> None:
    demonstrate_security_goals()
    demonstrate_caesar_cipher()
    demonstrate_frequency_analysis()
    demonstrate_one_time_pad()
    demonstrate_randomness()
    demonstrate_encoding()
    demonstrate_hash_functions()
    demonstrate_avalanche_effect()
    demonstrate_password_hashing()
    demonstrate_hmac()
    demonstrate_symmetric_concept()
    demonstrate_authenticated_encryption_model()
    demonstrate_modular_arithmetic()
    demonstrate_modular_inverse()
    demonstrate_prime_testing()
    demonstrate_diffie_hellman()
    demonstrate_rsa()
    demonstrate_digital_signature()
    demonstrate_replay_protection_model()
    demonstrate_domain_separation()
    demonstrate_constant_time_comparison()
    demonstrate_hash_chain()
    demonstrate_merkle_tree()
    demonstrate_key_derivation()
    demonstrate_key_rotation()
    demonstrate_certificate_model()
    demonstrate_tls_concept()
    demonstrate_common_failures()
    demonstrate_edge_cases()
    security_checklist()
    benchmark_hashing()
    demonstrate_algorithm_agility()
    demonstrate_post_quantum_context()
    run_assertion_tests()
    demonstrate_token_case_study()

    print_section("Cryptography study program complete")
    print("The examples covered classical cryptography, hashing, authentication,")
    print("symmetric and asymmetric cryptography, key agreement, signatures,")
    print("protocol design, key management, trust, testing, and modern security context.")


if __name__ == "__main__":
    main()
