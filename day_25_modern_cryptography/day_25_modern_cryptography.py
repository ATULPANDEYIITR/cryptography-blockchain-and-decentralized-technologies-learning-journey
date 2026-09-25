"""
Modern Cryptography: A Comprehensive Study and Demonstration
==============================================================

This standalone script teaches modern cryptography from fundamentals through
advanced practical concepts.

The demonstrations intentionally use the Python standard library wherever
possible. For real cryptographic primitives such as AES, ChaCha20-Poly1305,
Ed25519, X25519, and RSA, the script implements educational constructions or
uses standard-library-adjacent building blocks rather than presenting
hand-written cryptography as production-ready cryptography.

IMPORTANT:
    Cryptographic primitives are difficult to implement securely. Educational
    implementations are useful for understanding algorithms, but production
    systems should use mature, audited cryptographic libraries.

Topics demonstrated:
    1. Security goals and threat models
    2. Encoding versus encryption
    3. Cryptographic hashes
    4. Password hashing and key derivation
    5. HMAC
    6. Secure random numbers and nonces
    7. XOR and one-time-pad concepts
    8. Symmetric encryption concepts
    9. AES-style block-cipher concepts
    10. Authenticated encryption and AEAD concepts
    11. Public-key cryptography
    12. RSA mathematics and signatures
    13. Diffie-Hellman key exchange
    14. Elliptic-curve concepts
    15. Digital signatures
    16. Certificates and PKI concepts
    17. Hybrid encryption
    18. Key management
    19. Replay protection
    20. Secure protocol design
    21. Cryptographic failures and common mistakes
    22. Performance and production considerations
    23. Post-quantum cryptography concepts
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Iterable


# ============================================================================
# 1. FOUNDATIONS
# ============================================================================

def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_encoding_vs_encryption() -> None:
    """
    Encoding changes representation.

    Encryption changes information so that a party without the required key
    should not be able to recover the plaintext.

    Base64 is NOT encryption.
    """
    section("1. Encoding versus encryption")

    plaintext = b"Confidential message"

    encoded = base64.b64encode(plaintext)
    decoded = base64.b64decode(encoded)

    print("Plaintext:", plaintext)
    print("Base64:", encoded)
    print("Decoded:", decoded)

    assert decoded == plaintext


# ============================================================================
# 2. CRYPTOGRAPHIC HASHING
# ============================================================================

def demonstrate_hashes() -> None:
    """
    A cryptographic hash maps arbitrary-length input to a fixed-size digest.

    Important properties:
        - deterministic
        - one-way in the practical security sense
        - collision resistant
        - avalanche effect
        - fixed-length output

    SHA-256 is used here because hashlib provides a standard implementation.
    """
    section("2. Cryptographic hashing")

    message_a = b"modern cryptography"
    message_b = b"modern cryptographY"

    digest_a = hashlib.sha256(message_a).hexdigest()
    digest_b = hashlib.sha256(message_b).hexdigest()

    print("SHA-256 A:", digest_a)
    print("SHA-256 B:", digest_b)
    print("Digests differ:", digest_a != digest_b)

    # SHA-512 produces a larger digest.
    print("SHA-512:", hashlib.sha512(message_a).hexdigest())

    # Hashing is deterministic.
    assert hashlib.sha256(message_a).digest() == hashlib.sha256(message_a).digest()

    # A tiny input change normally produces a substantially different digest.
    differing_positions = sum(
        a != b for a, b in zip(digest_a, digest_b)
    )
    print("Different hexadecimal positions:", differing_positions)


def hash_file_like_data(chunks: Iterable[bytes]) -> str:
    """
    Incremental hashing avoids loading an arbitrarily large object into RAM.
    """
    digest = hashlib.sha256()

    for chunk in chunks:
        digest.update(chunk)

    return digest.hexdigest()


# ============================================================================
# 3. PASSWORD HASHING AND KEY DERIVATION
# ============================================================================

def derive_password_key(
    password: str,
    salt: bytes,
    iterations: int = 200_000,
    length: int = 32,
) -> bytes:
    """
    PBKDF2 derives a cryptographic key from a password.

    Password hashing and ordinary hashing have different purposes.

    A unique random salt prevents identical passwords from having identical
    stored hashes and defeats many precomputed lookup-table attacks.

    The iteration count is intentionally configurable. Production values
    should be calibrated against current hardware and application requirements.
    """
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    if len(salt) < 16:
        raise ValueError("salt should contain at least 16 random bytes")

    if iterations <= 0:
        raise ValueError("iterations must be positive")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=length,
    )


def demonstrate_password_derivation() -> None:
    section("3. Password hashing and key derivation")

    password = "correct horse battery staple"
    salt = secrets.token_bytes(16)

    key = derive_password_key(password, salt)

    print("Random salt:", salt.hex())
    print("Derived key:", key.hex())
    print("Key length:", len(key))

    same_key = derive_password_key(password, salt)
    different_salt_key = derive_password_key(
        password,
        secrets.token_bytes(16),
    )

    assert hmac.compare_digest(key, same_key)
    assert not hmac.compare_digest(key, different_salt_key)

    print("Same password + same salt gives same derived key:", True)
    print("Same password + different salt gives different key:", True)


# ============================================================================
# 4. HMAC
# ============================================================================

def demonstrate_hmac() -> None:
    """
    HMAC provides message authentication and integrity when both parties share
    a secret key.

    HMAC does NOT provide confidentiality.
    """
    section("4. HMAC")

    secret_key = secrets.token_bytes(32)
    message = b"transfer=5000&currency=INR"

    tag = hmac.new(
        secret_key,
        message,
        hashlib.sha256,
    ).digest()

    print("Message:", message)
    print("HMAC:", tag.hex())

    valid = hmac.compare_digest(
        tag,
        hmac.new(secret_key, message, hashlib.sha256).digest(),
    )

    tampered_message = b"transfer=9000&currency=INR"

    invalid = hmac.compare_digest(
        tag,
        hmac.new(secret_key, tampered_message, hashlib.sha256).digest(),
    )

    print("Original message authentic:", valid)
    print("Tampered message authentic:", invalid)


# ============================================================================
# 5. SECURE RANDOMNESS
# ============================================================================

def demonstrate_secure_randomness() -> None:
    """
    Cryptographic randomness must come from an operating-system-backed CSPRNG.

    random.random() is designed for simulations and general programming,
    not for cryptographic secrets.
    """
    section("5. Secure randomness")

    random_key = secrets.token_bytes(32)
    random_token = secrets.token_urlsafe(32)
    random_number = secrets.randbelow(1_000_000)

    print("256-bit key:", random_key.hex())
    print("URL-safe token:", random_token)
    print("Uniform random number below one million:", random_number)


# ============================================================================
# 6. XOR AND ONE-TIME-PAD CONCEPTS
# ============================================================================

def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal length")

    return bytes(a ^ b for a, b in zip(left, right))


def demonstrate_xor_and_one_time_pad() -> None:
    section("6. XOR and one-time-pad concepts")

    plaintext = b"secret"
    one_time_key = secrets.token_bytes(len(plaintext))

    ciphertext = xor_bytes(plaintext, one_time_key)
    recovered = xor_bytes(ciphertext, one_time_key)

    print("Plaintext:", plaintext)
    print("One-time key:", one_time_key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered:", recovered)

    assert recovered == plaintext

    print(
        "A true one-time pad requires a uniformly random key at least as long "
        "as the plaintext, used exactly once."
    )


# ============================================================================
# 7. FEISTEL-STYLE EDUCATIONAL BLOCK CIPHER
# ============================================================================

def rotate_left_32(value: int, amount: int) -> int:
    value &= 0xFFFFFFFF
    amount %= 32
    return ((value << amount) | (value >> (32 - amount))) & 0xFFFFFFFF


def educational_round_function(right: int, round_key: int) -> int:
    """
    Educational round function.

    This is NOT AES and is NOT suitable for real security.
    It demonstrates how substitution/mixing can be incorporated into a
    repeated block-cipher structure.
    """
    mixed = (right + round_key) & 0xFFFFFFFF
    mixed ^= rotate_left_32(mixed, 7)
    mixed = (mixed * 0x9E3779B1) & 0xFFFFFFFF
    return mixed


def educational_feistel_encrypt(block: bytes, key: int, rounds: int = 16) -> bytes:
    if len(block) != 8:
        raise ValueError("educational block cipher requires exactly 8 bytes")

    left, right = struct.unpack(">II", block)

    for round_number in range(rounds):
        round_key = (key + round_number * 0x9E3779B9) & 0xFFFFFFFF
        left, right = right, left ^ educational_round_function(right, round_key)

    return struct.pack(">II", left, right)


def educational_feistel_decrypt(block: bytes, key: int, rounds: int = 16) -> bytes:
    if len(block) != 8:
        raise ValueError("educational block cipher requires exactly 8 bytes")

    left, right = struct.unpack(">II", block)

    for round_number in reversed(range(rounds)):
        round_key = (key + round_number * 0x9E3779B9) & 0xFFFFFFFF
        left, right = right ^ educational_round_function(left, round_key), left

    return struct.pack(">II", left, right)


def demonstrate_block_cipher_structure() -> None:
    section("7. Educational Feistel block cipher")

    plaintext = b"12345678"
    key = 0x12345678

    ciphertext = educational_feistel_encrypt(plaintext, key)
    recovered = educational_feistel_decrypt(ciphertext, key)

    print("Plaintext:", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Recovered:", recovered)

    assert recovered == plaintext


# ============================================================================
# 8. AUTHENTICATED ENCRYPTION
# ============================================================================

@dataclass
class AuthenticatedMessage:
    nonce: bytes
    ciphertext: bytes
    tag: bytes


def stream_xor(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """
    Educational stream construction based on HMAC-derived keystream blocks.

    It demonstrates the mechanics of:
        plaintext XOR keystream = ciphertext
        ciphertext XOR same keystream = plaintext

    This is NOT a replacement for ChaCha20 or AES-GCM.
    """
    output = bytearray()
    counter = 0

    while len(output) < len(data):
        block = hmac.new(
            key,
            nonce + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()

        output.extend(block)
        counter += 1

    return xor_bytes(data, bytes(output[:len(data)]))


def authenticated_encrypt(
    key: bytes,
    plaintext: bytes,
    associated_data: bytes = b"",
) -> AuthenticatedMessage:
    """
    Educational Encrypt-then-MAC construction.

    Real applications should use a standard AEAD primitive such as
    AES-GCM or ChaCha20-Poly1305 from a vetted cryptographic library.
    """
    nonce = secrets.token_bytes(16)
    ciphertext = stream_xor(key, nonce, plaintext)

    authentication_input = (
        associated_data
        + len(associated_data).to_bytes(8, "big")
        + nonce
        + ciphertext
    )

    tag = hmac.new(
        key,
        authentication_input,
        hashlib.sha256,
    ).digest()

    return AuthenticatedMessage(nonce, ciphertext, tag)


def authenticated_decrypt(
    key: bytes,
    encrypted: AuthenticatedMessage,
    associated_data: bytes = b"",
) -> bytes:
    authentication_input = (
        associated_data
        + len(associated_data).to_bytes(8, "big")
        + encrypted.nonce
        + encrypted.ciphertext
    )

    expected_tag = hmac.new(
        key,
        authentication_input,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(expected_tag, encrypted.tag):
        raise ValueError("authentication failed")

    return stream_xor(
        key,
        encrypted.nonce,
        encrypted.ciphertext,
    )


def demonstrate_authenticated_encryption() -> None:
    section("8. Authenticated encryption")

    key = secrets.token_bytes(32)
    plaintext = b"Account balance: INR 125000"
    associated_data = b"account-id=42"

    encrypted = authenticated_encrypt(
        key,
        plaintext,
        associated_data,
    )

    recovered = authenticated_decrypt(
        key,
        encrypted,
        associated_data,
    )

    print("Nonce:", encrypted.nonce.hex())
    print("Ciphertext:", encrypted.ciphertext.hex())
    print("Authentication tag:", encrypted.tag.hex())
    print("Recovered:", recovered)

    assert recovered == plaintext

    tampered = AuthenticatedMessage(
        encrypted.nonce,
        encrypted.ciphertext[:-1] + bytes([encrypted.ciphertext[-1] ^ 1]),
        encrypted.tag,
    )

    try:
        authenticated_decrypt(key, tampered, associated_data)
    except ValueError as error:
        print("Tampering detected:", error)


# ============================================================================
# 9. RSA MATHEMATICS
# ============================================================================

def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0

    gcd_value, x1, y1 = extended_gcd(b, a % b)
    return gcd_value, y1, x1 - (a // b) * y1


def modular_inverse(a: int, modulus: int) -> int:
    gcd_value, x, _ = extended_gcd(a, modulus)

    if gcd_value != 1:
        raise ValueError("modular inverse does not exist")

    return x % modulus


def demonstrate_rsa_math() -> None:
    """
    Tiny RSA example for understanding the mathematics.

    These tiny numbers are intentionally insecure and must never be used for
    real cryptographic protection.
    """
    section("9. RSA mathematics")

    p = 61
    q = 53

    n = p * q
    phi = (p - 1) * (q - 1)

    public_exponent = 17
    private_exponent = modular_inverse(public_exponent, phi)

    message = 65

    ciphertext = pow(message, public_exponent, n)
    recovered = pow(ciphertext, private_exponent, n)

    print("n:", n)
    print("Euler phi:", phi)
    print("Public exponent:", public_exponent)
    print("Private exponent:", private_exponent)
    print("Message:", message)
    print("Ciphertext:", ciphertext)
    print("Recovered:", recovered)

    assert recovered == message


# ============================================================================
# 10. DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================================

@dataclass
class DHParameters:
    prime: int
    generator: int


def demonstrate_diffie_hellman() -> None:
    """
    Classic finite-field Diffie-Hellman demonstration.

    The small parameters are educational only. Real systems use standardized,
    sufficiently large groups or elliptic-curve mechanisms such as X25519.
    """
    section("10. Diffie-Hellman key exchange")

    parameters = DHParameters(
        prime=23,
        generator=5,
    )

    alice_private = 6
    bob_private = 15

    alice_public = pow(
        parameters.generator,
        alice_private,
        parameters.prime,
    )

    bob_public = pow(
        parameters.generator,
        bob_private,
        parameters.prime,
    )

    alice_shared = pow(
        bob_public,
        alice_private,
        parameters.prime,
    )

    bob_shared = pow(
        alice_public,
        bob_private,
        parameters.prime,
    )

    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared secret:", alice_shared)
    print("Bob shared secret:", bob_shared)

    assert alice_shared == bob_shared


# ============================================================================
# 11. ELLIPTIC-CURVE CONCEPTS
# ============================================================================

@dataclass(frozen=True)
class ECPoint:
    x: int
    y: int


class ToyEllipticCurve:
    """
    Tiny elliptic-curve implementation for conceptual study.

    Curve equation:
        y^2 = x^3 + ax + b (mod p)

    This implementation is deliberately small and is NOT suitable for
    cryptographic use.
    """

    def __init__(self, a: int, b: int, prime: int):
        self.a = a
        self.b = b
        self.p = prime

    def inverse(self, value: int) -> int:
        return pow(value % self.p, -1, self.p)

    def add(
        self,
        first: ECPoint | None,
        second: ECPoint | None,
    ) -> ECPoint | None:
        if first is None:
            return second
        if second is None:
            return first

        if first.x == second.x and (first.y + second.y) % self.p == 0:
            return None

        if first != second:
            slope = (
                (second.y - first.y)
                * self.inverse(second.x - first.x)
            ) % self.p
        else:
            if first.y % self.p == 0:
                return None

            slope = (
                (3 * first.x * first.x + self.a)
                * self.inverse(2 * first.y)
            ) % self.p

        x3 = (slope * slope - first.x - second.x) % self.p
        y3 = (slope * (first.x - x3) - first.y) % self.p

        return ECPoint(x3, y3)

    def multiply(
        self,
        scalar: int,
        point: ECPoint,
    ) -> ECPoint | None:
        if scalar < 0:
            raise ValueError("scalar must be non-negative")

        result = None
        current = point

        while scalar:
            if scalar & 1:
                result = self.add(result, current)

            current = self.add(current, current)
            scalar >>= 1

        return result


def demonstrate_elliptic_curves() -> None:
    section("11. Elliptic-curve arithmetic")

    curve = ToyEllipticCurve(
        a=2,
        b=2,
        prime=17,
    )

    generator = ECPoint(5, 1)

    public_a = curve.multiply(5, generator)
    public_b = curve.multiply(7, generator)

    shared_a = curve.multiply(5, public_b)
    shared_b = curve.multiply(7, public_a)

    print("Generator:", generator)
    print("Alice public point:", public_a)
    print("Bob public point:", public_b)
    print("Alice shared point:", shared_a)
    print("Bob shared point:", shared_b)

    assert shared_a == shared_b


# ============================================================================
# 12. DIGITAL SIGNATURE CONCEPT
# ============================================================================

def demonstrate_signature_concept() -> None:
    """
    Demonstrates the conceptual distinction between encryption and signatures.

    A signature is associated with:
        - authenticity
        - integrity
        - non-repudiation claims in appropriate legal/technical contexts

    This educational example uses HMAC to represent a shared-secret
    authentication tag. A real digital signature requires asymmetric keys,
    such as Ed25519 or RSA-PSS.
    """
    section("12. Authentication versus digital signatures")

    shared_secret = secrets.token_bytes(32)
    document = b"Approved purchase order #1042"

    signature_like_tag = hmac.new(
        shared_secret,
        document,
        hashlib.sha256,
    ).hexdigest()

    print("Document:", document)
    print("Authentication tag:", signature_like_tag)
    print(
        "Important distinction: HMAC is not a public-key digital signature."
    )


# ============================================================================
# 13. HYBRID ENCRYPTION
# ============================================================================

def demonstrate_hybrid_design() -> None:
    """
    Hybrid encryption combines asymmetric and symmetric cryptography.

    Typical pattern:
        1. Generate a random symmetric session key.
        2. Encrypt application data with an AEAD cipher.
        3. Protect the session key using a public-key mechanism.
        4. Receiver recovers the session key with the private key.
        5. Receiver authenticates and decrypts the data.

    This example models the architecture without pretending to implement
    production RSA-OAEP or X25519 correctly.
    """
    section("13. Hybrid encryption architecture")

    session_key = secrets.token_bytes(32)
    data = b"Large application payload"

    encrypted_payload = authenticated_encrypt(
        session_key,
        data,
        associated_data=b"message-v1",
    )

    print("Generated session key:", session_key.hex())
    print("Encrypted payload:", encrypted_payload.ciphertext.hex())
    print(
        "In a production protocol, the session key would be wrapped using "
        "RSA-OAEP, HPKE, or another standardized public-key mechanism."
    )


# ============================================================================
# 14. REPLAY PROTECTION
# ============================================================================

@dataclass
class SecureRequest:
    request_id: str
    timestamp: int
    body: bytes
    tag: bytes


class ReplayProtection:
    """
    Simple conceptual replay detector.

    Production distributed systems need carefully designed freshness windows,
    unique request identifiers, persistent state where required, and clock
    synchronization or protocol mechanisms that do not depend blindly on time.
    """

    def __init__(self, maximum_age_seconds: int = 300):
        self.maximum_age_seconds = maximum_age_seconds
        self.seen_ids: set[str] = set()

    def accept(self, request: SecureRequest, secret: bytes) -> bool:
        now = int(time.time())

        if abs(now - request.timestamp) > self.maximum_age_seconds:
            return False

        if request.request_id in self.seen_ids:
            return False

        payload = (
            request.request_id.encode()
            + request.timestamp.to_bytes(8, "big", signed=True)
            + request.body
        )

        expected = hmac.new(
            secret,
            payload,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(expected, request.tag):
            return False

        self.seen_ids.add(request.request_id)
        return True


def demonstrate_replay_protection() -> None:
    section("14. Replay protection")

    secret = secrets.token_bytes(32)
    request_id = secrets.token_hex(16)
    timestamp = int(time.time())
    body = b"withdraw=1000"

    payload = (
        request_id.encode()
        + timestamp.to_bytes(8, "big", signed=True)
        + body
    )

    tag = hmac.new(secret, payload, hashlib.sha256).digest()

    request = SecureRequest(
        request_id=request_id,
        timestamp=timestamp,
        body=body,
        tag=tag,
    )

    protection = ReplayProtection()

    print("First request accepted:", protection.accept(request, secret))
    print("Same request replayed:", protection.accept(request, secret))


# ============================================================================
# 15. TIMING-SAFE COMPARISON
# ============================================================================

def demonstrate_safe_comparison() -> None:
    section("15. Constant-time comparison")

    expected = hmac.new(
        b"secret",
        b"message",
        hashlib.sha256,
    ).digest()

    received = expected[:]

    print(
        "Authenticated using compare_digest:",
        hmac.compare_digest(expected, received),
    )

    print(
        "For secrets and authentication tags, avoid ordinary equality checks "
        "when a timing side channel could be relevant."
    )


# ============================================================================
# 16. KEY MANAGEMENT
# ============================================================================

@dataclass
class KeyRecord:
    key_id: str
    key_material: bytes
    created_at: int
    active: bool = True


class KeyRing:
    """
    Minimal conceptual key-management structure.

    Production systems often require:
        - KMS/HSM integration
        - access control
        - audit logs
        - rotation
        - versioning
        - backup and recovery
        - separation of duties
        - secure deletion where technically possible
    """

    def __init__(self):
        self.keys: dict[str, KeyRecord] = {}

    def generate_key(self) -> str:
        key_id = secrets.token_hex(8)

        self.keys[key_id] = KeyRecord(
            key_id=key_id,
            key_material=secrets.token_bytes(32),
            created_at=int(time.time()),
        )

        return key_id

    def get_active_key(self, key_id: str) -> bytes:
        record = self.keys.get(key_id)

        if record is None:
            raise KeyError("unknown key ID")

        if not record.active:
            raise ValueError("key is inactive")

        return record.key_material

    def deactivate(self, key_id: str) -> None:
        if key_id not in self.keys:
            raise KeyError("unknown key ID")

        self.keys[key_id].active = False


def demonstrate_key_management() -> None:
    section("16. Key management")

    key_ring = KeyRing()

    key_id = key_ring.generate_key()
    key_material = key_ring.get_active_key(key_id)

    print("Key ID:", key_id)
    print("Key length:", len(key_material))

    key_ring.deactivate(key_id)

    try:
        key_ring.get_active_key(key_id)
    except ValueError as error:
        print("Inactive-key protection:", error)


# ============================================================================
# 17. CRYPTOGRAPHIC AGILITY
# ============================================================================

@dataclass(frozen=True)
class AlgorithmPolicy:
    hash_algorithm: str
    encryption_algorithm: str
    signature_algorithm: str


def demonstrate_crypto_agility() -> None:
    """
    Crypto agility means a system can change cryptographic algorithms without
    redesigning the entire application protocol.
    """
    section("17. Cryptographic agility")

    current_policy = AlgorithmPolicy(
        hash_algorithm="SHA-256",
        encryption_algorithm="AES-256-GCM",
        signature_algorithm="Ed25519",
    )

    future_policy = AlgorithmPolicy(
        hash_algorithm="SHA-384",
        encryption_algorithm="ChaCha20-Poly1305",
        signature_algorithm="Post-quantum signature selected by deployment policy",
    )

    print("Current policy:", current_policy)
    print("Alternative policy:", future_policy)


# ============================================================================
# 18. POST-QUANTUM CRYPTOGRAPHY
# ============================================================================

def demonstrate_post_quantum_concepts() -> None:
    section("18. Post-quantum cryptography")

    print("Classical public-key families commonly include:")
    print("  RSA")
    print("  finite-field Diffie-Hellman")
    print("  elliptic-curve cryptography")

    print("\nQuantum-resistant cryptography is designed to resist known")
    print("quantum attacks against classical public-key constructions.")

    print("\nImportant concepts:")
    print("  - lattice-based cryptography")
    print("  - code-based cryptography")
    print("  - hash-based signatures")
    print("  - hybrid classical + post-quantum deployment")
    print("  - migration and crypto agility")

    print(
        "\nA major architectural issue is 'harvest now, decrypt later': "
        "encrypted traffic collected today may become useful to an attacker "
        "if future capabilities can break the protection."
    )


# ============================================================================
# 19. COMMON FAILURE MODES
# ============================================================================

def demonstrate_common_failures() -> None:
    section("19. Common cryptographic failures")

    failures = {
        "Using Base64 as encryption":
            "Encoding provides representation, not confidentiality.",
        "Using MD5 or SHA-1 for new security designs":
            "These algorithms have important collision weaknesses.",
        "Hashing passwords with plain SHA-256":
            "Fast hashes are unsuitable for password storage.",
        "Reusing a nonce with an AEAD construction":
            "Nonce misuse can severely compromise confidentiality or integrity.",
        "Hard-coding secret keys":
            "Secrets can leak through source code, repositories, logs, or builds.",
        "Writing cryptographic primitives from scratch":
            "Subtle implementation errors can invalidate otherwise sound mathematics.",
        "Encrypting without authentication":
            "Confidentiality alone does not detect malicious modification.",
        "Ignoring key rotation":
            "Long-lived keys increase the impact of compromise.",
        "Using predictable randomness":
            "Predictable keys, tokens, or nonces can destroy security.",
        "Logging plaintext secrets":
            "Application logs frequently have broad access and long retention.",
    }

    for failure, consequence in failures.items():
        print(f"\n{failure}\n  {consequence}")


# ============================================================================
# 20. PERFORMANCE MEASUREMENT
# ============================================================================

def benchmark_hashing() -> None:
    section("20. Performance measurement")

    data = os.urandom(2_000_000)

    start = time.perf_counter()
    digest = hashlib.sha256(data).digest()
    elapsed = time.perf_counter() - start

    megabytes_per_second = (len(data) / (1024 * 1024)) / elapsed

    print("Data size:", len(data), "bytes")
    print("Digest prefix:", digest.hex()[:32])
    print("Elapsed:", f"{elapsed:.6f}", "seconds")
    print("Approximate throughput:", f"{megabytes_per_second:.2f} MiB/s")

    print(
        "Benchmark results vary by CPU, operating system, Python version, "
        "hardware acceleration, and system load."
    )


# ============================================================================
# 21. THREAT MODELING
# ============================================================================

def demonstrate_threat_model() -> None:
    section("21. Threat modeling")

    threats = [
        ("Passive network observer", "Confidentiality"),
        ("Message tampering", "Integrity"),
        ("Impersonation", "Authentication"),
        ("Replay of valid requests", "Freshness"),
        ("Stolen database", "Password-hash resistance"),
        ("Compromised application server", "Key isolation and access control"),
        ("Lost encryption key", "Recovery and availability"),
        ("Future cryptanalytic capability", "Cryptographic agility"),
    ]

    for attacker, security_property in threats:
        print(f"{attacker:35} -> {security_property}")


# ============================================================================
# 22. PRODUCTION CHECKLIST
# ============================================================================

def production_checklist() -> None:
    section("22. Production cryptography checklist")

    checklist = [
        "Define the threat model before selecting primitives.",
        "Use standardized, well-reviewed cryptographic libraries.",
        "Prefer AEAD for encryption.",
        "Use unique, correctly generated nonces where required.",
        "Use a password-specific KDF for password-derived secrets.",
        "Generate keys using a cryptographically secure random source.",
        "Separate key identifiers from key material.",
        "Design explicit key rotation and revocation procedures.",
        "Do not place secrets in source code or ordinary logs.",
        "Authenticate protocol metadata as well as encrypted payloads.",
        "Protect against replay where requests have side effects.",
        "Validate input lengths and protocol states.",
        "Use constant-time comparisons for authentication material.",
        "Document algorithm choices and migration paths.",
        "Test failure paths, not only successful encryption and decryption.",
        "Plan for algorithm deprecation and post-quantum migration.",
    ]

    for number, item in enumerate(checklist, 1):
        print(f"{number:02}. {item}")


# ============================================================================
# 23. INTEGRATED SECURE MESSAGE SERVICE
# ============================================================================

class SecureMessageService:
    """
    Small integrated example combining several concepts.

    It models:
        - random symmetric keys
        - authenticated encryption
        - associated data
        - replay-resistant message IDs
        - key identifiers
        - explicit error handling
    """

    def __init__(self):
        self.key_ring = KeyRing()
        self.active_key_id = self.key_ring.generate_key()
        self.used_message_ids: set[str] = set()

    def rotate_key(self) -> str:
        old_key_id = self.active_key_id
        self.key_ring.deactivate(old_key_id)
        self.active_key_id = self.key_ring.generate_key()
        return self.active_key_id

    def encrypt(self, sender: str, plaintext: bytes) -> dict[str, str]:
        if not plaintext:
            raise ValueError("plaintext cannot be empty")

        key = self.key_ring.get_active_key(self.active_key_id)
        message_id = secrets.token_hex(16)

        associated_data = (
            f"sender={sender}&key-id={self.active_key_id}&"
            f"message-id={message_id}"
        ).encode()

        encrypted = authenticated_encrypt(
            key,
            plaintext,
            associated_data,
        )

        return {
            "sender": sender,
            "key_id": self.active_key_id,
            "message_id": message_id,
            "associated_data": base64.b64encode(associated_data).decode(),
            "nonce": base64.b64encode(encrypted.nonce).decode(),
            "ciphertext": base64.b64encode(encrypted.ciphertext).decode(),
            "tag": base64.b64encode(encrypted.tag).decode(),
        }

    def decrypt(self, package: dict[str, str]) -> bytes:
        message_id = package["message_id"]

        if message_id in self.used_message_ids:
            raise ValueError("replayed message")

        key = self.key_ring.get_active_key(package["key_id"])

        encrypted = AuthenticatedMessage(
            nonce=base64.b64decode(package["nonce"]),
            ciphertext=base64.b64decode(package["ciphertext"]),
            tag=base64.b64decode(package["tag"]),
        )

        associated_data = base64.b64decode(package["associated_data"])

        plaintext = authenticated_decrypt(
            key,
            encrypted,
            associated_data,
        )

        self.used_message_ids.add(message_id)

        return plaintext


def demonstrate_integrated_service() -> None:
    section("23. Integrated secure message service")

    service = SecureMessageService()

    package = service.encrypt(
        sender="alice@example.test",
        plaintext=b"Confidential payment instruction",
    )

    print("Message ID:", package["message_id"])
    print("Key ID:", package["key_id"])
    print("Ciphertext:", package["ciphertext"])

    plaintext = service.decrypt(package)

    print("Decrypted:", plaintext)

    try:
        service.decrypt(package)
    except ValueError as error:
        print("Replay blocked:", error)

    new_key = service.rotate_key()
    print("Rotated to key:", new_key)


# ============================================================================
# 24. MAIN STUDY RUNNER
# ============================================================================

def main() -> None:
    print("MODERN CRYPTOGRAPHY STUDY PROGRAM")
    print("Educational demonstrations from fundamentals to advanced concepts.")

    explain_encoding_vs_encryption()
    demonstrate_hashes()
    demonstrate_password_derivation()
    demonstrate_hmac()
    demonstrate_secure_randomness()
    demonstrate_xor_and_one_time_pad()
    demonstrate_block_cipher_structure()
    demonstrate_authenticated_encryption()
    demonstrate_rsa_math()
    demonstrate_diffie_hellman()
    demonstrate_elliptic_curves()
    demonstrate_signature_concept()
    demonstrate_hybrid_design()
    demonstrate_replay_protection()
    demonstrate_safe_comparison()
    demonstrate_key_management()
    demonstrate_crypto_agility()
    demonstrate_post_quantum_concepts()
    demonstrate_common_failures()
    benchmark_hashing()
    demonstrate_threat_model()
    production_checklist()
    demonstrate_integrated_service()

    section("Study program completed")
    print(
        "The examples are educational. Production cryptographic systems "
        "should use standardized primitives and audited implementations."
    )


if __name__ == "__main__":
    main()
