#!/usr/bin/env python3
"""
RSA Security and Limitations
Educational RSA implementation, security assessment, and lifecycle simulation.

The textbook RSA demonstration uses deliberately small keys and is NOT secure.
Production cryptography must use a vetted cryptographic library, RSA-OAEP for
encryption, RSA-PSS for signatures, and appropriately protected private keys.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class RSAError(Exception):
    """Base exception for RSA operations."""


class InvalidKeyError(RSAError):
    pass


class PolicyViolation(RSAError):
    pass


class KeyStatus(Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"
    COMPROMISED = "compromised"


class Operation(Enum):
    ENCRYPTION = "encryption"
    SIGNATURE = "signature"


class PaddingScheme(Enum):
    RAW = "raw"
    PKCS1_V15 = "pkcs1v15"
    OAEP_SHA256 = "oaep-sha256"
    PSS_SHA256 = "pss-sha256"


@dataclass
class RSAKeyMetadata:
    key_id: str
    modulus_bits: int
    public_exponent: int
    algorithm: str = "RSA"
    status: KeyStatus = KeyStatus.ACTIVE
    owner: str = "security-service"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    private_key_exportable: bool = False


@dataclass
class SecurityFinding:
    severity: str
    code: str
    description: str


@dataclass
class Assessment:
    key_id: str
    approved: bool
    findings: list[SecurityFinding]


class RSASecurityPolicy:
    """Evaluates RSA configuration without performing cryptographic operations."""

    def __init__(
        self,
        minimum_bits: int = 2048,
        required_exponent: int = 65537,
        allow_pkcs1_v15: bool = False,
    ):
        if minimum_bits < 2048:
            raise ValueError("Minimum production RSA size must be at least 2048")
        self.minimum_bits = minimum_bits
        self.required_exponent = required_exponent
        self.allow_pkcs1_v15 = allow_pkcs1_v15

    def assess(
        self,
        key: RSAKeyMetadata,
        operation: Operation,
        padding: PaddingScheme,
    ) -> Assessment:
        findings: list[SecurityFinding] = []

        def add(severity: str, code: str, description: str) -> None:
            findings.append(SecurityFinding(severity, code, description))

        if key.algorithm != "RSA":
            add("CRITICAL", "INVALID_ALGORITHM", "Unsupported key algorithm")

        if key.modulus_bits < self.minimum_bits:
            add("CRITICAL", "WEAK_MODULUS",
                f"RSA modulus is below {self.minimum_bits} bits")

        if key.public_exponent != self.required_exponent:
            add("HIGH", "NONSTANDARD_EXPONENT",
                "Public exponent differs from the required value")

        if key.status != KeyStatus.ACTIVE:
            add("CRITICAL", "INACTIVE_KEY",
                f"Key status is {key.status.value}")

        if key.private_key_exportable:
            add("HIGH", "EXPORTABLE_PRIVATE_KEY",
                "Exportable private keys increase exposure risk")

        if padding == PaddingScheme.RAW:
            add("CRITICAL", "TEXTBOOK_RSA",
                "Raw RSA does not provide secure encryption or signatures")

        if operation == Operation.ENCRYPTION:
            if padding != PaddingScheme.OAEP_SHA256:
                add("HIGH", "UNSAFE_ENCRYPTION_PADDING",
                    "Encryption requires RSA-OAEP with SHA-256")

        elif operation == Operation.SIGNATURE:
            if padding != PaddingScheme.PSS_SHA256:
                add("HIGH", "UNSAFE_SIGNATURE_PADDING",
                    "Signatures require RSA-PSS with SHA-256")

        if padding == PaddingScheme.PKCS1_V15:
            if not self.allow_pkcs1_v15:
                add("HIGH", "LEGACY_PADDING",
                    "PKCS#1 v1.5 is disabled by policy")

        return Assessment(
            key_id=key.key_id,
            approved=not findings,
            findings=findings,
        )


def is_probable_prime(n: int, rounds: int = 32) -> bool:
    """Miller-Rabin primality test for educational key generation."""

    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    if bits < 16:
        raise ValueError("Prime size must be at least 16 bits")

    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1

        if is_probable_prime(candidate):
            return candidate


@dataclass(frozen=True)
class EducationalRSAKey:
    n: int
    e: int
    d: int

    def encrypt_integer(self, message: int) -> int:
        if not 0 <= message < self.n:
            raise ValueError("Message must be within [0, n)")
        return pow(message, self.e, self.n)

    def decrypt_integer(self, ciphertext: int) -> int:
        if not 0 <= ciphertext < self.n:
            raise ValueError("Ciphertext must be within [0, n)")
        return pow(ciphertext, self.d, self.n)


def generate_educational_key(bits: int = 64) -> EducationalRSAKey:
    """
    Generates an intentionally small educational RSA key.
    Never use this implementation for real-world security.
    """

    if bits < 64:
        raise ValueError("Use at least 64 bits for this demonstration")

    e = 65537

    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits - bits // 2)

        if p == q:
            continue

        phi = (p - 1) * (q - 1)

        if math.gcd(e, phi) != 1:
            continue

        n = p * q
        d = pow(e, -1, phi)

        return EducationalRSAKey(n=n, e=e, d=d)


def demonstrate_textbook_rsa() -> dict:
    """Shows deterministic encryption and multiplicative malleability."""

    key = generate_educational_key(64)
    message = 42
    ciphertext1 = key.encrypt_integer(message)
    ciphertext2 = key.encrypt_integer(message)

    # RSA's multiplicative property:
    # E(m1) * E(m2) mod n = E(m1 * m2 mod n).
    left = (
        key.encrypt_integer(7) *
        key.encrypt_integer(9)
    ) % key.n

    right = key.encrypt_integer((7 * 9) % key.n)

    return {
        "modulus_bits": key.n.bit_length(),
        "same_plaintext_same_ciphertext": ciphertext1 == ciphertext2,
        "decryption_correct": key.decrypt_integer(ciphertext1) == message,
        "multiplicative_property_demonstrated": left == right,
        "warning": "Textbook RSA is not secure encryption."
    }


class KeyRegistry:
    """Maintains key metadata and records security assessments."""

    def __init__(self, policy: RSASecurityPolicy):
        self.policy = policy
        self.keys: dict[str, RSAKeyMetadata] = {}
        self.audit_log: list[dict] = []

    def register(self, key: RSAKeyMetadata) -> None:
        if key.key_id in self.keys:
            raise ValueError("Duplicate key identifier")

        self.keys[key.key_id] = key
        self.audit_log.append({
            "event": "KEY_REGISTERED",
            "key_id": key.key_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def evaluate(
        self,
        key_id: str,
        operation: Operation,
        padding: PaddingScheme,
    ) -> Assessment:
        if key_id not in self.keys:
            raise InvalidKeyError("Unknown key identifier")

        result = self.policy.assess(
            self.keys[key_id], operation, padding
        )

        self.audit_log.append({
            "event": "POLICY_ASSESSMENT",
            "key_id": key_id,
            "operation": operation.value,
            "padding": padding.value,
            "approved": result.approved,
        })

        return result

    def change_status(self, key_id: str, status: KeyStatus) -> None:
        if key_id not in self.keys:
            raise InvalidKeyError("Unknown key identifier")

        self.keys[key_id].status = status

        self.audit_log.append({
            "event": "KEY_STATUS_CHANGED",
            "key_id": key_id,
            "status": status.value,
        })

    def export_audit(self, path: str) -> None:
        """Writes metadata only; never exports private key material."""

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        temporary = destination.with_suffix(destination.suffix + ".tmp")

        try:
            temporary.write_text(
                json.dumps(self.audit_log, indent=2),
                encoding="utf-8",
            )
            temporary.replace(destination)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise


def display_assessment(result: Assessment) -> None:
    print(f"\nKey: {result.key_id}")
    print(f"Approved: {result.approved}")

    for finding in result.findings:
        print(
            f"[{finding.severity}] "
            f"{finding.code}: {finding.description}"
        )


def run_tests() -> None:
    policy = RSASecurityPolicy()

    secure = RSAKeyMetadata(
        key_id="RSA-PROD-001",
        modulus_bits=3072,
        public_exponent=65537,
        private_key_exportable=False,
    )

    result = policy.assess(
        secure,
        Operation.ENCRYPTION,
        PaddingScheme.OAEP_SHA256,
    )
    assert result.approved

    insecure = RSAKeyMetadata(
        key_id="RSA-LEGACY-001",
        modulus_bits=1024,
        public_exponent=3,
        private_key_exportable=True,
    )

    result = policy.assess(
        insecure,
        Operation.ENCRYPTION,
        PaddingScheme.RAW,
    )
    assert not result.approved
    assert len(result.findings) >= 4

    key = generate_educational_key()
    message = 123456
    assert key.decrypt_integer(key.encrypt_integer(message)) == message

    assert not is_probable_prime(1)
    assert not is_probable_prime(21)
    assert is_probable_prime(101)

    try:
        key.encrypt_integer(key.n)
        raise AssertionError("Out-of-range message was accepted")
    except ValueError:
        pass


def main() -> None:
    run_tests()

    registry = KeyRegistry(RSASecurityPolicy())

    registry.register(RSAKeyMetadata(
        key_id="PRODUCTION-RSA-001",
        modulus_bits=3072,
        public_exponent=65537,
    ))

    registry.register(RSAKeyMetadata(
        key_id="LEGACY-RSA-001",
        modulus_bits=1024,
        public_exponent=3,
        private_key_exportable=True,
    ))

    display_assessment(registry.evaluate(
        "PRODUCTION-RSA-001",
        Operation.ENCRYPTION,
        PaddingScheme.OAEP_SHA256,
    ))

    display_assessment(registry.evaluate(
        "LEGACY-RSA-001",
        Operation.ENCRYPTION,
        PaddingScheme.RAW,
    ))

    print("\nTextbook RSA limitations:")
    print(json.dumps(demonstrate_textbook_rsa(), indent=2))

    registry.change_status("LEGACY-RSA-001", KeyStatus.REVOKED)

    display_assessment(registry.evaluate(
        "LEGACY-RSA-001",
        Operation.SIGNATURE,
        PaddingScheme.PSS_SHA256,
    ))

    print("\nAll educational tests passed.")


if __name__ == "__main__":
    main()
