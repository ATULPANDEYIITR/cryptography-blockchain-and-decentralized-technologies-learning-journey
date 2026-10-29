#!/usr/bin/env python3
"""
Birthday Problem and Hash Attacks

Models collision probability, hash-table collisions, and the security impact
of birthday attacks. The program uses exact arithmetic for probability
calculations, deterministic demonstrations, Monte Carlo experiments, and
security-oriented policy checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from math import exp, log
from secrets import token_bytes
from typing import Iterable


class RiskLevel(Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class HashPolicy:
    digest_bits: int
    minimum_security_bits: int = 128

    def validate(self) -> None:
        if self.digest_bits <= 0:
            raise ValueError("digest_bits must be positive")
        if self.digest_bits % 8:
            raise ValueError("digest_bits must be byte-aligned")
        if self.minimum_security_bits <= 0:
            raise ValueError("minimum_security_bits must be positive")

    @property
    def collision_security_bits(self) -> float:
        # Generic birthday collision security is approximately n/2 bits.
        return self.digest_bits / 2

    def risk(self) -> RiskLevel:
        self.validate()
        effective = self.collision_security_bits
        if effective < 64:
            return RiskLevel.CRITICAL
        if effective < 96:
            return RiskLevel.HIGH
        if effective < self.minimum_security_bits:
            return RiskLevel.MODERATE
        return RiskLevel.LOW


def birthday_collision_probability(samples: int, space_size: int) -> float:
    """
    P(collision) = 1 - product(i=0..k-1) (N-i)/N.

    log1p/expm1 avoids avoidable floating-point loss when probability is small.
    """
    if samples < 0 or space_size <= 0:
        raise ValueError("samples must be non-negative and space_size positive")
    if samples <= 1:
        return 0.0
    if samples > space_size:
        return 1.0

    log_no_collision = 0.0
    for i in range(samples):
        log_no_collision += log1p_safe(-i / space_size)
    return -expm1_safe(log_no_collision)


def log1p_safe(value: float) -> float:
    # Small local implementation avoids depending on numerical libraries.
    if value <= -1.0:
        return float("-inf")
    if abs(value) < 1e-8:
        return value - value * value / 2 + value**3 / 3
    return log(1.0 + value)


def expm1_safe(value: float) -> float:
    if abs(value) < 1e-8:
        return value + value * value / 2 + value**3 / 6
    return exp(value) - 1.0


def approximate_collision_probability(samples: int, digest_bits: int) -> float:
    if samples < 0 or digest_bits <= 0:
        raise ValueError("invalid sample count or digest size")
    n = 2**digest_bits
    exponent = -(samples * (samples - 1)) / (2 * n)
    return 1.0 - exp(exponent)


def samples_for_probability(space_size: int, target_probability: float) -> int:
    """
    Binary-searches the smallest sample count whose exact collision
    probability reaches the requested threshold.
    """
    if space_size <= 0:
        raise ValueError("space_size must be positive")
    if not 0.0 < target_probability < 1.0:
        raise ValueError("target_probability must be between 0 and 1")

    low, high = 1, space_size
    while low < high:
        mid = (low + high) // 2
        if birthday_collision_probability(mid, space_size) >= target_probability:
            high = mid
        else:
            low = mid + 1
    return low


def birthday_bound(digest_bits: int, target_probability: float = 0.5) -> int:
    return samples_for_probability(2**digest_bits, target_probability)


def truncated_sha256(data: bytes, bits: int) -> int:
    if bits <= 0 or bits > 256:
        raise ValueError("bits must be in the range 1..256")
    digest = sha256(data).digest()
    value = int.from_bytes(digest, "big")
    return value >> (256 - bits)


@dataclass
class CollisionSearchResult:
    bits: int
    attempts: int
    first_input: bytes
    second_input: bytes
    digest_prefix: int


def find_truncated_hash_collision(bits: int, max_attempts: int = 2_000_000) -> CollisionSearchResult:
    """
    Demonstrates a controlled birthday collision against a deliberately
    truncated SHA-256 output. This is an educational simulation; it does
    not attack full SHA-256.
    """
    if not 8 <= bits <= 32:
        raise ValueError("demonstration requires 8..32 bits")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")

    seen: dict[int, bytes] = {}

    for attempt in range(1, max_attempts + 1):
        candidate = token_bytes(16)
        digest_prefix = truncated_sha256(candidate, bits)

        previous = seen.get(digest_prefix)
        if previous is not None and previous != candidate:
            return CollisionSearchResult(
                bits=bits,
                attempts=attempt,
                first_input=previous,
                second_input=candidate,
                digest_prefix=digest_prefix,
            )

        seen[digest_prefix] = candidate

    raise RuntimeError("no collision found within max_attempts")


def monte_carlo_collision_rate(
    samples: int, space_size: int, trials: int = 10_000
) -> float:
    if samples < 0 or space_size <= 0 or trials <= 0:
        raise ValueError("invalid Monte Carlo parameters")

    collisions = 0
    for _ in range(trials):
        values: set[int] = set()
        collision = False

        for _ in range(samples):
            value = int.from_bytes(token_bytes(8), "big") % space_size
            if value in values:
                collision = True
                break
            values.add(value)

        collisions += collision

    return collisions / trials


def validate_hash_design(policy: HashPolicy) -> list[str]:
    policy.validate()
    warnings: list[str] = []

    if policy.digest_bits < 128:
        warnings.append("Digest is shorter than the recommended 128-bit collision-security target.")
    if policy.digest_bits < 256:
        warnings.append("Digest provides less collision margin than a 256-bit hash.")
    if policy.digest_bits <= 64:
        warnings.append("Birthday collisions become computationally relevant much earlier than preimage attacks.")

    return warnings


def run_assertions() -> None:
    assert birthday_collision_probability(1, 365) == 0.0
    assert birthday_collision_probability(366, 365) == 1.0
    assert samples_for_probability(365, 0.5) == 23
    assert truncated_sha256(b"abc", 8) == truncated_sha256(b"abc", 8)

    policy = HashPolicy(256)
    assert policy.collision_security_bits == 128
    assert policy.risk() == RiskLevel.LOW


def print_probability_table() -> None:
    print("Birthday collision probabilities")
    print("-" * 60)

    for bits in (8, 16, 32, 64, 128, 256):
        space = 2**bits
        half = birthday_bound(bits)
        approximate = 2 ** ((bits - 1) / 2)
        print(
            f"{bits:>3}-bit: "
            f"50% threshold ≈ {half:,} samples; "
            f"sqrt-space estimate ≈ {approximate:,.0f}"
        )


def main() -> None:
    run_assertions()
    print_probability_table()

    print("\nPolicy evaluation")
    for bits in (32, 64, 128, 160, 256):
        policy = HashPolicy(bits)
        print(
            f"{bits:>3}-bit digest: "
            f"collision security ≈ {policy.collision_security_bits:.0f} bits, "
            f"risk={policy.risk().value}"
        )

    print("\nControlled truncated-hash collision")
    result = find_truncated_hash_collision(16)
    print(f"Found a 16-bit collision after {result.attempts:,} attempts.")
    print(f"Digest prefix: {result.digest_prefix:04x}")
    print(f"Input A: {result.first_input.hex()}")
    print(f"Input B: {result.second_input.hex()}")

    print("\nMonte Carlo check")
    empirical = monte_carlo_collision_rate(
        samples=23,
        space_size=365,
        trials=2_000,
    )
    theoretical = birthday_collision_probability(23, 365)
    print(f"Empirical:  {empirical:.3f}")
    print(f"Theoretical: {theoretical:.3f}")

    print("\nSecurity controls")
    for warning in validate_hash_design(HashPolicy(256)):
        print(f"- {warning}")
    print("- Use collision-resistant hashes for integrity and identifiers.")
    print("- Do not truncate cryptographic hashes without a quantified security requirement.")
    print("- Do not treat collision resistance as equivalent to preimage resistance.")
    print("- For password storage, use dedicated password-hashing schemes rather than plain SHA-256.")


if __name__ == "__main__":
    main()
