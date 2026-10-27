#!/usr/bin/env python3
"""
Preimage Resistance: executable hash-security model.

This program models:
1. First-preimage resistance
2. Second-preimage resistance
3. Collision resistance as a distinct property
4. Hash-based commitments
5. Password-like verification without storing the original secret
6. Brute-force preimage search on deliberately small toy hash spaces
7. Domain separation
8. Verification and failure handling

The real SHA-256 demonstrations use hashlib. Brute-force experiments use
truncated SHA-256 values so that the search is computationally practical.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import secrets
import string
from typing import Iterable, Optional


class HashAlgorithm(str, Enum):
    SHA256 = "sha256"
    SHA512 = "sha512"


class VerificationError(ValueError):
    """Raised when supplied data cannot be verified safely."""


def hash_bytes(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    if algorithm is HashAlgorithm.SHA256:
        return hashlib.sha256(data).digest()
    if algorithm is HashAlgorithm.SHA512:
        return hashlib.sha512(data).digest()
    raise ValueError(f"Unsupported algorithm: {algorithm}")


def hash_hex(data: bytes, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> str:
    return hash_bytes(data, algorithm).hex()


def truncated_digest(data: bytes, bits: int) -> int:
    """
    Return the first 'bits' of SHA-256 as an integer.

    Small truncations are intentional: they make exhaustive experiments
    possible while illustrating the relationship between output size and
    preimage search effort.
    """
    if not 1 <= bits <= 32:
        raise ValueError("bits must be between 1 and 32")

    digest = hashlib.sha256(data).digest()
    value = int.from_bytes(digest[:4], "big")
    return value >> (32 - bits)


def brute_force_preimage(
    target: int,
    bits: int,
    alphabet: str = string.ascii_lowercase,
    max_length: int = 5,
) -> Optional[str]:
    """
    Search a deliberately small message space for a preimage.

    This is not an attack on full SHA-256. It is an experiment showing
    why a sufficiently large output space makes exhaustive inversion
    impractical.
    """
    if not alphabet:
        raise ValueError("alphabet must not be empty")
    if max_length < 1:
        raise ValueError("max_length must be positive")

    attempts = 0

    def generate(prefix: str, remaining: int) -> Iterable[str]:
        nonlocal attempts

        if remaining == 0:
            attempts += 1
            yield prefix
            return

        for character in alphabet:
            yield from generate(prefix + character, remaining - 1)

    for length in range(1, max_length + 1):
        for candidate in generate("", length):
            if truncated_digest(candidate.encode(), bits) == target:
                return candidate

    return None


@dataclass(frozen=True)
class Commitment:
    digest: bytes
    algorithm: HashAlgorithm
    context: bytes


class HashCommitment:
    """
    A commitment binds a value to a digest without publishing the value.

    Domain separation is included in the committed byte string so that
    the same raw value used in another protocol context is not silently
    interpreted as the same commitment input.
    """

    def __init__(
        self,
        algorithm: HashAlgorithm = HashAlgorithm.SHA256,
        context: bytes = b"preimage-resistance-commitment-v1",
    ) -> None:
        if not context:
            raise ValueError("context must not be empty")
        self.algorithm = algorithm
        self.context = context

    def _encode(self, message: bytes) -> bytes:
        return len(self.context).to_bytes(2, "big") + self.context + message

    def commit(self, message: bytes) -> Commitment:
        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")

        return Commitment(
            digest=hash_bytes(self._encode(message), self.algorithm),
            algorithm=self.algorithm,
            context=self.context,
        )

    def verify(self, commitment: Commitment, message: bytes) -> bool:
        if commitment.algorithm is not self.algorithm:
            return False
        if commitment.context != self.context:
            return False

        expected = self.commit(message).digest
        return hmac.compare_digest(expected, commitment.digest)


@dataclass(frozen=True)
class ReviewArtifact:
    repository: str
    branch: str
    commit_id: str
    content_hash: str


class ArtifactVerifier:
    """
    Demonstrates integrity verification.

    A digest confirms that the supplied bytes correspond to the expected
    digest. It does not authenticate an attacker-controlled digest.
    """

    def __init__(self, algorithm: HashAlgorithm = HashAlgorithm.SHA256) -> None:
        self.algorithm = algorithm

    def create(self, repository: str, branch: str, commit_id: str, content: bytes) -> ReviewArtifact:
        if not repository.strip() or not branch.strip() or not commit_id.strip():
            raise VerificationError("repository, branch, and commit_id are required")

        return ReviewArtifact(
            repository=repository,
            branch=branch,
            commit_id=commit_id,
            content_hash=hash_hex(content, self.algorithm),
        )

    def verify(self, artifact: ReviewArtifact, content: bytes) -> bool:
        supplied = hash_hex(content, self.algorithm)
        return hmac.compare_digest(supplied, artifact.content_hash)


def demonstrate_real_hash() -> None:
    print("=== SHA-256 preimage-resistance model ===")

    secret = b"release-candidate:repository-policy:v3"
    digest = hash_hex(secret)

    print(f"Original message : {secret.decode()}")
    print(f"SHA-256 digest   : {digest}")
    print("A verifier can check a candidate by hashing it again.")
    print("The digest alone is not a practical way to recover the original message.")


def demonstrate_commitment() -> None:
    print("\n=== Hash commitment ===")

    commitment_scheme = HashCommitment()
    original = b"merge-policy-approved-at-17:42"
    commitment = commitment_scheme.commit(original)

    print(f"Commitment digest: {commitment.digest.hex()}")
    print(f"Correct opening  : {commitment_scheme.verify(commitment, original)}")
    print(
        f"Wrong opening    : "
        f"{commitment_scheme.verify(commitment, b'merge-policy-approved-at-17:43')}"
    )


def demonstrate_truncated_preimage_search() -> None:
    print("\n=== Deliberately small preimage search ===")

    target_message = b"cab"
    bits = 16
    target = truncated_digest(target_message, bits)

    print(f"Target message   : {target_message.decode()}")
    print(f"Truncated bits   : {bits}")
    print(f"Target value     : {target}")

    recovered = brute_force_preimage(
        target=target,
        bits=bits,
        alphabet=string.ascii_lowercase,
        max_length=3,
    )

    if recovered is None:
        print("No preimage found in the selected finite search space.")
    else:
        print(f"Found preimage   : {recovered}")
        print(f"Matches target   : {truncated_digest(recovered.encode(), bits) == target}")

    print(
        "The experiment is feasible only because the digest was truncated "
        "and the candidate space was deliberately constrained."
    )


def demonstrate_domain_separation() -> None:
    print("\n=== Domain separation ===")

    message = b"approved"

    signing_context = HashCommitment(context=b"signature-v1")
    commitment_context = HashCommitment(context=b"commitment-v1")

    signing_digest = signing_context.commit(message).digest
    commitment_digest = commitment_context.commit(message).digest

    print(f"Signature context digest  : {signing_digest.hex()}")
    print(f"Commitment context digest : {commitment_digest.hex()}")
    print(f"Equal digests              : {signing_digest == commitment_digest}")


def demonstrate_artifact_integrity() -> None:
    print("\n=== Artifact integrity ===")

    verifier = ArtifactVerifier()

    content = b"repository policy: require two approvals"
    artifact = verifier.create(
        repository="security-platform",
        branch="main",
        commit_id="a1b2c3d4",
        content=content,
    )

    print(f"Stored content hash: {artifact.content_hash}")
    print(f"Valid content      : {verifier.verify(artifact, content)}")
    print(
        "Tampered content   : "
        f"{verifier.verify(artifact, b'repository policy: require one approval')}"
    )


def demonstrate_validation() -> None:
    print("\n=== Validation and failure handling ===")

    try:
        HashCommitment(context=b"")
    except ValueError as exc:
        print(f"Rejected empty context: {exc}")

    try:
        truncated_digest(b"data", 0)
    except ValueError as exc:
        print(f"Rejected invalid digest size: {exc}")

    try:
        ArtifactVerifier().create("", "main", "abc123", b"data")
    except VerificationError as exc:
        print(f"Rejected invalid artifact metadata: {exc}")


def main() -> None:
    demonstrate_real_hash()
    demonstrate_commitment()
    demonstrate_truncated_preimage_search()
    demonstrate_domain_separation()
    demonstrate_artifact_integrity()
    demonstrate_validation()

    print("\n=== Security notes ===")
    print("Use modern cryptographic hashes with sufficiently large output sizes.")
    print("Do not treat a hash as encryption: hashing is not intended to be reversible.")
    print("For passwords, use a dedicated password hashing/KDF scheme with salt.")
    print("For authentication, an attacker-controlled expected digest is not a trust anchor.")
    print("Preimage resistance does not imply collision resistance, and collision resistance")
    print("does not by itself provide authentication.")


if __name__ == "__main__":
    main()
