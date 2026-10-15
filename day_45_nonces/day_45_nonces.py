"""
Nonce Laboratory
================

A self-contained progression from basic nonce uniqueness to practical
cryptographic nonce management.

The examples cover:
- What a nonce is and what uniqueness means
- Random, counter-based, and hybrid nonce generation
- Replay detection
- AES-GCM-style nonce requirements
- ChaCha20-Poly1305-style nonce handling
- Sequence-number based protocol messages
- Persistent nonce allocation
- Concurrency-safe allocation
- Validation and failure handling
- Collision analysis
- Production design considerations

The script uses only the Python standard library. It intentionally does
not implement AES or ChaCha20 itself. Cryptographic primitives should be
provided by audited cryptographic libraries; this program focuses on the
nonce-management mechanisms surrounding those primitives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
import json
import math
import secrets
import threading
import time
from typing import Iterable


# ---------------------------------------------------------------------------
# Fundamental nonce representations
# ---------------------------------------------------------------------------

def random_nonce(byte_length: int = 12) -> bytes:
    """
    Generate a cryptographically strong random nonce.

    Twelve bytes is a common nonce size for AEAD constructions such as
    AES-GCM. The nonce length must always be chosen according to the
    cryptographic construction being used.
    """
    if byte_length <= 0:
        raise ValueError("Nonce length must be positive.")
    return secrets.token_bytes(byte_length)


def counter_nonce(counter: int, byte_length: int = 12) -> bytes:
    """
    Encode a monotonically increasing integer into a fixed-width nonce.

    A counter must never repeat for the same key. Overflow is rejected
    instead of silently wrapping around and reusing an earlier nonce.
    """
    if counter < 0:
        raise ValueError("Counter cannot be negative.")

    maximum = (1 << (8 * byte_length)) - 1
    if counter > maximum:
        raise OverflowError("Counter does not fit inside the nonce.")

    return counter.to_bytes(byte_length, "big")


def nonce_hex(nonce: bytes) -> str:
    return nonce.hex()


# ---------------------------------------------------------------------------
# Basic uniqueness demonstrations
# ---------------------------------------------------------------------------

def demonstrate_random_uniqueness() -> None:
    print("\n=== Random nonce uniqueness ===")

    generated = [random_nonce(12) for _ in range(10_000)]
    unique = len(set(generated))

    print(f"Generated: {len(generated):,}")
    print(f"Unique:    {unique:,}")
    print(f"Collision: {len(generated) != unique}")


def demonstrate_counter_nonce() -> None:
    print("\n=== Counter-based nonces ===")

    nonces = [counter_nonce(i, 12) for i in range(5)]

    for index, nonce in enumerate(nonces):
        print(f"counter={index} nonce={nonce_hex(nonce)}")


# ---------------------------------------------------------------------------
# Collision probability
# ---------------------------------------------------------------------------

def birthday_collision_probability(samples: int, bits: int) -> float:
    """
    Approximate the probability of at least one collision after generating
    'samples' uniformly random values from a 'bits'-wide space.

    For large spaces and relatively small samples:
        p ~= n(n-1)/(2*2^bits)

    The exponential expression is more stable for the relevant range.
    """
    if samples < 0:
        raise ValueError("Sample count cannot be negative.")
    if bits <= 0:
        raise ValueError("Bit width must be positive.")
    if samples <= 1:
        return 0.0

    denominator = 2 ** bits
    exponent = -(samples * (samples - 1)) / (2 * denominator)

    if exponent < -700:
        return 1.0

    return 1.0 - math.exp(exponent)


def demonstrate_collision_math() -> None:
    print("\n=== Random collision analysis ===")

    for samples in (1_000, 1_000_000, 1_000_000_000):
        probability = birthday_collision_probability(samples, 96)
        print(
            f"{samples:,} generated 96-bit nonces -> "
            f"collision probability ≈ {probability:.3e}"
        )


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Message:
    sender: str
    nonce: bytes
    payload: bytes
    timestamp: float


class ReplayDetector:
    """
    Tracks recently accepted nonces.

    A real distributed system usually needs a bounded retention strategy,
    persistent state, or a protocol-specific sequence window. Keeping every
    nonce forever is not a scalable production design.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive.")

        self.max_entries = max_entries
        self._seen: dict[bytes, float] = {}
        self._lock = threading.Lock()

    def accept(self, nonce: bytes, now: float | None = None) -> bool:
        """
        Return True only when this nonce has not already been accepted.

        The check and insertion occur under one lock so two concurrent
        requests cannot both pass the replay check.
        """
        if not nonce:
            raise ValueError("Nonce cannot be empty.")

        timestamp = time.time() if now is None else now

        with self._lock:
            if nonce in self._seen:
                return False

            self._seen[nonce] = timestamp

            while len(self._seen) > self.max_entries:
                oldest_nonce = min(self._seen, key=self._seen.get)
                del self._seen[oldest_nonce]

            return True


def demonstrate_replay_detection() -> None:
    print("\n=== Replay detection ===")

    detector = ReplayDetector(max_entries=3)
    nonce = random_nonce()

    print("First message accepted:", detector.accept(nonce))
    print("Replay accepted:", detector.accept(nonce))


# ---------------------------------------------------------------------------
# Sequence-number protocol
# ---------------------------------------------------------------------------

@dataclass
class SequenceWindow:
    """
    A simplified anti-replay window.

    The receiver remembers the largest accepted sequence number and a
    bitmap of recently accepted numbers. This is useful for protocols
    where messages may arrive out of order.
    """

    window_size: int = 64
    highest: int = -1
    bitmap: int = 0

    def __post_init__(self) -> None:
        if self.window_size <= 0:
            raise ValueError("window_size must be positive.")

    def accept(self, sequence: int) -> bool:
        if sequence < 0:
            raise ValueError("Sequence number cannot be negative.")

        if self.highest == -1:
            self.highest = sequence
            self.bitmap = 1
            return True

        if sequence > self.highest:
            shift = sequence - self.highest

            if shift >= self.window_size:
                self.bitmap = 1
            else:
                mask = (1 << self.window_size) - 1
                self.bitmap = ((self.bitmap << shift) | 1) & mask

            self.highest = sequence
            return True

        distance = self.highest - sequence

        if distance >= self.window_size:
            return False

        bit = 1 << distance

        if self.bitmap & bit:
            return False

        self.bitmap |= bit
        return True


def demonstrate_sequence_window() -> None:
    print("\n=== Sequence-number anti-replay window ===")

    window = SequenceWindow(window_size=4)

    for sequence in (10, 11, 9, 12, 11, 8, 13):
        print(
            f"sequence={sequence:2d} "
            f"accepted={window.accept(sequence)} "
            f"highest={window.highest}"
        )


# ---------------------------------------------------------------------------
# Protocol-specific nonce construction
# ---------------------------------------------------------------------------

def build_structured_nonce(
    session_id: int,
    message_counter: int,
    *,
    session_bytes: int = 4,
    counter_bytes: int = 8,
) -> bytes:
    """
    Construct a deterministic nonce from a session identifier and counter.

    The important property is domain separation: a new session must not
    reuse a nonce sequence under the same cryptographic key.

    A production protocol must define the encoding and key lifecycle
    precisely rather than improvising a nonce format.
    """
    if session_id < 0 or message_counter < 0:
        raise ValueError("Identifiers cannot be negative.")

    max_session = (1 << (8 * session_bytes)) - 1
    max_counter = (1 << (8 * counter_bytes)) - 1

    if session_id > max_session:
        raise OverflowError("Session identifier is too large.")
    if message_counter > max_counter:
        raise OverflowError("Message counter is too large.")

    return (
        session_id.to_bytes(session_bytes, "big")
        + message_counter.to_bytes(counter_bytes, "big")
    )


def demonstrate_structured_nonces() -> None:
    print("\n=== Structured session/counter nonce ===")

    session = 0xA17C2026

    for counter in range(3):
        nonce = build_structured_nonce(session, counter)
        print(f"counter={counter} nonce={nonce_hex(nonce)}")


# ---------------------------------------------------------------------------
# Persistent nonce allocation
# ---------------------------------------------------------------------------

class PersistentCounter:
    """
    Durable counter allocator using an atomic replace operation.

    This implementation is intended as an educational local allocator.
    Production multi-process systems should use a transactional database,
    an operating-system-protected monotonic counter, or a dedicated
    coordination mechanism.

    The file is rewritten to a temporary file and atomically replaced.
    A process-level lock prevents concurrent threads in this process from
    allocating the same value.
    """

    def __init__(self, path: str | Path, initial: int = 0) -> None:
        self.path = Path(path)
        self.lock = threading.Lock()

        if initial < 0:
            raise ValueError("Initial counter cannot be negative.")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        if not self.path.exists():
            self._write(initial)

    def _read(self) -> int:
        try:
            value = int(self.path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise RuntimeError("Nonce counter state is unreadable.") from exc

        if value < 0:
            raise RuntimeError("Nonce counter state is invalid.")

        return value

    def _write(self, value: int) -> None:
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(str(value), encoding="utf-8")
        temporary.replace(self.path)

    def allocate(self) -> int:
        with self.lock:
            current = self._read()
            next_value = current + 1
            self._write(next_value)
            return next_value


def demonstrate_persistent_counter() -> None:
    print("\n=== Persistent nonce counter ===")

    path = Path("nonce_counter_demo.state")

    try:
        allocator = PersistentCounter(path)

        for _ in range(3):
            value = allocator.allocate()
            print(f"allocated counter={value}")

    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Concurrent nonce allocation
# ---------------------------------------------------------------------------

class ThreadSafeNonceAllocator:
    """
    A thread-safe monotonic nonce allocator.

    The lock makes allocation atomic inside one process. It does not solve
    coordination across multiple independent processes or machines.
    """

    def __init__(self, starting_value: int = 0, width: int = 12) -> None:
        if starting_value < 0:
            raise ValueError("Starting value cannot be negative.")
        if width <= 0:
            raise ValueError("Nonce width must be positive.")

        self._counter = starting_value
        self._width = width
        self._lock = threading.Lock()

    def allocate(self) -> bytes:
        with self._lock:
            maximum = (1 << (8 * self._width)) - 1

            if self._counter >= maximum:
                raise OverflowError("Nonce counter exhausted.")

            self._counter += 1
            return counter_nonce(self._counter, self._width)


def demonstrate_concurrency() -> None:
    print("\n=== Concurrent allocation ===")

    allocator = ThreadSafeNonceAllocator()
    generated: list[bytes] = []
    output_lock = threading.Lock()

    def worker() -> None:
        local = [allocator.allocate() for _ in range(1_000)]
        with output_lock:
            generated.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(8)]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    print(f"Generated: {len(generated):,}")
    print(f"Unique:    {len(set(generated)):,}")


# ---------------------------------------------------------------------------
# Key-scoped nonce registry
# ---------------------------------------------------------------------------

class KeyScopedNonceRegistry:
    """
    Associates a nonce namespace with a cryptographic key identifier.

    A nonce can safely be considered unique only within the scope required
    by the cryptographic construction. Reusing the same nonce under a
    different key is often acceptable for AEAD constructions, while
    reusing it under the same key can be catastrophic.
    """

    def __init__(self) -> None:
        self._used: dict[str, set[bytes]] = {}
        self._lock = threading.Lock()

    def reserve(self, key_id: str, nonce: bytes) -> bool:
        if not key_id:
            raise ValueError("key_id cannot be empty.")
        if not nonce:
            raise ValueError("nonce cannot be empty.")

        with self._lock:
            namespace = self._used.setdefault(key_id, set())

            if nonce in namespace:
                return False

            namespace.add(nonce)
            return True

    def count(self, key_id: str) -> int:
        return len(self._used.get(key_id, set()))


def demonstrate_key_scoping() -> None:
    print("\n=== Key-scoped nonce uniqueness ===")

    registry = KeyScopedNonceRegistry()
    nonce = random_nonce()

    print("Key-A reservation:", registry.reserve("key-A", nonce))
    print("Key-A replay:", registry.reserve("key-A", nonce))
    print("Key-B reservation:", registry.reserve("key-B", nonce))


# ---------------------------------------------------------------------------
# Nonce misuse detection
# ---------------------------------------------------------------------------

@dataclass
class NoncePolicy:
    nonce_bytes: int = 12
    require_unique: bool = True
    maximum_messages: int | None = None


class NonceManager:
    """
    Higher-level manager that applies a nonce policy.

    This class does not encrypt anything. Its job is to make nonce lifecycle
    rules explicit before an application calls a cryptographic primitive.
    """

    def __init__(self, policy: NoncePolicy) -> None:
        if policy.nonce_bytes <= 0:
            raise ValueError("nonce_bytes must be positive.")

        if (
            policy.maximum_messages is not None
            and policy.maximum_messages <= 0
        ):
            raise ValueError("maximum_messages must be positive.")

        self.policy = policy
        self._used: set[bytes] = set()
        self._lock = threading.Lock()
        self._generated = 0

    def generate(self) -> bytes:
        with self._lock:
            if (
                self.policy.maximum_messages is not None
                and self._generated >= self.policy.maximum_messages
            ):
                raise RuntimeError("Message limit for nonce policy reached.")

            while True:
                nonce = random_nonce(self.policy.nonce_bytes)

                if not self.policy.require_unique or nonce not in self._used:
                    break

            if self.policy.require_unique:
                self._used.add(nonce)

            self._generated += 1
            return nonce


def demonstrate_nonce_manager() -> None:
    print("\n=== Policy-aware nonce manager ===")

    manager = NonceManager(
        NoncePolicy(
            nonce_bytes=12,
            require_unique=True,
            maximum_messages=5,
        )
    )

    for _ in range(5):
        print(nonce_hex(manager.generate()))

    try:
        manager.generate()
    except RuntimeError as exc:
        print("Expected failure:", exc)


# ---------------------------------------------------------------------------
# Safe comparison and nonce-associated metadata
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthenticatedEnvelope:
    """
    Represents the metadata normally passed alongside an AEAD ciphertext.

    The authentication tag is treated as opaque data. This program does not
    implement the cryptographic primitive itself.
    """

    key_id: str
    nonce: bytes
    ciphertext: bytes
    authentication_tag: bytes
    associated_data: bytes = b""

    def fingerprint(self) -> str:
        material = (
            self.key_id.encode("utf-8")
            + self.nonce
            + self.ciphertext
            + self.authentication_tag
            + self.associated_data
        )
        return sha256(material).hexdigest()


def validate_envelope(
    envelope: AuthenticatedEnvelope,
    expected_nonce_length: int,
) -> None:
    if not envelope.key_id:
        raise ValueError("Missing key identifier.")

    if len(envelope.nonce) != expected_nonce_length:
        raise ValueError("Unexpected nonce length.")

    if not envelope.ciphertext:
        raise ValueError("Ciphertext cannot be empty.")

    if not envelope.authentication_tag:
        raise ValueError("Authentication tag cannot be empty.")


def demonstrate_envelope_validation() -> None:
    print("\n=== AEAD envelope validation ===")

    envelope = AuthenticatedEnvelope(
        key_id="production-key-2026",
        nonce=random_nonce(12),
        ciphertext=b"encrypted-data",
        authentication_tag=b"example-tag",
        associated_data=b"protocol=v1",
    )

    validate_envelope(envelope, expected_nonce_length=12)
    print("Envelope accepted.")
    print("Fingerprint:", envelope.fingerprint())


# ---------------------------------------------------------------------------
# Deterministic test nonce source
# ---------------------------------------------------------------------------

class TestNonceSource:
    """
    Deterministic nonce source for tests.

    Production cryptographic code should use a cryptographically secure
    source or a carefully designed monotonic allocator. Deterministic
    nonces are useful in tests because expected values become reproducible.
    """

    def __init__(self, start: int = 1, width: int = 12) -> None:
        self._counter = start
        self._width = width

    def next(self) -> bytes:
        nonce = counter_nonce(self._counter, self._width)
        self._counter += 1
        return nonce


def demonstrate_deterministic_testing() -> None:
    print("\n=== Deterministic nonce source for tests ===")

    source = TestNonceSource(start=100)

    first = source.next()
    second = source.next()

    print("First :", nonce_hex(first))
    print("Second:", nonce_hex(second))

    assert first != second
    assert len(first) == 12


# ---------------------------------------------------------------------------
# Nonce lifecycle simulation
# ---------------------------------------------------------------------------

@dataclass
class Session:
    session_id: int
    key_id: str
    nonce_counter: int = 0
    closed: bool = False
    accepted_nonces: set[bytes] = field(default_factory=set)

    def next_nonce(self) -> bytes:
        if self.closed:
            raise RuntimeError("Cannot allocate a nonce for a closed session.")

        nonce = build_structured_nonce(
            session_id=self.session_id,
            message_counter=self.nonce_counter,
        )

        if nonce in self.accepted_nonces:
            raise RuntimeError("Nonce reuse detected.")

        self.accepted_nonces.add(nonce)
        self.nonce_counter += 1
        return nonce

    def close(self) -> None:
        self.closed = True


def demonstrate_session_lifecycle() -> None:
    print("\n=== Session nonce lifecycle ===")

    session = Session(
        session_id=0x12345678,
        key_id="session-key-A",
    )

    for _ in range(3):
        print(nonce_hex(session.next_nonce()))

    session.close()

    try:
        session.next_nonce()
    except RuntimeError as exc:
        print("Expected failure:", exc)


# ---------------------------------------------------------------------------
# Security review helper
# ---------------------------------------------------------------------------

def security_review() -> dict[str, str]:
    """
    Return concise operational checks that can be incorporated into a
    security review or automated deployment validation.
    """
    return {
        "random_source": "Use an OS-backed CSPRNG for random nonces.",
        "scope": "Define uniqueness scope explicitly: normally per key.",
        "counter": "Never silently wrap a nonce counter.",
        "persistence": "Persist counters when process restarts can occur.",
        "concurrency": "Coordinate allocation across threads/processes/nodes.",
        "key_rotation": "Tie nonce state to key lifecycle and rotation.",
        "replay": "Use replay detection when the protocol requires it.",
        "primitive": "Follow the exact nonce size and reuse rules of the AEAD primitive.",
        "logging": "Avoid logging plaintext secrets; treat nonce metadata as protocol data.",
        "testing": "Use deterministic nonce sources only in controlled tests.",
    }


def demonstrate_security_review() -> None:
    print("\n=== Security review ===")

    for control, requirement in security_review().items():
        print(f"{control}: {requirement}")


# ---------------------------------------------------------------------------
# Main demonstration
# ---------------------------------------------------------------------------

def main() -> None:
    print("NONCE LABORATORY")
    print("================")
    print(
        "This program demonstrates nonce generation, uniqueness, "
        "replay protection, persistence, concurrency, and validation."
    )

    demonstrate_random_uniqueness()
    demonstrate_counter_nonce()
    demonstrate_collision_math()
    demonstrate_replay_detection()
    demonstrate_sequence_window()
    demonstrate_structured_nonces()
    demonstrate_persistent_counter()
    demonstrate_concurrency()
    demonstrate_key_scoping()
    demonstrate_nonce_manager()
    demonstrate_envelope_validation()
    demonstrate_deterministic_testing()
    demonstrate_session_lifecycle()
    demonstrate_security_review()

    print("\nAll demonstrations completed successfully.")


if __name__ == "__main__":
    main()
