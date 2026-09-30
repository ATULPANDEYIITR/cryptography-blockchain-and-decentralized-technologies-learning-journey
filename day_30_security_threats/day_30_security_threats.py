#!/usr/bin/env python3
"""
Security Threats and Basic Security Principles

A self-contained security laboratory that demonstrates:
- CIA triad and security properties
- Threat modeling
- Input validation and canonicalization
- Password hashing and verification
- Authentication and authorization
- Least privilege
- Secure session handling
- Rate limiting
- Audit logging
- Integrity protection with HMAC
- Encryption concepts using the Python standard library
- Path traversal prevention
- Secure secret handling
- Replay protection
- Common failure modes and defensive controls

The examples are intentionally local and defensive. They do not attack
external systems or perform real credential cracking.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Security principles
# ---------------------------------------------------------------------------

CIA_CONTROLS = {
    "confidentiality": [
        "Strong authentication",
        "Authorization",
        "Encryption",
        "Secret management",
    ],
    "integrity": [
        "Input validation",
        "HMAC verification",
        "Audit logging",
        "Change control",
    ],
    "availability": [
        "Rate limiting",
        "Resource limits",
        "Backups",
        "Failure isolation",
    ],
}


def demonstrate_cia_triad() -> None:
    print("\n=== CIA Triad ===")
    for property_name, controls in CIA_CONTROLS.items():
        print(f"{property_name.title()}:")
        for control in controls:
            print(f"  - {control}")


# ---------------------------------------------------------------------------
# Threat modeling
# ---------------------------------------------------------------------------

@dataclass
class Threat:
    name: str
    asset: str
    attack_surface: str
    impact: str
    likelihood: str
    controls: list[str]

    @property
    def priority(self) -> str:
        high_values = {"high", "critical"}
        if self.impact.lower() in high_values and self.likelihood.lower() in high_values:
            return "critical"
        if self.impact.lower() in high_values or self.likelihood.lower() in high_values:
            return "high"
        return "moderate"


def build_threat_model() -> list[Threat]:
    return [
        Threat(
            name="Credential stuffing",
            asset="User accounts",
            attack_surface="Login endpoint",
            impact="high",
            likelihood="high",
            controls=[
                "Password hashing",
                "Rate limiting",
                "Multi-factor authentication",
                "Monitoring",
            ],
        ),
        Threat(
            name="Path traversal",
            asset="Private files",
            attack_surface="File download endpoint",
            impact="high",
            likelihood="medium",
            controls=[
                "Canonical path validation",
                "Allowlisted filenames",
                "Sandboxed storage",
            ],
        ),
        Threat(
            name="Tampered API message",
            asset="Transaction request",
            attack_surface="Application message boundary",
            impact="high",
            likelihood="medium",
            controls=[
                "HMAC authentication",
                "Nonce validation",
                "Timestamp validation",
            ],
        ),
        Threat(
            name="Denial of service",
            asset="Application availability",
            attack_surface="Public API",
            impact="high",
            likelihood="medium",
            controls=[
                "Rate limiting",
                "Request size limits",
                "Resource quotas",
            ],
        ),
    ]


def demonstrate_threat_model() -> None:
    print("\n=== Threat Model ===")
    for threat in build_threat_model():
        print(
            f"{threat.name}: asset={threat.asset}, "
            f"surface={threat.attack_surface}, priority={threat.priority}"
        )
        print(f"  Controls: {', '.join(threat.controls)}")


# ---------------------------------------------------------------------------
# Input validation and canonicalization
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when untrusted input violates an application security rule."""


def validate_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValidationError("Username must be text")

    normalized = username.strip()

    if not 3 <= len(normalized) <= 32:
        raise ValidationError("Username length must be between 3 and 32")

    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if any(character not in allowed for character in normalized):
        raise ValidationError("Username contains unsupported characters")

    return normalized


def validate_amount(amount: Any) -> int:
    """
    A security boundary should reject ambiguous numeric representations.
    Using an integer here prevents values such as NaN or infinity from
    entering a transaction calculation.
    """
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise ValidationError("Amount must be an integer")

    if not 1 <= amount <= 1_000_000:
        raise ValidationError("Amount is outside the permitted range")

    return amount


def demonstrate_validation() -> None:
    print("\n=== Input Validation ===")

    valid_values = ["atul_pandey", "security-user", "analyst01"]
    invalid_values = ["../admin", "user name", "x", "admin!"]

    for value in valid_values:
        print(f"Accepted username: {validate_username(value)}")

    for value in invalid_values:
        try:
            validate_username(value)
        except ValidationError as exc:
            print(f"Rejected username {value!r}: {exc}")


def safe_join(base_directory: Path, requested_name: str) -> Path:
    """
    Canonicalization converts path representations into an absolute,
    normalized representation before the security decision is made.
    """
    if not requested_name or "\x00" in requested_name:
        raise ValidationError("Invalid filename")

    base = base_directory.resolve()
    candidate = (base / requested_name).resolve()

    try:
        candidate.relative_to(base)
    except ValueError as exc:
        raise ValidationError("Path escapes the permitted directory") from exc

    return candidate


def demonstrate_path_traversal_defense() -> None:
    print("\n=== Path Traversal Defense ===")

    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        (base / "report.txt").write_text("private report", encoding="utf-8")

        for requested in ["report.txt", "../report.txt", "../../etc/passwd"]:
            try:
                safe_path = safe_join(base, requested)
                print(f"Allowed path: {safe_path.name}")
            except ValidationError as exc:
                print(f"Blocked {requested!r}: {exc}")


# ---------------------------------------------------------------------------
# Password security
# ---------------------------------------------------------------------------

@dataclass
class PasswordRecord:
    username: str
    salt: bytes
    password_hash: bytes
    iterations: int


class PasswordHasher:
    """
    PBKDF2 is available in the Python standard library and is suitable for
    demonstrating salted password derivation. A production system should
    choose a password-specific KDF such as Argon2id when available.
    """

    def __init__(self, iterations: int = 600_000) -> None:
        if iterations < 100_000:
            raise ValueError("Password KDF cost is too low")
        self.iterations = iterations

    def create(self, username: str, password: str) -> PasswordRecord:
        if len(password) < 12:
            raise ValidationError("Password must contain at least 12 characters")

        salt = secrets.token_bytes(16)
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.iterations,
        )

        return PasswordRecord(
            username=username,
            salt=salt,
            password_hash=derived,
            iterations=self.iterations,
        )

    def verify(self, password: str, record: PasswordRecord) -> bool:
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            record.salt,
            record.iterations,
        )
        return hmac.compare_digest(candidate, record.password_hash)


def demonstrate_password_security() -> None:
    print("\n=== Password Hashing ===")

    hasher = PasswordHasher(iterations=600_000)
    record = hasher.create("atul", "Correct-Horse-Battery-7")

    print(f"Salt bytes: {len(record.salt)}")
    print(f"Hash bytes: {len(record.password_hash)}")
    print(f"Correct password: {hasher.verify('Correct-Horse-Battery-7', record)}")
    print(f"Wrong password: {hasher.verify('wrong-password', record)}")


# ---------------------------------------------------------------------------
# Authentication, authorization, and least privilege
# ---------------------------------------------------------------------------

@dataclass
class User:
    username: str
    roles: set[str]
    active: bool = True


ROLE_PERMISSIONS = {
    "viewer": {"read:reports"},
    "analyst": {"read:reports", "create:reports"},
    "admin": {
        "read:reports",
        "create:reports",
        "delete:reports",
        "manage:users",
    },
}


class AuthorizationService:
    def allowed(self, user: User, permission: str) -> bool:
        if not user.active:
            return False

        effective_permissions: set[str] = set()
        for role in user.roles:
            effective_permissions.update(ROLE_PERMISSIONS.get(role, set()))

        return permission in effective_permissions


def demonstrate_authorization() -> None:
    print("\n=== Authentication and Authorization ===")

    users = [
        User("reader", {"viewer"}),
        User("analyst", {"analyst"}),
        User("administrator", {"admin"}),
    ]

    authorization = AuthorizationService()

    for user in users:
        can_delete = authorization.allowed(user, "delete:reports")
        can_read = authorization.allowed(user, "read:reports")
        print(
            f"{user.username}: read={can_read}, "
            f"delete={can_delete}"
        )


# ---------------------------------------------------------------------------
# Secure sessions
# ---------------------------------------------------------------------------

@dataclass
class Session:
    session_id: str
    username: str
    created_at: float
    expires_at: float
    used_nonces: set[str] = field(default_factory=set)


class SessionManager:
    def __init__(self, lifetime_seconds: int = 900) -> None:
        self.lifetime_seconds = lifetime_seconds
        self.sessions: dict[str, Session] = {}

    def create(self, username: str) -> Session:
        now = time.time()
        session_id = secrets.token_urlsafe(32)

        session = Session(
            session_id=session_id,
            username=username,
            created_at=now,
            expires_at=now + self.lifetime_seconds,
        )

        self.sessions[session_id] = session
        return session

    def get_valid(self, session_id: str) -> Session:
        session = self.sessions.get(session_id)

        if session is None:
            raise ValidationError("Unknown session")

        if time.time() >= session.expires_at:
            del self.sessions[session_id]
            raise ValidationError("Session expired")

        return session

    def revoke(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)


def demonstrate_sessions() -> None:
    print("\n=== Session Security ===")

    manager = SessionManager(lifetime_seconds=60)
    session = manager.create("atul")

    print(f"Session identifier length: {len(session.session_id)}")
    print(f"Authenticated user: {manager.get_valid(session.session_id).username}")

    manager.revoke(session.session_id)

    try:
        manager.get_valid(session.session_id)
    except ValidationError as exc:
        print(f"Revoked session rejected: {exc}")


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

class SlidingWindowRateLimiter:
    def __init__(self, limit: int, window_seconds: float) -> None:
        if limit <= 0 or window_seconds <= 0:
            raise ValueError("Rate limiter parameters must be positive")

        self.limit = limit
        self.window_seconds = window_seconds
        self.events: dict[str, list[float]] = {}

    def allow(self, identity: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        timestamps = self.events.setdefault(identity, [])

        cutoff = current - self.window_seconds
        while timestamps and timestamps[0] <= cutoff:
            timestamps.pop(0)

        if len(timestamps) >= self.limit:
            return False

        timestamps.append(current)
        return True


def demonstrate_rate_limiting() -> None:
    print("\n=== Rate Limiting ===")

    limiter = SlidingWindowRateLimiter(limit=3, window_seconds=10)

    for attempt in range(5):
        print(f"Request {attempt + 1}: allowed={limiter.allow('192.0.2.10', now=100)}")


# ---------------------------------------------------------------------------
# Integrity protection
# ---------------------------------------------------------------------------

class MessageAuthenticator:
    def __init__(self, secret_key: bytes) -> None:
        if len(secret_key) < 32:
            raise ValueError("HMAC key should contain at least 256 bits")
        self.secret_key = secret_key

    def sign(self, message: bytes) -> str:
        mac = hmac.new(self.secret_key, message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii")

    def verify(self, message: bytes, signature: str) -> bool:
        try:
            supplied = base64.urlsafe_b64decode(signature.encode("ascii"))
        except Exception:
            return False

        expected = hmac.new(
            self.secret_key,
            message,
            hashlib.sha256,
        ).digest()

        return hmac.compare_digest(supplied, expected)


def demonstrate_integrity() -> None:
    print("\n=== Message Integrity ===")

    authenticator = MessageAuthenticator(secrets.token_bytes(32))
    message = b'{"operation":"transfer","amount":250}'
    signature = authenticator.sign(message)

    print(f"Original accepted: {authenticator.verify(message, signature)}")

    tampered = b'{"operation":"transfer","amount":250000}'
    print(f"Tampered accepted: {authenticator.verify(tampered, signature)}")


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

class ReplayGuard:
    def __init__(self, maximum_age_seconds: int = 300) -> None:
        self.maximum_age_seconds = maximum_age_seconds
        self.seen: dict[str, float] = {}

    def accept(self, nonce: str, timestamp: float, now: float) -> bool:
        if abs(now - timestamp) > self.maximum_age_seconds:
            return False

        if nonce in self.seen:
            return False

        self.seen[nonce] = now
        return True


def demonstrate_replay_protection() -> None:
    print("\n=== Replay Protection ===")

    guard = ReplayGuard(maximum_age_seconds=300)
    nonce = secrets.token_urlsafe(16)

    print(f"First request: {guard.accept(nonce, 1000, 1001)}")
    print(f"Replay request: {guard.accept(nonce, 1000, 1002)}")
    print(f"Expired request: {guard.accept('old', 1000, 1401)}")


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

class AuditLogger:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def record(
        self,
        event_type: str,
        actor: str,
        outcome: str,
        resource: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.events.append(
            {
                "timestamp": time.time(),
                "event_type": event_type,
                "actor": actor,
                "outcome": outcome,
                "resource": resource,
                "metadata": metadata or {},
            }
        )

    def export_json(self) -> str:
        return json.dumps(self.events, indent=2)


def demonstrate_audit_logging() -> None:
    print("\n=== Security Audit Logging ===")

    logger = AuditLogger()
    logger.record(
        event_type="authentication",
        actor="atul",
        outcome="success",
        resource="account",
        metadata={"method": "password"},
    )
    logger.record(
        event_type="authorization",
        actor="reader",
        outcome="denied",
        resource="reports/delete",
        metadata={"required_permission": "delete:reports"},
    )

    print(logger.export_json())


# ---------------------------------------------------------------------------
# Secret handling
# ---------------------------------------------------------------------------

def load_secret_from_environment(name: str) -> str:
    """
    Secrets should not be embedded directly in source code. Environment
    variables are still only one secret-management option; production
    deployments often use a dedicated secret manager.
    """
    value = os.environ.get(name)

    if not value:
        raise RuntimeError(f"Required secret {name!r} is unavailable")

    return value


def demonstrate_secret_handling() -> None:
    print("\n=== Secret Handling ===")

    os.environ["SECURITY_DEMO_KEY"] = "loaded-at-runtime-not-hard-coded-in-code"

    secret = load_secret_from_environment("SECURITY_DEMO_KEY")
    print(f"Secret loaded successfully: {bool(secret)}")


# ---------------------------------------------------------------------------
# Secure transaction workflow
# ---------------------------------------------------------------------------

@dataclass
class TransactionRequest:
    actor: User
    destination: str
    amount: int
    nonce: str
    timestamp: float
    payload: bytes
    signature: str


class SecureTransactionService:
    def __init__(self, hmac_key: bytes) -> None:
        self.authorization = AuthorizationService()
        self.authenticator = MessageAuthenticator(hmac_key)
        self.replay_guard = ReplayGuard(maximum_age_seconds=300)

    def process(
        self,
        request: TransactionRequest,
        now: float,
    ) -> str:
        if not request.actor.active:
            return "rejected: inactive account"

        if not self.authorization.allowed(request.actor, "create:reports"):
            return "rejected: insufficient privilege"

        try:
            validate_username(request.destination)
            validate_amount(request.amount)
        except ValidationError as exc:
            return f"rejected: invalid input ({exc})"

        if not self.replay_guard.accept(
            request.nonce,
            request.timestamp,
            now,
        ):
            return "rejected: replay or stale request"

        if not self.authenticator.verify(
            request.payload,
            request.signature,
        ):
            return "rejected: invalid integrity signature"

        return "accepted"


def demonstrate_secure_workflow() -> None:
    print("\n=== Layered Secure Workflow ===")

    key = secrets.token_bytes(32)
    service = SecureTransactionService(key)

    actor = User("analyst", {"analyst"})
    payload = b'{"destination":"secure_account","amount":500}'
    signature = MessageAuthenticator(key).sign(payload)

    request = TransactionRequest(
        actor=actor,
        destination="secure_account",
        amount=500,
        nonce=secrets.token_urlsafe(16),
        timestamp=1000,
        payload=payload,
        signature=signature,
    )

    print(service.process(request, now=1001))

    print(
        "Replay attempt:",
        service.process(request, now=1002),
    )


# ---------------------------------------------------------------------------
# Security decision table
# ---------------------------------------------------------------------------

def evaluate_security_controls() -> None:
    print("\n=== Security Control Mapping ===")

    controls = {
        "Untrusted input": "Validate syntax, range, encoding, and canonical form",
        "Passwords": "Use salted, deliberately expensive password KDFs",
        "Privileges": "Check authorization for every protected operation",
        "Sessions": "Use unpredictable identifiers, expiration, and revocation",
        "Messages": "Authenticate integrity with HMAC or an authenticated protocol",
        "Repeated requests": "Apply rate and resource limits",
        "Sensitive actions": "Record security-relevant audit events",
        "Secrets": "Keep credentials outside source code",
        "Files": "Resolve canonical paths and enforce a storage boundary",
    }

    for threat, control in controls.items():
        print(f"{threat}: {control}")


# ---------------------------------------------------------------------------
# Testable assertions
# ---------------------------------------------------------------------------

def run_security_assertions() -> None:
    assert validate_username("security_user") == "security_user"

    try:
        validate_username("../admin")
    except ValidationError:
        pass
    else:
        raise AssertionError("Traversal-like username should be rejected")

    assert validate_amount(100) == 100

    try:
        validate_amount(-1)
    except ValidationError:
        pass
    else:
        raise AssertionError("Negative transaction amount should be rejected")

    hasher = PasswordHasher(iterations=100_000)
    record = hasher.create("tester", "strong-password-123")
    assert hasher.verify("strong-password-123", record)
    assert not hasher.verify("wrong-password", record)

    limiter = SlidingWindowRateLimiter(2, 10)
    assert limiter.allow("client", now=0)
    assert limiter.allow("client", now=1)
    assert not limiter.allow("client", now=2)

    key = secrets.token_bytes(32)
    authenticator = MessageAuthenticator(key)
    message = b"security-message"
    signature = authenticator.sign(message)
    assert authenticator.verify(message, signature)
    assert not authenticator.verify(b"modified-message", signature)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("SECURITY THREATS AND BASIC SECURITY PRINCIPLES")
    print("=" * 54)

    demonstrate_cia_triad()
    demonstrate_threat_model()
    demonstrate_validation()
    demonstrate_path_traversal_defense()
    demonstrate_password_security()
    demonstrate_authorization()
    demonstrate_sessions()
    demonstrate_rate_limiting()
    demonstrate_integrity()
    demonstrate_replay_protection()
    demonstrate_audit_logging()
    demonstrate_secret_handling()
    demonstrate_secure_workflow()
    evaluate_security_controls()

    print("\n=== Security Assertions ===")
    run_security_assertions()
    print("All security assertions passed.")

    print("\nThe demonstrations show a layered security model:")
    print("validation -> authentication -> authorization -> integrity ->")
    print("replay protection -> rate limiting -> auditing")


if __name__ == "__main__":
    main()
