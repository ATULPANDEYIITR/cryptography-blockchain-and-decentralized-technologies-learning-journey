"""
CONFIDENTIALITY
===============

A comprehensive, executable study of confidentiality in information security.

This script progresses from beginner concepts to practical and advanced
implementations involving:

- Confidentiality fundamentals
- Information classification
- Access control
- Authentication and authorization
- Least privilege
- Data at rest, in transit, and in use
- Symmetric encryption
- A self-contained educational encryption implementation
- One-time pads
- Hashing versus encryption
- Password handling
- Key management concepts
- Digital signatures and confidentiality distinction
- Access-control models
- Data minimization
- Secure logging
- Threat modeling
- Information leakage
- Side-channel considerations
- Secure deletion limitations
- Secure application design
- Performance considerations
- Security testing
- A practical end-to-end confidentiality workflow

The program intentionally uses only Python's standard library. The
cryptographic demonstrations are educational and are not intended to replace
well-reviewed production cryptographic libraries.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import statistics
import string
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Optional


# ============================================================================
# 1. FUNDAMENTAL DEFINITIONS
# ============================================================================

def section(title: str) -> None:
    """Print a consistent section heading."""
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain_fundamentals() -> None:
    section("1. FUNDAMENTALS OF CONFIDENTIALITY")

    definitions = {
        "Confidentiality":
            "Information is accessible only to authorized subjects.",
        "Asset":
            "Something valuable that needs protection, such as customer data.",
        "Threat":
            "A potential cause of unwanted disclosure.",
        "Vulnerability":
            "A weakness that could permit unauthorized disclosure.",
        "Control":
            "A safeguard that reduces security risk.",
        "Authorization":
            "A decision about what an authenticated subject is allowed to do.",
        "Authentication":
            "Verification of the identity of a subject.",
        "Encryption":
            "Transformation of readable plaintext into protected ciphertext.",
        "Decryption":
            "Transformation of ciphertext back into plaintext using a key.",
        "Least privilege":
            "Granting only the access required to perform an authorized task.",
        "Data minimization":
            "Collecting and retaining only information that is necessary.",
    }

    for term, meaning in definitions.items():
        print(f"{term}: {meaning}")

    print("\nThe CIA triad contains three distinct security objectives:")
    print("  Confidentiality -> prevent unauthorized disclosure.")
    print("  Integrity      -> prevent unauthorized alteration.")
    print("  Availability   -> keep authorized services and information usable.")

    print("\nConfidentiality is therefore not synonymous with encryption.")
    print("Encryption is one control. Access control, authentication,")
    print("classification, secure storage, privacy practices, and monitoring")
    print("also contribute to confidentiality.")


# ============================================================================
# 2. INFORMATION CLASSIFICATION
# ============================================================================

class Classification(Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"


@dataclass
class InformationAsset:
    name: str
    owner: str
    classification: Classification
    description: str
    retention_days: int
    encryption_required: bool


def demonstrate_classification() -> list[InformationAsset]:
    section("2. INFORMATION CLASSIFICATION")

    assets = [
        InformationAsset(
            name="Company website",
            owner="Marketing",
            classification=Classification.PUBLIC,
            description="Information intentionally published to everyone.",
            retention_days=3650,
            encryption_required=False,
        ),
        InformationAsset(
            name="Internal engineering documentation",
            owner="Engineering",
            classification=Classification.INTERNAL,
            description="Useful to employees but not intended for public release.",
            retention_days=1825,
            encryption_required=True,
        ),
        InformationAsset(
            name="Customer contract",
            owner="Legal",
            classification=Classification.CONFIDENTIAL,
            description="Business information requiring controlled access.",
            retention_days=2555,
            encryption_required=True,
        ),
        InformationAsset(
            name="Authentication secret",
            owner="Security",
            classification=Classification.RESTRICTED,
            description="Highly sensitive information requiring strict controls.",
            retention_days=90,
            encryption_required=True,
        ),
    ]

    for asset in assets:
        print(
            f"{asset.name:35} | "
            f"{asset.classification.value:11} | "
            f"encryption={asset.encryption_required}"
        )

    return assets


# ============================================================================
# 3. AUTHENTICATION AND AUTHORIZATION
# ============================================================================

@dataclass(frozen=True)
class User:
    username: str
    roles: frozenset[str]


class AuthorizationEngine:
    """
    Simple role-based access-control demonstration.

    Authentication answers:
        "Who are you?"

    Authorization answers:
        "What are you allowed to access?"
    """

    def __init__(self) -> None:
        self.permissions: dict[str, set[str]] = defaultdict(set)

    def grant(self, role: str, permission: str) -> None:
        self.permissions[role].add(permission)

    def is_allowed(self, user: User, permission: str) -> bool:
        return any(
            permission in self.permissions.get(role, set())
            for role in user.roles
        )


def demonstrate_authorization() -> None:
    section("3. AUTHENTICATION AND AUTHORIZATION")

    access = AuthorizationEngine()

    access.grant("analyst", "read_reports")
    access.grant("manager", "read_reports")
    access.grant("manager", "approve_reports")
    access.grant("security_admin", "read_audit_logs")
    access.grant("security_admin", "rotate_keys")

    analyst = User("alice", frozenset({"analyst"}))
    manager = User("bob", frozenset({"manager"}))
    administrator = User(
        "carol",
        frozenset({"security_admin"}),
    )

    checks = [
        (analyst, "read_reports"),
        (analyst, "rotate_keys"),
        (manager, "approve_reports"),
        (administrator, "read_audit_logs"),
    ]

    for user, permission in checks:
        print(
            f"{user.username:12} -> {permission:20} -> "
            f"{'ALLOW' if access.is_allowed(user, permission) else 'DENY'}"
        )


# ============================================================================
# 4. LEAST PRIVILEGE
# ============================================================================

def demonstrate_least_privilege() -> None:
    section("4. LEAST PRIVILEGE")

    broad_permissions = {
        "database_user": {
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "ALTER",
        }
    }

    minimal_permissions = {
        "reporting_user": {
            "SELECT",
        }
    }

    print("Broad database permissions:", broad_permissions["database_user"])
    print("Minimal reporting permissions:", minimal_permissions["reporting_user"])

    print(
        "\nA reporting application that only needs to read data should not "
        "receive destructive database privileges."
    )


# ============================================================================
# 5. DATA STATES
# ============================================================================

def demonstrate_data_states() -> None:
    section("5. DATA AT REST, IN TRANSIT, AND IN USE")

    states = {
        "Data at rest": [
            "database records",
            "files",
            "backups",
            "laptops",
            "object-storage objects",
        ],
        "Data in transit": [
            "browser to server",
            "server to server",
            "API calls",
            "database connections",
        ],
        "Data in use": [
            "plaintext in application memory",
            "data being processed",
            "temporary application structures",
        ],
    }

    for state, examples in states.items():
        print(f"\n{state}:")
        for example in examples:
            print(f"  - {example}")

    print(
        "\nConfidentiality requires controls appropriate to each state. "
        "Encrypting a database does not automatically protect plaintext "
        "while an authorized application is processing it."
    )


# ============================================================================
# 6. EDUCATIONAL XOR ENCRYPTION
# ============================================================================

def xor_transform(data: bytes, key: bytes) -> bytes:
    """
    Educational symmetric transformation.

    XOR is useful for learning the mechanics of reversible transformations,
    but this function is NOT secure encryption. Reusing keys or using short
    predictable keys can expose plaintext relationships.
    """
    if not key:
        raise ValueError("The key cannot be empty.")

    return bytes(
        byte ^ key[index % len(key)]
        for index, byte in enumerate(data)
    )


def demonstrate_xor() -> None:
    section("6. EDUCATIONAL SYMMETRIC ENCRYPTION")

    plaintext = b"Confidential engineering document"
    key = b"training-key"

    ciphertext = xor_transform(plaintext, key)
    recovered = xor_transform(ciphertext, key)

    print("Plaintext :", plaintext.decode())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered.decode())

    assert recovered == plaintext

    print(
        "\nThis demonstration shows reversibility, but XOR with a reused "
        "ordinary key is not a production encryption design."
    )


# ============================================================================
# 7. ONE-TIME PAD CONCEPT
# ============================================================================

def one_time_pad_encrypt(message: bytes, key: bytes) -> bytes:
    """
    Demonstrates the one-time-pad transformation.

    For theoretical perfect secrecy, the key must:
    - be truly random,
    - be at least as long as the plaintext,
    - remain secret,
    - never be reused.
    """
    if len(key) != len(message):
        raise ValueError("One-time-pad key must equal message length.")

    return bytes(a ^ b for a, b in zip(message, key))


def demonstrate_one_time_pad() -> None:
    section("7. ONE-TIME PAD")

    plaintext = b"TOP SECRET"
    key = secrets.token_bytes(len(plaintext))

    ciphertext = one_time_pad_encrypt(plaintext, key)
    recovered = one_time_pad_encrypt(ciphertext, key)

    print("Plaintext :", plaintext.decode())
    print("Random key:", key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered.decode())

    print(
        "\nThe mathematical property is strong, but practical key "
        "distribution and secure key reuse prevention make one-time pads "
        "difficult to deploy at scale."
    )


# ============================================================================
# 8. HASHING VERSUS ENCRYPTION
# ============================================================================

def demonstrate_hashing() -> None:
    section("8. HASHING VERSUS ENCRYPTION")

    message = b"confidential record"

    digest = hashlib.sha256(message).hexdigest()

    print("Message :", message.decode())
    print("SHA-256 :", digest)
    print("\nHashing is designed as a one-way transformation.")
    print("Encryption is designed to permit recovery using the correct key.")
    print("A SHA-256 digest is not a replacement for encryption.")

    altered_message = b"confidential record."
    altered_digest = hashlib.sha256(altered_message).hexdigest()

    print("\nOne-character change:")
    print("Original:", digest)
    print("Altered :", altered_digest)
    print("Different:", digest != altered_digest)


# ============================================================================
# 9. PASSWORD HANDLING
# ============================================================================

def derive_password_verifier(
    password: str,
    salt: bytes,
    iterations: int = 300_000,
) -> bytes:
    """
    Educational password-verifier construction using PBKDF2-HMAC-SHA256.

    Real systems should choose password-hashing parameters based on current
    threat models and available infrastructure. Memory-hard password hashing
    such as Argon2id is commonly preferred where available.
    """
    if iterations <= 0:
        raise ValueError("Iterations must be positive.")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )


def verify_password(
    password: str,
    salt: bytes,
    expected_verifier: bytes,
    iterations: int = 300_000,
) -> bool:
    candidate = derive_password_verifier(
        password,
        salt,
        iterations,
    )
    return hmac.compare_digest(candidate, expected_verifier)


def demonstrate_password_storage() -> None:
    section("9. PASSWORD STORAGE")

    password = "Correct-Horse-Battery-Staple"
    salt = secrets.token_bytes(16)

    verifier = derive_password_verifier(password, salt)

    print("Salt:", salt.hex())
    print("Stored verifier:", verifier.hex())

    print(
        "Correct password:",
        verify_password(password, salt, verifier),
    )

    print(
        "Incorrect password:",
        verify_password("wrong-password", salt, verifier),
    )

    print(
        "\nA password should generally not be stored as plaintext or "
        "as a reversible encrypted value merely to authenticate users."
    )


# ============================================================================
# 10. SECRET GENERATION
# ============================================================================

def demonstrate_secure_randomness() -> None:
    section("10. SECURE RANDOMNESS")

    token = secrets.token_urlsafe(32)
    session_identifier = secrets.token_hex(32)

    print("Example random token:", token)
    print("Example random identifier:", session_identifier)

    print(
        "\nThe secrets module is intended for security-sensitive random "
        "values. The random module is intended for ordinary simulations "
        "and is not a cryptographic random-number generator."
    )


# ============================================================================
# 11. ACCESS CONTROL MODELS
# ============================================================================

@dataclass
class Resource:
    identifier: str
    owner: str
    classification: Classification


def demonstrate_access_control_models() -> None:
    section("11. ACCESS-CONTROL MODELS")

    models = {
        "DAC":
            "Discretionary Access Control: resource owners can control access.",
        "MAC":
            "Mandatory Access Control: policy and security labels control access.",
        "RBAC":
            "Role-Based Access Control: permissions are associated with roles.",
        "ABAC":
            "Attribute-Based Access Control: decisions use attributes and policy.",
    }

    for model, description in models.items():
        print(f"{model}: {description}")

    resource = Resource(
        identifier="customer-001",
        owner="sales",
        classification=Classification.CONFIDENTIAL,
    )

    print(
        f"\nExample resource: {resource.identifier}, "
        f"classification={resource.classification.value}"
    )


# ============================================================================
# 12. ATTRIBUTE-BASED ACCESS CONTROL
# ============================================================================

@dataclass(frozen=True)
class AccessRequest:
    subject_department: str
    subject_clearance: int
    resource_department: str
    resource_classification: Classification
    requested_action: str
    business_hours: bool


CLASSIFICATION_LEVEL = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}


def abac_policy(request: AccessRequest) -> bool:
    """
    Simplified ABAC policy.

    Conditions:
    - clearance must meet classification;
    - confidential/restricted data requires business hours;
    - destructive operations are not allowed by this policy;
    - cross-department access is allowed only for public/internal data.
    """
    required_level = CLASSIFICATION_LEVEL[request.resource_classification]

    if request.subject_clearance < required_level:
        return False

    if request.requested_action in {"delete", "export"}:
        return False

    if (
        request.resource_classification
        in {Classification.CONFIDENTIAL, Classification.RESTRICTED}
        and not request.business_hours
    ):
        return False

    if (
        request.subject_department != request.resource_department
        and required_level >= CLASSIFICATION_LEVEL[Classification.CONFIDENTIAL]
    ):
        return False

    return True


def demonstrate_abac() -> None:
    section("12. ATTRIBUTE-BASED ACCESS CONTROL")

    requests = [
        AccessRequest(
            "finance", 2, "finance",
            Classification.CONFIDENTIAL, "read", True
        ),
        AccessRequest(
            "finance", 2, "finance",
            Classification.CONFIDENTIAL, "read", False
        ),
        AccessRequest(
            "engineering", 3, "finance",
            Classification.RESTRICTED, "read", True
        ),
        AccessRequest(
            "finance", 2, "finance",
            Classification.CONFIDENTIAL, "delete", True
        ),
    ]

    for request in requests:
        print(
            request,
            "=>",
            "ALLOW" if abac_policy(request) else "DENY",
        )


# ============================================================================
# 13. DATA MINIMIZATION
# ============================================================================

def minimize_record(record: dict[str, object]) -> dict[str, object]:
    """
    Keep only fields required by a hypothetical shipment workflow.

    Data minimization reduces the quantity of information that could be
    exposed by a compromise.
    """
    allowed_fields = {
        "customer_id",
        "name",
        "shipping_address",
        "order_id",
    }

    return {
        key: value
        for key, value in record.items()
        if key in allowed_fields
    }


def demonstrate_data_minimization() -> None:
    section("13. DATA MINIMIZATION")

    customer_record = {
        "customer_id": "C-1001",
        "name": "Example Customer",
        "shipping_address": "100 Example Street",
        "order_id": "O-2001",
        "passport_number": "SENSITIVE",
        "bank_account": "SENSITIVE",
        "private_notes": "SENSITIVE",
    }

    minimized = minimize_record(customer_record)

    print("Original fields :", list(customer_record))
    print("Required fields :", list(minimized))
    print("Reduced record  :", minimized)


# ============================================================================
# 14. SECURE LOGGING
# ============================================================================

SENSITIVE_FIELD_NAMES = {
    "password",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "private_key",
    "session_id",
}


def redact_for_log(record: dict[str, object]) -> dict[str, object]:
    """Remove or mask known sensitive values before logging."""
    result: dict[str, object] = {}

    for key, value in record.items():
        if key.lower() in SENSITIVE_FIELD_NAMES:
            result[key] = "[REDACTED]"
        else:
            result[key] = value

    return result


def demonstrate_secure_logging() -> None:
    section("14. SECURE LOGGING")

    event = {
        "event": "login",
        "username": "alice",
        "password": "Never-log-this",
        "session_id": "secret-session-value",
        "source_ip": "192.0.2.10",
    }

    print("Safe log record:")
    print(redact_for_log(event))

    print(
        "\nLogs are often copied into monitoring systems, backups, "
        "support tools, and developer environments. Sensitive values "
        "should therefore not be logged unnecessarily."
    )


# ============================================================================
# 15. CONFIDENTIALITY LEAKAGE
# ============================================================================

def demonstrate_information_leakage() -> None:
    section("15. INFORMATION LEAKAGE")

    examples = [
        "Passwords printed in logs",
        "Sensitive data included in error messages",
        "Database backups stored without protection",
        "Secrets embedded in source code",
        "Excessive API response fields",
        "Autocomplete or search results exposing private records",
        "Unprotected temporary files",
        "Screenshots containing confidential information",
        "Metadata revealing sensitive operational information",
        "Verbose debugging output in production",
    ]

    for example in examples:
        print(" -", example)


# ============================================================================
# 16. SECURE FILE HANDLING
# ============================================================================

def write_confidential_file(path: Path, content: str) -> None:
    """
    Demonstrate restrictive local file permissions where the operating
    system supports POSIX-style permission bits.

    This does not provide encryption.
    """
    path.write_text(content, encoding="utf-8")

    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows and some filesystems may not provide equivalent semantics.
        pass


def demonstrate_file_handling() -> None:
    section("16. CONFIDENTIAL FILE HANDLING")

    path = Path("confidential_training_example.txt")

    try:
        write_confidential_file(
            path,
            "This file contains confidential training information.\n",
        )

        print("Created:", path)
        print("File content:", path.read_text(encoding="utf-8").strip())

        print(
            "\nFile permissions are an access-control mechanism. They are "
            "not equivalent to encryption and should not be treated as such."
        )
    finally:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


# ============================================================================
# 17. DIGITAL SIGNATURE DISTINCTION
# ============================================================================

def demonstrate_integrity_vs_confidentiality() -> None:
    section("17. CONFIDENTIALITY VERSUS INTEGRITY")

    message = b"Transfer 100 units to account A."

    digest = hashlib.sha256(message).hexdigest()

    print("Original message:", message.decode())
    print("Digest:", digest)

    modified = b"Transfer 900 units to account A."
    modified_digest = hashlib.sha256(modified).hexdigest()

    print("Modified message:", modified.decode())
    print("Digest changed:", digest != modified_digest)

    print(
        "\nA hash can help detect changes, but it does not make the message "
        "confidential. Anyone who can see the plaintext can still read it."
    )


# ============================================================================
# 18. AUTHENTICATED ENCRYPTION CONCEPT
# ============================================================================

def educational_authenticated_encryption(
    plaintext: bytes,
    encryption_key: bytes,
    authentication_key: bytes,
) -> tuple[bytes, bytes]:
    """
    Educational composition showing confidentiality plus authenticity.

    This is NOT a replacement for an AEAD construction such as AES-GCM or
    ChaCha20-Poly1305. It demonstrates why encryption and authentication
    address different security properties.

    A production system should use a vetted AEAD implementation rather than
    designing its own construction.
    """
    ciphertext = xor_transform(plaintext, encryption_key)

    tag = hmac.new(
        authentication_key,
        ciphertext,
        hashlib.sha256,
    ).digest()

    return ciphertext, tag


def educational_authenticated_decryption(
    ciphertext: bytes,
    tag: bytes,
    encryption_key: bytes,
    authentication_key: bytes,
) -> bytes:
    expected_tag = hmac.new(
        authentication_key,
        ciphertext,
        hashlib.sha256,
    ).digest()

    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Authentication failed.")

    return xor_transform(ciphertext, encryption_key)


def demonstrate_authenticated_encryption() -> None:
    section("18. CONFIDENTIALITY PLUS AUTHENTICITY")

    plaintext = b"Confidential payroll data"
    encryption_key = secrets.token_bytes(16)
    authentication_key = secrets.token_bytes(32)

    ciphertext, tag = educational_authenticated_encryption(
        plaintext,
        encryption_key,
        authentication_key,
    )

    recovered = educational_authenticated_decryption(
        ciphertext,
        tag,
        encryption_key,
        authentication_key,
    )

    print("Ciphertext:", ciphertext.hex())
    print("Authentication tag:", tag.hex())
    print("Recovered:", recovered.decode())

    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    try:
        educational_authenticated_decryption(
            bytes(tampered),
            tag,
            encryption_key,
            authentication_key,
        )
    except ValueError as exc:
        print("Tampering detected:", exc)


# ============================================================================
# 19. KEY MANAGEMENT
# ============================================================================

@dataclass
class KeyMetadata:
    key_id: str
    created_at: float
    purpose: str
    status: str
    version: int


class KeyRegistry:
    """
    Demonstration of key metadata management.

    Actual secret keys should be protected by a dedicated key-management
    system, hardware security module, or appropriately secured secret store.
    """

    def __init__(self) -> None:
        self._metadata: dict[str, KeyMetadata] = {}

    def register(self, purpose: str) -> str:
        key_id = secrets.token_hex(12)

        self._metadata[key_id] = KeyMetadata(
            key_id=key_id,
            created_at=time.time(),
            purpose=purpose,
            status="active",
            version=1,
        )

        return key_id

    def rotate(self, key_id: str) -> None:
        metadata = self._metadata[key_id]
        metadata.version += 1
        metadata.created_at = time.time()

    def revoke(self, key_id: str) -> None:
        self._metadata[key_id].status = "revoked"

    def get(self, key_id: str) -> KeyMetadata:
        return self._metadata[key_id]


def demonstrate_key_management() -> None:
    section("19. KEY MANAGEMENT")

    registry = KeyRegistry()
    key_id = registry.register("database encryption")

    print("Created:", registry.get(key_id))

    registry.rotate(key_id)
    print("After rotation:", registry.get(key_id))

    registry.revoke(key_id)
    print("After revocation:", registry.get(key_id))

    print(
        "\nKey management includes generation, distribution, storage, "
        "rotation, revocation, backup, recovery, usage restrictions, "
        "auditing, and eventual destruction."
    )


# ============================================================================
# 20. THREAT MODELING
# ============================================================================

@dataclass
class Threat:
    name: str
    asset: str
    attack_vector: str
    impact: str
    likelihood: str
    controls: list[str]


def demonstrate_threat_modeling() -> None:
    section("20. CONFIDENTIALITY THREAT MODEL")

    threats = [
        Threat(
            name="Stolen credentials",
            asset="Customer portal",
            attack_vector="Credential compromise",
            impact="Unauthorized access to customer data",
            likelihood="Medium",
            controls=[
                "MFA",
                "rate limiting",
                "strong authentication",
                "session protection",
            ],
        ),
        Threat(
            name="Lost laptop",
            asset="Local customer files",
            attack_vector="Physical loss",
            impact="Offline disclosure",
            likelihood="Medium",
            controls=[
                "full-disk encryption",
                "device management",
                "screen lock",
            ],
        ),
        Threat(
            name="Misconfigured storage",
            asset="Cloud backups",
            attack_vector="Public exposure",
            impact="Bulk disclosure",
            likelihood="Medium",
            controls=[
                "private-by-default storage",
                "policy checks",
                "access reviews",
            ],
        ),
    ]

    for threat in threats:
        print(f"\nThreat: {threat.name}")
        print(f"  Asset: {threat.asset}")
        print(f"  Vector: {threat.attack_vector}")
        print(f"  Impact: {threat.impact}")
        print(f"  Likelihood: {threat.likelihood}")
        print("  Controls:", ", ".join(threat.controls))


# ============================================================================
# 21. SECURE DATA ACCESS SERVICE
# ============================================================================

@dataclass
class ConfidentialRecord:
    record_id: str
    owner: str
    classification: Classification
    content: str


class ConfidentialRecordService:
    """
    Small end-to-end example combining:
    - identity,
    - authorization,
    - classification,
    - least privilege,
    - audit logging,
    - minimization of returned information.
    """

    def __init__(self) -> None:
        self.records: dict[str, ConfidentialRecord] = {}
        self.audit_log: list[dict[str, object]] = []

    def add_record(self, record: ConfidentialRecord) -> None:
        self.records[record.record_id] = record

    def read_record(
        self,
        user: User,
        record_id: str,
        permitted_roles: set[str],
    ) -> Optional[dict[str, object]]:
        record = self.records.get(record_id)

        if record is None:
            self._audit(user.username, record_id, "not_found")
            return None

        if not (set(user.roles) & permitted_roles):
            self._audit(user.username, record_id, "denied")
            return None

        self._audit(user.username, record_id, "allowed")

        # Return only fields required by the caller.
        return {
            "record_id": record.record_id,
            "classification": record.classification.value,
            "content": record.content,
        }

    def _audit(
        self,
        username: str,
        record_id: str,
        result: str,
    ) -> None:
        self.audit_log.append(
            {
                "timestamp": time.time(),
                "username": username,
                "record_id": record_id,
                "result": result,
            }
        )


def demonstrate_end_to_end_service() -> None:
    section("21. END-TO-END CONFIDENTIAL RECORD SERVICE")

    service = ConfidentialRecordService()

    service.add_record(
        ConfidentialRecord(
            record_id="CASE-001",
            owner="security",
            classification=Classification.CONFIDENTIAL,
            content="Investigation material.",
        )
    )

    authorized_user = User(
        username="security-analyst",
        roles=frozenset({"security_analyst"}),
    )

    unauthorized_user = User(
        username="marketing-user",
        roles=frozenset({"marketing"}),
    )

    permitted_roles = {"security_analyst", "security_manager"}

    print(
        "Authorized result:",
        service.read_record(
            authorized_user,
            "CASE-001",
            permitted_roles,
        ),
    )

    print(
        "Unauthorized result:",
        service.read_record(
            unauthorized_user,
            "CASE-001",
            permitted_roles,
        ),
    )

    print("\nAudit records:")
    for event in service.audit_log:
        print(event)


# ============================================================================
# 22. TIMING-SAFE COMPARISON
# ============================================================================

def demonstrate_constant_time_comparison() -> None:
    section("22. TIMING-SAFE SECRET COMPARISON")

    expected = secrets.token_bytes(32)
    candidate = bytes(expected)

    print(
        "Ordinary equality:",
        candidate == expected,
    )

    print(
        "Constant-time comparison:",
        hmac.compare_digest(candidate, expected),
    )

    print(
        "\nFor security-sensitive secret comparisons, compare_digest can "
        "reduce timing side-channel risks compared with ordinary comparison."
    )


# ============================================================================
# 23. SIDE-CHANNEL AWARENESS
# ============================================================================

def explain_side_channels() -> None:
    section("23. SIDE-CHANNEL CONSIDERATIONS")

    channels = {
        "Timing":
            "Execution time can reveal information about secret-dependent operations.",
        "Memory access":
            "Cache behavior can sometimes reveal which secret-dependent paths were used.",
        "Power":
            "Physical devices may leak information through power consumption.",
        "Electromagnetic":
            "Electronic emissions can reveal implementation details in some environments.",
        "Errors":
            "Different error messages can reveal whether protected information exists.",
        "Metadata":
            "File size, timing, sender, recipient, or traffic patterns can reveal context.",
    }

    for channel, description in channels.items():
        print(f"{channel}: {description}")


# ============================================================================
# 24. SECURE DELETION LIMITATIONS
# ============================================================================

def explain_secure_deletion() -> None:
    section("24. SECURE DELETION LIMITATIONS")

    print("Deleting a filename does not necessarily destroy underlying data.")
    print("Copies may exist in:")
    print("  - backups")
    print("  - snapshots")
    print("  - caches")
    print("  - replication systems")
    print("  - temporary files")
    print("  - logs")
    print("  - version histories")

    print(
        "\nEncryption with controlled key destruction can sometimes make "
        "retained ciphertext computationally inaccessible, but key "
        "destruction must itself be reliable and appropriately designed."
    )


# ============================================================================
# 25. CONFIDENTIALITY POLICY
# ============================================================================

@dataclass
class ConfidentialityPolicy:
    classification: Classification
    allowed_roles: set[str]
    encryption_required: bool
    retention_days: int
    audit_required: bool


def evaluate_policy(
    policy: ConfidentialityPolicy,
    user: User,
) -> bool:
    return bool(policy.allowed_roles & set(user.roles))


def demonstrate_policy_engine() -> None:
    section("25. CONFIDENTIALITY POLICY ENGINE")

    policy = ConfidentialityPolicy(
        classification=Classification.RESTRICTED,
        allowed_roles={"security_manager", "security_admin"},
        encryption_required=True,
        retention_days=90,
        audit_required=True,
    )

    users = [
        User("analyst", frozenset({"security_analyst"})),
        User("manager", frozenset({"security_manager"})),
        User("admin", frozenset({"security_admin"})),
    ]

    for user in users:
        print(
            f"{user.username:10} -> "
            f"{'ALLOW' if evaluate_policy(policy, user) else 'DENY'}"
        )


# ============================================================================
# 26. CONFIDENTIALITY TESTING
# ============================================================================

def run_confidentiality_tests() -> None:
    section("26. AUTOMATED CONFIDENTIALITY TESTS")

    # Access-control test.
    engine = AuthorizationEngine()
    engine.grant("reader", "read_confidential")

    reader = User("reader-user", frozenset({"reader"}))
    attacker = User("attacker", frozenset({"guest"}))

    assert engine.is_allowed(reader, "read_confidential")
    assert not engine.is_allowed(attacker, "read_confidential")

    # Encryption round-trip test.
    plaintext = b"secret"
    key = b"safe-key"
    encrypted = xor_transform(plaintext, key)
    assert xor_transform(encrypted, key) == plaintext

    # Password verification test.
    password = "secret-password"
    salt = secrets.token_bytes(16)
    verifier = derive_password_verifier(password, salt)

    assert verify_password(password, salt, verifier)
    assert not verify_password("wrong", salt, verifier)

    # Authentication tag test.
    encryption_key = secrets.token_bytes(16)
    authentication_key = secrets.token_bytes(32)

    ciphertext, tag = educational_authenticated_encryption(
        plaintext,
        encryption_key,
        authentication_key,
    )

    assert (
        educational_authenticated_decryption(
            ciphertext,
            tag,
            encryption_key,
            authentication_key,
        )
        == plaintext
    )

    print("All confidentiality tests passed.")


# ============================================================================
# 27. PERFORMANCE CONSIDERATIONS
# ============================================================================

def benchmark_hashing() -> None:
    section("27. PERFORMANCE CONSIDERATIONS")

    payload = os.urandom(1024 * 1024)
    repetitions = 5

    durations = []

    for _ in range(repetitions):
        start = time.perf_counter()
        hashlib.sha256(payload).digest()
        durations.append(time.perf_counter() - start)

    print(
        f"SHA-256 of 1 MiB, {repetitions} runs: "
        f"average={statistics.mean(durations):.6f}s"
    )

    print(
        "\nSecurity controls have operational costs. Stronger password "
        "derivation intentionally consumes more computational resources, "
        "while encryption may consume CPU, memory, and latency."
    )


# ============================================================================
# 28. SECURITY DESIGN CHECKLIST
# ============================================================================

def print_design_checklist() -> None:
    section("28. CONFIDENTIALITY DESIGN CHECKLIST")

    checklist = [
        "Classify sensitive information.",
        "Identify who should access each information category.",
        "Authenticate users and services.",
        "Authorize every sensitive operation.",
        "Apply least privilege.",
        "Encrypt sensitive data where appropriate.",
        "Protect encryption keys separately from encrypted data.",
        "Use authenticated encryption for protected application data.",
        "Protect data in transit using appropriate secure protocols.",
        "Avoid logging secrets.",
        "Minimize collected and returned data.",
        "Review access permissions regularly.",
        "Protect backups and replicas.",
        "Control retention and disposal.",
        "Monitor access to sensitive resources.",
        "Test denial paths as well as successful paths.",
        "Handle errors without revealing sensitive details.",
        "Consider metadata and side channels.",
        "Document assumptions and trust boundaries.",
        "Plan key rotation and revocation.",
    ]

    for index, item in enumerate(checklist, start=1):
        print(f"{index:02d}. {item}")


# ============================================================================
# 29. MAIN STUDY PROGRAM
# ============================================================================

def main() -> None:
    """
    Execute the complete confidentiality study.

    Each section is intentionally executable so the file can function both
    as reference material and as a practical laboratory.
    """
    explain_fundamentals()
    demonstrate_classification()
    demonstrate_authorization()
    demonstrate_least_privilege()
    demonstrate_data_states()
    demonstrate_xor()
    demonstrate_one_time_pad()
    demonstrate_hashing()
    demonstrate_password_storage()
    demonstrate_secure_randomness()
    demonstrate_access_control_models()
    demonstrate_abac()
    demonstrate_data_minimization()
    demonstrate_secure_logging()
    demonstrate_information_leakage()
    demonstrate_file_handling()
    demonstrate_integrity_vs_confidentiality()
    demonstrate_authenticated_encryption()
    demonstrate_key_management()
    demonstrate_threat_modeling()
    demonstrate_end_to_end_service()
    demonstrate_constant_time_comparison()
    explain_side_channels()
    explain_secure_deletion()
    demonstrate_policy_engine()
    run_confidentiality_tests()
    benchmark_hashing()
    print_design_checklist()

    section("STUDY PROGRAM COMPLETE")
    print("Confidentiality demonstrations completed successfully.")


if __name__ == "__main__":
    main()
