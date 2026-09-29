"""
Non-Repudiation: A Complete Python Study and Demonstration

This standalone program teaches non-repudiation from foundational concepts through
cryptographic signatures, hashing, evidence records, verification, key management,
tamper detection, replay considerations, audit trails, and a small evidence-aware
transaction system.

The examples use only Python's standard library.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import secrets
import textwrap
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. FOUNDATIONS
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def explain(text: str) -> None:
    print(textwrap.fill(text, width=76))


def canonical_json(value: Any) -> bytes:
    """
    Canonical JSON gives logically equivalent records a deterministic byte
    representation.

    Important: a digital signature signs bytes, not an abstract Python object.
    If two systems serialize the same object differently, their signatures can
    fail verification even though the human-visible information looks equal.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 2. BASIC HASHING
# ---------------------------------------------------------------------------

def demonstrate_hashing() -> None:
    section("1. Cryptographic Hashing")

    message = "Approve purchase order PO-1007 for INR 250000."
    digest = sha256_hex(message.encode())

    print("Message:", message)
    print("SHA-256:", digest)

    modified_message = "Approve purchase order PO-1007 for INR 250001."
    modified_digest = sha256_hex(modified_message.encode())

    print("\nChanged message:", modified_message)
    print("Changed SHA-256:", modified_digest)
    print("Digest changed:", digest != modified_digest)

    explain(
        "A cryptographic hash creates a fixed-length digest from input data. "
        "Hashing supports integrity evidence, but a hash alone does not prove "
        "who created the data. Non-repudiation normally requires stronger "
        "evidence, such as a digital signature tied to an identifiable signing key."
    )


# ---------------------------------------------------------------------------
# 3. HMAC: AUTHENTICATION, BUT NOT THE SAME AS PUBLIC-KEY NON-REPUDIATION
# ---------------------------------------------------------------------------

def demonstrate_hmac() -> None:
    section("2. HMAC and the Non-Repudiation Distinction")

    shared_secret = secrets.token_bytes(32)
    message = b"Transfer INR 50000 from account A to account B."

    tag = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(
        tag,
        hmac.new(shared_secret, message, hashlib.sha256).hexdigest(),
    )

    print("HMAC:", tag)
    print("Verification:", valid)

    explain(
        "HMAC provides message authentication and integrity to parties sharing "
        "the secret. It does not normally provide the same non-repudiation "
        "property as a public-key digital signature. Both parties possess the "
        "same secret, so a verifier cannot cryptographically distinguish which "
        "party generated a valid HMAC."
    )


# ---------------------------------------------------------------------------
# 4. DIGITAL SIGNATURES
# ---------------------------------------------------------------------------

class SignatureScheme:
    """
    A small RSA-like educational signature implementation.

    This is intentionally a teaching implementation, not production cryptography.
    Real systems should use established libraries and standardized algorithms
    such as RSA-PSS, ECDSA, or Ed25519.
    """

    def __init__(self, p: int = 1000003, q: int = 1000033) -> None:
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)

        # 65537 is a common RSA public exponent. We choose different small
        # educational primes only so the arithmetic remains understandable.
        self.e = 65537

        if self._gcd(self.e, self.phi) != 1:
            raise ValueError("Educational parameters are incompatible.")

        self.d = pow(self.e, -1, self.phi)

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    def digest_as_integer(self, message: bytes) -> int:
        digest = hashlib.sha256(message).digest()
        return int.from_bytes(digest, "big") % self.n

    def sign(self, message: bytes) -> int:
        digest_number = self.digest_as_integer(message)
        return pow(digest_number, self.d, self.n)

    def verify(self, message: bytes, signature: int) -> bool:
        expected = self.digest_as_integer(message)
        recovered = pow(signature, self.e, self.n)
        return recovered == expected


def demonstrate_digital_signature() -> None:
    section("3. Digital Signature Fundamentals")

    signer = SignatureScheme()

    message = b"Employee 417 approved invoice INV-9001."
    signature = signer.sign(message)

    print("Public key components:")
    print("  n =", signer.n)
    print("  e =", signer.e)
    print("Signature:", signature)
    print("Valid signature:", signer.verify(message, signature))

    altered_message = b"Employee 417 approved invoice INV-9002."
    print("After message modification:", signer.verify(altered_message, signature))

    explain(
        "A digital signature is generated with a private signing key and checked "
        "with a corresponding public verification key. The signature protects "
        "the signed representation of the message. If the message changes, "
        "verification should fail."
    )


# ---------------------------------------------------------------------------
# 5. IDENTITY, KEY OWNERSHIP, AND TRUST
# ---------------------------------------------------------------------------

@dataclass
class PublicKeyCertificate:
    subject: str
    public_key_fingerprint: str
    issuer: str
    serial_number: str
    valid_from: str
    valid_until: str
    status: str = "VALID"


def demonstrate_identity_binding() -> None:
    section("4. Identity Binding")

    key_material = secrets.token_bytes(32)
    fingerprint = sha256_hex(key_material)

    certificate = PublicKeyCertificate(
        subject="alice@example.test",
        public_key_fingerprint=fingerprint,
        issuer="Example Corporate CA",
        serial_number=uuid.uuid4().hex,
        valid_from=utc_now(),
        valid_until="2030-12-31T23:59:59+00:00",
    )

    print(json.dumps(asdict(certificate), indent=2))

    explain(
        "A signature proves possession of a private key, but a non-repudiation "
        "argument often also requires evidence connecting the public key to a "
        "real-world identity. Certificates, registration records, controlled "
        "key issuance, identity verification, and trustworthy key directories "
        "can contribute to that binding."
    )


# ---------------------------------------------------------------------------
# 6. SIGNED BUSINESS RECORDS
# ---------------------------------------------------------------------------

@dataclass
class SignedRecord:
    record_id: str
    signer_id: str
    event_type: str
    payload: Dict[str, Any]
    created_at: str
    sequence_number: int
    previous_record_hash: Optional[str]
    payload_hash: str
    signature: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def unsigned_representation(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("signature", None)
        return data


class EvidenceLedger:
    """
    Append-only logical ledger.

    It is not a blockchain and does not magically guarantee legal
    non-repudiation. It demonstrates how cryptographic evidence can be
    organized so later modifications become detectable.
    """

    def __init__(self, signer: SignatureScheme, signer_id: str) -> None:
        self.signer = signer
        self.signer_id = signer_id
        self.records: List[SignedRecord] = []

    def create_record(
        self,
        event_type: str,
        payload: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SignedRecord:
        payload_bytes = canonical_json(payload)
        payload_hash = sha256_hex(payload_bytes)

        previous_hash = None
        if self.records:
            previous_hash = sha256_hex(
                canonical_json(self.records[-1].unsigned_representation())
            )

        record = SignedRecord(
            record_id=str(uuid.uuid4()),
            signer_id=self.signer_id,
            event_type=event_type,
            payload=copy.deepcopy(payload),
            created_at=utc_now(),
            sequence_number=len(self.records) + 1,
            previous_record_hash=previous_hash,
            payload_hash=payload_hash,
            metadata=metadata or {},
        )

        unsigned_bytes = canonical_json(record.unsigned_representation())
        record.signature = str(self.signer.sign(unsigned_bytes))
        self.records.append(record)
        return record

    def verify_record(self, record: SignedRecord) -> Tuple[bool, str]:
        if sha256_hex(canonical_json(record.payload)) != record.payload_hash:
            return False, "Payload hash mismatch."

        unsigned_bytes = canonical_json(record.unsigned_representation())

        try:
            signature = int(record.signature)
        except ValueError:
            return False, "Signature is not a valid integer."

        if not self.signer.verify(unsigned_bytes, signature):
            return False, "Digital signature verification failed."

        return True, "Record signature and payload integrity are valid."

    def verify_chain(self) -> List[Tuple[str, bool, str]]:
        results: List[Tuple[str, bool, str]] = []

        for index, record in enumerate(self.records):
            valid, reason = self.verify_record(record)

            if not valid:
                results.append((record.record_id, False, reason))
                continue

            if index == 0:
                if record.previous_record_hash is not None:
                    results.append(
                        (
                            record.record_id,
                            False,
                            "First record unexpectedly has a previous hash.",
                        )
                    )
                    continue
            else:
                expected_previous = sha256_hex(
                    canonical_json(self.records[index - 1].unsigned_representation())
                )
                if record.previous_record_hash != expected_previous:
                    results.append(
                        (
                            record.record_id,
                            False,
                            "Previous-record hash mismatch.",
                        )
                    )
                    continue

            results.append((record.record_id, True, "Chain links are valid."))

        return results


def demonstrate_signed_ledger() -> EvidenceLedger:
    section("5. Signed Records and an Evidence Chain")

    signer = SignatureScheme()
    ledger = EvidenceLedger(signer, "alice@example.test")

    first = ledger.create_record(
        "PURCHASE_APPROVAL",
        {
            "purchase_order": "PO-1007",
            "amount": 250000,
            "currency": "INR",
            "approved": True,
        },
        {"application": "procurement-system", "source": "web"},
    )

    second = ledger.create_record(
        "PAYMENT_RELEASE",
        {
            "purchase_order": "PO-1007",
            "amount": 250000,
            "currency": "INR",
            "released": True,
        },
        {"application": "finance-system"},
    )

    print("First record:")
    print(json.dumps(asdict(first), indent=2))

    print("\nSecond record:")
    print(json.dumps(asdict(second), indent=2))

    print("\nVerification:")
    for record_id, valid, reason in ledger.verify_chain():
        print(record_id, "VALID" if valid else "INVALID", reason)

    return ledger


# ---------------------------------------------------------------------------
# 7. TAMPERING AND DETECTION
# ---------------------------------------------------------------------------

def demonstrate_tampering(ledger: EvidenceLedger) -> None:
    section("6. Tampering Detection")

    original_amount = ledger.records[0].payload["amount"]

    print("Original amount:", original_amount)
    ledger.records[0].payload["amount"] = 999999999

    valid, reason = ledger.verify_record(ledger.records[0])
    print("After payload tampering:")
    print("Valid:", valid)
    print("Reason:", reason)

    # Restore the payload so subsequent examples operate on valid evidence.
    ledger.records[0].payload["amount"] = original_amount

    original_signer = ledger.records[1].signer_id
    ledger.records[1].signer_id = "attacker@example.test"

    valid, reason = ledger.verify_record(ledger.records[1])
    print("\nAfter signer identity modification:")
    print("Valid:", valid)
    print("Reason:", reason)

    ledger.records[1].signer_id = original_signer


# ---------------------------------------------------------------------------
# 8. REPLAY AND FRESHNESS
# ---------------------------------------------------------------------------

@dataclass
class ReplayProtectedRequest:
    request_id: str
    nonce: str
    issued_at: float
    expires_at: float
    operation: str
    parameters: Dict[str, Any]


class RequestValidator:
    def __init__(self, allowed_clock_skew_seconds: int = 60) -> None:
        self.allowed_clock_skew_seconds = allowed_clock_skew_seconds
        self.seen_nonces: set[str] = set()

    def validate(
        self,
        request: ReplayProtectedRequest,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        current = time.time() if now is None else now

        if request.nonce in self.seen_nonces:
            return False, "Replay detected: nonce has already been used."

        if request.issued_at > current + self.allowed_clock_skew_seconds:
            return False, "Request timestamp is too far in the future."

        if request.expires_at < current - self.allowed_clock_skew_seconds:
            return False, "Request has expired."

        if request.expires_at <= request.issued_at:
            return False, "Invalid request lifetime."

        self.seen_nonces.add(request.nonce)
        return True, "Request freshness checks passed."


def demonstrate_replay_protection() -> None:
    section("7. Replay Protection")

    validator = RequestValidator()

    now = time.time()

    request = ReplayProtectedRequest(
        request_id=str(uuid.uuid4()),
        nonce=secrets.token_urlsafe(16),
        issued_at=now,
        expires_at=now + 300,
        operation="RELEASE_PAYMENT",
        parameters={"payment_id": "PAY-1007", "amount": 250000},
    )

    first_valid, first_reason = validator.validate(request, now)
    second_valid, second_reason = validator.validate(request, now)

    print("First submission:", first_valid, first_reason)
    print("Second submission:", second_valid, second_reason)

    explain(
        "Non-repudiation does not automatically prevent replay. A valid signature "
        "can remain valid when an attacker copies the signed message and submits "
        "it again. Nonces, unique identifiers, timestamps, sequence numbers, "
        "expiration windows, and server-side state can provide freshness controls."
    )


# ---------------------------------------------------------------------------
# 9. KEY LIFECYCLE
# ---------------------------------------------------------------------------

@dataclass
class KeyStatus:
    key_id: str
    owner: str
    status: str
    created_at: str
    expires_at: str
    revoked_at: Optional[str] = None


class KeyRegistry:
    def __init__(self) -> None:
        self.keys: Dict[str, KeyStatus] = {}

    def register(
        self,
        owner: str,
        lifetime_days: int = 365,
    ) -> KeyStatus:
        key_id = "key-" + uuid.uuid4().hex[:12]
        created = datetime.now(timezone.utc)
        expires = created.timestamp() + lifetime_days * 86400

        status = KeyStatus(
            key_id=key_id,
            owner=owner,
            status="ACTIVE",
            created_at=created.isoformat(),
            expires_at=datetime.fromtimestamp(
                expires,
                tz=timezone.utc,
            ).isoformat(),
        )

        self.keys[key_id] = status
        return status

    def revoke(self, key_id: str) -> None:
        key = self.keys[key_id]
        key.status = "REVOKED"
        key.revoked_at = utc_now()

    def can_verify_for_new_event(self, key_id: str) -> bool:
        key = self.keys[key_id]
        return key.status == "ACTIVE"


def demonstrate_key_lifecycle() -> None:
    section("8. Key Lifecycle")

    registry = KeyRegistry()
    key = registry.register("alice@example.test", lifetime_days=365)

    print("Registered:", json.dumps(asdict(key), indent=2))
    print("Active:", registry.can_verify_for_new_event(key.key_id))

    registry.revoke(key.key_id)

    print("\nAfter revocation:")
    print(json.dumps(asdict(key), indent=2))
    print("Active:", registry.can_verify_for_new_event(key.key_id))

    explain(
        "Signing-key management is central to non-repudiation. Systems need "
        "controlled generation, secure storage, activation, rotation, expiration, "
        "revocation, backup, recovery, and evidence of historical key status. "
        "A signature should not be interpreted without considering the relevant "
        "key's lifecycle and the time of the signed event."
    )


# ---------------------------------------------------------------------------
# 10. TRUSTED TIME AND TIMESTAMPING
# ---------------------------------------------------------------------------

@dataclass
class TimestampEvidence:
    record_hash: str
    timestamp: str
    timestamp_authority: str
    authority_token: str


def create_timestamp_evidence(record: SignedRecord) -> TimestampEvidence:
    record_hash = sha256_hex(canonical_json(record.unsigned_representation()))

    # This is a local simulation. A production timestamp token would be
    # produced by a trusted timestamping service using its own signing key.
    token_input = (
        record_hash
        + "|"
        + utc_now()
        + "|"
        + "Example Timestamp Authority"
    ).encode()

    authority_token = sha256_hex(token_input)

    return TimestampEvidence(
        record_hash=record_hash,
        timestamp=utc_now(),
        timestamp_authority="Example Timestamp Authority",
        authority_token=authority_token,
    )


def demonstrate_timestamping(ledger: EvidenceLedger) -> None:
    section("9. Trusted Timestamping")

    evidence = create_timestamp_evidence(ledger.records[0])

    print(json.dumps(asdict(evidence), indent=2))

    explain(
        "A trusted timestamp can provide evidence that specific data existed "
        "in a particular time context. The local hash simulation here is not a "
        "real trusted timestamp service. Production systems use independently "
        "operated timestamp authorities or equivalent trusted infrastructure."
    )


# ---------------------------------------------------------------------------
# 11. AUDIT TRAILS
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    event_id: str
    actor: str
    action: str
    resource: str
    timestamp: str
    result: str
    evidence_hash: str


class AuditLog:
    def __init__(self) -> None:
        self.events: List[AuditEvent] = []

    def append(
        self,
        actor: str,
        action: str,
        resource: str,
        result: str,
        evidence: Dict[str, Any],
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            actor=actor,
            action=action,
            resource=resource,
            timestamp=utc_now(),
            result=result,
            evidence_hash=sha256_hex(canonical_json(evidence)),
        )
        self.events.append(event)
        return event

    def search(self, actor: Optional[str] = None) -> List[AuditEvent]:
        if actor is None:
            return list(self.events)
        return [event for event in self.events if event.actor == actor]


def demonstrate_audit_log() -> None:
    section("10. Audit Evidence")

    audit = AuditLog()

    audit.append(
        actor="alice@example.test",
        action="SIGN",
        resource="PO-1007",
        result="SUCCESS",
        evidence={"amount": 250000, "currency": "INR"},
    )

    audit.append(
        actor="system@example.test",
        action="VERIFY",
        resource="PO-1007",
        result="SUCCESS",
        evidence={"signature_valid": True},
    )

    for event in audit.search():
        print(json.dumps(asdict(event), indent=2))


# ---------------------------------------------------------------------------
# 12. SECURITY CONSIDERATIONS
# ---------------------------------------------------------------------------

def demonstrate_security_properties() -> None:
    section("11. Security Properties and Failure Modes")

    examples = {
        "confidentiality": "Usually provided by encryption, not signatures.",
        "integrity": "Detecting unauthorized modification.",
        "authentication": "Binding an action to a credential or identity.",
        "non_repudiation": "Evidence intended to make denial difficult or legally
        /technically contestable, subject to system and legal context.",
        "availability": "Keeping systems and evidence accessible.",
    }

    for property_name, meaning in examples.items():
        print(f"{property_name}: {meaning}")

    explain(
        "Non-repudiation should not be confused with confidentiality. Digital "
        "signatures normally provide integrity and origin authentication, while "
        "encryption addresses confidentiality. The strength of a non-repudiation "
        "claim also depends on identity proofing, key protection, trustworthy "
        "verification, auditability, time evidence, policy, and applicable law."
    )


# ---------------------------------------------------------------------------
# 13. VERIFICATION REPORT
# ---------------------------------------------------------------------------

def build_verification_report(ledger: EvidenceLedger) -> Dict[str, Any]:
    results = ledger.verify_chain()

    valid_count = sum(1 for _, valid, _ in results if valid)
    invalid_count = len(results) - valid_count

    return {
        "verified_at": utc_now(),
        "record_count": len(results),
        "valid_records": valid_count,
        "invalid_records": invalid_count,
        "chain_valid": invalid_count == 0,
        "records": [
            {
                "record_id": record_id,
                "valid": valid,
                "reason": reason,
            }
            for record_id, valid, reason in results
        ],
    }


# ---------------------------------------------------------------------------
# 14. UNIT-STYLE TESTS
# ---------------------------------------------------------------------------

def run_tests() -> None:
    section("12. Self-Tests")

    signer = SignatureScheme()
    message = b"test message"

    assert signer.verify(message, signer.sign(message))
    assert not signer.verify(b"modified message", signer.sign(message))

    ledger = EvidenceLedger(signer, "tester@example.test")
    record = ledger.create_record(
        "TEST",
        {"value": 42},
    )

    valid, _ = ledger.verify_record(record)
    assert valid

    record.payload["value"] = 43
    valid, _ = ledger.verify_record(record)
    assert not valid

    validator = RequestValidator()
    now = time.time()

    request = ReplayProtectedRequest(
        request_id="req-1",
        nonce="unique-nonce",
        issued_at=now,
        expires_at=now + 60,
        operation="TEST",
        parameters={},
    )

    assert validator.validate(request, now)[0]
    assert not validator.validate(request, now)[0]

    print("All self-tests passed.")


# ---------------------------------------------------------------------------
# 15. PRACTICAL WORKFLOW
# ---------------------------------------------------------------------------

def demonstrate_end_to_end_workflow() -> None:
    section("13. End-to-End Non-Repudiation Workflow")

    signer = SignatureScheme()
    ledger = EvidenceLedger(signer, "approver@example.test")

    business_event = {
        "document_id": "CONTRACT-2026-0042",
        "document_version": 7,
        "action": "APPROVE",
        "amount": 1250000,
        "currency": "INR",
        "decision": "APPROVED",
    }

    record = ledger.create_record(
        event_type="DOCUMENT_APPROVAL",
        payload=business_event,
        metadata={
            "application": "contract-management",
            "authentication_method": "certificate-backed-key",
        },
    )

    timestamp = create_timestamp_evidence(record)
    report = build_verification_report(ledger)

    print("Record ID:", record.record_id)
    print("Signer:", record.signer_id)
    print("Payload hash:", record.payload_hash)
    print("Signature valid:", ledger.verify_record(record)[0])
    print("Timestamp authority:", timestamp.timestamp_authority)
    print("Chain valid:", report["chain_valid"])

    explain(
        "A realistic evidence workflow starts with a precisely defined business "
        "event, serializes the event deterministically, hashes and signs the "
        "result, stores identity and key metadata, records audit information, "
        "adds trusted time evidence where required, and preserves the resulting "
        "evidence under controlled retention and access policies."
    )


# ---------------------------------------------------------------------------
# 16. LIMITATIONS AND EDGE CASES
# ---------------------------------------------------------------------------

def demonstrate_edge_cases() -> None:
    section("14. Edge Cases and Limitations")

    cases = [
        (
            "Same meaning, different serialization",
            '{"amount":100,"currency":"INR"}',
            '{"currency":"INR","amount":100}',
        ),
        (
            "Whitespace modification",
            "APPROVE",
            " APPROVE ",
        ),
        (
            "Case modification",
            "Approved",
            "approved",
        ),
    ]

    for name, first, second in cases:
        first_hash = sha256_hex(first.encode())
        second_hash = sha256_hex(second.encode())

        print(name)
        print("  First digest :", first_hash)
        print("  Second digest:", second_hash)
        print("  Equal:", first_hash == second_hash)

    explain(
        "Evidence systems must define exactly what is signed. Human-readable "
        "documents can contain ambiguous formatting, metadata, Unicode variants, "
        "line endings, hidden fields, or dynamically generated content. "
        "Canonicalization reduces ambiguity, but the canonicalization rules "
        "themselves become part of the protocol."
    )


# ---------------------------------------------------------------------------
# 17. PERFORMANCE
# ---------------------------------------------------------------------------

def benchmark_hashing() -> None:
    section("15. Basic Performance Measurement")

    data = b"x" * 1_000_000
    start = time.perf_counter()

    digest = hashlib.sha256(data).hexdigest()

    elapsed = time.perf_counter() - start

    print("Input size:", len(data), "bytes")
    print("SHA-256:", digest)
    print(f"Hashing time: {elapsed:.6f} seconds")

    explain(
        "Hashing is generally much cheaper than public-key signing, so systems "
        "usually hash large documents and sign the digest or a standardized "
        "signature structure rather than repeatedly processing the full document "
        "with an expensive asymmetric operation."
    )


# ---------------------------------------------------------------------------
# 18. MAIN
# ---------------------------------------------------------------------------

def main() -> None:
    print("NON-REPUDIATION: PYTHON STUDY PROGRAM")
    print("Standard-library implementation and executable demonstrations.")

    demonstrate_hashing()
    demonstrate_hmac()
    demonstrate_digital_signature()
    demonstrate_identity_binding()

    ledger = demonstrate_signed_ledger()
    demonstrate_tampering(ledger)
    demonstrate_replay_protection()
    demonstrate_key_lifecycle()
    demonstrate_timestamping(ledger)
    demonstrate_audit_log()
    demonstrate_security_properties()

    report = build_verification_report(ledger)

    section("16. Final Verification Report")
    print(json.dumps(report, indent=2))

    run_tests()
    demonstrate_end_to_end_workflow()
    demonstrate_edge_cases()
    benchmark_hashing()

    section("Study Checklist")
    checklist = [
        "Hashing and integrity",
        "HMAC versus digital signatures",
        "Private and public signing keys",
        "Identity and certificate binding",
        "Canonical serialization",
        "Signed business records",
        "Append-only evidence chains",
        "Tamper detection",
        "Replay protection",
        "Key lifecycle management",
        "Timestamp evidence",
        "Audit trails",
        "Verification reports",
        "Security and confidentiality distinctions",
        "Performance and operational considerations",
    ]

    for item in checklist:
        print("[x]", item)


if __name__ == "__main__":
    main()
