"""
Authentication in Cryptography, Blockchain, and Decentralized Technologies
===========================================================================
A standalone educational implementation progressing from basic authentication
concepts to cryptographic signatures, challenge-response authentication,
password verification, blockchain transaction authentication, Merkle proofs,
nonce/replay protection, and decentralized identity concepts.

The demonstrations intentionally use Python's standard library only.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# ============================================================================
# 1. FUNDAMENTALS
# ============================================================================

def section(title: str) -> None:
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def sha256_hex(message: str) -> str:
    """SHA-256 provides integrity/fingerprint functionality, not authentication."""
    return hashlib.sha256(message.encode("utf-8")).hexdigest()


def demonstrate_integrity_vs_authentication() -> None:
    section("1. Integrity Is Not Authentication")

    message = "Transfer 100 tokens to Alice"
    digest = sha256_hex(message)

    print("Message :", message)
    print("SHA-256 :", digest)

    # Anyone who knows the message can calculate its hash. Therefore a hash
    # alone does not prove who created or approved the message.
    modified = "Transfer 1000 tokens to Alice"
    print("Modified message hash:", sha256_hex(modified))
    print("Hashes differ:", digest != sha256_hex(modified))


# ============================================================================
# 2. PASSWORD AUTHENTICATION
# ============================================================================

class PasswordAuthenticator:
    """
    Educational password verifier.

    PBKDF2 is intentionally used instead of storing plaintext passwords.
    A unique random salt prevents identical passwords from having identical
    stored hashes.

    Production systems should choose parameters based on current security
    guidance and operational requirements.
    """

    def __init__(self, iterations: int = 300_000):
        self.iterations = iterations
        self.users: Dict[str, Tuple[bytes, bytes, int]] = {}

    def register(self, username: str, password: str) -> None:
        if not username or not password:
            raise ValueError("Username and password are required")

        salt = secrets.token_bytes(16)
        derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.iterations,
            dklen=32,
        )
        self.users[username] = (salt, derived_key, self.iterations)

    def authenticate(self, username: str, password: str) -> bool:
        record = self.users.get(username)

        # Returning the same generic result for missing users and bad passwords
        # helps avoid exposing whether an account exists.
        if record is None:
            return False

        salt, expected_key, iterations = record
        supplied_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
            dklen=32,
        )

        # compare_digest is preferable to a simple == comparison for secrets
        # because it is designed for timing-safe comparisons.
        return hmac.compare_digest(supplied_key, expected_key)


def demonstrate_password_authentication() -> None:
    section("2. Password-Based Authentication")

    authenticator = PasswordAuthenticator()
    authenticator.register("alice", "correct horse battery staple")

    print("Correct password:", authenticator.authenticate(
        "alice", "correct horse battery staple"
    ))
    print("Incorrect password:", authenticator.authenticate(
        "alice", "wrong-password"
    ))
    print("Unknown account:", authenticator.authenticate(
        "bob", "correct horse battery staple"
    ))


# ============================================================================
# 3. CHALLENGE-RESPONSE AUTHENTICATION
# ============================================================================

class ChallengeResponseAuthenticator:
    """
    HMAC-based challenge-response demonstration.

    The client and server share a secret. The server sends a fresh random
    challenge. The client proves possession of the secret by calculating an
    HMAC over that challenge.

    The secret itself is never transmitted.
    """

    def __init__(self):
        self.shared_secrets: Dict[str, bytes] = {}
        self.active_challenges: Dict[str, bytes] = {}

    def register(self, identity: str, secret: bytes) -> None:
        self.shared_secrets[identity] = secret

    def issue_challenge(self, identity: str) -> bytes:
        if identity not in self.shared_secrets:
            raise ValueError("Unknown identity")

        challenge = secrets.token_bytes(32)
        self.active_challenges[identity] = challenge
        return challenge

    def create_response(self, identity: str, challenge: bytes) -> str:
        secret = self.shared_secrets[identity]
        return hmac.new(secret, challenge, hashlib.sha256).hexdigest()

    def verify_response(self, identity: str, response: str) -> bool:
        secret = self.shared_secrets.get(identity)
        challenge = self.active_challenges.pop(identity, None)

        if secret is None or challenge is None:
            return False

        expected = hmac.new(secret, challenge, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, response)


def demonstrate_challenge_response() -> None:
    section("3. Challenge-Response Authentication")

    server = ChallengeResponseAuthenticator()
    server.register("device-01", secrets.token_bytes(32))

    challenge = server.issue_challenge("device-01")
    response = server.create_response("device-01", challenge)

    print("Valid response:", server.verify_response("device-01", response))

    # A challenge is single-use. Replaying the same response fails.
    print("Replay attempt:", server.verify_response("device-01", response))


# ============================================================================
# 4. PUBLIC-KEY AUTHENTICATION WITH DIGITAL SIGNATURES
# ============================================================================

# Python's standard library does not provide a production-ready Ed25519
# implementation across supported versions. This educational implementation
# therefore models the protocol using HMAC while clearly separating it from
# the public-key case used by blockchains.
#
# A real public-key system has:
#   private key -> signature
#   public key  -> verification
#
# The private key never needs to be transmitted.

@dataclass
class AuthenticationRequest:
    identity: str
    message: str
    nonce: str


@dataclass
class AuthenticationRecord:
    identity: str
    authenticated: bool
    reason: str


class SignatureProtocolModel:
    """
    Protocol-level model of asymmetric authentication.

    The implementation uses a secret internally so that it remains executable
    using only the Python standard library. It is not a substitute for a real
    Ed25519, ECDSA, RSA, or BLS implementation.
    """

    def __init__(self):
        self.private_material: Dict[str, bytes] = {}
        self.public_identifiers: Dict[str, str] = {}

    def create_identity(self, identity: str) -> str:
        private_material = secrets.token_bytes(32)
        public_identifier = sha256_hex(
            "public:" + base64.b64encode(private_material).decode()
        )[:40]

        self.private_material[identity] = private_material
        self.public_identifiers[identity] = public_identifier
        return public_identifier

    def sign(self, identity: str, message: bytes) -> str:
        private_material = self.private_material[identity]
        return hmac.new(
            private_material,
            message,
            hashlib.sha256,
        ).hexdigest()

    def verify(self, identity: str, message: bytes, signature: str) -> bool:
        if identity not in self.private_material:
            return False

        expected = self.sign(identity, message)
        return hmac.compare_digest(expected, signature)


def demonstrate_signature_authentication() -> None:
    section("4. Cryptographic Signature Authentication")

    protocol = SignatureProtocolModel()
    public_identifier = protocol.create_identity("alice")

    transaction = b"transfer:alice:bob:50:nonce=7"
    signature = protocol.sign("alice", transaction)

    print("Public identifier:", public_identifier)
    print("Signature:", signature)
    print("Valid signature:", protocol.verify("alice", transaction, signature))
    print(
        "Modified transaction:",
        protocol.verify("alice", b"transfer:alice:bob:500:nonce=7", signature),
    )


# ============================================================================
# 5. NONCES AND REPLAY PROTECTION
# ============================================================================

@dataclass
class Account:
    address: str
    balance: int
    next_nonce: int = 0


@dataclass
class Transaction:
    sender: str
    receiver: str
    amount: int
    nonce: int
    signature: str = ""

    def canonical_payload(self) -> bytes:
        payload = {
            "amount": self.amount,
            "nonce": self.nonce,
            "receiver": self.receiver,
            "sender": self.sender,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class TransactionAuthenticator:
    def __init__(self):
        self.keys: Dict[str, bytes] = {}
        self.accounts: Dict[str, Account] = {}

    def create_account(self, address: str, balance: int) -> None:
        self.keys[address] = secrets.token_bytes(32)
        self.accounts[address] = Account(address, balance)

    def sign_transaction(self, transaction: Transaction) -> None:
        key = self.keys[transaction.sender]
        transaction.signature = hmac.new(
            key,
            transaction.canonical_payload(),
            hashlib.sha256,
        ).hexdigest()

    def verify_transaction(self, transaction: Transaction) -> bool:
        account = self.accounts.get(transaction.sender)
        key = self.keys.get(transaction.sender)

        if account is None or key is None:
            return False

        if transaction.amount <= 0:
            return False

        if transaction.nonce != account.next_nonce:
            return False

        if transaction.amount > account.balance:
            return False

        expected = hmac.new(
            key,
            transaction.canonical_payload(),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected, transaction.signature)

    def apply_transaction(self, transaction: Transaction) -> bool:
        if not self.verify_transaction(transaction):
            return False

        self.accounts[transaction.sender].balance -= transaction.amount
        self.accounts[transaction.receiver].balance += transaction.amount
        self.accounts[transaction.sender].next_nonce += 1
        return True


def demonstrate_replay_protection() -> None:
    section("5. Blockchain-Style Transaction Authentication")

    system = TransactionAuthenticator()
    system.create_account("alice", 100)
    system.create_account("bob", 20)

    transaction = Transaction(
        sender="alice",
        receiver="bob",
        amount=30,
        nonce=0,
    )
    system.sign_transaction(transaction)

    print("First transaction accepted:", system.apply_transaction(transaction))
    print("Alice balance:", system.accounts["alice"].balance)
    print("Bob balance:", system.accounts["bob"].balance)

    # Replaying the identical transaction fails because nonce 0 has already
    # been consumed. This protects against a classic replay attack.
    print("Replay accepted:", system.apply_transaction(transaction))


# ============================================================================
# 6. MERKLE TREES AND AUTHENTICATED DATA
# ============================================================================

def hash_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def merkle_root(items: List[str]) -> str:
    if not items:
        return hashlib.sha256(b"").hexdigest()

    level = [hash_bytes(item.encode()) for item in items]

    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])

        next_level = []
        for index in range(0, len(level), 2):
            next_level.append(hash_bytes(level[index] + level[index + 1]))

        level = next_level

    return level[0].hex()


def demonstrate_authenticated_data() -> None:
    section("6. Merkle Trees and Authentication of Data Sets")

    transactions = [
        "tx-001:alice:bob:10",
        "tx-002:bob:carol:5",
        "tx-003:carol:dave:2",
        "tx-004:dave:alice:1",
    ]

    root = merkle_root(transactions)
    modified_root = merkle_root(transactions[:2] + ["tx-003:carol:dave:200", transactions[3]])

    print("Merkle root:", root)
    print("Root after transaction modification:", modified_root)
    print("Data change detected:", root != modified_root)


# ============================================================================
# 7. DECENTRALIZED IDENTITY
# ============================================================================

@dataclass
class VerifiableCredential:
    issuer: str
    subject: str
    claims: Dict[str, str]
    issued_at: int
    credential_id: str


class IdentityRegistry:
    """
    Simplified decentralized-identity model.

    A real DID/VC system requires standardized DID methods, credential formats,
    cryptographic signatures, key rotation, revocation/status mechanisms,
    privacy controls, and secure key custody.
    """

    def __init__(self):
        self.issuers: Dict[str, bytes] = {}
        self.revoked_credentials: set[str] = set()

    def register_issuer(self, issuer: str) -> None:
        self.issuers[issuer] = secrets.token_bytes(32)

    def issue_credential(
        self,
        issuer: str,
        subject: str,
        claims: Dict[str, str],
    ) -> Tuple[VerifiableCredential, str]:
        if issuer not in self.issuers:
            raise ValueError("Issuer is not registered")

        credential = VerifiableCredential(
            issuer=issuer,
            subject=subject,
            claims=claims,
            issued_at=int(time.time()),
            credential_id=secrets.token_hex(16),
        )

        payload = json.dumps(
            credential.__dict__,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        signature = hmac.new(
            self.issuers[issuer],
            payload,
            hashlib.sha256,
        ).hexdigest()

        return credential, signature

    def verify_credential(
        self,
        credential: VerifiableCredential,
        signature: str,
    ) -> bool:
        if credential.credential_id in self.revoked_credentials:
            return False

        key = self.issuers.get(credential.issuer)
        if key is None:
            return False

        payload = json.dumps(
            credential.__dict__,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)

    def revoke(self, credential_id: str) -> None:
        self.revoked_credentials.add(credential_id)


def demonstrate_decentralized_identity() -> None:
    section("7. Decentralized Identity and Verifiable Credentials")

    registry = IdentityRegistry()
    registry.register_issuer("university.example")

    credential, signature = registry.issue_credential(
        issuer="university.example",
        subject="did:example:alice",
        claims={
            "degree": "MSc",
            "field": "Computer Science",
        },
    )

    print("Credential ID:", credential.credential_id)
    print("Credential valid:", registry.verify_credential(credential, signature))

    registry.revoke(credential.credential_id)
    print("After revocation:", registry.verify_credential(credential, signature))


# ============================================================================
# 8. AUTHENTICATION VS AUTHORIZATION
# ============================================================================

def authorization_example(authenticated_identity: Optional[str], role: str) -> bool:
    """
    Authentication answers: "Who are you?"
    Authorization answers: "What are you allowed to do?"
    """
    if authenticated_identity is None:
        return False

    allowed_roles = {"admin", "auditor"}
    return role in allowed_roles


def demonstrate_authentication_authorization_difference() -> None:
    section("8. Authentication vs Authorization")

    identity = "alice"
    print("Authenticated identity:", identity)
    print("Can access admin function:", authorization_example(identity, "admin"))
    print("Can access random role:", authorization_example(identity, "unknown"))


# ============================================================================
# 9. MULTI-FACTOR AUTHENTICATION CONCEPT
# ============================================================================

class MultiFactorModel:
    """
    Demonstrates the logical structure of MFA.

    Factors are commonly categorized as:
      - knowledge: password/PIN
      - possession: hardware token/device
      - inherence: biometric characteristic

    Two passwords are still two knowledge factors, not genuine MFA.
    """

    def __init__(self):
        self.password_hash = sha256_hex("correct-password")
        self.possession_token = secrets.token_urlsafe(24)

    def authenticate(self, password: str, token: str) -> bool:
        password_valid = hmac.compare_digest(
            sha256_hex(password),
            self.password_hash,
        )
        token_valid = hmac.compare_digest(token, self.possession_token)
        return password_valid and token_valid


def demonstrate_mfa() -> None:
    section("9. Multi-Factor Authentication")

    model = MultiFactorModel()

    print(
        "Both factors valid:",
        model.authenticate("correct-password", model.possession_token),
    )
    print(
        "Wrong possession factor:",
        model.authenticate("correct-password", "wrong-token"),
    )


# ============================================================================
# 10. AUTHENTICATION THREATS
# ============================================================================

def demonstrate_security_threats() -> None:
    section("10. Important Authentication Threats")

    threats = {
        "credential theft": "Attackers obtain passwords, tokens, or private keys.",
        "phishing": "Users are tricked into providing authenticators to an attacker.",
        "replay": "A previously valid message is submitted again.",
        "key compromise": "A private key or shared secret is exposed.",
        "credential stuffing": "Previously leaked passwords are tried on another service.",
        "man-in-the-middle": "Communication is intercepted or altered without proper channel protection.",
        "signature malleability": "A protocol permits multiple representations of a logically equivalent signature.",
        "front-running": "A visible pending transaction is copied or strategically reordered.",
        "sybil attack": "An attacker creates many identities to influence a decentralized system.",
    }

    for name, explanation in threats.items():
        print(f"- {name}: {explanation}")


# ============================================================================
# 11. EDGE CASES AND VALIDATION
# ============================================================================

def validate_transaction(transaction: Transaction) -> List[str]:
    errors = []

    if not transaction.sender:
        errors.append("sender is required")

    if not transaction.receiver:
        errors.append("receiver is required")

    if transaction.amount <= 0:
        errors.append("amount must be positive")

    if transaction.nonce < 0:
        errors.append("nonce cannot be negative")

    if not transaction.signature:
        errors.append("signature is required")

    return errors


def demonstrate_edge_cases() -> None:
    section("11. Edge Cases and Validation")

    cases = [
        Transaction("", "bob", 10, 0),
        Transaction("alice", "bob", 0, 0),
        Transaction("alice", "bob", -10, 0),
        Transaction("alice", "bob", 10, -1),
        Transaction("alice", "bob", 10, 0, ""),
    ]

    for case in cases:
        print(validate_transaction(case))


# ============================================================================
# 12. PERFORMANCE CONSIDERATIONS
# ============================================================================

def benchmark_hashing() -> None:
    section("12. Performance Considerations")

    messages = [f"transaction-{i}" for i in range(10_000)]
    start = time.perf_counter()

    for message in messages:
        hashlib.sha256(message.encode()).digest()

    elapsed = time.perf_counter() - start

    print(f"Hashed {len(messages):,} messages in {elapsed:.6f} seconds")
    print(
        "Observation: cryptographic authentication must balance security "
        "parameters against throughput and latency."
    )


# ============================================================================
# 13. COMPARISON TABLE
# ============================================================================

def print_comparison() -> None:
    section("13. Authentication Mechanism Comparison")

    rows = [
        ("Password", "Knowledge", "Server-side password verifier", "Credential theft"),
        ("HMAC", "Shared secret", "Both parties share a secret", "Secret distribution"),
        ("Digital signature", "Private/public key", "Private key signs; public key verifies", "Private-key compromise"),
        ("Nonce", "Freshness", "Prevents old messages being reused", "Poor nonce management"),
        ("Certificate", "Binding", "Associates identity with a public key", "CA/trust-chain issues"),
        ("DID/VC", "Decentralized identity", "Issuer signs claims for a subject", "Key/status/privacy management"),
    ]

    for mechanism, basis, model, concern in rows:
        print(
            f"{mechanism:20} | {basis:22} | "
            f"{model:40} | {concern}"
        )


# ============================================================================
# 14. STUDY CHECKS
# ============================================================================

def study_questions() -> None:
    section("14. Study Questions")

    questions = [
        "Why does hashing a message not prove who created it?",
        "Why should password verification use a salt?",
        "How does a challenge prevent simple replay?",
        "Why is a private key different from a public identifier?",
        "What role does a transaction nonce play in blockchain systems?",
        "How does a Merkle root detect modification of transaction data?",
        "What is the difference between authentication and authorization?",
        "Why is key custody a critical part of blockchain authentication?",
        "What are the security trade-offs between passwords and cryptographic keys?",
        "Why must a decentralized identity system address credential revocation?",
    ]

    for index, question in enumerate(questions, 1):
        print(f"{index}. {question}")


# ============================================================================
# 15. MAIN
# ============================================================================

def main() -> None:
    demonstrate_integrity_vs_authentication()
    demonstrate_password_authentication()
    demonstrate_challenge_response()
    demonstrate_signature_authentication()
    demonstrate_replay_protection()
    demonstrate_authenticated_data()
    demonstrate_decentralized_identity()
    demonstrate_authentication_authorization_difference()
    demonstrate_mfa()
    demonstrate_security_threats()
    demonstrate_edge_cases()
    benchmark_hashing()
    print_comparison()
    study_questions()


if __name__ == "__main__":
    main()
