"""
Integrity in Cryptography and Blockchain
========================================

A standalone study and executable demonstration of data integrity from
beginner concepts through cryptographic hashes, authenticated data,
Merkle trees, digital signatures, blockchain blocks, proof of work,
tamper detection, validation, and practical security considerations.

The examples intentionally use Python's standard library only.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Iterable


# ============================================================================
# 1. FUNDAMENTALS: WHAT IS INTEGRITY?
# ============================================================================

def explain_integrity() -> None:
    """
    Integrity means confidence that data has not been changed in an
    unauthorized or undetected manner.

    Integrity is different from:
      - Confidentiality: preventing unauthorized disclosure.
      - Availability: keeping systems and data accessible.
      - Authentication: establishing who or what is communicating.
      - Authorization: deciding what an authenticated entity may do.

    A cryptographic integrity mechanism normally makes unauthorized
    modification detectable rather than physically impossible.
    """
    print("\n=== 1. DATA INTEGRITY ===")
    print("Original data : transaction amount = 100")
    print("Modified data : transaction amount = 900")
    print("Integrity goal: detect the unauthorized modification.")


# ============================================================================
# 2. CRYPTOGRAPHIC HASH FUNCTIONS
# ============================================================================

def sha256(data: bytes) -> str:
    """Return the hexadecimal SHA-256 digest of arbitrary bytes."""
    return hashlib.sha256(data).hexdigest()


def demonstrate_hashes() -> None:
    print("\n=== 2. CRYPTOGRAPHIC HASHES ===")

    message_a = b"Transfer 100 coins to Alice"
    message_b = b"Transfer 900 coins to Alice"

    digest_a = sha256(message_a)
    digest_b = sha256(message_b)

    print("Message A:", message_a.decode())
    print("SHA-256 A:", digest_a)
    print("Message B:", message_b.decode())
    print("SHA-256 B:", digest_b)
    print("Digests equal:", digest_a == digest_b)

    # The avalanche effect means a small input change should produce a
    # substantially different digest.
    differing_hex_characters = sum(
        left != right for left, right in zip(digest_a, digest_b)
    )
    print("Different hexadecimal positions:", differing_hex_characters)

    # A digest is a fingerprint, not encryption. It does not provide
    # confidentiality and normally cannot be reversed to recover the input.
    print("Hashing is not encryption: the digest is not a ciphertext.")


# ============================================================================
# 3. SERIALIZATION AND CANONICAL REPRESENTATION
# ============================================================================

def canonical_json(value: Any) -> bytes:
    """
    Serialize JSON deterministically.

    Canonical serialization matters because cryptographic hashes operate on
    bytes, not abstract objects. Equivalent objects represented by different
    byte sequences can have different hashes.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def demonstrate_serialization_integrity() -> None:
    print("\n=== 3. CANONICAL REPRESENTATION ===")

    record = {"amount": 100, "recipient": "Alice", "sender": "Bob"}

    representation_one = json.dumps(record).encode()
    representation_two = canonical_json(record)

    print("Ordinary JSON bytes:", representation_one)
    print("Canonical JSON bytes:", representation_two)
    print("Ordinary hash:", sha256(representation_one))
    print("Canonical hash:", sha256(representation_two))


# ============================================================================
# 4. HASH-BASED INTEGRITY CHECK
# ============================================================================

@dataclass
class IntegrityRecord:
    data: bytes
    digest: str


def create_integrity_record(data: bytes) -> IntegrityRecord:
    return IntegrityRecord(data=data, digest=sha256(data))


def verify_integrity(record: IntegrityRecord) -> bool:
    """
    Recalculate the digest and compare it using constant-time comparison.

    Constant-time comparison is particularly useful when comparing
    authentication-related values because ordinary early-exit comparison
    can reveal information through timing in some threat models.
    """
    calculated = sha256(record.data)
    return hmac.compare_digest(calculated, record.digest)


def demonstrate_tamper_detection() -> None:
    print("\n=== 4. TAMPER DETECTION ===")

    record = create_integrity_record(b"salary=50000;employee=42")
    print("Valid before modification:", verify_integrity(record))

    record.data = b"salary=90000;employee=42"
    print("Valid after modification:", verify_integrity(record))


# ============================================================================
# 5. HASH CHAINS
# ============================================================================

@dataclass
class ChainEntry:
    index: int
    data: str
    previous_hash: str
    hash: str


class HashChain:
    """
    A simple hash chain.

    Each entry commits to:
        current data + previous entry hash

    This creates a dependency across the sequence.
    """

    def __init__(self) -> None:
        self.entries: list[ChainEntry] = []

    @staticmethod
    def calculate_hash(index: int, data: str, previous_hash: str) -> str:
        payload = canonical_json(
            {
                "index": index,
                "data": data,
                "previous_hash": previous_hash,
            }
        )
        return sha256(payload)

    def append(self, data: str) -> ChainEntry:
        index = len(self.entries)
        previous_hash = self.entries[-1].hash if self.entries else "0" * 64
        current_hash = self.calculate_hash(index, data, previous_hash)

        entry = ChainEntry(index, data, previous_hash, current_hash)
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, str]:
        for position, entry in enumerate(self.entries):
            expected_previous = (
                self.entries[position - 1].hash if position else "0" * 64
            )

            if entry.previous_hash != expected_previous:
                return False, f"Entry {position}: previous hash mismatch"

            expected_hash = self.calculate_hash(
                entry.index,
                entry.data,
                entry.previous_hash,
            )

            if not hmac.compare_digest(entry.hash, expected_hash):
                return False, f"Entry {position}: content hash mismatch"

        return True, "Hash chain is valid"


def demonstrate_hash_chain() -> None:
    print("\n=== 5. HASH CHAIN ===")

    chain = HashChain()
    chain.append("Alice pays Bob 10")
    chain.append("Bob pays Carol 5")
    chain.append("Carol pays Dave 2")

    valid, message = chain.verify()
    print(message)

    # Altering an earlier entry changes its expected hash and breaks the
    # connection to the next entry.
    chain.entries[0].data = "Alice pays Bob 10000"
    valid, message = chain.verify()
    print("After tampering:", message)


# ============================================================================
# 6. MERKLE TREES
# ============================================================================

class MerkleTree:
    """
    Binary Merkle tree.

    Leaf nodes contain transaction hashes. Internal nodes contain the hash
    of the concatenation of their two child hashes.

    A Merkle root commits to all leaves while allowing efficient inclusion
    proofs whose size grows logarithmically with the number of leaves.
    """

    def __init__(self, values: Iterable[bytes]) -> None:
        self.leaves = [sha256(value) for value in values]
        if not self.leaves:
            raise ValueError("A Merkle tree requires at least one leaf.")

        self.levels: list[list[str]] = [self.leaves]
        self._build()

    @staticmethod
    def parent_hash(left: str, right: str) -> str:
        return sha256(bytes.fromhex(left) + bytes.fromhex(right))

    def _build(self) -> None:
        current = self.leaves

        while len(current) > 1:
            next_level: list[str] = []

            for index in range(0, len(current), 2):
                left = current[index]
                # Duplicating the final node is one common convention for
                # odd-sized levels. Other protocols may use different rules.
                right = (
                    current[index + 1]
                    if index + 1 < len(current)
                    else left
                )
                next_level.append(self.parent_hash(left, right))

            self.levels.append(next_level)
            current = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def inclusion_proof(self, leaf_index: int) -> list[tuple[str, str]]:
        if not 0 <= leaf_index < len(self.leaves):
            raise IndexError("Leaf index out of range.")

        proof: list[tuple[str, str]] = []
        index = leaf_index

        for level in self.levels[:-1]:
            sibling = index - 1 if index % 2 else index + 1

            if sibling >= len(level):
                sibling = index

            side = "left" if sibling < index else "right"
            proof.append((level[sibling], side))
            index //= 2

        return proof

    @staticmethod
    def verify_inclusion(
        leaf: bytes,
        leaf_index: int,
        proof: list[tuple[str, str]],
        expected_root: str,
    ) -> bool:
        current = sha256(leaf)
        index = leaf_index

        for sibling_hash, side in proof:
            if side == "left":
                current = MerkleTree.parent_hash(sibling_hash, current)
            else:
                current = MerkleTree.parent_hash(current, sibling_hash)

            index //= 2

        return hmac.compare_digest(current, expected_root)


def demonstrate_merkle_tree() -> None:
    print("\n=== 6. MERKLE TREE ===")

    transactions = [
        b"TX1: Alice -> Bob: 10",
        b"TX2: Bob -> Carol: 5",
        b"TX3: Carol -> Dave: 2",
        b"TX4: Dave -> Erin: 1",
    ]

    tree = MerkleTree(transactions)
    print("Merkle root:", tree.root)

    proof = tree.inclusion_proof(2)
    verified = MerkleTree.verify_inclusion(
        transactions[2],
        2,
        proof,
        tree.root,
    )
    print("TX3 inclusion proof valid:", verified)

    tampered = b"TX3: Carol -> Dave: 200000"
    verified = MerkleTree.verify_inclusion(
        tampered,
        2,
        proof,
        tree.root,
    )
    print("Tampered TX3 proof valid:", verified)


# ============================================================================
# 7. MESSAGE AUTHENTICATION WITH HMAC
# ============================================================================

def create_hmac(message: bytes, secret_key: bytes) -> str:
    """Create a keyed integrity/authentication tag."""
    return hmac.new(secret_key, message, hashlib.sha256).hexdigest()


def verify_hmac(message: bytes, tag: str, secret_key: bytes) -> bool:
    expected = create_hmac(message, secret_key)
    return hmac.compare_digest(expected, tag)


def demonstrate_hmac() -> None:
    print("\n=== 7. HMAC ===")

    key = secrets.token_bytes(32)
    message = b"temperature=25.4"

    tag = create_hmac(message, key)
    print("HMAC:", tag)
    print("Valid:", verify_hmac(message, tag, key))
    print("Tampered message valid:", verify_hmac(b"temperature=95.4", tag, key))

    # HMAC requires a shared secret. It does not provide non-repudiation.
    print("HMAC provides keyed integrity/authentication, not public verification.")


# ============================================================================
# 8. DIGITAL SIGNATURE CONCEPT
# ============================================================================

def explain_digital_signatures() -> None:
    print("\n=== 8. DIGITAL SIGNATURES ===")
    print("A digital signature normally provides:")
    print("  1. Integrity: signed data changes invalidate verification.")
    print("  2. Authentication: verification uses a public key corresponding")
    print("     to the private signing key.")
    print("  3. Non-repudiation properties under appropriate legal and")
    print("     cryptographic assumptions.")
    print()
    print("This standard-library-only script does not implement RSA/ECDSA/EdDSA")
    print("because production public-key cryptography should use audited")
    print("cryptographic libraries rather than handwritten algorithms.")


# ============================================================================
# 9. BLOCKCHAIN BLOCK MODEL
# ============================================================================

@dataclass
class Block:
    index: int
    timestamp: float
    transactions: list[dict[str, Any]]
    previous_hash: str
    nonce: int = 0
    merkle_root: str = ""
    hash: str = ""

    def calculate_merkle_root(self) -> str:
        if not self.transactions:
            return sha256(b"")

        transaction_bytes = [
            canonical_json(transaction) for transaction in self.transactions
        ]
        return MerkleTree(transaction_bytes).root

    def calculate_hash(self) -> str:
        self.merkle_root = self.calculate_merkle_root()

        header = canonical_json(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "previous_hash": self.previous_hash,
                "merkle_root": self.merkle_root,
                "nonce": self.nonce,
            }
        )
        return sha256(header)

    def seal(self) -> None:
        self.hash = self.calculate_hash()


class Blockchain:
    """
    Educational proof-of-work blockchain.

    This demonstrates structural integrity. It is not a production
    cryptocurrency implementation.
    """

    def __init__(self, difficulty: int = 4) -> None:
        if difficulty < 1 or difficulty > 6:
            raise ValueError("Use a demonstration difficulty from 1 to 6.")

        self.difficulty = difficulty
        self.chain: list[Block] = [self._create_genesis_block()]

    def _create_genesis_block(self) -> Block:
        genesis = Block(
            index=0,
            timestamp=1700000000.0,
            transactions=[{"type": "genesis"}],
            previous_hash="0" * 64,
        )
        genesis.seal()
        return genesis

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def mine_block(self, transactions: list[dict[str, Any]]) -> Block:
        block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            transactions=copy.deepcopy(transactions),
            previous_hash=self.latest_block.hash,
        )

        target_prefix = "0" * self.difficulty

        # Proof of work changes the nonce until the block hash satisfies
        # the selected target. This does not make data immutable by itself;
        # it increases the computational cost of rewriting history.
        while True:
            block.seal()
            if block.hash.startswith(target_prefix):
                break
            block.nonce += 1

        self.chain.append(block)
        return block

    def verify(self) -> tuple[bool, str]:
        for index, block in enumerate(self.chain):
            expected_hash = block.calculate_hash()

            if not hmac.compare_digest(block.hash, expected_hash):
                return False, f"Block {index}: hash mismatch"

            if index == 0:
                if block.previous_hash != "0" * 64:
                    return False, "Genesis block has an invalid previous hash"
                continue

            previous = self.chain[index - 1]

            if block.previous_hash != previous.hash:
                return False, f"Block {index}: broken previous-hash link"

            if not block.hash.startswith("0" * self.difficulty):
                return False, f"Block {index}: proof of work is invalid"

        return True, "Blockchain is valid"


def demonstrate_blockchain() -> None:
    print("\n=== 9. BLOCKCHAIN INTEGRITY ===")

    blockchain = Blockchain(difficulty=3)

    blockchain.mine_block(
        [
            {"sender": "Alice", "recipient": "Bob", "amount": 10},
            {"sender": "Bob", "recipient": "Carol", "amount": 3},
        ]
    )

    blockchain.mine_block(
        [
            {"sender": "Carol", "recipient": "Dave", "amount": 2},
        ]
    )

    valid, message = blockchain.verify()
    print(message)

    # Tampering with transaction data changes the Merkle root and block hash.
    blockchain.chain[1].transactions[0]["amount"] = 999999
    valid, message = blockchain.verify()
    print("After transaction tampering:", message)


# ============================================================================
# 10. REPAIR ATTEMPT AND CHAIN DEPENDENCY
# ============================================================================

def demonstrate_history_rewrite() -> None:
    print("\n=== 10. HISTORY REWRITE ===")

    blockchain = Blockchain(difficulty=2)

    blockchain.mine_block(
        [{"sender": "A", "recipient": "B", "amount": 10}]
    )
    blockchain.mine_block(
        [{"sender": "B", "recipient": "C", "amount": 4}]
    )

    original_second_hash = blockchain.chain[1].hash

    # An attacker changes an old transaction.
    blockchain.chain[1].transactions[0]["amount"] = 10000
    blockchain.chain[1].nonce = 0
    blockchain.chain[1].seal()

    print("Original block-1 hash:", original_second_hash)
    print("Recalculated block-1 hash:", blockchain.chain[1].hash)
    print(
        "Block-2 still points to original hash:",
        blockchain.chain[2].previous_hash == original_second_hash,
    )

    valid, message = blockchain.verify()
    print(message)


# ============================================================================
# 11. INTEGRITY VS AUTHENTICITY
# ============================================================================

def compare_security_properties() -> None:
    print("\n=== 11. SECURITY PROPERTY COMPARISON ===")

    mechanisms = {
        "Hash": "Detects changes when a trusted digest is available.",
        "HMAC": "Detects changes and authenticates a message to holders of a shared key.",
        "Digital signature": "Supports integrity and public-key authentication.",
        "Merkle tree": "Commits efficiently to a collection of data.",
        "Hash chain": "Makes sequential modifications detectable.",
        "Blockchain": "Combines linked blocks with a consensus mechanism.",
    }

    for mechanism, property_description in mechanisms.items():
        print(f"{mechanism:18} -> {property_description}")


# ============================================================================
# 12. EDGE CASES
# ============================================================================

def demonstrate_edge_cases() -> None:
    print("\n=== 12. EDGE CASES ===")

    print("Empty SHA-256:", sha256(b""))

    try:
        MerkleTree([])
    except ValueError as error:
        print("Empty Merkle tree:", error)

    tree = MerkleTree([b"only transaction"])
    print("One-leaf Merkle root:", tree.root)

    try:
        tree.inclusion_proof(5)
    except IndexError as error:
        print("Invalid proof index:", error)

    # Equal strings are not the same as strings differing by invisible
    # encoding details. Integrity mechanisms always operate on bytes.
    utf8_a = "café".encode("utf-8")
    utf8_b = "cafe\u0301".encode("utf-8")
    print("Visually similar Unicode hashes equal:", sha256(utf8_a) == sha256(utf8_b))


# ============================================================================
# 13. PERFORMANCE CONSIDERATIONS
# ============================================================================

def explain_complexity() -> None:
    print("\n=== 13. PERFORMANCE ===")
    print("SHA-256 over n bytes: approximately O(n) work.")
    print("Merkle-tree construction: O(n) hashes for n leaves.")
    print("Merkle inclusion proof: O(log n) sibling hashes.")
    print("Hash-chain validation: O(n) entries.")
    print("Proof-of-work mining: variable and intentionally expensive.")
    print("Blockchain verification: generally O(number of blocks + transactions).")


# ============================================================================
# 14. SECURITY LIMITATIONS
# ============================================================================

def explain_security_limitations() -> None:
    print("\n=== 14. SECURITY LIMITATIONS ===")

    limitations = [
        "A hash does not prove who created the data.",
        "A hash alone is insufficient if an attacker can replace both data and digest.",
        "HMAC keys must remain secret.",
        "Digital signatures depend on secure private-key management.",
        "A Merkle root is meaningful only when the root itself is trusted or authenticated.",
        "Blockchain structure does not guarantee that every transaction is truthful.",
        "Consensus security depends on the blockchain's specific protocol and threat model.",
        "Proof of work makes rewriting costly, but does not make it mathematically impossible.",
        "Hash algorithms must remain collision resistant for their intended security role.",
        "Application-level validation is still required; cryptography cannot correct invalid business logic.",
    ]

    for number, limitation in enumerate(limitations, start=1):
        print(f"{number:2}. {limitation}")


# ============================================================================
# 15. INTEGRITY TESTING
# ============================================================================

def test_hash_chain() -> None:
    chain = HashChain()
    chain.append("A")
    chain.append("B")
    valid, _ = chain.verify()
    assert valid

    chain.entries[0].data = "TAMPERED"
    valid, _ = chain.verify()
    assert not valid


def test_merkle_tree() -> None:
    values = [b"A", b"B", b"C", b"D"]
    tree = MerkleTree(values)
    proof = tree.inclusion_proof(1)

    assert MerkleTree.verify_inclusion(
        b"B", 1, proof, tree.root
    )
    assert not MerkleTree.verify_inclusion(
        b"X", 1, proof, tree.root
    )


def test_blockchain() -> None:
    blockchain = Blockchain(difficulty=1)
    blockchain.mine_block(
        [{"sender": "A", "recipient": "B", "amount": 1}]
    )

    valid, _ = blockchain.verify()
    assert valid

    blockchain.chain[1].transactions[0]["amount"] = 2
    valid, _ = blockchain.verify()
    assert not valid


def run_tests() -> None:
    print("\n=== 16. SELF-TESTS ===")
    test_hash_chain()
    test_merkle_tree()
    test_blockchain()
    print("All integrity tests passed.")


# ============================================================================
# 16. PRACTICAL DESIGN CHECKLIST
# ============================================================================

def print_best_practices() -> None:
    print("\n=== 17. BEST PRACTICES ===")

    practices = [
        "Hash canonical bytes rather than ambiguous representations.",
        "Use established cryptographic libraries for production public-key cryptography.",
        "Do not invent cryptographic algorithms for production security.",
        "Protect secret keys with appropriate key-management controls.",
        "Authenticate integrity metadata when an attacker can modify storage.",
        "Separate integrity, authenticity, confidentiality, and authorization.",
        "Validate transactions before committing them to a ledger.",
        "Define the threat model before selecting a cryptographic mechanism.",
        "Version cryptographic algorithms and plan for algorithm migration.",
        "Test tampering, malformed input, replay, truncation, and serialization edge cases.",
        "Log security-relevant verification failures without exposing secrets.",
    ]

    for practice in practices:
        print("-", practice)


# ============================================================================
# 17. MAIN STUDY RUNNER
# ============================================================================

def main() -> None:
    print("=" * 78)
    print("INTEGRITY IN CRYPTOGRAPHY AND BLOCKCHAIN")
    print("=" * 78)

    explain_integrity()
    demonstrate_hashes()
    demonstrate_serialization_integrity()
    demonstrate_tamper_detection()
    demonstrate_hash_chain()
    demonstrate_merkle_tree()
    demonstrate_hmac()
    explain_digital_signatures()
    demonstrate_blockchain()
    demonstrate_history_rewrite()
    compare_security_properties()
    demonstrate_edge_cases()
    explain_complexity()
    explain_security_limitations()
    run_tests()
    print_best_practices()

    print("\n=== STUDY COMPLETE ===")
    print("The demonstrations show how integrity evolves from a simple")
    print("digest into authenticated structures and blockchain-linked history.")


if __name__ == "__main__":
    main()
