"""
Cryptography, Blockchain and Decentralized Technologies
========================================================

A self-contained study script covering:

1. Cryptographic fundamentals
2. Classical and modern cryptography
3. Hash functions
4. Symmetric encryption concepts
5. Asymmetric cryptography concepts
6. Digital signatures
7. Key exchange
8. Merkle trees
9. Blockchain fundamentals
10. Proof of Work
11. Mining and difficulty
12. Blockchain validation
13. Transactions and UTXO-style accounting
14. Proof of Stake concepts
15. Consensus concepts
16. Smart contracts
17. Decentralized applications
18. Distributed storage concepts
19. Wallets and addresses
20. Security, attacks, limitations, and production concerns

The examples intentionally use simplified educational implementations.
They are NOT suitable replacements for production cryptographic libraries
or production blockchain systems.

Standard-library modules are used whenever possible.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import math
import secrets
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ============================================================================
# 1. GENERAL UTILITIES
# ============================================================================

def heading(title: str) -> None:
    """Print a visible section heading."""
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def canonical_json(data: Any) -> str:
    """
    Convert data into deterministic JSON.

    Deterministic serialization is essential when data is hashed or signed.
    Different representations of logically identical data must not produce
    accidental differences in the bytes being authenticated.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hex(data: bytes | str) -> str:
    """Return the SHA-256 digest as hexadecimal text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_int(data: bytes | str) -> int:
    """Return SHA-256 output as an integer."""
    return int(sha256_hex(data), 16)


# ============================================================================
# 2. INFORMATION, ENCODING, AND ENTROPY
# ============================================================================

def shannon_entropy(values: Iterable[Any]) -> float:
    """
    Calculate Shannon entropy in bits.

    Entropy measures uncertainty or unpredictability. Cryptographic keys need
    high-quality unpredictability. Human-chosen passwords usually have much
    lower real-world entropy than their apparent character count suggests.
    """
    values = list(values)

    if not values:
        return 0.0

    frequencies = Counter(values)
    total = len(values)

    entropy = 0.0
    for count in frequencies.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def demonstrate_entropy() -> None:
    heading("1. INFORMATION AND ENTROPY")

    predictable = "aaaaaaaaaaaaaaaaaaaa"
    varied = "a9K!2zP#7mQ@4xL$8vT"

    print("Predictable sample:", predictable)
    print("Entropy:", round(shannon_entropy(predictable), 4), "bits per symbol")

    print("\nVaried sample:", varied)
    print("Entropy:", round(shannon_entropy(varied), 4), "bits per symbol")

    print(
        "\nImportant: character-frequency entropy of one visible string is not "
        "the same as cryptographic entropy. A random generator must be secure."
    )


# ============================================================================
# 3. CLASSICAL CRYPTOGRAPHY
# ============================================================================

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypt text using a Caesar substitution.

    Caesar cipher is historically important but cryptographically insecure.
    Its small key space makes brute force trivial.
    """
    result = []

    for character in plaintext:
        if "a" <= character <= "z":
            base = ord("a")
            result.append(chr((ord(character) - base + shift) % 26 + base))
        elif "A" <= character <= "Z":
            base = ord("A")
            result.append(chr((ord(character) - base + shift) % 26 + base))
        else:
            result.append(character)

    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt Caesar cipher text."""
    return caesar_encrypt(ciphertext, -shift)


def demonstrate_classical_cryptography() -> None:
    heading("2. CLASSICAL CRYPTOGRAPHY")

    plaintext = "Cryptography protects information."
    shift = 5

    ciphertext = caesar_encrypt(plaintext, shift)
    recovered = caesar_decrypt(ciphertext, shift)

    print("Plaintext :", plaintext)
    print("Shift     :", shift)
    print("Ciphertext:", ciphertext)
    print("Recovered :", recovered)

    print("\nBrute-force attack against the small Caesar key space:")
    for candidate_shift in range(26):
        print(
            f"Shift {candidate_shift:2}:",
            caesar_decrypt(ciphertext, candidate_shift),
        )


# ============================================================================
# 4. MODULAR ARITHMETIC
# ============================================================================

def gcd(a: int, b: int) -> int:
    """Calculate greatest common divisor using Euclid's algorithm."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Return gcd(a, b), x, y such that:

        a*x + b*y = gcd(a, b)
    """
    if b == 0:
        return a, 1, 0

    current_gcd, x1, y1 = extended_gcd(b, a % b)

    x = y1
    y = x1 - (a // b) * y1

    return current_gcd, x, y


def modular_inverse(value: int, modulus: int) -> int:
    """
    Find x such that:

        value * x ≡ 1 (mod modulus)

    An inverse exists only when value and modulus are coprime.
    """
    divisor, coefficient, _ = extended_gcd(value, modulus)

    if divisor != 1:
        raise ValueError(
            f"{value} has no modular inverse modulo {modulus}"
        )

    return coefficient % modulus


def demonstrate_modular_arithmetic() -> None:
    heading("3. MODULAR ARITHMETIC")

    print("17 mod 5 =", 17 % 5)
    print("2^10 mod 17 =", pow(2, 10, 17))

    inverse = modular_inverse(3, 11)
    print("Inverse of 3 modulo 11 =", inverse)
    print("(3 * inverse) mod 11 =", (3 * inverse) % 11)

    print(
        "\nModular arithmetic is central to many public-key cryptosystems, "
        "including RSA and finite-field cryptography."
    )


# ============================================================================
# 5. CRYPTOGRAPHIC HASH FUNCTIONS
# ============================================================================

def demonstrate_hash_functions() -> None:
    heading("4. CRYPTOGRAPHIC HASH FUNCTIONS")

    message = "Blockchain"

    digest = sha256_hex(message)

    print("Message:", message)
    print("SHA-256:", digest)

    modified_message = "blockchain"
    modified_digest = sha256_hex(modified_message)

    print("\nModified message:", modified_message)
    print("SHA-256:", modified_digest)

    print("\nAvalanche demonstration:")
    print("Hashes equal?", digest == modified_digest)

    print("\nImportant hash properties:")
    print("- Deterministic")
    print("- Fixed-length output")
    print("- Efficient computation")
    print("- Preimage resistance")
    print("- Second-preimage resistance")
    print("- Collision resistance")
    print("- Strong avalanche behavior")

    print(
        "\nHashing is not encryption. Encryption is intended to be reversible "
        "with the correct key. A cryptographic hash is intended to be one-way."
    )


# ============================================================================
# 6. HASH COLLISIONS AND TRUNCATED HASH DEMONSTRATION
# ============================================================================

def truncated_hash(value: str, bits: int = 16) -> int:
    """
    Educational hash truncation.

    Small output spaces make collisions easy. Real SHA-256 uses 256 bits,
    making random collisions computationally infeasible with current methods.
    """
    if bits <= 0 or bits > 256:
        raise ValueError("bits must be between 1 and 256")

    digest_integer = sha256_int(value)
    return digest_integer >> (256 - bits)


def find_truncated_collision(bits: int = 12) -> Tuple[str, str, int]:
    """
    Demonstrate the birthday paradox by finding a collision in a tiny hash space.

    Expected work is approximately proportional to sqrt(2^bits).
    """
    seen: Dict[int, str] = {}
    counter = 0

    while True:
        candidate = f"candidate-{counter}"
        digest = truncated_hash(candidate, bits)

        if digest in seen:
            return seen[digest], candidate, digest

        seen[digest] = candidate
        counter += 1


def demonstrate_hash_collision_concept() -> None:
    heading("5. HASH COLLISION CONCEPT")

    first, second, collision_value = find_truncated_collision(bits=12)

    print("First input :", first)
    print("Second input:", second)
    print("Same 12-bit truncated hash:", collision_value)
    print(
        "\nThis does NOT break SHA-256. The example deliberately reduces the "
        "hash output to only 12 bits."
    )


# ============================================================================
# 7. MESSAGE AUTHENTICATION CODES
# ============================================================================

def create_hmac(key: bytes, message: bytes) -> str:
    """Create an HMAC-SHA256 authentication tag."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, message: bytes, tag: str) -> bool:
    """
    Verify an HMAC using constant-time comparison.

    Constant-time comparison reduces timing-leakage risk.
    """
    expected_tag = create_hmac(key, message)
    return hmac.compare_digest(expected_tag, tag)


def demonstrate_hmac() -> None:
    heading("6. MESSAGE AUTHENTICATION WITH HMAC")

    key = secrets.token_bytes(32)
    message = b"Transfer 100 units to Bob."

    tag = create_hmac(key, message)

    print("Message:", message.decode())
    print("Authentication tag:", tag)
    print("Verification:", verify_hmac(key, message, tag))

    modified_message = b"Transfer 1000 units to Bob."

    print(
        "Modified message verification:",
        verify_hmac(key, modified_message, tag),
    )

    print(
        "\nHMAC provides integrity and authenticity when the communicating "
        "parties share a secret key."
    )


# ============================================================================
# 8. SYMMETRIC ENCRYPTION CONCEPTS
# ============================================================================

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """
    XOR bytes with a repeating key.

    This demonstrates the mathematical structure of stream encryption, but a
    repeating key is insecure and must not be used for real cryptography.
    """
    if not key:
        raise ValueError("Key must not be empty")

    return bytes(
        byte ^ key[index % len(key)]
        for index, byte in enumerate(data)
    )


def demonstrate_xor_encryption() -> None:
    heading("7. SYMMETRIC ENCRYPTION CONCEPTS")

    plaintext = b"Confidential message"
    key = b"secret"

    ciphertext = xor_bytes(plaintext, key)
    recovered = xor_bytes(ciphertext, key)

    print("Plaintext :", plaintext)
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered)

    print(
        "\nXOR is reversible because applying the same key twice restores "
        "the original data."
    )

    print(
        "\nSecurity warning: repeating-key XOR is insecure. Modern symmetric "
        "encryption uses carefully designed algorithms and authenticated modes."
    )


# ============================================================================
# 9. ONE-TIME PAD PRINCIPLE
# ============================================================================

def one_time_pad_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt using the one-time-pad principle.

    Perfect secrecy requires:
    - Truly random key
    - Key at least as long as plaintext
    - Key used exactly once
    - Key kept secret
    """
    if len(plaintext) != len(key):
        raise ValueError("OTP key must have the same length as plaintext")

    return bytes(a ^ b for a, b in zip(plaintext, key))


def demonstrate_one_time_pad() -> None:
    heading("8. ONE-TIME PAD PRINCIPLE")

    plaintext = b"SECRET"
    key = secrets.token_bytes(len(plaintext))

    ciphertext = one_time_pad_encrypt(plaintext, key)
    recovered = one_time_pad_encrypt(ciphertext, key)

    print("Plaintext :", plaintext)
    print("Key       :", key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Recovered :", recovered)

    print(
        "\nThe one-time pad has perfect secrecy under strict assumptions, "
        "but secure generation, distribution, storage, and one-time use of "
        "large keys make it impractical for many systems."
    )


# ============================================================================
# 10. KEY DERIVATION
# ============================================================================

def derive_key_from_password(
    password: str,
    salt: bytes,
    iterations: int = 200_000,
    length: int = 32,
) -> bytes:
    """
    Derive a key from a password using PBKDF2-HMAC-SHA256.

    Passwords should not be used directly as encryption keys.

    Salt:
        Prevents identical passwords from producing identical derived keys.

    Iterations:
        Increase computational cost for password guessing.
    """
    if iterations < 1:
        raise ValueError("iterations must be positive")

    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=length,
    )


def demonstrate_key_derivation() -> None:
    heading("9. PASSWORD-BASED KEY DERIVATION")

    password = "correct horse battery staple"
    salt = secrets.token_bytes(16)

    key = derive_key_from_password(password, salt)

    print("Salt:", salt.hex())
    print("Derived key:", key.hex())

    same_key = derive_key_from_password(password, salt)
    print("Same password + same salt -> same key:", key == same_key)

    different_salt = secrets.token_bytes(16)
    different_key = derive_key_from_password(password, different_salt)

    print(
        "Same password + different salt -> different key:",
        key != different_key,
    )


# ============================================================================
# 11. DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================================

def demonstrate_diffie_hellman() -> None:
    heading("10. DIFFIE-HELLMAN KEY EXCHANGE")

    # Small values are used only for demonstration.
    # Real systems use standardized large groups or elliptic curves.
    prime_modulus = 23
    generator = 5

    alice_private = 6
    bob_private = 15

    alice_public = pow(generator, alice_private, prime_modulus)
    bob_public = pow(generator, bob_private, prime_modulus)

    alice_shared = pow(bob_public, alice_private, prime_modulus)
    bob_shared = pow(alice_public, bob_private, prime_modulus)

    print("Prime modulus:", prime_modulus)
    print("Generator:", generator)
    print("Alice public value:", alice_public)
    print("Bob public value:", bob_public)
    print("Alice shared secret:", alice_shared)
    print("Bob shared secret:", bob_shared)
    print("Shared secrets equal:", alice_shared == bob_shared)

    print(
        "\nA passive observer can see the public values but should not be able "
        "to efficiently derive the private exponents for secure parameters."
    )

    print(
        "\nImportant limitation: unauthenticated Diffie-Hellman is vulnerable "
        "to man-in-the-middle attacks because public values are not authenticated."
    )


# ============================================================================
# 12. TOY RSA
# ============================================================================

@dataclass
class ToyRSAKeyPair:
    """
    Educational RSA key pair.

    Real RSA requires very large primes, secure padding, and hardened libraries.
    Raw textbook RSA is insecure in practice.
    """

    public_exponent: int
    private_exponent: int
    modulus: int


def create_toy_rsa_keypair() -> ToyRSAKeyPair:
    """
    Create a tiny RSA example.

    Fixed primes are deliberately small for inspectability.
    """
    prime_p = 61
    prime_q = 53

    modulus = prime_p * prime_q
    phi = (prime_p - 1) * (prime_q - 1)

    public_exponent = 17
    private_exponent = modular_inverse(public_exponent, phi)

    return ToyRSAKeyPair(
        public_exponent=public_exponent,
        private_exponent=private_exponent,
        modulus=modulus,
    )


def rsa_encrypt_number(message: int, keypair: ToyRSAKeyPair) -> int:
    if not 0 <= message < keypair.modulus:
        raise ValueError("Message must be in the range [0, modulus)")
    return pow(message, keypair.public_exponent, keypair.modulus)


def rsa_decrypt_number(ciphertext: int, keypair: ToyRSAKeyPair) -> int:
    return pow(ciphertext, keypair.private_exponent, keypair.modulus)


def demonstrate_toy_rsa() -> None:
    heading("11. ASYMMETRIC CRYPTOGRAPHY WITH TOY RSA")

    keypair = create_toy_rsa_keypair()

    message = 65
    ciphertext = rsa_encrypt_number(message, keypair)
    recovered = rsa_decrypt_number(ciphertext, keypair)

    print("Public exponent:", keypair.public_exponent)
    print("Private exponent:", keypair.private_exponent)
    print("Modulus:", keypair.modulus)

    print("\nMessage:", message)
    print("Ciphertext:", ciphertext)
    print("Recovered:", recovered)

    print(
        "\nProduction warning: real RSA requires large keys and secure padding "
        "schemes such as OAEP for encryption and modern signature schemes for "
        "signing. Never use textbook RSA directly."
    )


# ============================================================================
# 13. DIGITAL SIGNATURE PRINCIPLES
# ============================================================================

def toy_sign(message: str, keypair: ToyRSAKeyPair) -> int:
    """
    Educational RSA-style signing.

    Hash first, then exponentiate with the private exponent.

    Real signature schemes require carefully designed padding and protocols.
    """
    message_hash = sha256_int(message) % keypair.modulus
    return pow(message_hash, keypair.private_exponent, keypair.modulus)


def toy_verify(
    message: str,
    signature: int,
    keypair: ToyRSAKeyPair,
) -> bool:
    """Verify the educational RSA-style signature."""
    expected_hash = sha256_int(message) % keypair.modulus
    recovered_hash = pow(
        signature,
        keypair.public_exponent,
        keypair.modulus,
    )
    return recovered_hash == expected_hash


def demonstrate_digital_signatures() -> None:
    heading("12. DIGITAL SIGNATURE CONCEPTS")

    keypair = create_toy_rsa_keypair()

    message = "Pay Bob 50 tokens"
    signature = toy_sign(message, keypair)

    print("Message:", message)
    print("Signature:", signature)
    print("Valid signature:", toy_verify(message, signature, keypair))

    modified_message = "Pay Bob 500 tokens"

    print(
        "Modified message valid:",
        toy_verify(modified_message, signature, keypair),
    )

    print(
        "\nDigital signatures provide evidence that a holder of the private key "
        "authorized a message, while anyone with the public key can verify it."
    )


# ============================================================================
# 14. SIMPLE ADDRESS DERIVATION
# ============================================================================

def derive_address(public_identifier: str) -> str:
    """
    Derive a simplified address-like identifier.

    Real blockchain address formats may use multiple hashes, checksums,
    version bytes, Base58, Bech32, or other encoding systems.
    """
    version = "00"
    payload = sha256_hex(public_identifier)[:40]
    checksum = sha256_hex(version + payload)[:8]

    return version + payload + checksum


def demonstrate_addresses() -> None:
    heading("13. PUBLIC KEYS, ADDRESSES, AND IDENTIFIERS")

    public_identifier = "educational-public-key-123"
    address = derive_address(public_identifier)

    print("Public identifier:", public_identifier)
    print("Derived address:", address)

    print(
        "\nAn address is often a derived identifier rather than the same thing "
        "as the underlying public key."
    )


# ============================================================================
# 15. MERKLE TREES
# ============================================================================

class MerkleTree:
    """
    Simple binary Merkle tree.

    Leaves are hashes of data items.
    Each parent is the hash of two child hashes.

    Merkle trees provide efficient commitment to a collection of records.
    """

    def __init__(self, values: List[str]):
        if not values:
            raise ValueError("Merkle tree requires at least one value")

        self.values = values
        self.levels: List[List[str]] = []

        current_level = [
            sha256_hex(value)
            for value in values
        ]

        self.levels.append(current_level)

        while len(current_level) > 1:
            if len(current_level) % 2 == 1:
                # Duplicate the final hash to make a complete pair.
                current_level = current_level + [current_level[-1]]

            next_level = []

            for index in range(0, len(current_level), 2):
                combined = (
                    current_level[index]
                    + current_level[index + 1]
                )
                next_level.append(sha256_hex(combined))

            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, str]]:
        """
        Create a Merkle proof.

        Each proof element contains:
            ("left", sibling_hash)
        or:
            ("right", sibling_hash)
        """
        if not 0 <= index < len(self.values):
            raise IndexError("Leaf index out of range")

        proof_steps: List[Tuple[str, str]] = []
        current_index = index

        for level in self.levels[:-1]:
            working_level = level

            if len(working_level) % 2 == 1:
                working_level = working_level + [working_level[-1]]

            sibling_index = (
                current_index + 1
                if current_index % 2 == 0
                else current_index - 1
            )

            position = (
                "right"
                if current_index % 2 == 0
                else "left"
            )

            proof_steps.append(
                (position, working_level[sibling_index])
            )

            current_index //= 2

        return proof_steps

    @staticmethod
    def verify_proof(
        value: str,
        proof_steps: List[Tuple[str, str]],
        expected_root: str,
    ) -> bool:
        """Verify that a value belongs to a committed Merkle tree."""
        current_hash = sha256_hex(value)

        for position, sibling_hash in proof_steps:
            if position == "left":
                current_hash = sha256_hex(
                    sibling_hash + current_hash
                )
            elif position == "right":
                current_hash = sha256_hex(
                    current_hash + sibling_hash
                )
            else:
                raise ValueError("Invalid proof position")

        return current_hash == expected_root


def demonstrate_merkle_tree() -> None:
    heading("14. MERKLE TREES")

    transactions = [
        "Alice pays Bob 10",
        "Bob pays Carol 5",
        "Carol pays Dave 2",
        "Dave pays Eve 1",
    ]

    tree = MerkleTree(transactions)

    print("Merkle root:", tree.root)

    target_index = 1
    proof = tree.proof(target_index)

    print("\nTarget transaction:", transactions[target_index])
    print("Proof:")
    for position, sibling_hash in proof:
        print(f"  {position:5} -> {sibling_hash}")

    verified = MerkleTree.verify_proof(
        transactions[target_index],
        proof,
        tree.root,
    )

    print("\nProof verified:", verified)

    tampered = "Bob pays Carol 500"

    print(
        "Tampered transaction verified:",
        MerkleTree.verify_proof(
            tampered,
            proof,
            tree.root,
        ),
    )


# ============================================================================
# 16. BLOCK STRUCTURE
# ============================================================================

@dataclass
class Block:
    """
    Simplified blockchain block.

    A block links to its predecessor using previous_hash.
    Changing historical content changes the block hash.
    """

    index: int
    previous_hash: str
    transactions: List[Dict[str, Any]]
    timestamp: float = field(default_factory=time.time)
    nonce: int = 0
    difficulty: int = 3

    def header_data(self) -> Dict[str, Any]:
        """
        Return data included in the block hash.

        The transaction list is included through deterministic serialization.
        """
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "difficulty": self.difficulty,
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.header_data()))

    @property
    def hash(self) -> str:
        return self.compute_hash()


# ============================================================================
# 17. PROOF OF WORK
# ============================================================================

def satisfies_difficulty(block_hash: str, difficulty: int) -> bool:
    """
    Simplified difficulty rule.

    A valid block hash must begin with a number of zero hexadecimal characters.
    """
    return block_hash.startswith("0" * difficulty)


def mine_block(block: Block, max_attempts: int = 10_000_000) -> int:
    """
    Search for a nonce satisfying the simplified proof-of-work target.

    Returns the number of attempts.

    Production systems define difficulty using numerical targets rather than
    a simple prefix-count rule.
    """
    attempts = 0

    while attempts < max_attempts:
        current_hash = block.compute_hash()

        if satisfies_difficulty(current_hash, block.difficulty):
            return attempts + 1

        block.nonce += 1
        attempts += 1

    raise RuntimeError("Mining attempts exceeded configured maximum")


def demonstrate_proof_of_work() -> None:
    heading("15. PROOF OF WORK")

    block = Block(
        index=1,
        previous_hash="0" * 64,
        transactions=[
            {
                "sender": "network",
                "recipient": "Alice",
                "amount": 50,
            }
        ],
        difficulty=3,
    )

    start = time.perf_counter()
    attempts = mine_block(block)
    elapsed = time.perf_counter() - start

    print("Nonce:", block.nonce)
    print("Hash :", block.hash)
    print("Attempts:", attempts)
    print("Elapsed seconds:", round(elapsed, 6))
    print(
        "Valid proof:",
        satisfies_difficulty(block.hash, block.difficulty),
    )

    print(
        "\nProof of Work makes block creation computationally expensive while "
        "verification remains comparatively inexpensive."
    )


# ============================================================================
# 18. BASIC BLOCKCHAIN
# ============================================================================

class BasicBlockchain:
    """
    Educational blockchain with:

    - Genesis block
    - Hash-linked blocks
    - Pending transactions
    - Proof-of-Work mining
    - Chain validation

    This is a teaching model, not a production blockchain.
    """

    def __init__(
        self,
        difficulty: int = 3,
        mining_reward: int = 50,
    ):
        if difficulty < 1:
            raise ValueError("difficulty must be at least 1")

        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []

        genesis_block = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[],
            difficulty=difficulty,
        )

        mine_block(genesis_block)
        self.chain.append(genesis_block)

    @property
    def latest_block(self) -> Block:
        return self.chain[-1]

    def add_transaction(
        self,
        sender: str,
        recipient: str,
        amount: int,
    ) -> None:
        if not sender or not recipient:
            raise ValueError("Sender and recipient are required")

        if amount <= 0:
            raise ValueError("Transaction amount must be positive")

        self.pending_transactions.append(
            {
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
            }
        )

    def mine_pending_transactions(self, miner: str) -> Block:
        """
        Mine pending transactions and create a block reward transaction.

        This simplistic model does not enforce account balances. A later UTXO
        model demonstrates stronger transaction validation.
        """
        reward_transaction = {
            "sender": "network",
            "recipient": miner,
            "amount": self.mining_reward,
        }

        transactions = (
            copy.deepcopy(self.pending_transactions)
            + [reward_transaction]
        )

        new_block = Block(
            index=len(self.chain),
            previous_hash=self.latest_block.hash,
            transactions=transactions,
            difficulty=self.difficulty,
        )

        mine_block(new_block)

        self.chain.append(new_block)
        self.pending_transactions.clear()

        return new_block

    def validate_chain(self) -> bool:
        """Validate hashes, links, and proof-of-work requirements."""
        if not self.chain:
            return False

        for index, block in enumerate(self.chain):
            if block.hash != block.compute_hash():
                return False

            if not satisfies_difficulty(
                block.hash,
                block.difficulty,
            ):
                return False

            if index == 0:
                if block.previous_hash != "0" * 64:
                    return False
            else:
                previous_block = self.chain[index - 1]

                if block.previous_hash != previous_block.hash:
                    return False

        return True

    def balance_of(self, address: str) -> int:
        """
        Calculate a naive account-style balance.

        This is a ledger interpretation and not a secure transaction validation
        system because it does not prevent overspending before mining.
        """
        balance = 0

        for block in self.chain:
            for transaction in block.transactions:
                if transaction["recipient"] == address:
                    balance += transaction["amount"]

                if transaction["sender"] == address:
                    balance -= transaction["amount"]

        return balance


def demonstrate_basic_blockchain() -> None:
    heading("16. BASIC BLOCKCHAIN")

    blockchain = BasicBlockchain(difficulty=2)

    blockchain.add_transaction("network", "Alice", 100)
    blockchain.add_transaction("Alice", "Bob", 25)

    mined_block = blockchain.mine_pending_transactions("Miner-1")

    print("Mined block index:", mined_block.index)
    print("Mined block hash :", mined_block.hash)
    print("Chain valid      :", blockchain.validate_chain())

    print("\nBalances:")
    for participant in ["Alice", "Bob", "Miner-1"]:
        print(
            f"  {participant}:",
            blockchain.balance_of(participant),
        )

    print("\nTampering demonstration:")

    blockchain.chain[1].transactions[0]["amount"] = 999999

    print(
        "Chain valid after modification:",
        blockchain.validate_chain(),
    )

    print(
        "\nChanging transaction data changes the expected hash and invalidates "
        "the block. Because later blocks reference previous hashes, historical "
        "changes propagate through the chain."
    )


# ============================================================================
# 19. TRANSACTION MODEL AND UTXO CONCEPT
# ============================================================================

@dataclass(frozen=True)
class UTXO:
    """
    Unspent Transaction Output.

    A UTXO represents a discrete spendable output.
    """

    transaction_id: str
    output_index: int
    owner: str
    amount: int

    @property
    def identifier(self) -> str:
        return f"{self.transaction_id}:{self.output_index}"


@dataclass
class UTXOTransaction:
    """
    Simplified UTXO transaction.

    Inputs reference previously unspent outputs.
    Outputs create new spendable outputs.
    """

    inputs: List[str]
    outputs: List[Tuple[str, int]]

    def transaction_id(self) -> str:
        data = {
            "inputs": self.inputs,
            "outputs": self.outputs,
        }
        return sha256_hex(canonical_json(data))


class UTXOLedger:
    """
    Simplified UTXO ledger.

    Demonstrates:
    - Input existence
    - Ownership
    - Double-spending prevention
    - Conservation of value

    Digital signatures are omitted here to keep focus on accounting mechanics.
    A production system requires authorization proofs.
    """

    def __init__(self):
        self.utxos: Dict[str, UTXO] = {}

    def create_genesis_output(
        self,
        owner: str,
        amount: int,
    ) -> UTXO:
        if amount <= 0:
            raise ValueError("Amount must be positive")

        transaction_id = sha256_hex(
            f"genesis:{owner}:{amount}:{secrets.token_hex(8)}"
        )

        output = UTXO(
            transaction_id=transaction_id,
            output_index=0,
            owner=owner,
            amount=amount,
        )

        self.utxos[output.identifier] = output
        return output

    def validate_transaction(
        self,
        transaction: UTXOTransaction,
        spender: str,
    ) -> None:
        if not transaction.inputs:
            raise ValueError("Transaction must contain at least one input")

        if not transaction.outputs:
            raise ValueError("Transaction must contain at least one output")

        if len(set(transaction.inputs)) != len(transaction.inputs):
            raise ValueError("Same UTXO cannot appear twice in one transaction")

        input_total = 0

        for input_identifier in transaction.inputs:
            utxo = self.utxos.get(input_identifier)

            if utxo is None:
                raise ValueError(
                    f"Referenced UTXO does not exist: {input_identifier}"
                )

            if utxo.owner != spender:
                raise PermissionError(
                    "Spender does not own all referenced UTXOs"
                )

            input_total += utxo.amount

        output_total = 0

        for recipient, amount in transaction.outputs:
            if not recipient:
                raise ValueError("Output recipient is required")

            if amount <= 0:
                raise ValueError("Output amount must be positive")

            output_total += amount

        if output_total > input_total:
            raise ValueError("Transaction creates value from nothing")

    def apply_transaction(
        self,
        transaction: UTXOTransaction,
        spender: str,
    ) -> str:
        self.validate_transaction(transaction, spender)

        transaction_id = transaction.transaction_id()

        # Remove spent outputs.
        for input_identifier in transaction.inputs:
            del self.utxos[input_identifier]

        # Create new outputs.
        for output_index, (recipient, amount) in enumerate(
            transaction.outputs
        ):
            new_output = UTXO(
                transaction_id=transaction_id,
                output_index=output_index,
                owner=recipient,
                amount=amount,
            )

            self.utxos[new_output.identifier] = new_output

        return transaction_id

    def balance_of(self, owner: str) -> int:
        return sum(
            utxo.amount
            for utxo in self.utxos.values()
            if utxo.owner == owner
        )


def demonstrate_utxo_model() -> None:
    heading("17. UTXO TRANSACTION MODEL")

    ledger = UTXOLedger()

    alice_output = ledger.create_genesis_output(
        owner="Alice",
        amount=100,
    )

    print("Alice initial balance:", ledger.balance_of("Alice"))

    transaction = UTXOTransaction(
        inputs=[alice_output.identifier],
        outputs=[
            ("Bob", 30),
            ("Alice", 70),
        ],
    )

    transaction_id = ledger.apply_transaction(
        transaction,
        spender="Alice",
    )

    print("Transaction ID:", transaction_id)
    print("Alice balance:", ledger.balance_of("Alice"))
    print("Bob balance  :", ledger.balance_of("Bob"))

    print("\nDouble-spending attempt:")

    try:
        ledger.apply_transaction(
            transaction,
            spender="Alice",
        )
    except ValueError as error:
        print("Rejected:", error)

    print(
        "\nThe referenced input was removed after spending, preventing it from "
        "being spent again in this ledger state."
    )


# ============================================================================
# 20. ACCOUNT MODEL
# ============================================================================

class AccountLedger:
    """
    Simplified account-based ledger.

    Unlike UTXO systems, each account has a mutable balance and transaction
    sequencing can use a nonce to prevent replay and ordering ambiguity.
    """

    def __init__(self):
        self.balances: Dict[str, int] = defaultdict(int)
        self.nonces: Dict[str, int] = defaultdict(int)

    def fund(self, account: str, amount: int) -> None:
        if amount <= 0:
            raise ValueError("Funding amount must be positive")
        self.balances[account] += amount

    def transfer(
        self,
        sender: str,
        recipient: str,
        amount: int,
        nonce: int,
    ) -> None:
        if amount <= 0:
            raise ValueError("Amount must be positive")

        expected_nonce = self.nonces[sender]

        if nonce != expected_nonce:
            raise ValueError(
                f"Invalid nonce. Expected {expected_nonce}, received {nonce}"
            )

        if self.balances[sender] < amount:
            raise ValueError("Insufficient balance")

        self.balances[sender] -= amount
        self.balances[recipient] += amount
        self.nonces[sender] += 1


def demonstrate_account_model() -> None:
    heading("18. ACCOUNT MODEL")

    ledger = AccountLedger()

    ledger.fund("Alice", 100)

    ledger.transfer(
        sender="Alice",
        recipient="Bob",
        amount=40,
        nonce=0,
    )

    print("Alice balance:", ledger.balances["Alice"])
    print("Bob balance:", ledger.balances["Bob"])

    try:
        ledger.transfer(
            sender="Alice",
            recipient="Carol",
            amount=10,
            nonce=0,
        )
    except ValueError as error:
        print("Replay/order rejection:", error)

    print(
        "\nAccount models maintain balances directly. UTXO models maintain a "
        "set of discrete spendable outputs."
    )


# ============================================================================
# 21. CONSENSUS FUNDAMENTALS
# ============================================================================

@dataclass
class Validator:
    """
    Simplified Proof-of-Stake validator.
    """

    name: str
    stake: int
    honest: bool = True


def weighted_validator_selection(
    validators: List[Validator],
) -> Validator:
    """
    Select a validator proportionally to stake.

    Real Proof-of-Stake systems include additional rules involving randomness,
    epochs, committees, slashing, finality, and anti-centralization mechanisms.
    """
    if not validators:
        raise ValueError("At least one validator is required")

    total_stake = sum(
        validator.stake
        for validator in validators
        if validator.stake > 0
    )

    if total_stake <= 0:
        raise ValueError("Total positive stake is required")

    selection = secrets.randbelow(total_stake)

    cumulative = 0

    for validator in validators:
        if validator.stake <= 0:
            continue

        cumulative += validator.stake

        if selection < cumulative:
            return validator

    raise RuntimeError("Validator selection failed")


def demonstrate_proof_of_stake() -> None:
    heading("19. PROOF OF STAKE CONCEPT")

    validators = [
        Validator("Validator-A", stake=50),
        Validator("Validator-B", stake=30),
        Validator("Validator-C", stake=20),
    ]

    selections = Counter()

    for _ in range(10_000):
        selected = weighted_validator_selection(validators)
        selections[selected.name] += 1

    for validator in validators:
        observed_percentage = (
            selections[validator.name] / 10_000 * 100
        )

        expected_percentage = (
            validator.stake
            / sum(v.stake for v in validators)
            * 100
        )

        print(
            f"{validator.name}: "
            f"observed={observed_percentage:.2f}% "
            f"expected≈{expected_percentage:.2f}%"
        )

    print(
        "\nStake-weighted selection can reduce energy expenditure compared with "
        "Proof of Work, but it introduces different economic and governance "
        "trade-offs."
    )


# ============================================================================
# 22. BYZANTINE FAULT TOLERANCE CONCEPT
# ============================================================================

def byzantine_threshold_example(total_nodes: int) -> Dict[str, int]:
    """
    Illustrate common thresholds for systems tolerating Byzantine behavior.

    A frequently encountered theoretical model requires:

        n >= 3f + 1

    where:
        n = total validators
        f = maximum Byzantine validators tolerated

    This threshold depends on protocol assumptions and network models.
    """
    if total_nodes < 1:
        raise ValueError("total_nodes must be positive")

    max_faults = (total_nodes - 1) // 3
    minimum_quorum = 2 * max_faults + 1

    return {
        "total_nodes": total_nodes,
        "maximum_byzantine_faults": max_faults,
        "example_quorum": minimum_quorum,
    }


def demonstrate_byzantine_fault_tolerance() -> None:
    heading("20. BYZANTINE FAULT TOLERANCE")

    for node_count in [4, 7, 10, 13]:
        values = byzantine_threshold_example(node_count)
        print(values)

    print(
        "\nConsensus is not merely majority voting. Byzantine environments "
        "consider nodes that can lie, equivocate, delay, or coordinate attacks."
    )


# ============================================================================
# 23. FORKS
# ============================================================================

@dataclass
class ChainCandidate:
    """Simplified chain candidate used to demonstrate fork selection."""

    name: str
    accumulated_work: int
    length: int


def choose_chain_by_work(
    candidates: List[ChainCandidate],
) -> ChainCandidate:
    """
    Select the chain with the greatest accumulated work.

    Longest-chain descriptions are simplifications. Proof-of-Work systems
    generally compare accumulated work rather than merely block count.
    """
    if not candidates:
        raise ValueError("At least one candidate is required")

    return max(
        candidates,
        key=lambda candidate: (
            candidate.accumulated_work,
            candidate.length,
        ),
    )


def demonstrate_forks() -> None:
    heading("21. BLOCKCHAIN FORKS")

    candidates = [
        ChainCandidate("Chain-A", accumulated_work=1000, length=100),
        ChainCandidate("Chain-B", accumulated_work=1200, length=98),
    ]

    selected = choose_chain_by_work(candidates)

    for candidate in candidates:
        print(candidate)

    print("\nSelected chain:", selected.name)

    print(
        "\nA temporary fork can occur when different participants observe "
        "competing valid blocks before the network converges."
    )


# ============================================================================
# 24. SMART CONTRACT CONCEPT
# ============================================================================

@dataclass
class SimpleEscrowContract:
    """
    Educational state machine representing a smart contract.

    States:
        CREATED
        FUNDED
        RELEASED
        REFUNDED
    """

    buyer: str
    seller: str
    arbiter: str
    amount: int
    state: str = "CREATED"
    deposited_amount: int = 0

    def fund(self, caller: str, amount: int) -> None:
        if caller != self.buyer:
            raise PermissionError("Only buyer can fund escrow")

        if self.state != "CREATED":
            raise ValueError("Escrow cannot be funded in current state")

        if amount != self.amount:
            raise ValueError("Funding amount must exactly match escrow amount")

        self.deposited_amount = amount
        self.state = "FUNDED"

    def release(self, caller: str) -> None:
        if self.state != "FUNDED":
            raise ValueError("Escrow is not funded")

        if caller not in {self.buyer, self.arbiter}:
            raise PermissionError("Caller cannot release funds")

        self.state = "RELEASED"

    def refund(self, caller: str) -> None:
        if self.state != "FUNDED":
            raise ValueError("Escrow is not funded")

        if caller not in {self.seller, self.arbiter}:
            raise PermissionError("Caller cannot refund funds")

        self.state = "REFUNDED"


def demonstrate_smart_contract_state_machine() -> None:
    heading("22. SMART CONTRACT STATE MACHINE")

    escrow = SimpleEscrowContract(
        buyer="Alice",
        seller="Bob",
        arbiter="Carol",
        amount=100,
    )

    print("Initial state:", escrow.state)

    escrow.fund("Alice", 100)

    print("After funding:", escrow.state)
    print("Deposited amount:", escrow.deposited_amount)

    escrow.release("Alice")

    print("Final state:", escrow.state)

    print(
        "\nSmart contracts are programs whose state transitions are executed "
        "according to deterministic rules agreed upon by the network."
    )


# ============================================================================
# 25. SMART CONTRACT VULNERABILITY CONCEPT: REENTRANCY
# ============================================================================

class UnsafeWithdrawalContract:
    """
    Conceptual example of unsafe interaction ordering.

    This model demonstrates why state should often be updated before making an
    external interaction in smart-contract systems.
    """

    def __init__(self):
        self.balances: Dict[str, int] = defaultdict(int)

    def deposit(self, user: str, amount: int) -> None:
        self.balances[user] += amount

    def unsafe_withdraw(
        self,
        user: str,
        external_callback,
    ) -> int:
        amount = self.balances[user]

        if amount <= 0:
            return 0

        # Conceptually dangerous ordering:
        # external interaction occurs before state is cleared.
        external_callback()

        self.balances[user] = 0
        return amount


class SafeWithdrawalContract:
    """
    Safer checks-effects-interactions structure.

    1. Check conditions.
    2. Update internal state.
    3. Perform external interaction.
    """

    def __init__(self):
        self.balances: Dict[str, int] = defaultdict(int)

    def deposit(self, user: str, amount: int) -> None:
        self.balances[user] += amount

    def safe_withdraw(
        self,
        user: str,
        external_callback,
    ) -> int:
        amount = self.balances[user]

        if amount <= 0:
            return 0

        self.balances[user] = 0

        external_callback()

        return amount


def demonstrate_contract_security_pattern() -> None:
    heading("23. SMART CONTRACT SECURITY PATTERN")

    unsafe = UnsafeWithdrawalContract()
    unsafe.deposit("Alice", 100)

    safe = SafeWithdrawalContract()
    safe.deposit("Alice", 100)

    print("Unsafe balance before:", unsafe.balances["Alice"])

    unsafe.unsafe_withdraw(
        "Alice",
        lambda: print(
            "External interaction occurred before balance update"
        ),
    )

    print("Unsafe balance after:", unsafe.balances["Alice"])

    print("\nSafe balance before:", safe.balances["Alice"])

    safe.safe_withdraw(
        "Alice",
        lambda: print(
            "External interaction occurred after balance update"
        ),
    )

    print("Safe balance after:", safe.balances["Alice"])

    print(
        "\nReal smart-contract security requires formal review, access control, "
        "integer safety, oracle security, reentrancy defenses, and extensive "
        "testing. This Python example demonstrates only ordering principles."
    )


# ============================================================================
# 26. DECENTRALIZED NETWORK CONCEPT
# ============================================================================

class Peer:
    """
    Simplified peer in a decentralized gossip network.
    """

    def __init__(self, name: str):
        self.name = name
        self.neighbors: List["Peer"] = []
        self.received_messages: set[str] = set()

    def connect(self, other: "Peer") -> None:
        if other is self:
            return

        if other not in self.neighbors:
            self.neighbors.append(other)

        if self not in other.neighbors:
            other.neighbors.append(self)

    def broadcast(
        self,
        message: str,
        visited: Optional[set[str]] = None,
    ) -> None:
        if visited is None:
            visited = set()

        if self.name in visited:
            return

        visited.add(self.name)
        self.received_messages.add(message)

        for neighbor in self.neighbors:
            neighbor.broadcast(message, visited)


def demonstrate_gossip_network() -> None:
    heading("24. DECENTRALIZED GOSSIP NETWORK")

    alice_node = Peer("Alice-Node")
    bob_node = Peer("Bob-Node")
    carol_node = Peer("Carol-Node")
    dave_node = Peer("Dave-Node")

    alice_node.connect(bob_node)
    bob_node.connect(carol_node)
    carol_node.connect(dave_node)

    alice_node.broadcast("New transaction")

    for node in [
        alice_node,
        bob_node,
        carol_node,
        dave_node,
    ]:
        print(
            node.name,
            "received:",
            "New transaction" in node.received_messages,
        )

    print(
        "\nDecentralized networks distribute communication and state across "
        "multiple participants rather than depending on one central server."
    )


# ============================================================================
# 27. DISTRIBUTED STORAGE CONCEPT
# ============================================================================

def chunk_data(data: bytes, chunk_size: int) -> List[bytes]:
    """Split data into fixed-size chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    return [
        data[index:index + chunk_size]
        for index in range(0, len(data), chunk_size)
    ]


def content_identifier(data: bytes) -> str:
    """
    Content-address data using its hash.

    Content addressing means the identifier depends on content rather than
    on a mutable location.
    """
    return sha256_hex(data)


def demonstrate_content_addressing() -> None:
    heading("25. CONTENT-ADDRESSED DATA")

    document = (
        b"Decentralized storage can identify content using cryptographic hashes."
    )

    chunks = chunk_data(document, chunk_size=20)

    for index, chunk in enumerate(chunks):
        print(
            f"Chunk {index}:",
            chunk,
            "ID:",
            content_identifier(chunk),
        )

    original_identifier = content_identifier(document)

    modified_document = document + b"!"
    modified_identifier = content_identifier(modified_document)

    print("\nOriginal content ID:", original_identifier)
    print("Modified content ID:", modified_identifier)
    print("IDs equal:", original_identifier == modified_identifier)


# ============================================================================
# 28. TOKEN AND DIGITAL ASSET ACCOUNTING
# ============================================================================

class FungibleToken:
    """
    Simplified fungible token accounting.

    Demonstrates:
    - Supply
    - Transfer
    - Balance checks
    - Allowance-like delegated transfer
    """

    def __init__(self, name: str, symbol: str):
        self.name = name
        self.symbol = symbol
        self.total_supply = 0
        self.balances: Dict[str, int] = defaultdict(int)
        self.allowances: Dict[Tuple[str, str], int] = defaultdict(int)

    def mint(self, recipient: str, amount: int) -> None:
        if amount <= 0:
            raise ValueError("Mint amount must be positive")

        self.total_supply += amount
        self.balances[recipient] += amount

    def transfer(
        self,
        sender: str,
        recipient: str,
        amount: int,
    ) -> None:
        if amount <= 0:
            raise ValueError("Transfer amount must be positive")

        if self.balances[sender] < amount:
            raise ValueError("Insufficient token balance")

        self.balances[sender] -= amount
        self.balances[recipient] += amount

    def approve(
        self,
        owner: str,
        spender: str,
        amount: int,
    ) -> None:
        if amount < 0:
            raise ValueError("Allowance cannot be negative")

        self.allowances[(owner, spender)] = amount

    def transfer_from(
        self,
        spender: str,
        owner: str,
        recipient: str,
        amount: int,
    ) -> None:
        if amount <= 0:
            raise ValueError("Transfer amount must be positive")

        allowance_key = (owner, spender)

        if self.allowances[allowance_key] < amount:
            raise PermissionError("Allowance is insufficient")

        if self.balances[owner] < amount:
            raise ValueError("Owner balance is insufficient")

        self.allowances[allowance_key] -= amount
        self.balances[owner] -= amount
        self.balances[recipient] += amount


def demonstrate_token_model() -> None:
    heading("26. FUNGIBLE TOKEN MODEL")

    token = FungibleToken(
        name="Educational Token",
        symbol="EDU",
    )

    token.mint("Alice", 1_000)

    token.transfer("Alice", "Bob", 200)

    print("Total supply:", token.total_supply)
    print("Alice:", token.balances["Alice"])
    print("Bob  :", token.balances["Bob"])

    token.approve("Alice", "Carol", 100)

    token.transfer_from(
        spender="Carol",
        owner="Alice",
        recipient="Dave",
        amount=75,
    )

    print("\nAfter delegated transfer:")
    print("Alice:", token.balances["Alice"])
    print("Dave :", token.balances["Dave"])
    print(
        "Remaining allowance:",
        token.allowances[("Alice", "Carol")],
    )


# ============================================================================
# 29. NON-FUNGIBLE ASSET CONCEPT
# ============================================================================

@dataclass
class UniqueAsset:
    """Simplified unique digital asset."""

    token_id: int
    owner: str
    metadata_uri: str


class UniqueAssetRegistry:
    """
    Registry where every token identifier represents a unique asset.
    """

    def __init__(self):
        self.assets: Dict[int, UniqueAsset] = {}

    def mint(
        self,
        token_id: int,
        owner: str,
        metadata_uri: str,
    ) -> None:
        if token_id in self.assets:
            raise ValueError("Token ID already exists")

        self.assets[token_id] = UniqueAsset(
            token_id=token_id,
            owner=owner,
            metadata_uri=metadata_uri,
        )

    def transfer(
        self,
        token_id: int,
        sender: str,
        recipient: str,
    ) -> None:
        asset = self.assets.get(token_id)

        if asset is None:
            raise ValueError("Unknown asset")

        if asset.owner != sender:
            raise PermissionError("Sender does not own asset")

        asset.owner = recipient


def demonstrate_unique_assets() -> None:
    heading("27. UNIQUE DIGITAL ASSETS")

    registry = UniqueAssetRegistry()

    registry.mint(
        token_id=1,
        owner="Alice",
        metadata_uri="content://asset/1",
    )

    print("Asset:", registry.assets[1])

    registry.transfer(
        token_id=1,
        sender="Alice",
        recipient="Bob",
    )

    print("New owner:", registry.assets[1].owner)

    print(
        "\nFungible units are interchangeable by quantity. Unique assets are "
        "distinguished by individual identifiers."
    )


# ============================================================================
# 30. ORACLES AND EXTERNAL DATA
# ============================================================================

class PriceOracle:
    """
    Simplified oracle.

    Smart contracts cannot safely assume that arbitrary off-chain information
    is automatically trustworthy. Oracle design introduces trust and integrity
    questions.
    """

    def __init__(self):
        self.sources: Dict[str, List[float]] = defaultdict(list)

    def submit_price(
        self,
        source: str,
        asset: str,
        price: float,
    ) -> None:
        if price <= 0:
            raise ValueError("Price must be positive")

        key = f"{asset}"
        self.sources[key].append(price)

    def median_price(self, asset: str) -> float:
        prices = self.sources.get(asset, [])

        if not prices:
            raise ValueError("No prices available")

        return statistics.median(prices)


def demonstrate_oracle_concept() -> None:
    heading("28. ORACLES AND EXTERNAL DATA")

    oracle = PriceOracle()

    prices = [
        ("Source-A", 100.0),
        ("Source-B", 101.0),
        ("Source-C", 99.5),
        ("Outlier", 10_000.0),
    ]

    for source, price in prices:
        oracle.submit_price(
            source,
            "ASSET",
            price,
        )

    print("Reported prices:", [price for _, price in prices])
    print("Median price:", oracle.median_price("ASSET"))

    print(
        "\nMedian aggregation can reduce sensitivity to extreme outliers, but "
        "oracle systems still require source selection and integrity controls."
    )


# ============================================================================
# 31. WALLET AND PRIVATE KEY SECURITY CONCEPTS
# ============================================================================

class EducationalWallet:
    """
    Simplified wallet abstraction.

    Real wallets use standardized asymmetric cryptography and secure key
    management. This class intentionally avoids claiming that its identifiers
    are production-grade private/public keys.
    """

    def __init__(self):
        self._private_secret = secrets.token_bytes(32)

        self.public_identifier = sha256_hex(
            self._private_secret
        )

        self.address = derive_address(
            self.public_identifier
        )

    def create_authorization_tag(
        self,
        message: str,
    ) -> str:
        """
        Demonstrate secret-based authorization.

        Production digital signatures should use standardized public-key
        signature algorithms instead.
        """
        return hmac.new(
            self._private_secret,
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()


def demonstrate_wallet_concept() -> None:
    heading("29. WALLET CONCEPTS")

    wallet = EducationalWallet()

    print("Public identifier:", wallet.public_identifier)
    print("Address:", wallet.address)

    authorization = wallet.create_authorization_tag(
        "Authorize transaction"
    )

    print("Authorization tag:", authorization)

    print(
        "\nThe most important wallet security principle is protection of secret "
        "key material. Loss or compromise of private keys can result in loss "
        "of control over associated assets."
    )


# ============================================================================
# 32. REPLAY ATTACK PREVENTION
# ============================================================================

@dataclass
class SignedIntent:
    """
    Simplified transaction intent.

    Nonce and domain separation help distinguish one authorization from another.
    """

    sender: str
    recipient: str
    amount: int
    nonce: int
    network_id: str

    def canonical_message(self) -> str:
        return canonical_json(asdict(self))


class ReplayProtectedProcessor:
    """
    Demonstrates monotonically increasing transaction nonces.
    """

    def __init__(self):
        self.expected_nonces: Dict[str, int] = defaultdict(int)

    def process(self, intent: SignedIntent) -> None:
        expected = self.expected_nonces[intent.sender]

        if intent.nonce != expected:
            raise ValueError(
                f"Replay or ordering violation: expected nonce {expected}"
            )

        self.expected_nonces[intent.sender] += 1


def demonstrate_replay_protection() -> None:
    heading("30. REPLAY PROTECTION")

    processor = ReplayProtectedProcessor()

    transaction = SignedIntent(
        sender="Alice",
        recipient="Bob",
        amount=10,
        nonce=0,
        network_id="network-1",
    )

    processor.process(transaction)

    print("First transaction accepted")

    try:
        processor.process(transaction)
    except ValueError as error:
        print("Replay rejected:", error)


# ============================================================================
# 33. DOUBLE-SPENDING RACE CONCEPT
# ============================================================================

def demonstrate_double_spend_race() -> None:
    heading("31. DOUBLE-SPENDING RACE")

    ledger = AccountLedger()
    ledger.fund("Alice", 100)

    print("Initial Alice balance:", ledger.balances["Alice"])

    first_transaction = {
        "sender": "Alice",
        "recipient": "Bob",
        "amount": 80,
    }

    second_transaction = {
        "sender": "Alice",
        "recipient": "Carol",
        "amount": 80,
    }

    print("Competing transaction A:", first_transaction)
    print("Competing transaction B:", second_transaction)

    ledger.transfer(
        sender="Alice",
        recipient="Bob",
        amount=80,
        nonce=0,
    )

    try:
        ledger.transfer(
            sender="Alice",
            recipient="Carol",
            amount=80,
            nonce=1,
        )
    except ValueError as error:
        print("Second spend rejected:", error)

    print(
        "\nConsensus determines transaction ordering so that conflicting spends "
        "cannot both become valid in the same canonical ledger history."
    )


# ============================================================================
# 34. BLOCKCHAIN PERFORMANCE CONCEPTS
# ============================================================================

def calculate_throughput(
    transactions_per_block: int,
    average_block_interval_seconds: float,
) -> float:
    """Calculate approximate transactions per second."""
    if transactions_per_block <= 0:
        raise ValueError("transactions_per_block must be positive")

    if average_block_interval_seconds <= 0:
        raise ValueError("block interval must be positive")

    return (
        transactions_per_block
        / average_block_interval_seconds
    )


def demonstrate_scalability_tradeoffs() -> None:
    heading("32. BLOCKCHAIN SCALABILITY")

    examples = [
        (100, 10),
        (1_000, 10),
        (1_000, 2),
    ]

    for transactions_per_block, interval in examples:
        throughput = calculate_throughput(
            transactions_per_block,
            interval,
        )

        print(
            f"{transactions_per_block} transactions/block, "
            f"{interval} seconds/block -> "
            f"{throughput:.2f} transactions/second"
        )

    print(
        "\nIncreasing block size or reducing block intervals can increase "
        "throughput, but may increase bandwidth, storage, hardware demands, "
        "fork probability, or centralization pressure."
    )


# ============================================================================
# 35. DECENTRALIZATION TRADE-OFF CONCEPT
# ============================================================================

@dataclass
class SystemTradeoff:
    """
    Illustrative comparison of system priorities.
    """

    name: str
    scalability: str
    decentralization: str
    security: str


def demonstrate_tradeoffs() -> None:
    heading("33. SECURITY, SCALABILITY, AND DECENTRALIZATION TRADE-OFFS")

    systems = [
        SystemTradeoff(
            "High-throughput centralized system",
            scalability="High",
            decentralization="Low",
            security="Depends on operator",
        ),
        SystemTradeoff(
            "Distributed permissioned system",
            scalability="Moderate to High",
            decentralization="Moderate",
            security="Depends on governance and consensus",
        ),
        SystemTradeoff(
            "Large permissionless blockchain",
            scalability="Protocol-dependent",
            decentralization="Potentially high",
            security="Distributed economic/security model",
        ),
    ]

    for system in systems:
        print(system)

    print(
        "\nThere is no universal numerical formula that ranks every architecture. "
        "Trade-offs depend on the threat model, consensus protocol, hardware, "
        "network topology, governance, and implementation."
    )


# ============================================================================
# 36. BASIC BLOCKCHAIN ATTACK ANALYSIS
# ============================================================================

def majority_attack_probability_explanation(
    attacker_fraction: float,
) -> str:
    """
    Explain the broad security implication of an attacker resource fraction.

    This is intentionally qualitative rather than presenting a complete
    probability model.
    """
    if not 0 <= attacker_fraction <= 1:
        raise ValueError("Fraction must be between 0 and 1")

    if attacker_fraction == 0:
        return "No attacker consensus resource in this model."

    if attacker_fraction < 0.5:
        return (
            "Attacker is below majority resource but may still create risks "
            "depending on confirmations and protocol assumptions."
        )

    if attacker_fraction == 0.5:
        return (
            "Attacker controls half of the modeled consensus resource; "
            "security assumptions are critically weakened."
        )

    return (
        "Attacker controls a majority of the modeled consensus resource and "
        "can potentially influence canonical history under simplified models."
    )


def demonstrate_attack_analysis() -> None:
    heading("34. CONSENSUS ATTACK CONCEPTS")

    for fraction in [0.0, 0.1, 0.3, 0.5, 0.7]:
        print(
            f"Attacker resource fraction {fraction:.0%}:",
            majority_attack_probability_explanation(fraction),
        )

    print(
        "\nA majority attack does not automatically reveal private keys or allow "
        "arbitrary creation of valid signatures. Its capabilities depend on the "
        "specific consensus protocol and validation rules."
    )


# ============================================================================
# 37. PRIVACY CONCEPTS
# ============================================================================

def pseudonymity_analysis(
    addresses: List[str],
    observed_links: List[Tuple[str, str]],
) -> Dict[str, set[str]]:
    """
    Build a simple graph of observed address relationships.

    Public ledger visibility can enable transaction graph analysis even when
    addresses do not directly contain legal identities.
    """
    graph: Dict[str, set[str]] = defaultdict(set)

    for first, second in observed_links:
        graph[first].add(second)
        graph[second].add(first)

    for address in addresses:
        graph[address]

    return graph


def demonstrate_privacy() -> None:
    heading("35. PRIVACY AND PSEUDONYMITY")

    addresses = ["A1", "A2", "B1", "C1"]

    links = [
        ("A1", "B1"),
        ("A2", "B1"),
        ("B1", "C1"),
    ]

    graph = pseudonymity_analysis(addresses, links)

    for address, connected_addresses in graph.items():
        print(
            address,
            "connected to",
            sorted(connected_addresses),
        )

    print(
        "\nPseudonymity means an identifier may not directly reveal a legal "
        "identity. It does not guarantee anonymity when transaction patterns "
        "and external information can be correlated."
    )


# ============================================================================
# 38. VALIDATION AND SECURITY PRINCIPLES
# ============================================================================

def validate_transfer_request(
    sender: str,
    recipient: str,
    amount: int,
    maximum_amount: int = 10**12,
) -> None:
    """
    Demonstrate defensive input validation.
    """
    if not isinstance(sender, str) or not sender:
        raise ValueError("sender must be a non-empty string")

    if not isinstance(recipient, str) or not recipient:
        raise ValueError("recipient must be a non-empty string")

    if sender == recipient:
        raise ValueError("sender and recipient must differ")

    if isinstance(amount, bool) or not isinstance(amount, int):
        raise TypeError("amount must be an integer")

    if amount <= 0:
        raise ValueError("amount must be positive")

    if amount > maximum_amount:
        raise ValueError("amount exceeds configured maximum")


def demonstrate_validation() -> None:
    heading("36. VALIDATION AND DEFENSIVE PROGRAMMING")

    valid_request = ("Alice", "Bob", 100)

    validate_transfer_request(*valid_request)

    print("Valid request accepted:", valid_request)

    invalid_cases = [
        ("", "Bob", 10),
        ("Alice", "Alice", 10),
        ("Alice", "Bob", 0),
        ("Alice", "Bob", -1),
        ("Alice", "Bob", True),
    ]

    for case in invalid_cases:
        try:
            validate_transfer_request(*case)
        except (ValueError, TypeError) as error:
            print("Rejected", case, "->", error)


# ============================================================================
# 39. TESTING
# ============================================================================

def test_hash_determinism() -> None:
    assert sha256_hex("test") == sha256_hex("test")
    assert sha256_hex("test") != sha256_hex("Test")


def test_xor_round_trip() -> None:
    message = b"hello"
    key = b"key"

    ciphertext = xor_bytes(message, key)

    assert xor_bytes(ciphertext, key) == message


def test_modular_inverse() -> None:
    inverse = modular_inverse(7, 19)
    assert (7 * inverse) % 19 == 1


def test_merkle_proof() -> None:
    values = ["A", "B", "C", "D"]
    tree = MerkleTree(values)

    proof = tree.proof(2)

    assert MerkleTree.verify_proof(
        "C",
        proof,
        tree.root,
    )

    assert not MerkleTree.verify_proof(
        "X",
        proof,
        tree.root,
    )


def test_basic_blockchain_tampering() -> None:
    blockchain = BasicBlockchain(difficulty=1)

    blockchain.add_transaction(
        "network",
        "Alice",
        100,
    )

    blockchain.mine_pending_transactions("Miner")

    assert blockchain.validate_chain()

    blockchain.chain[1].transactions[0]["amount"] = 999

    assert not blockchain.validate_chain()


def test_utxo_double_spending() -> None:
    ledger = UTXOLedger()

    output = ledger.create_genesis_output(
        "Alice",
        50,
    )

    transaction = UTXOTransaction(
        inputs=[output.identifier],
        outputs=[("Bob", 50)],
    )

    ledger.apply_transaction(
        transaction,
        "Alice",
    )

    failed = False

    try:
        ledger.apply_transaction(
            transaction,
            "Alice",
        )
    except ValueError:
        failed = True

    assert failed


def run_tests() -> None:
    heading("37. AUTOMATED TESTS")

    tests = [
        test_hash_determinism,
        test_xor_round_trip,
        test_modular_inverse,
        test_merkle_proof,
        test_basic_blockchain_tampering,
        test_utxo_double_spending,
    ]

    for test_function in tests:
        test_function()
        print("PASSED:", test_function.__name__)


# ============================================================================
# 40. PERFORMANCE BENCHMARKING
# ============================================================================

def benchmark_hashing(iterations: int = 100_000) -> None:
    """
    Measure approximate SHA-256 throughput.

    Results depend on CPU, Python version, operating system, and environment.
    """
    heading("38. PERFORMANCE: HASHING")

    data = b"Performance measurement input"

    start = time.perf_counter()

    for _ in range(iterations):
        hashlib.sha256(data).digest()

    elapsed = time.perf_counter() - start

    hashes_per_second = (
        iterations / elapsed
        if elapsed > 0
        else float("inf")
    )

    print("Iterations:", iterations)
    print("Elapsed seconds:", round(elapsed, 6))
    print(
        "Approximate hashes/second:",
        round(hashes_per_second, 2),
    )


# ============================================================================
# 41. SERIALIZATION PITFALLS
# ============================================================================

def demonstrate_serialization_problem() -> None:
    heading("39. SERIALIZATION AND CONSENSUS")

    data_one = {
        "sender": "Alice",
        "recipient": "Bob",
        "amount": 10,
    }

    data_two = {
        "amount": 10,
        "recipient": "Bob",
        "sender": "Alice",
    }

    naive_one = json.dumps(data_one)
    naive_two = json.dumps(data_two)

    canonical_one = canonical_json(data_one)
    canonical_two = canonical_json(data_two)

    print("Naive serialization equal:", naive_one == naive_two)
    print(
        "Canonical serialization equal:",
        canonical_one == canonical_two,
    )

    print(
        "\nConsensus systems require participants to agree on exactly which "
        "bytes are hashed and validated. Ambiguous serialization can cause "
        "nodes to disagree about logically identical data."
    )


# ============================================================================
# 42. TIME AND FINALITY
# ============================================================================

@dataclass
class Confirmation:
    block_height: int
    transaction_id: str


def confirmations(
    chain_height: int,
    transaction_block_height: int,
) -> int:
    """Calculate simple confirmation count."""
    if transaction_block_height > chain_height:
        return 0

    return chain_height - transaction_block_height + 1


def demonstrate_confirmations() -> None:
    heading("40. CONFIRMATIONS AND FINALITY")

    current_height = 100

    for transaction_height in [100, 99, 95, 90]:
        count = confirmations(
            current_height,
            transaction_height,
        )

        print(
            f"Transaction in block {transaction_height}: "
            f"{count} confirmations"
        )

    print(
        "\nSome consensus protocols provide probabilistic confidence that "
        "increases with additional blocks, while others provide explicit "
        "finality after defined validator conditions are met."
    )


# ============================================================================
# 43. DECENTRALIZED GOVERNANCE CONCEPT
# ============================================================================

@dataclass
class Proposal:
    proposal_id: int
    description: str
    votes_for: int = 0
    votes_against: int = 0
    closed: bool = False

    def vote(self, support: bool, voting_power: int) -> None:
        if self.closed:
            raise ValueError("Proposal is closed")

        if voting_power <= 0:
            raise ValueError("Voting power must be positive")

        if support:
            self.votes_for += voting_power
        else:
            self.votes_against += voting_power

    def result(self) -> str:
        if not self.closed:
            return "OPEN"

        if self.votes_for > self.votes_against:
            return "APPROVED"

        return "REJECTED"

    def close(self) -> None:
        self.closed = True


def demonstrate_governance() -> None:
    heading("41. DECENTRALIZED GOVERNANCE CONCEPT")

    proposal = Proposal(
        proposal_id=1,
        description="Change protocol parameter",
    )

    proposal.vote(True, voting_power=100)
    proposal.vote(False, voting_power=40)
    proposal.vote(True, voting_power=20)

    proposal.close()

    print("Votes for:", proposal.votes_for)
    print("Votes against:", proposal.votes_against)
    print("Result:", proposal.result())

    print(
        "\nToken-weighted governance can concentrate influence among large "
        "holders. Other governance mechanisms may use delegates, quorums, "
        "quadratic approaches, identity systems, or off-chain processes."
    )


# ============================================================================
# 44. PRODUCTION DESIGN CHECKLIST
# ============================================================================

PRODUCTION_CONSIDERATIONS = [
    "Use standardized and audited cryptographic libraries.",
    "Never design custom cryptographic primitives for production use.",
    "Use cryptographically secure randomness for keys and nonces.",
    "Protect private keys using appropriate hardware or secure storage.",
    "Authenticate network communication where required.",
    "Define canonical serialization rules.",
    "Validate all transaction inputs and state transitions.",
    "Prevent replay through nonces, sequence numbers, or equivalent rules.",
    "Protect against denial-of-service through resource limits and fees.",
    "Perform code review and automated testing.",
    "Use deterministic execution for consensus-critical code.",
    "Plan for software upgrades and governance.",
    "Monitor nodes and infrastructure.",
    "Consider data privacy and regulatory requirements.",
    "Document threat models and trust assumptions.",
]


def demonstrate_production_considerations() -> None:
    heading("42. PRODUCTION CONSIDERATIONS")

    for number, consideration in enumerate(
        PRODUCTION_CONSIDERATIONS,
        start=1,
    ):
        print(f"{number}. {consideration}")


# ============================================================================
# 45. COMPLETE INTEGRATED DEMONSTRATION
# ============================================================================

def integrated_demo() -> None:
    """
    Connect several concepts in one workflow.

    Flow:
    1. Create transaction data.
    2. Hash it.
    3. Authenticate it.
    4. Place transactions in a Merkle tree.
    5. Mine a block containing the transactions.
    6. Validate the block and chain.
    """
    heading("43. INTEGRATED CRYPTOGRAPHY AND BLOCKCHAIN DEMONSTRATION")

    transactions = [
        {
            "sender": "Alice",
            "recipient": "Bob",
            "amount": 10,
            "nonce": 0,
        },
        {
            "sender": "Bob",
            "recipient": "Carol",
            "amount": 3,
            "nonce": 0,
        },
    ]

    serialized_transactions = [
        canonical_json(transaction)
        for transaction in transactions
    ]

    transaction_hashes = [
        sha256_hex(transaction)
        for transaction in serialized_transactions
    ]

    print("Transaction hashes:")
    for transaction_hash in transaction_hashes:
        print(" ", transaction_hash)

    merkle_tree = MerkleTree(serialized_transactions)

    print("\nMerkle root:", merkle_tree.root)

    secret_key = secrets.token_bytes(32)

    first_transaction_tag = create_hmac(
        secret_key,
        serialized_transactions[0].encode("utf-8"),
    )

    print(
        "\nAuthentication valid:",
        verify_hmac(
            secret_key,
            serialized_transactions[0].encode("utf-8"),
            first_transaction_tag,
        ),
    )

    blockchain = BasicBlockchain(
        difficulty=2,
        mining_reward=50,
    )

    for transaction in transactions:
        blockchain.add_transaction(
            transaction["sender"],
            transaction["recipient"],
            transaction["amount"],
        )

    block = blockchain.mine_pending_transactions(
        miner="Miner-1"
    )

    print("\nMined block:", block.index)
    print("Block hash:", block.hash)
    print("Previous hash:", block.previous_hash)
    print("Blockchain valid:", blockchain.validate_chain())


# ============================================================================
# MAIN PROGRAM
# ============================================================================

def main() -> None:
    """
    Run all demonstrations in progressive order.

    Difficulty is intentionally kept low so Proof-of-Work examples finish
    quickly on ordinary hardware.
    """
    demonstrate_entropy()
    demonstrate_classical_cryptography()
    demonstrate_modular_arithmetic()
    demonstrate_hash_functions()
    demonstrate_hash_collision_concept()
    demonstrate_hmac()
    demonstrate_xor_encryption()
    demonstrate_one_time_pad()
    demonstrate_key_derivation()
    demonstrate_diffie_hellman()
    demonstrate_toy_rsa()
    demonstrate_digital_signatures()
    demonstrate_addresses()
    demonstrate_merkle_tree()
    demonstrate_proof_of_work()
    demonstrate_basic_blockchain()
    demonstrate_utxo_model()
    demonstrate_account_model()
    demonstrate_proof_of_stake()
    demonstrate_byzantine_fault_tolerance()
    demonstrate_forks()
    demonstrate_smart_contract_state_machine()
    demonstrate_contract_security_pattern()
    demonstrate_gossip_network()
    demonstrate_content_addressing()
    demonstrate_token_model()
    demonstrate_unique_assets()
    demonstrate_oracle_concept()
    demonstrate_wallet_concept()
    demonstrate_replay_protection()
    demonstrate_double_spend_race()
    demonstrate_scalability_tradeoffs()
    demonstrate_tradeoffs()
    demonstrate_attack_analysis()
    demonstrate_privacy()
    demonstrate_validation()
    run_tests()
    benchmark_hashing(iterations=50_000)
    demonstrate_serialization_problem()
    demonstrate_confirmations()
    demonstrate_governance()
    demonstrate_production_considerations()
    integrated_demo()


if __name__ == "__main__":
    main()
