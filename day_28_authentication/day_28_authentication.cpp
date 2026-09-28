/*
 * Authentication in Cryptography, Blockchain, and Decentralized Technologies
 * ===========================================================================
 *
 * C++17 industry-style case study:
 *
 * A simplified blockchain payment network authenticates transactions using
 * cryptographic signatures, protects against replay using account nonces,
 * validates state transitions, stores authenticated transactions in blocks,
 * calculates a Merkle root, and verifies a chain.
 *
 * The C++ standard library does not provide a complete production-grade
 * Ed25519/ECDSA implementation, so this program uses a deterministic
 * educational signature model built from SHA-256-style hashing primitives.
 *
 * This is intentionally a protocol case study, not a replacement for a
 * vetted cryptographic library.
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;

static std::string toHex(const Bytes& data) {
    std::ostringstream output;

    for (Byte value : data) {
        output << std::hex << std::setw(2) << std::setfill('0')
               << static_cast<int>(value);
    }

    return output.str();
}

/*
 * A compact educational hash function.
 *
 * It is deliberately not presented as a secure replacement for SHA-256.
 * A production blockchain should use a standardized, independently audited
 * cryptographic primitive and a vetted implementation.
 */
class EducationalHash {
public:
    static std::string hash(const std::string& input) {
        std::uint64_t state1 = 0x243F6A8885A308D3ULL;
        std::uint64_t state2 = 0x13198A2E03707344ULL;
        std::uint64_t state3 = 0xA4093822299F31D0ULL;
        std::uint64_t state4 = 0x082EFA98EC4E6C89ULL;

        for (unsigned char byte : input) {
            state1 ^= byte;
            state1 *= 0x100000001B3ULL;
            state1 ^= state1 >> 29;

            state2 += byte + (state1 << 7);
            state2 ^= state2 >> 31;
            state2 *= 0x9E3779B185EBCA87ULL;

            state3 ^= state2 + byte;
            state3 *= 0xC2B2AE3D27D4EB4FULL;
            state3 ^= state3 >> 33;

            state4 += state3 ^ (static_cast<std::uint64_t>(byte) << 17);
            state4 *= 0x165667B19E3779F9ULL;
            state4 ^= state4 >> 32;
        }

        std::ostringstream output;
        output << std::hex
               << std::setw(16) << std::setfill('0') << state1
               << std::setw(16) << state2
               << std::setw(16) << state3
               << std::setw(16) << state4;

        return output.str();
    }
};

/*
 * Educational signature identity.
 *
 * Real asymmetric authentication has a private key and a mathematically
 * related public key. The private key signs, while anyone with the public key
 * verifies. This case study models that architectural boundary explicitly.
 */
class Identity {
private:
    std::string privateKey_;
    std::string publicKey_;

public:
    explicit Identity(const std::string& privateKey)
        : privateKey_(privateKey),
          publicKey_(EducationalHash::hash("PUBLIC|" + privateKey)) {}

    const std::string& publicKey() const {
        return publicKey_;
    }

    std::string sign(const std::string& message) const {
        /*
         * The signature depends on both private key and exact message bytes.
         * Changing one transaction field therefore changes the signature.
         */
        return EducationalHash::hash("SIGNATURE|" + privateKey_ + "|" + message);
    }

    bool verify(const std::string& message,
                const std::string& signature) const {
        return sign(message) == signature;
    }
};

struct Account {
    std::string address;
    std::int64_t balance;
    std::uint64_t nonce;
    Identity identity;

    Account(
        std::string addressValue,
        std::int64_t initialBalance,
        std::string privateKey
    )
        : address(std::move(addressValue)),
          balance(initialBalance),
          nonce(0),
          identity(std::move(privateKey)) {}
};

struct Transaction {
    std::string sender;
    std::string receiver;
    std::int64_t amount;
    std::uint64_t nonce;
    std::string signature;

    std::string canonicalPayload() const {
        /*
         * Deterministic serialization is essential. Every validator must sign
         * and verify exactly the same representation.
         */
        std::ostringstream output;
        output << "amount=" << amount
               << "|nonce=" << nonce
               << "|receiver=" << receiver
               << "|sender=" << sender;

        return output.str();
    }
};

struct ValidationResult {
    bool valid;
    std::string reason;
};

class Blockchain {
private:
    std::map<std::string, Account> accounts_;

public:
    void addAccount(
        const std::string& address,
        std::int64_t initialBalance,
        const std::string& privateKey
    ) {
        if (address.empty()) {
            throw std::invalid_argument("Address cannot be empty");
        }

        if (initialBalance < 0) {
            throw std::invalid_argument("Initial balance cannot be negative");
        }

        if (accounts_.find(address) != accounts_.end()) {
            throw std::invalid_argument("Account already exists");
        }

        accounts_.emplace(
            std::piecewise_construct,
            std::forward_as_tuple(address),
            std::forward_as_tuple(
                address,
                initialBalance,
                privateKey
            )
        );
    }

    Transaction createTransaction(
        const std::string& sender,
        const std::string& receiver,
        std::int64_t amount
    ) {
        auto senderIt = accounts_.find(sender);

        if (senderIt == accounts_.end()) {
            throw std::invalid_argument("Sender account does not exist");
        }

        Transaction transaction{
            sender,
            receiver,
            amount,
            senderIt->second.nonce,
            ""
        };

        transaction.signature =
            senderIt->second.identity.sign(transaction.canonicalPayload());

        return transaction;
    }

    ValidationResult validate(const Transaction& transaction) const {
        if (transaction.sender.empty() || transaction.receiver.empty()) {
            return {false, "Sender and receiver are required"};
        }

        if (transaction.amount <= 0) {
            return {false, "Amount must be positive"};
        }

        auto senderIt = accounts_.find(transaction.sender);
        auto receiverIt = accounts_.find(transaction.receiver);

        if (senderIt == accounts_.end() ||
            receiverIt == accounts_.end()) {
            return {false, "Unknown sender or receiver"};
        }

        const Account& sender = senderIt->second;

        if (transaction.amount > sender.balance) {
            return {false, "Insufficient balance"};
        }

        /*
         * A nonce binds an authenticated transaction to the expected sequence.
         * Reusing an old transaction therefore fails after the state advances.
         */
        if (transaction.nonce != sender.nonce) {
            return {false, "Invalid nonce or replay detected"};
        }

        if (transaction.signature.empty()) {
            return {false, "Missing signature"};
        }

        if (!sender.identity.verify(
                transaction.canonicalPayload(),
                transaction.signature)) {
            return {false, "Invalid cryptographic signature"};
        }

        return {true, "Transaction authenticated"};
    }

    ValidationResult apply(const Transaction& transaction) {
        ValidationResult result = validate(transaction);

        if (!result.valid) {
            return result;
        }

        Account& sender = accounts_.at(transaction.sender);
        Account& receiver = accounts_.at(transaction.receiver);

        sender.balance -= transaction.amount;
        receiver.balance += transaction.amount;

        ++sender.nonce;

        return {true, "Transaction applied"};
    }

    const Account& account(const std::string& address) const {
        return accounts_.at(address);
    }
};

/*
 * MerkleTree authenticates a collection of transaction identifiers.
 *
 * Hashes are combined pairwise until one root remains. If a leaf changes,
 * every ancestor on its path changes, eventually changing the root.
 */
class MerkleTree {
public:
    static std::string root(const std::vector<std::string>& transactions) {
        if (transactions.empty()) {
            return EducationalHash::hash("");
        }

        std::vector<std::string> level;

        for (const auto& transaction : transactions) {
            level.push_back(EducationalHash::hash(transaction));
        }

        while (level.size() > 1) {
            if (level.size() % 2 != 0) {
                level.push_back(level.back());
            }

            std::vector<std::string> nextLevel;

            for (std::size_t i = 0; i < level.size(); i += 2) {
                nextLevel.push_back(
                    EducationalHash::hash(
                        level[i] + "|" + level[i + 1]
                    )
                );
            }

            level = std::move(nextLevel);
        }

        return level.front();
    }
};

struct Block {
    std::size_t index;
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string merkleRoot;
    std::string blockHash;

    std::string calculateHash() const {
        std::ostringstream payload;

        payload << index << "|"
                << previousHash << "|"
                << merkleRoot;

        for (const auto& transaction : transactions) {
            payload << "|"
                    << transaction.canonicalPayload()
                    << "|"
                    << transaction.signature;
        }

        return EducationalHash::hash(payload.str());
    }
};

class AuthenticatedLedger {
private:
    Blockchain state_;
    std::vector<Block> chain_;

public:
    AuthenticatedLedger() {
        Block genesis{
            0,
            "0",
            {},
            MerkleTree::root({}),
            ""
        };

        genesis.blockHash = genesis.calculateHash();
        chain_.push_back(genesis);
    }

    Blockchain& state() {
        return state_;
    }

    const std::vector<Block>& chain() const {
        return chain_;
    }

    bool appendBlock(const std::vector<Transaction>& transactions) {
        if (transactions.empty()) {
            return false;
        }

        /*
         * Validate everything before mutating state. This avoids partially
         * applying a block when a later transaction fails.
         */
        for (const auto& transaction : transactions) {
            ValidationResult result = state_.validate(transaction);

            if (!result.valid) {
                std::cerr << "Block rejected: " << result.reason << "\n";
                return false;
            }
        }

        for (const auto& transaction : transactions) {
            ValidationResult result = state_.apply(transaction);

            if (!result.valid) {
                return false;
            }
        }

        std::vector<std::string> transactionHashes;

        for (const auto& transaction : transactions) {
            transactionHashes.push_back(
                EducationalHash::hash(
                    transaction.canonicalPayload() +
                    "|" +
                    transaction.signature
                )
            );
        }

        Block block{
            chain_.size(),
            chain_.back().blockHash,
            transactions,
            MerkleTree::root(transactionHashes),
            ""
        };

        block.blockHash = block.calculateHash();
        chain_.push_back(std::move(block));

        return true;
    }

    bool verifyChain() const {
        for (std::size_t i = 1; i < chain_.size(); ++i) {
            const Block& current = chain_[i];
            const Block& previous = chain_[i - 1];

            if (current.previousHash != previous.blockHash) {
                return false;
            }

            if (current.blockHash != current.calculateHash()) {
                return false;
            }

            std::vector<std::string> transactionHashes;

            for (const auto& transaction : current.transactions) {
                transactionHashes.push_back(
                    EducationalHash::hash(
                        transaction.canonicalPayload() +
                        "|" +
                        transaction.signature
                    )
                );
            }

            if (MerkleTree::root(transactionHashes) != current.merkleRoot) {
                return false;
            }
        }

        return true;
    }
};

static void printSection(const std::string& title) {
    std::cout << "\n" << std::string(78, '=') << "\n";
    std::cout << title << "\n";
    std::cout << std::string(78, '=') << "\n";
}

static void demonstrateBasicAuthentication() {
    printSection("1. Basic Authentication Concepts");

    Identity alice("alice-private-key");

    const std::string message = "authenticated message";
    const std::string signature = alice.sign(message);

    std::cout << "Public identifier: " << alice.publicKey() << "\n";
    std::cout << "Signature: " << signature << "\n";
    std::cout << "Valid message: "
              << std::boolalpha
              << alice.verify(message, signature)
              << "\n";

    std::cout << "Modified message: "
              << alice.verify("modified message", signature)
              << "\n";
}

static void demonstrateBlockchainTransactions() {
    printSection("2. Authenticated Blockchain Transactions");

    Blockchain blockchain;

    blockchain.addAccount("alice", 100, "alice-secret");
    blockchain.addAccount("bob", 20, "bob-secret");

    Transaction transaction =
        blockchain.createTransaction("alice", "bob", 30);

    ValidationResult result = blockchain.apply(transaction);

    std::cout << "Transaction status: "
              << result.reason << "\n";

    std::cout << "Alice balance: "
              << blockchain.account("alice").balance
              << "\n";

    std::cout << "Bob balance: "
              << blockchain.account("bob").balance
              << "\n";

    /*
     * The exact same signed transaction is replayed.
     * Alice's nonce is now 1, while the transaction carries nonce 0.
     */
    ValidationResult replay = blockchain.apply(transaction);

    std::cout << "Replay status: "
              << replay.reason
              << "\n";
}

static void demonstrateTampering() {
    printSection("3. Signature Tampering Detection");

    Blockchain blockchain;

    blockchain.addAccount("alice", 100, "alice-secret");
    blockchain.addAccount("bob", 20, "bob-secret");

    Transaction transaction =
        blockchain.createTransaction("alice", "bob", 30);

    transaction.amount = 90;

    ValidationResult result = blockchain.validate(transaction);

    std::cout << "Tampered transaction accepted: "
              << result.valid
              << "\n";

    std::cout << "Reason: "
              << result.reason
              << "\n";
}

static void demonstrateMerkleTree() {
    printSection("4. Merkle Root Authentication");

    std::vector<std::string> transactions{
        "tx1:alice:bob:10",
        "tx2:bob:carol:5",
        "tx3:carol:dave:2",
        "tx4:dave:alice:1"
    };

    const std::string originalRoot =
        MerkleTree::root(transactions);

    transactions[2] = "tx3:carol:dave:200";

    const std::string modifiedRoot =
        MerkleTree::root(transactions);

    std::cout << "Original root: "
              << originalRoot << "\n";

    std::cout << "Modified root: "
              << modifiedRoot << "\n";

    std::cout << "Modification detected: "
              << (originalRoot != modifiedRoot)
              << "\n";
}

static void demonstrateFullLedger() {
    printSection("5. Complete Authenticated Ledger Case Study");

    AuthenticatedLedger ledger;

    ledger.state().addAccount("alice", 1000, "alice-secret");
    ledger.state().addAccount("bob", 200, "bob-secret");
    ledger.state().addAccount("carol", 50, "carol-secret");

    Transaction first =
        ledger.state().createTransaction("alice", "bob", 150);

    Transaction second =
        ledger.state().createTransaction("bob", "carol", 25);

    /*
     * These transactions use independent accounts, so both carry the correct
     * current nonce of zero.
     */
    bool blockAccepted =
        ledger.appendBlock({first, second});

    std::cout << "Block accepted: "
              << blockAccepted
              << "\n";

    std::cout << "Alice: "
              << ledger.state().account("alice").balance
              << "\n";

    std::cout << "Bob: "
              << ledger.state().account("bob").balance
              << "\n";

    std::cout << "Carol: "
              << ledger.state().account("carol").balance
              << "\n";

    std::cout << "Chain valid: "
              << ledger.verifyChain()
              << "\n";

    std::cout << "Blocks: "
              << ledger.chain().size()
              << "\n";
}

static void demonstrateFailureConditions() {
    printSection("6. Failure Conditions");

    Blockchain blockchain;

    blockchain.addAccount("alice", 100, "alice-secret");
    blockchain.addAccount("bob", 20, "bob-secret");

    Transaction excessive =
        blockchain.createTransaction("alice", "bob", 500);

    ValidationResult excessiveResult =
        blockchain.validate(excessive);

    std::cout << "Insufficient funds: "
              << excessiveResult.reason
              << "\n";

    Transaction valid =
        blockchain.createTransaction("alice", "bob", 10);

    valid.signature = "forged-signature";

    ValidationResult forged =
        blockchain.validate(valid);

    std::cout << "Forged signature: "
              << forged.reason
              << "\n";

    Transaction invalidAmount =
        blockchain.createTransaction("alice", "bob", -1);

    ValidationResult negative =
        blockchain.validate(invalidAmount);

    std::cout << "Negative amount: "
              << negative.reason
              << "\n";
}

static void demonstrateDesignConsiderations() {
    printSection("7. Design and Security Considerations");

    const std::vector<std::string> principles{
        "Authentication proves control of a credential or cryptographic key.",
        "Authorization determines what an authenticated identity may do.",
        "Digital signatures authenticate message origin and protect integrity.",
        "Nonces provide transaction freshness and replay protection.",
        "Canonical serialization prevents ambiguous signed representations.",
        "Merkle roots authenticate large collections through compact commitments.",
        "Private-key compromise can allow an attacker to impersonate the key holder.",
        "Public blockchains make permanent data exposure an important privacy concern.",
        "Key rotation and recovery must be designed before production deployment.",
        "Cryptographic algorithms should come from audited standard libraries."
    };

    for (const auto& principle : principles) {
        std::cout << "- " << principle << "\n";
    }
}

int main() {
    try {
        demonstrateBasicAuthentication();
        demonstrateBlockchainTransactions();
        demonstrateTampering();
        demonstrateMerkleTree();
        demonstrateFullLedger();
        demonstrateFailureConditions();
        demonstrateDesignConsiderations();

        printSection("8. Complexity Notes");

        std::cout
            << "Signature verification is generally much more expensive than "
               "ordinary field validation.\n"
            << "Nonce lookup is O(log n) with the std::map used here.\n"
            << "Merkle-root construction is O(n log n) in this straightforward "
               "implementation.\n"
            << "Block validation is O(t) for t transactions, excluding the "
               "cost of cryptographic operations.\n"
            << "Real systems use optimized cryptographic primitives, persistent "
               "state, concurrency controls, networking, consensus, and durable "
               "storage.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what()
                  << "\n";
        return 1;
    }
}
