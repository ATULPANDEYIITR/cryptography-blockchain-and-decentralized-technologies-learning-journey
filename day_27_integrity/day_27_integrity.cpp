/*
 * Integrity in Cryptography and Blockchain
 * ========================================
 *
 * C++17 case study:
 * A tamper-evident digital asset ledger using:
 *   - SHA-256
 *   - deterministic transaction serialization
 *   - Merkle trees
 *   - hash-linked blocks
 *   - proof of work
 *   - transaction validation
 *   - complete-chain verification
 *
 * This program intentionally uses only the C++ standard library.
 * SHA-256 is implemented here for educational purposes. Production systems
 * should use a professionally reviewed cryptographic library.
 */

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

using Byte = std::uint8_t;
using Digest = std::array<Byte, 32>;


// ============================================================================
// 1. SHA-256 IMPLEMENTATION
// ============================================================================

class SHA256 {
private:
    std::array<std::uint32_t, 64> roundConstants = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static std::uint32_t rotateRight(std::uint32_t value, int amount) {
        return (value >> amount) | (value << (32 - amount));
    }

    static std::uint32_t choose(std::uint32_t x,
                                 std::uint32_t y,
                                 std::uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static std::uint32_t majority(std::uint32_t x,
                                  std::uint32_t y,
                                  std::uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static std::uint32_t sigma0(std::uint32_t x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }

    static std::uint32_t sigma1(std::uint32_t x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }

    static std::uint32_t gamma0(std::uint32_t x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
    }

    static std::uint32_t gamma1(std::uint32_t x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
    }

    static std::uint32_t readBigEndian(const Byte* data) {
        return (static_cast<std::uint32_t>(data[0]) << 24) |
               (static_cast<std::uint32_t>(data[1]) << 16) |
               (static_cast<std::uint32_t>(data[2]) << 8) |
               static_cast<std::uint32_t>(data[3]);
    }

public:
    static Digest hash(const std::string& input) {
        std::vector<Byte> message(input.begin(), input.end());

        const std::uint64_t bitLength =
            static_cast<std::uint64_t>(message.size()) * 8ULL;

        message.push_back(0x80);

        while ((message.size() % 64) != 56) {
            message.push_back(0x00);
        }

        for (int shift = 56; shift >= 0; shift -= 8) {
            message.push_back(
                static_cast<Byte>((bitLength >> shift) & 0xff)
            );
        }

        std::uint32_t h0 = 0x6a09e667;
        std::uint32_t h1 = 0xbb67ae85;
        std::uint32_t h2 = 0x3c6ef372;
        std::uint32_t h3 = 0xa54ff53a;
        std::uint32_t h4 = 0x510e527f;
        std::uint32_t h5 = 0x9b05688c;
        std::uint32_t h6 = 0x1f83d9ab;
        std::uint32_t h7 = 0x5be0cd19;

        for (std::size_t offset = 0; offset < message.size(); offset += 64) {
            std::array<std::uint32_t, 64> w{};

            for (int i = 0; i < 16; ++i) {
                w[i] = readBigEndian(&message[offset + i * 4]);
            }

            for (int i = 16; i < 64; ++i) {
                w[i] = gamma1(w[i - 2]) + w[i - 7] +
                       gamma0(w[i - 15]) + w[i - 16];
            }

            std::uint32_t a = h0;
            std::uint32_t b = h1;
            std::uint32_t c = h2;
            std::uint32_t d = h3;
            std::uint32_t e = h4;
            std::uint32_t f = h5;
            std::uint32_t g = h6;
            std::uint32_t h = h7;

            for (int i = 0; i < 64; ++i) {
                const std::uint32_t temp1 =
                    h + sigma1(e) + choose(e, f, g) +
                    roundConstants[i] + w[i];

                const std::uint32_t temp2 =
                    sigma0(a) + majority(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }

        const std::array<std::uint32_t, 8> words = {
            h0, h1, h2, h3, h4, h5, h6, h7
        };

        Digest result{};

        for (std::size_t i = 0; i < words.size(); ++i) {
            result[i * 4] =
                static_cast<Byte>((words[i] >> 24) & 0xff);
            result[i * 4 + 1] =
                static_cast<Byte>((words[i] >> 16) & 0xff);
            result[i * 4 + 2] =
                static_cast<Byte>((words[i] >> 8) & 0xff);
            result[i * 4 + 3] =
                static_cast<Byte>(words[i] & 0xff);
        }

        return result;
    }

    static std::string hex(const Digest& digest) {
        std::ostringstream output;
        output << std::hex << std::setfill('0');

        for (Byte value : digest) {
            output << std::setw(2) << static_cast<int>(value);
        }

        return output.str();
    }
};


// ============================================================================
// 2. TRANSACTION MODEL
// ============================================================================

struct Transaction {
    std::string sender;
    std::string recipient;
    std::uint64_t amount;

    bool isValid() const {
        return !sender.empty() &&
               !recipient.empty() &&
               amount > 0 &&
               amount <= 1000000000000ULL;
    }

    /*
     * Delimiter-based serialization is deterministic for this controlled
     * example. Production protocols should use a rigorously specified
     * canonical serialization format.
     */
    std::string serialize() const {
        return sender + "|" + recipient + "|" + std::to_string(amount);
    }

    std::string hash() const {
        return SHA256::hex(SHA256::hash(serialize()));
    }
};


// ============================================================================
// 3. MERKLE TREE
// ============================================================================

class MerkleTree {
private:
    std::vector<std::string> leaves;
    std::vector<std::vector<std::string>> levels;

    static std::string parentHash(const std::string& left,
                                  const std::string& right) {
        return SHA256::hex(
            SHA256::hash(left + right)
        );
    }

public:
    explicit MerkleTree(const std::vector<Transaction>& transactions) {
        if (transactions.empty()) {
            throw std::invalid_argument(
                "Merkle tree requires at least one transaction."
            );
        }

        for (const auto& transaction : transactions) {
            leaves.push_back(transaction.hash());
        }

        levels.push_back(leaves);

        while (levels.back().size() > 1) {
            const auto& current = levels.back();
            std::vector<std::string> next;

            for (std::size_t i = 0; i < current.size(); i += 2) {
                const std::string& left = current[i];
                const std::string& right =
                    (i + 1 < current.size()) ? current[i + 1] : left;

                next.push_back(parentHash(left, right));
            }

            levels.push_back(next);
        }
    }

    std::string root() const {
        return levels.back().front();
    }

    std::size_t leafCount() const {
        return leaves.size();
    }

    /*
     * Verify a leaf directly against the root by rebuilding the tree.
     * A real inclusion proof would carry only O(log n) sibling hashes.
     */
    bool contains(const Transaction& target) const {
        const std::string targetHash = target.hash();

        std::vector<std::string> current = leaves;

        while (current.size() > 1) {
            std::vector<std::string> next;

            for (std::size_t i = 0; i < current.size(); i += 2) {
                const std::string& left = current[i];
                const std::string& right =
                    (i + 1 < current.size()) ? current[i + 1] : left;

                next.push_back(parentHash(left, right));
            }

            current = std::move(next);
        }

        return current.front() == root() &&
               std::find(leaves.begin(), leaves.end(), targetHash)
                   != leaves.end();
    }
};


// ============================================================================
// 4. BLOCK
// ============================================================================

struct Block {
    std::size_t index;
    std::uint64_t timestamp;
    std::vector<Transaction> transactions;
    std::string previousHash;
    std::string merkleRoot;
    std::uint64_t nonce;
    std::string hash;

    Block(
        std::size_t blockIndex,
        std::vector<Transaction> blockTransactions,
        std::string previous,
        std::uint64_t blockTimestamp
    )
        : index(blockIndex),
          timestamp(blockTimestamp),
          transactions(std::move(blockTransactions)),
          previousHash(std::move(previous)),
          merkleRoot(""),
          nonce(0),
          hash("") {}

    void calculateMerkleRoot() {
        MerkleTree tree(transactions);
        merkleRoot = tree.root();
    }

    std::string calculateHash() {
        calculateMerkleRoot();

        /*
         * The block header commits to:
         *   index
         *   timestamp
         *   previous block hash
         *   Merkle root
         *   nonce
         *
         * Any change to committed fields changes the resulting hash.
         */
        const std::string header =
            std::to_string(index) + "|" +
            std::to_string(timestamp) + "|" +
            previousHash + "|" +
            merkleRoot + "|" +
            std::to_string(nonce);

        return SHA256::hex(SHA256::hash(header));
    }

    void mine(std::size_t difficulty) {
        if (difficulty == 0 || difficulty > 6) {
            throw std::invalid_argument(
                "Demonstration difficulty must be between 1 and 6."
            );
        }

        const std::string target(difficulty, '0');

        do {
            hash = calculateHash();
            ++nonce;
        } while (hash.substr(0, difficulty) != target);
    }
};


// ============================================================================
// 5. BLOCKCHAIN LEDGER
// ============================================================================

class Blockchain {
private:
    std::vector<Block> chain;
    std::size_t difficulty;

    static std::uint64_t genesisTimestamp() {
        return 1700000000ULL;
    }

    void createGenesisBlock() {
        std::vector<Transaction> transactions = {
            {"SYSTEM", "LEDGER", 1}
        };

        Block genesis(
            0,
            transactions,
            std::string(64, '0'),
            genesisTimestamp()
        );

        genesis.mine(difficulty);
        chain.push_back(std::move(genesis));
    }

public:
    explicit Blockchain(std::size_t proofDifficulty = 3)
        : difficulty(proofDifficulty) {
        if (difficulty == 0 || difficulty > 6) {
            throw std::invalid_argument("Invalid proof-of-work difficulty.");
        }

        createGenesisBlock();
    }

    const Block& latest() const {
        return chain.back();
    }

    std::size_t size() const {
        return chain.size();
    }

    void addBlock(const std::vector<Transaction>& transactions) {
        if (transactions.empty()) {
            throw std::invalid_argument(
                "Cannot add a block without transactions."
            );
        }

        for (const auto& transaction : transactions) {
            if (!transaction.isValid()) {
                throw std::invalid_argument(
                    "Transaction failed validation."
                );
            }
        }

        Block block(
            chain.size(),
            transactions,
            latest().hash,
            static_cast<std::uint64_t>(
                std::chrono::system_clock::to_time_t(
                    std::chrono::system_clock::now()
                )
            )
        );

        block.mine(difficulty);
        chain.push_back(std::move(block));
    }

    bool verify(std::string& reason) {
        const std::string target(difficulty, '0');

        for (std::size_t i = 0; i < chain.size(); ++i) {
            Block& current = chain[i];

            const std::string expectedHash = current.calculateHash();

            if (expectedHash != current.hash) {
                reason = "Block " + std::to_string(i) +
                         ": stored hash does not match contents.";
                return false;
            }

            if (current.hash.substr(0, difficulty) != target) {
                reason = "Block " + std::to_string(i) +
                         ": proof of work is invalid.";
                return false;
            }

            if (i == 0) {
                if (current.previousHash != std::string(64, '0')) {
                    reason = "Genesis block has an invalid previous hash.";
                    return false;
                }
            } else {
                if (current.previousHash != chain[i - 1].hash) {
                    reason = "Block " + std::to_string(i) +
                             ": previous-hash link is broken.";
                    return false;
                }
            }

            for (const auto& transaction : current.transactions) {
                if (!transaction.isValid()) {
                    reason = "Block " + std::to_string(i) +
                             ": contains an invalid transaction.";
                    return false;
                }
            }
        }

        reason = "Blockchain is valid.";
        return true;
    }

    /*
     * Deliberately exposes mutable access for the educational attack
     * simulation. A production ledger would tightly control mutation.
     */
    Block& blockAt(std::size_t index) {
        if (index >= chain.size()) {
            throw std::out_of_range("Block index out of range.");
        }

        return chain[index];
    }

    void print() const {
        std::cout << "\nLedger contains " << chain.size()
                  << " blocks.\n";

        for (const auto& block : chain) {
            std::cout << "Block " << block.index
                      << "\n  Hash: " << block.hash
                      << "\n  Previous: " << block.previousHash
                      << "\n  Merkle root: " << block.merkleRoot
                      << "\n  Nonce: " << block.nonce
                      << "\n  Transactions: "
                      << block.transactions.size()
                      << "\n";
        }
    }
};


// ============================================================================
// 6. APPLICATION-LEVEL VALIDATION
// ============================================================================

class LedgerService {
private:
    Blockchain blockchain;

public:
    explicit LedgerService(std::size_t difficulty)
        : blockchain(difficulty) {}

    void transfer(
        const std::string& sender,
        const std::string& recipient,
        std::uint64_t amount
    ) {
        Transaction transaction{sender, recipient, amount};

        if (!transaction.isValid()) {
            throw std::invalid_argument(
                "Transfer rejected: invalid sender, recipient, or amount."
            );
        }

        blockchain.addBlock({transaction});
    }

    bool audit() {
        std::string reason;
        const bool valid = blockchain.verify(reason);

        std::cout << "\nAUDIT: " << reason << "\n";
        return valid;
    }

    Blockchain& ledger() {
        return blockchain;
    }
};


// ============================================================================
// 7. TESTS
// ============================================================================

void testSHA256() {
    const std::string knownInput = "abc";
    const std::string expected =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    const std::string actual =
        SHA256::hex(SHA256::hash(knownInput));

    if (actual != expected) {
        throw std::runtime_error("SHA-256 known-value test failed.");
    }
}

void testTransactionValidation() {
    Transaction valid{"Alice", "Bob", 10};
    Transaction invalidAmount{"Alice", "Bob", 0};
    Transaction invalidSender{"", "Bob", 10};

    if (!valid.isValid()) {
        throw std::runtime_error("Valid transaction was rejected.");
    }

    if (invalidAmount.isValid()) {
        throw std::runtime_error("Zero amount was accepted.");
    }

    if (invalidSender.isValid()) {
        throw std::runtime_error("Empty sender was accepted.");
    }
}

void testMerkleIntegrity() {
    std::vector<Transaction> transactions = {
        {"A", "B", 10},
        {"B", "C", 5},
        {"C", "D", 2},
        {"D", "E", 1}
    };

    MerkleTree tree(transactions);

    if (!tree.contains(transactions[2])) {
        throw std::runtime_error(
            "Expected transaction missing from Merkle tree."
        );
    }

    Transaction tampered{"C", "D", 99999};

    if (tree.contains(tampered)) {
        throw std::runtime_error(
            "Tampered transaction incorrectly validated."
        );
    }
}

void testBlockchainIntegrity() {
    Blockchain blockchain(1);

    blockchain.addBlock({
        {"Alice", "Bob", 10}
    });

    std::string reason;

    if (!blockchain.verify(reason)) {
        throw std::runtime_error(
            "New blockchain failed validation: " + reason
        );
    }

    blockchain.blockAt(1).transactions[0].amount = 999999;

    if (blockchain.verify(reason)) {
        throw std::runtime_error(
            "Tampered blockchain incorrectly passed validation."
        );
    }
}

void runTests() {
    std::cout << "\n=== SELF-TESTS ===\n";

    testSHA256();
    testTransactionValidation();
    testMerkleIntegrity();
    testBlockchainIntegrity();

    std::cout << "All tests passed.\n";
}


// ============================================================================
// 8. ATTACK SIMULATION
// ============================================================================

void demonstrateTampering() {
    std::cout << "\n=== TAMPERING CASE STUDY ===\n";

    LedgerService service(2);

    service.transfer("Alice", "Bob", 100);
    service.transfer("Bob", "Carol", 25);
    service.transfer("Carol", "Dave", 10);

    service.audit();

    Blockchain& ledger = service.ledger();

    const std::string originalBlockHash =
        ledger.blockAt(1).hash;

    /*
     * Attack:
     * Modify an already committed transaction without legitimately
     * rebuilding the chain.
     */
    ledger.blockAt(1).transactions[0].amount = 1000000;

    std::cout << "Original block-1 hash: "
              << originalBlockHash << "\n";

    service.audit();

    /*
     * Even if an attacker recomputed block 1, block 2 would still contain
     * the old block-1 hash. A successful history rewrite would therefore
     * require rewriting later dependent blocks and satisfying the consensus
     * requirements of the real network.
     */
}


// ============================================================================
// 9. HASH AVALANCHE DEMONSTRATION
// ============================================================================

void demonstrateAvalancheEffect() {
    std::cout << "\n=== HASH AVALANCHE EFFECT ===\n";

    const std::string first = "Transfer 100";
    const std::string second = "Transfer 101";

    const std::string hashA =
        SHA256::hex(SHA256::hash(first));
    const std::string hashB =
        SHA256::hex(SHA256::hash(second));

    std::size_t differingCharacters = 0;

    for (std::size_t i = 0;
         i < hashA.size() && i < hashB.size();
         ++i) {
        if (hashA[i] != hashB[i]) {
            ++differingCharacters;
        }
    }

    std::cout << "Hash A: " << hashA << "\n";
    std::cout << "Hash B: " << hashB << "\n";
    std::cout << "Different hexadecimal positions: "
              << differingCharacters << "\n";
}


// ============================================================================
// 10. MAIN CASE STUDY
// ============================================================================

int main() {
    try {
        std::cout << "============================================\n";
        std::cout << "INTEGRITY IN CRYPTOGRAPHY AND BLOCKCHAIN\n";
        std::cout << "============================================\n";

        std::cout << "\n=== BASIC HASH ===\n";
        const std::string message = "Alice pays Bob 10";
        std::cout << "Message: " << message << "\n";
        std::cout << "SHA-256: "
                  << SHA256::hex(SHA256::hash(message))
                  << "\n";

        demonstrateAvalancheEffect();

        std::cout << "\n=== LEDGER CASE STUDY ===\n";

        LedgerService service(2);

        service.transfer("Alice", "Bob", 100);
        service.transfer("Bob", "Carol", 25);
        service.transfer("Carol", "Dave", 10);

        service.audit();
        service.ledger().print();

        demonstrateTampering();

        std::cout << "\n=== PERFORMANCE CONSIDERATIONS ===\n";
        std::cout << "SHA-256 processing is O(n) for n input bytes.\n";
        std::cout << "Merkle-tree construction is O(n) for n leaves.\n";
        std::cout << "A Merkle inclusion proof requires O(log n) hashes.\n";
        std::cout << "Chain verification is O(B + T), where B is the number\n";
        std::cout << "of blocks and T is the number of transactions checked.\n";
        std::cout << "Proof of work intentionally increases computational cost.\n";

        std::cout << "\n=== SECURITY DESIGN NOTES ===\n";
        std::cout << "1. A hash detects changes only when its trusted value is protected.\n";
        std::cout << "2. Hashing does not authenticate the creator.\n";
        std::cout << "3. Digital signatures provide a public verification mechanism.\n";
        std::cout << "4. Merkle roots efficiently commit to transaction collections.\n";
        std::cout << "5. Block links make historical modifications detectable.\n";
        std::cout << "6. Consensus determines how a distributed blockchain agrees on history.\n";
        std::cout << "7. Application validation remains necessary before commitment.\n";
        std::cout << "8. Production cryptography should use audited implementations.\n";

        runTests();

        std::cout << "\nCase study completed successfully.\n";
    }
    catch (const std::exception& error) {
        std::cerr << "\nERROR: " << error.what() << "\n";
        return 1;
    }

    return 0;
}
