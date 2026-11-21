#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * ECDSA IN BLOCKCHAIN AND CRYPTOGRAPHY
 *
 * C++17 implementation of a small elliptic-curve signature engine.
 *
 * IMPORTANT:
 * This program uses a deliberately small finite-field elliptic curve.
 * It demonstrates the mathematical structure of ECDSA, not production
 * cryptographic security.
 *
 * Production secp256k1 requires secure 256-bit arithmetic, validated
 * cryptographic implementations, secure nonce generation, and audited
 * key management. The C++ standard library does not provide these.
 */

// ============================================================
// 1. Domain definitions
// ============================================================

using Integer = std::int64_t;

constexpr Integer FIELD = 97;
constexpr Integer ORDER = 79;
constexpr Integer CURVE_A = 2;
constexpr Integer CURVE_B = 3;

struct Point {
    Integer x;
    Integer y;
    bool infinity = false;
};

struct Signature {
    Integer r;
    Integer s;
};

enum class TransactionState {
    Created,
    Signed,
    Verified,
    Rejected,
    Included
};

enum class ReviewResult {
    Valid,
    Invalid,
    Missing
};

// ============================================================
// 2. Arithmetic utilities
// ============================================================

Integer mod(Integer value, Integer modulus) {
    value %= modulus;

    if (value < 0) {
        value += modulus;
    }

    return value;
}

Integer modularPower(Integer base, Integer exponent, Integer modulus) {
    Integer result = 1;
    base = mod(base, modulus);

    while (exponent > 0) {
        if (exponent & 1) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent >>= 1;
    }

    return result;
}

Integer modularInverse(Integer value, Integer modulus) {
    value = mod(value, modulus);

    for (Integer candidate = 1; candidate < modulus; ++candidate) {
        if ((value * candidate) % modulus == 1) {
            return candidate;
        }
    }

    throw std::domain_error("Modular inverse does not exist");
}

bool validPoint(const Point& point) {
    if (point.infinity) {
        return true;
    }

    if (point.x < 0 || point.x >= FIELD ||
        point.y < 0 || point.y >= FIELD) {
        return false;
    }

    Integer left = mod(point.y * point.y, FIELD);

    Integer right = mod(
        point.x * point.x * point.x +
        CURVE_A * point.x +
        CURVE_B,
        FIELD
    );

    return left == right;
}

// ============================================================
// 3. Elliptic-curve operations
// ============================================================

Point pointAdd(const Point& first, const Point& second) {
    if (!validPoint(first) || !validPoint(second)) {
        throw std::invalid_argument("Invalid elliptic-curve point");
    }

    if (first.infinity) {
        return second;
    }

    if (second.infinity) {
        return first;
    }

    if (first.x == second.x &&
        mod(first.y + second.y, FIELD) == 0) {
        return {0, 0, true};
    }

    Integer numerator;
    Integer denominator;

    if (first.x == second.x && first.y == second.y) {
        if (first.y == 0) {
            return {0, 0, true};
        }

        numerator = 3 * first.x * first.x + CURVE_A;
        denominator = 2 * first.y;
    } else {
        numerator = second.y - first.y;
        denominator = second.x - first.x;
    }

    Integer slope = mod(
        numerator * modularInverse(denominator, FIELD),
        FIELD
    );

    Integer x3 = mod(
        slope * slope - first.x - second.x,
        FIELD
    );

    Integer y3 = mod(
        slope * (first.x - x3) - first.y,
        FIELD
    );

    return {x3, y3, false};
}

Point scalarMultiply(Integer scalar, Point point) {
    if (scalar < 0) {
        throw std::invalid_argument("Negative scalar is unsupported");
    }

    if (!validPoint(point)) {
        throw std::invalid_argument("Invalid point");
    }

    Point result{0, 0, true};

    while (scalar > 0) {
        if (scalar & 1) {
            result = pointAdd(result, point);
        }

        point = pointAdd(point, point);
        scalar >>= 1;
    }

    return result;
}

// G = (3, 6) is a point of order 79 on this demonstration curve.
const Point GENERATOR{3, 6, false};

// ============================================================
// 4. ECDSA key and signature operations
// ============================================================

class ECDSAEngine {
private:
    Integer privateKey;
    Point publicKey;

    Integer messageHash(const std::string& message) const {
        // A small deterministic educational hash mapping.
        // This is NOT SHA-256 and must never be used in production.
        Integer hash = 0;

        for (unsigned char character : message) {
            hash = mod(hash * 31 + character, ORDER);
        }

        return hash;
    }

public:
    explicit ECDSAEngine(Integer secret)
        : privateKey(secret), publicKey{0, 0, true} {

        if (secret <= 0 || secret >= ORDER) {
            throw std::invalid_argument("Invalid private key");
        }

        publicKey = scalarMultiply(privateKey, GENERATOR);
    }

    Point getPublicKey() const {
        return publicKey;
    }

    Signature sign(const std::string& message, Integer nonce) const {
        if (nonce <= 0 || nonce >= ORDER) {
            throw std::invalid_argument("Invalid signing nonce");
        }

        Integer z = messageHash(message);

        Point noncePoint = scalarMultiply(nonce, GENERATOR);

        Integer r = mod(noncePoint.x, ORDER);

        if (r == 0) {
            throw std::runtime_error("Invalid r component");
        }

        Integer s = mod(
            modularInverse(nonce, ORDER) *
            (z + r * privateKey),
            ORDER
        );

        if (s == 0) {
            throw std::runtime_error("Invalid s component");
        }

        // Normalize s to reduce signature malleability.
        if (s > ORDER / 2) {
            s = ORDER - s;
        }

        return {r, s};
    }

    bool verify(
        const std::string& message,
        const Signature& signature
    ) const {
        if (signature.r <= 0 || signature.r >= ORDER ||
            signature.s <= 0 || signature.s >= ORDER) {
            return false;
        }

        // This demonstration enforces low-S signatures.
        if (signature.s > ORDER / 2) {
            return false;
        }

        try {
            Integer z = messageHash(message);

            Integer inverseS = modularInverse(signature.s, ORDER);

            Integer u1 = mod(z * inverseS, ORDER);
            Integer u2 = mod(signature.r * inverseS, ORDER);

            Point first = scalarMultiply(u1, GENERATOR);
            Point second = scalarMultiply(u2, publicKey);

            Point result = pointAdd(first, second);

            if (result.infinity) {
                return false;
            }

            return mod(result.x, ORDER) == signature.r;
        } catch (const std::exception&) {
            return false;
        }
    }
};

// ============================================================
// 5. Repository-style blockchain domain model
// ============================================================

struct Transaction {
    std::string id;
    std::string sender;
    std::string recipient;
    Integer amount;
    Integer nonce;
    std::string payload;
    Signature signature{0, 0};
    TransactionState state = TransactionState::Created;
};

class TransactionPool {
private:
    std::vector<Transaction> transactions;
    std::set<std::string> knownIds;

public:
    void submit(Transaction transaction) {
        if (transaction.amount <= 0) {
            throw std::invalid_argument("Amount must be positive");
        }

        if (transaction.nonce < 0) {
            throw std::invalid_argument("Invalid nonce");
        }

        if (transaction.id.empty()) {
            throw std::invalid_argument("Transaction ID is required");
        }

        if (!knownIds.insert(transaction.id).second) {
            throw std::invalid_argument("Duplicate transaction");
        }

        transactions.push_back(std::move(transaction));
    }

    std::vector<Transaction>& getTransactions() {
        return transactions;
    }

    std::size_t size() const {
        return transactions.size();
    }
};

// ============================================================
// 6. Blockchain governance and eligibility
// ============================================================

struct GovernancePolicy {
    bool requireSignature = true;
    bool requireVerifiedState = true;
    bool rejectDuplicateTransactions = true;
    bool enforcePositiveAmounts = true;
};

class MergeEligibilityEngine {
private:
    GovernancePolicy policy;

public:
    explicit MergeEligibilityEngine(GovernancePolicy configuration)
        : policy(configuration) {}

    ReviewResult evaluate(const Transaction& transaction,
                          const ECDSAEngine& engine) const {

        if (transaction.signature.r == 0 ||
            transaction.signature.s == 0) {
            return ReviewResult::Missing;
        }

        if (!engine.verify(
                transaction.payload,
                transaction.signature)) {
            return ReviewResult::Invalid;
        }

        return ReviewResult::Valid;
    }

    bool eligible(
        const Transaction& transaction,
        const ECDSAEngine& engine
    ) const {

        if (policy.enforcePositiveAmounts && transaction.amount <= 0) {
            return false;
        }

        if (policy.requireVerifiedState &&
            transaction.state != TransactionState::Verified) {
            return false;
        }

        if (policy.requireSignature &&
            evaluate(transaction, engine) != ReviewResult::Valid) {
            return false;
        }

        return true;
    }
};

// ============================================================
// 7. Block management
// ============================================================

struct Block {
    std::size_t index;
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string blockHash;
};

class Blockchain {
private:
    std::vector<Block> blocks;

    std::string calculateHash(
        std::size_t index,
        const std::string& previousHash,
        const std::vector<Transaction>& transactions
    ) const {

        // Educational checksum, not a cryptographic block hash.
        std::uint64_t hash = 1469598103934665603ULL;

        auto mix = [&hash](const std::string& value) {
            for (unsigned char character : value) {
                hash ^= character;
                hash *= 1099511628211ULL;
            }
        };

        mix(std::to_string(index));
        mix(previousHash);

        for (const auto& transaction : transactions) {
            mix(transaction.id);
            mix(transaction.payload);
            mix(std::to_string(transaction.signature.r));
            mix(std::to_string(transaction.signature.s));
        }

        std::ostringstream output;
        output << std::hex << hash;

        return output.str();
    }

public:
    Blockchain() {
        Block genesis{
            0,
            "0",
            {},
            ""
        };

        genesis.blockHash = calculateHash(
            genesis.index,
            genesis.previousHash,
            genesis.transactions
        );

        blocks.push_back(genesis);
    }

    void addBlock(
        std::vector<Transaction> transactions,
        const MergeEligibilityEngine& governance,
        const ECDSAEngine& engine
    ) {
        if (transactions.empty()) {
            throw std::invalid_argument("Empty block rejected");
        }

        std::set<std::string> uniqueIds;

        for (const auto& transaction : transactions) {
            if (!governance.eligible(transaction, engine)) {
                throw std::runtime_error(
                    "Transaction failed governance validation"
                );
            }

            if (!uniqueIds.insert(transaction.id).second) {
                throw std::runtime_error("Duplicate transaction");
            }
        }

        const Block& previous = blocks.back();

        Block block{
            blocks.size(),
            previous.blockHash,
            std::move(transactions),
            ""
        };

        block.blockHash = calculateHash(
            block.index,
            block.previousHash,
            block.transactions
        );

        blocks.push_back(std::move(block));
    }

    bool validate() const {
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            const Block& block = blocks[i];

            if (block.index != i) {
                return false;
            }

            if (block.blockHash != calculateHash(
                    block.index,
                    block.previousHash,
                    block.transactions)) {
                return false;
            }

            if (i > 0 &&
                block.previousHash != blocks[i - 1].blockHash) {
                return false;
            }
        }

        return true;
    }

    std::size_t size() const {
        return blocks.size();
    }

    const Block& latest() const {
        return blocks.back();
    }
};

// ============================================================
// 8. Executable scenario
// ============================================================

int main() {
    try {
        std::cout << "ECDSA BLOCKCHAIN GOVERNANCE ENGINE\n";
        std::cout << "========================================\n";

        std::cout << "\n1. CURVE CONFIGURATION\n";

        std::cout << "Curve equation: y^2 = x^3 + 2x + 3 mod 97\n";
        std::cout << "Generator: (3, 6)\n";
        std::cout << "Subgroup order: 79\n";

        ECDSAEngine engine(17);

        Point publicKey = engine.getPublicKey();

        std::cout << "Public key: ("
                  << publicKey.x << ", "
                  << publicKey.y << ")\n";

        std::cout << "\n2. ECDSA SIGNING\n";

        const std::string message = "Transfer 250 units";

        Signature signature = engine.sign(message, 11);

        std::cout << "r: " << signature.r << "\n";
        std::cout << "s: " << signature.s << "\n";

        bool valid = engine.verify(message, signature);

        std::cout << "Signature valid: "
                  << std::boolalpha << valid << "\n";

        std::cout << "Tampered message valid: "
                  << engine.verify(message + " altered", signature)
                  << "\n";

        std::cout << "\n3. TRANSACTION POOL\n";

        Transaction transaction{
            "TX-1001",
            "WALLET-A",
            "WALLET-B",
            250,
            1,
            message,
            signature,
            TransactionState::Verified
        };

        TransactionPool pool;
        pool.submit(transaction);

        std::cout << "Pending transactions: "
                  << pool.size() << "\n";

        std::cout << "\n4. GOVERNANCE EVALUATION\n";

        GovernancePolicy policy;
        MergeEligibilityEngine governance(policy);

        std::cout << "Signature result: "
                  << static_cast<int>(
                         governance.evaluate(transaction, engine))
                  << "\n";

        std::cout << "Merge eligibility: "
                  << governance.eligible(transaction, engine)
                  << "\n";

        std::cout << "\n5. BLOCKCHAIN INCLUSION\n";

        Blockchain blockchain;

        blockchain.addBlock(
            pool.getTransactions(),
            governance,
            engine
        );

        std::cout << "Block count: " << blockchain.size() << "\n";
        std::cout << "Latest block hash: "
                  << blockchain.latest().blockHash << "\n";
        std::cout << "Blockchain valid: "
                  << blockchain.validate() << "\n";

        std::cout << "\n6. FAILURE TESTS\n";

        try {
            ECDSAEngine invalidEngine(0);
        } catch (const std::exception& error) {
            std::cout << "Invalid private key rejected: "
                      << error.what() << "\n";
        }

        try {
            engine.sign("invalid nonce", 0);
        } catch (const std::exception& error) {
            std::cout << "Invalid nonce rejected: "
                      << error.what() << "\n";
        }

        Signature invalidSignature{0, 0};

        std::cout << "Zero signature accepted: "
                  << engine.verify(message, invalidSignature)
                  << "\n";

        std::cout << "\n7. COMPLEXITY CHARACTERISTICS\n";

        std::cout << "Point multiplication: O(log n) group operations\n";
        std::cout << "Transaction duplicate detection: O(log T) per insertion\n";
        std::cout << "Block validation: O(B + T) for this model\n";

        if (!valid || !blockchain.validate()) {
            throw std::runtime_error("Validation failure");
        }

        std::cout << "\nAll demonstration checks passed.\n";

    } catch (const std::exception& error) {
        std::cerr << "Execution error: " << error.what() << "\n";
        return 1;
    }

    return 0;
}
