#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * ECDH in Blockchain: C++17 Governance and Cryptographic Model
 *
 * Implements an educational elliptic-curve key agreement system,
 * wallet registry, transaction validation and blockchain integrity.
 *
 * Uses a small demonstration curve:
 * y^2 = x^3 + 2x + 2 (mod 17)
 * Generator G = (5, 1), order = 19.
 *
 * This curve is intentionally insecure and MUST NOT be used
 * for real cryptocurrency wallets or production key exchange.
 *
 * Production systems should use secp256k1 or another approved
 * curve through an audited cryptographic implementation.
 */

using namespace std;

using Integer = long long;

constexpr Integer FIELD = 17;
constexpr Integer ORDER = 19;
constexpr Integer CURVE_A = 2;
constexpr Integer CURVE_B = 2;

struct Point {
    Integer x;
    Integer y;
    bool infinity = false;

    bool operator==(const Point& other) const {
        return x == other.x &&
               y == other.y &&
               infinity == other.infinity;
    }
};

const Point GENERATOR{5, 1, false};

class CryptoError : public runtime_error {
public:
    explicit CryptoError(const string& message)
        : runtime_error(message) {}
};

class BlockchainError : public runtime_error {
public:
    explicit BlockchainError(const string& message)
        : runtime_error(message) {}
};

Integer mod(Integer value, Integer modulus) {
    return (value % modulus + modulus) % modulus;
}

Integer modularPower(Integer base, Integer exponent, Integer modulus) {
    Integer result = 1;
    base = mod(base, modulus);

    while (exponent > 0) {
        if (exponent & 1) {
            result = mod(result * base, modulus);
        }

        base = mod(base * base, modulus);
        exponent >>= 1;
    }

    return result;
}

Integer modularInverse(Integer value, Integer modulus) {
    value = mod(value, modulus);

    for (Integer i = 1; i < modulus; ++i) {
        if (mod(value * i, modulus) == 1) {
            return i;
        }
    }

    throw CryptoError("Modular inverse does not exist.");
}

bool validPoint(const Point& point) {
    if (point.infinity) {
        return false;
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

Point addPoints(const Point& p, const Point& q) {
    if (p.infinity) return q;
    if (q.infinity) return p;

    if (p.x == q.x && mod(p.y + q.y, FIELD) == 0) {
        return {0, 0, true};
    }

    Integer numerator;
    Integer denominator;

    if (p == q) {
        if (p.y == 0) {
            return {0, 0, true};
        }

        numerator = 3 * p.x * p.x + CURVE_A;
        denominator = 2 * p.y;
    } else {
        numerator = q.y - p.y;
        denominator = q.x - p.x;
    }

    Integer slope = mod(
        numerator * modularInverse(denominator, FIELD),
        FIELD
    );

    Integer x3 = mod(
        slope * slope - p.x - q.x,
        FIELD
    );

    Integer y3 = mod(
        slope * (p.x - x3) - p.y,
        FIELD
    );

    return {x3, y3, false};
}

Point multiplyPoint(Integer scalar, Point point = GENERATOR) {
    if (scalar < 0 || scalar >= ORDER) {
        throw CryptoError("Scalar outside valid range.");
    }

    Point result{0, 0, true};

    while (scalar > 0) {
        if (scalar & 1) {
            result = addPoints(result, point);
        }

        point = addPoints(point, point);
        scalar >>= 1;
    }

    return result;
}

struct Wallet {
    string address;
    Point publicKey;
    Integer privateKey;
};

Wallet generateWallet(Integer privateKey) {
    if (privateKey < 1 || privateKey >= ORDER) {
        throw CryptoError("Invalid private key.");
    }

    Point publicKey = multiplyPoint(privateKey);

    if (!validPoint(publicKey)) {
        throw CryptoError("Public-key generation failed.");
    }

    string address = "WALLET-" +
        to_string(publicKey.x) + "-" +
        to_string(publicKey.y);

    return {address, publicKey, privateKey};
}

Point calculateSharedPoint(
    Integer privateKey,
    const Point& peerPublicKey
) {
    if (!validPoint(peerPublicKey)) {
        throw CryptoError("Invalid peer public key.");
    }

    Point shared = multiplyPoint(privateKey, peerPublicKey);

    if (shared.infinity) {
        throw CryptoError("Invalid shared point.");
    }

    return shared;
}

string deriveEducationalKey(const Point& shared) {
    // A production KDF must use HKDF-SHA256 and a cryptographic
    // library. This compact encoding is only for the toy curve.
    return "DEMO-CHANNEL-" +
        to_string(shared.x) + "-" +
        to_string(shared.y);
}

struct Transaction {
    string id;
    string sender;
    string recipient;
    string channelCommitment;
    Integer amount;
    Integer nonce;
};

struct Block {
    size_t index;
    string previousHash;
    vector<Transaction> transactions;
    string hash;
};

class Blockchain {
private:
    vector<Block> blocks;
    vector<Transaction> pending;

    map<string, Wallet> wallets;
    map<string, Integer> nonces;
    set<string> transactionIds;

    static string hashBlock(const Block& block) {
        // Deterministic educational hash representation.
        // Replace with a standard cryptographic hash in production.
        stringstream stream;

        stream << block.index
               << "|" << block.previousHash;

        for (const auto& transaction : block.transactions) {
            stream << "|" << transaction.id
                   << "|" << transaction.sender
                   << "|" << transaction.recipient
                   << "|" << transaction.amount
                   << "|" << transaction.nonce
                   << "|" << transaction.channelCommitment;
        }

        const string input = stream.str();

        // FNV-1a is not a cryptographic hash.
        uint64_t hash = 14695981039346656037ULL;

        for (unsigned char character : input) {
            hash ^= character;
            hash *= 1099511628211ULL;
        }

        stringstream output;
        output << hex << setw(16) << setfill('0') << hash;

        return output.str();
    }

public:
    Blockchain() {
        Block genesis{
            0,
            "GENESIS",
            {},
            ""
        };

        genesis.hash = hashBlock(genesis);
        blocks.push_back(genesis);
    }

    void registerWallet(const Wallet& wallet) {
        if (wallets.count(wallet.address)) {
            throw BlockchainError("Wallet already registered.");
        }

        if (!validPoint(wallet.publicKey)) {
            throw CryptoError("Invalid wallet public key.");
        }

        wallets.emplace(wallet.address, wallet);
        nonces[wallet.address] = 0;
    }

    void submitTransaction(const Transaction& transaction) {
        if (!wallets.count(transaction.sender) ||
            !wallets.count(transaction.recipient)) {
            throw BlockchainError("Unknown wallet.");
        }

        if (transaction.sender == transaction.recipient) {
            throw BlockchainError("Self-transfer prohibited.");
        }

        if (transaction.amount <= 0) {
            throw BlockchainError("Invalid transaction amount.");
        }

        if (transaction.id.empty()) {
            throw BlockchainError("Transaction ID required.");
        }

        if (transaction.channelCommitment.empty()) {
            throw BlockchainError("Channel commitment required.");
        }

        if (transactionIds.count(transaction.id)) {
            throw BlockchainError("Duplicate transaction.");
        }

        if (transaction.nonce != nonces[transaction.sender]) {
            throw BlockchainError("Invalid transaction nonce.");
        }

        transactionIds.insert(transaction.id);
        ++nonces[transaction.sender];

        pending.push_back(transaction);
    }

    Block mineBlock() {
        if (pending.empty()) {
            throw BlockchainError("No pending transactions.");
        }

        Block block{
            blocks.size(),
            blocks.back().hash,
            pending,
            ""
        };

        block.hash = hashBlock(block);

        blocks.push_back(block);
        pending.clear();

        return block;
    }

    bool verifyChain() const {
        for (size_t i = 0; i < blocks.size(); ++i) {
            const Block& block = blocks[i];

            if (block.hash != hashBlock(block)) {
                return false;
            }

            if (i > 0) {
                if (block.previousHash != blocks[i - 1].hash) {
                    return false;
                }

                if (block.index != blocks[i - 1].index + 1) {
                    return false;
                }
            }
        }

        return true;
    }

    void printChain() const {
        for (const auto& block : blocks) {
            cout << "Block " << block.index
                 << " | Hash: " << block.hash
                 << " | Transactions: "
                 << block.transactions.size() << '\n';
        }
    }

    void tamperFirstTransaction() {
        if (blocks.size() < 2 ||
            blocks[1].transactions.empty()) {
            throw BlockchainError("No transaction to modify.");
        }

        blocks[1].transactions[0].amount += 100;
    }
};

int main() {
    try {
        cout << "ECDH IN BLOCKCHAIN - C++17\n";
        cout << "==========================\n\n";

        Wallet alice = generateWallet(7);
        Wallet bob = generateWallet(11);

        cout << "Alice: " << alice.address << '\n';
        cout << "Bob:   " << bob.address << '\n';

        // Independent ECDH calculations.
        Point aliceShared = calculateSharedPoint(
            alice.privateKey,
            bob.publicKey
        );

        Point bobShared = calculateSharedPoint(
            bob.privateKey,
            alice.publicKey
        );

        if (!(aliceShared == bobShared)) {
            throw CryptoError("ECDH agreement failed.");
        }

        string aliceKey = deriveEducationalKey(aliceShared);
        string bobKey = deriveEducationalKey(bobShared);

        if (aliceKey != bobKey) {
            throw CryptoError("Derived channel keys differ.");
        }

        cout << "\nECDH key agreement successful.\n";
        cout << "Shared point: ("
             << aliceShared.x << ", "
             << aliceShared.y << ")\n";

        cout << "Channel key fingerprint: "
             << aliceKey << '\n';

        Blockchain blockchain;

        blockchain.registerWallet(alice);
        blockchain.registerWallet(bob);

        Transaction transaction{
            "TX-1001",
            alice.address,
            bob.address,
            "COMMITMENT-EC-DH-001",
            250,
            0
        };

        blockchain.submitTransaction(transaction);

        Block mined = blockchain.mineBlock();

        cout << "\nMined block: " << mined.index << '\n';
        cout << "Block hash: " << mined.hash << '\n';

        cout << "\nBlockchain:\n";
        blockchain.printChain();

        cout << "\nChain valid: "
             << boolalpha
             << blockchain.verifyChain() << '\n';

        // Duplicate transaction rejection.
        try {
            blockchain.submitTransaction(transaction);
        } catch (const BlockchainError& error) {
            cout << "Replay rejected: "
                 << error.what() << '\n';
        }

        // Tamper detection.
        blockchain.tamperFirstTransaction();

        cout << "Chain valid after tampering: "
             << blockchain.verifyChain() << '\n';

    } catch (const exception& error) {
        cerr << "Execution error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
