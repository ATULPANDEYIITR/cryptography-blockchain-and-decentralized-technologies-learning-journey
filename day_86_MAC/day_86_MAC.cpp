#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstring>

/*
 * MAC IN CRYPTOGRAPHY AND BLOCKCHAIN
 *
 * C++17 implementation:
 * - SHA-256
 * - HMAC-SHA256
 * - Constant-time MAC comparison
 * - Transaction authentication
 * - Nonce-based replay protection
 * - Branch-independent blockchain integrity engine
 * - Merge-style validation of block state
 *
 * No external dependencies.
 *
 * The SHA-256 and HMAC implementations are educational.
 * Production deployments should use an audited cryptographic library.
 */

// ============================================================
// 1. DOMAIN ERRORS
// ============================================================

class MACException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class ValidationException : public MACException {
public:
    using MACException::MACException;
};

class AuthenticationException : public MACException {
public:
    using MACException::MACException;
};

// ============================================================
// 2. SHA-256
// ============================================================

class SHA256 {

private:
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf,
        0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98,
        0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8,
        0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85,
        0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e,
        0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c,
        0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
        0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2
    };

    static uint32_t rotateRight(uint32_t value, unsigned int bits) {
        return (value >> bits) | (value << (32 - bits));
    }

public:

    static std::array<uint8_t, 32> hash(
        const std::vector<uint8_t>& input
    ) {

        std::vector<uint8_t> data = input;

        uint64_t bitLength =
            static_cast<uint64_t>(data.size()) * 8ULL;

        data.push_back(0x80);

        while (data.size() % 64 != 56) {
            data.push_back(0x00);
        }

        for (int i = 7; i >= 0; --i) {
            data.push_back(
                static_cast<uint8_t>(
                    (bitLength >> (i * 8)) & 0xff
                )
            );
        }

        std::array<uint32_t, 8> state = {
            0x6a09e667, 0xbb67ae85,
            0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c,
            0x1f83d9ab, 0x5be0cd19
        };

        for (size_t offset = 0; offset < data.size(); offset += 64) {

            uint32_t w[64] = {};

            for (int i = 0; i < 16; ++i) {
                size_t j = offset + i * 4;

                w[i] =
                    (uint32_t(data[j]) << 24) |
                    (uint32_t(data[j + 1]) << 16) |
                    (uint32_t(data[j + 2]) << 8) |
                    uint32_t(data[j + 3]);
            }

            for (int i = 16; i < 64; ++i) {
                uint32_t s0 =
                    rotateRight(w[i - 15], 7) ^
                    rotateRight(w[i - 15], 18) ^
                    (w[i - 15] >> 3);

                uint32_t s1 =
                    rotateRight(w[i - 2], 17) ^
                    rotateRight(w[i - 2], 19) ^
                    (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 +
                       w[i - 7] + s1;
            }

            uint32_t a = state[0];
            uint32_t b = state[1];
            uint32_t c = state[2];
            uint32_t d = state[3];
            uint32_t e = state[4];
            uint32_t f = state[5];
            uint32_t g = state[6];
            uint32_t h = state[7];

            for (int i = 0; i < 64; ++i) {

                uint32_t S1 =
                    rotateRight(e, 6) ^
                    rotateRight(e, 11) ^
                    rotateRight(e, 25);

                uint32_t choice =
                    (e & f) ^ (~e & g);

                uint32_t temp1 =
                    h + S1 + choice + K[i] + w[i];

                uint32_t S0 =
                    rotateRight(a, 2) ^
                    rotateRight(a, 13) ^
                    rotateRight(a, 22);

                uint32_t majority =
                    (a & b) ^ (a & c) ^ (b & c);

                uint32_t temp2 = S0 + majority;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        std::array<uint8_t, 32> result{};

        for (size_t i = 0; i < 8; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                result[i * 4 + j] =
                    static_cast<uint8_t>(
                        state[i] >> (24 - j * 8)
                    );
            }
        }

        return result;
    }

    static std::string hex(
        const std::array<uint8_t, 32>& digest
    ) {
        std::ostringstream output;

        output << std::hex << std::setfill('0');

        for (uint8_t byte : digest) {
            output << std::setw(2)
                   << static_cast<unsigned int>(byte);
        }

        return output.str();
    }
};

// ============================================================
// 3. HMAC-SHA256
// ============================================================

class HMAC {

public:

    static std::array<uint8_t, 32> generate(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& message
    ) {

        constexpr size_t BLOCK_SIZE = 64;

        std::vector<uint8_t> normalized = key;

        if (normalized.size() > BLOCK_SIZE) {
            auto digest = SHA256::hash(normalized);

            normalized.assign(
                digest.begin(),
                digest.end()
            );
        }

        normalized.resize(BLOCK_SIZE, 0);

        std::vector<uint8_t> inner(BLOCK_SIZE);
        std::vector<uint8_t> outer(BLOCK_SIZE);

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            inner[i] = normalized[i] ^ 0x36;
            outer[i] = normalized[i] ^ 0x5c;
        }

        inner.insert(
            inner.end(),
            message.begin(),
            message.end()
        );

        auto innerHash = SHA256::hash(inner);

        outer.insert(
            outer.end(),
            innerHash.begin(),
            innerHash.end()
        );

        return SHA256::hash(outer);
    }

    static bool verify(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& message,
        const std::array<uint8_t, 32>& supplied
    ) {

        auto expected = generate(key, message);

        // Avoid ordinary early-exit comparison.
        uint8_t difference = 0;

        for (size_t i = 0; i < expected.size(); ++i) {
            difference |= expected[i] ^ supplied[i];
        }

        return difference == 0;
    }
};

// ============================================================
// 4. CRYPTOGRAPHIC KEY REGISTRY
// ============================================================

class KeyRegistry {

private:
    std::map<std::string, std::vector<uint8_t>> keys;

public:

    void registerKey(
        const std::string& id,
        const std::vector<uint8_t>& secret
    ) {

        if (id.empty() || secret.size() < 32) {
            throw ValidationException("Invalid key configuration");
        }

        if (keys.count(id)) {
            throw ValidationException("Duplicate key identifier");
        }

        keys.emplace(id, secret);
    }

    const std::vector<uint8_t>& get(
        const std::string& id
    ) const {

        auto it = keys.find(id);

        if (it == keys.end()) {
            throw ValidationException("Unknown key");
        }

        return it->second;
    }
};

// ============================================================
// 5. TRANSACTION DOMAIN MODEL
// ============================================================

struct Transaction {

    std::string id;
    std::string sender;
    std::string receiver;

    uint64_t amountMinor;
    uint64_t nonce;

    std::string keyId;

    std::array<uint8_t, 32> mac{};
};

// Use integer minor units rather than floating-point currency.
std::vector<uint8_t> serialize(const Transaction& tx) {

    std::ostringstream out;

    out << tx.id << '|'
        << tx.sender << '|'
        << tx.receiver << '|'
        << tx.amountMinor << '|'
        << tx.nonce << '|'
        << tx.keyId;

    std::string value = out.str();

    return std::vector<uint8_t>(
        value.begin(),
        value.end()
    );
}

// ============================================================
// 6. TRANSACTION AUTHENTICATION
// ============================================================

class TransactionAuthenticator {

private:
    const KeyRegistry& registry;

public:

    explicit TransactionAuthenticator(
        const KeyRegistry& keyRegistry
    ) : registry(keyRegistry) {}

    void authenticate(Transaction& tx) const {

        if (
            tx.id.empty() ||
            tx.sender.empty() ||
            tx.receiver.empty() ||
            tx.keyId.empty()
        ) {
            throw ValidationException("Missing transaction fields");
        }

        if (tx.sender == tx.receiver) {
            throw ValidationException("Self-transfer prohibited");
        }

        if (tx.amountMinor == 0) {
            throw ValidationException("Amount must be positive");
        }

        tx.mac = HMAC::generate(
            registry.get(tx.keyId),
            serialize(tx)
        );
    }

    bool verify(const Transaction& tx) const {

        return HMAC::verify(
            registry.get(tx.keyId),
            serialize(tx),
            tx.mac
        );
    }
};

// ============================================================
// 7. REPLAY PROTECTION
// ============================================================

class ReplayGuard {

private:
    std::set<std::pair<std::string, uint64_t>> processed;

public:

    bool accept(const Transaction& tx) {

        auto identity = std::make_pair(
            tx.sender,
            tx.nonce
        );

        return processed.insert(identity).second;
    }
};

// ============================================================
// 8. BLOCKCHAIN DOMAIN MODEL
// ============================================================

struct Block {

    uint64_t index;
    uint64_t timestamp;

    std::string previousHash;
    std::string hash;

    std::vector<Transaction> transactions;
};

// ============================================================
// 9. BLOCKCHAIN GOVERNANCE ENGINE
// ============================================================

class Blockchain {

private:

    std::vector<Block> blocks;

    const TransactionAuthenticator& authenticator;

    static uint64_t currentTime() {

        return static_cast<uint64_t>(
            std::chrono::duration_cast<
                std::chrono::seconds
            >(
                std::chrono::system_clock::now()
                    .time_since_epoch()
            ).count()
        );
    }

    static std::string hashBlock(const Block& block) {

        std::ostringstream serialized;

        serialized << block.index << '|'
                   << block.timestamp << '|'
                   << block.previousHash;

        for (const auto& tx : block.transactions) {
            serialized << '|'
                       << SHA256::hex(tx.mac)
                       << '|'
                       << SHA256::hex(
                           SHA256::hash(serialize(tx))
                       );
        }

        std::string content = serialized.str();

        std::vector<uint8_t> bytes(
            content.begin(),
            content.end()
        );

        return SHA256::hex(SHA256::hash(bytes));
    }

public:

    explicit Blockchain(
        const TransactionAuthenticator& service
    ) : authenticator(service) {

        Block genesis;

        genesis.index = 0;
        genesis.timestamp = currentTime();
        genesis.previousHash = std::string(64, '0');
        genesis.hash = hashBlock(genesis);

        blocks.push_back(genesis);
    }

    void addBlock(
        const std::vector<Transaction>& transactions
    ) {

        if (transactions.empty()) {
            throw ValidationException(
                "Cannot create an empty non-genesis block"
            );
        }

        std::set<std::string> identifiers;

        for (const auto& tx : transactions) {

            if (!authenticator.verify(tx)) {
                throw AuthenticationException(
                    "Invalid transaction authentication"
                );
            }

            if (!identifiers.insert(tx.id).second) {
                throw ValidationException(
                    "Duplicate transaction in block"
                );
            }

            for (const auto& existing : blocks) {
                for (const auto& stored : existing.transactions) {
                    if (stored.id == tx.id) {
                        throw ValidationException(
                            "Transaction already included in blockchain"
                        );
                    }
                }
            }
        }

        const Block& previous = blocks.back();

        Block block;

        block.index = blocks.size();
        block.timestamp = currentTime();
        block.previousHash = previous.hash;
        block.transactions = transactions;
        block.hash = hashBlock(block);

        blocks.push_back(std::move(block));
    }

    bool validate() const {

        for (size_t i = 0; i < blocks.size(); ++i) {

            const Block& current = blocks[i];

            if (current.hash != hashBlock(current)) {
                return false;
            }

            if (i == 0) {
                if (current.previousHash != std::string(64, '0')) {
                    return false;
                }
            } else {
                if (
                    current.previousHash !=
                    blocks[i - 1].hash
                ) {
                    return false;
                }
            }

            for (const auto& tx : current.transactions) {
                if (!authenticator.verify(tx)) {
                    return false;
                }
            }
        }

        return true;
    }

    const std::vector<Block>& getBlocks() const {
        return blocks;
    }
};

// ============================================================
// 10. TEST UTILITIES
// ============================================================

std::vector<uint8_t> toBytes(const std::string& value) {
    return std::vector<uint8_t>(
        value.begin(),
        value.end()
    );
}

// ============================================================
// 11. EXECUTION
// ============================================================

int main() {

    try {

        std::cout << "MAC AND BLOCKCHAIN ENGINE\n";
        std::cout << "========================================\n";

        // Known SHA-256 test vector.
        auto emptyHash = SHA256::hash(toBytes(""));

        std::cout << "\n1. SHA-256\n";
        std::cout << "Empty input: "
                  << SHA256::hex(emptyHash)
                  << '\n';

        if (
            SHA256::hex(emptyHash) !=
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ) {
            throw MACException("SHA-256 self-test failed");
        }

        // HMAC.
        std::vector<uint8_t> key(32, 0x42);

        auto message = toBytes("Blockchain transaction");

        auto mac = HMAC::generate(key, message);

        std::cout << "\n2. HMAC-SHA256\n";
        std::cout << "MAC: " << SHA256::hex(mac) << '\n';

        std::cout << "Valid: "
                  << HMAC::verify(key, message, mac)
                  << '\n';

        std::cout << "Tampered: "
                  << HMAC::verify(
                      key,
                      toBytes("Modified transaction"),
                      mac
                  )
                  << '\n';

        // Key registration.
        KeyRegistry registry;

        registry.registerKey(
            "node-001",
            key
        );

        // Transaction.
        Transaction tx{
            "TX-1001",
            "wallet-A",
            "wallet-B",
            10050,
            1,
            "node-001",
            {}
        };

        TransactionAuthenticator authenticator(registry);

        authenticator.authenticate(tx);

        std::cout << "\n3. Transaction Authentication\n";

        std::cout << "Authenticated: "
                  << authenticator.verify(tx)
                  << '\n';

        // Replay protection.
        std::cout << "\n4. Replay Protection\n";

        ReplayGuard replay;

        std::cout << "First submission: "
                  << replay.accept(tx)
                  << '\n';

        std::cout << "Second submission: "
                  << replay.accept(tx)
                  << '\n';

        // Blockchain.
        std::cout << "\n5. Blockchain\n";

        Blockchain blockchain(authenticator);

        blockchain.addBlock({tx});

        std::cout << "Block count: "
                  << blockchain.getBlocks().size()
                  << '\n';

        std::cout << "Chain valid: "
                  << blockchain.validate()
                  << '\n';

        std::cout << "Latest hash: "
                  << blockchain.getBlocks().back().hash
                  << '\n';

        // Tampering.
        std::cout << "\n6. Tampering Detection\n";

        Transaction modified = tx;

        modified.amountMinor = 999999;

        std::cout << "Modified transaction valid: "
                  << authenticator.verify(modified)
                  << '\n';

        // Invalid transaction.
        std::cout << "\n7. Validation\n";

        try {

            Transaction invalid{
                "TX-1002",
                "wallet-A",
                "wallet-A",
                100,
                2,
                "node-001",
                {}
            };

            authenticator.authenticate(invalid);

        } catch (const ValidationException& error) {
            std::cout << "Rejected: "
                      << error.what()
                      << '\n';
        }

        // Assertions.
        if (!blockchain.validate()) {
            throw MACException("Blockchain validation failed");
        }

        if (authenticator.verify(modified)) {
            throw MACException("Tampering detection failed");
        }

        if (replay.accept(tx)) {
            throw MACException("Replay detection failed");
        }

        std::cout << "\nAll tests passed.\n";

    } catch (const std::exception& error) {

        std::cerr << "Execution error: "
                  << error.what()
                  << '\n';

        return 1;
    }

    return 0;
}
