#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * HMAC-SHA256 and Blockchain Governance Engine
 *
 * C++17
 * No external libraries.
 *
 * Components:
 * 1. SHA-256 implementation.
 * 2. HMAC-SHA256 construction.
 * 3. Constant-time tag comparison.
 * 4. Transaction authentication.
 * 5. Nonce and transaction-ID validation.
 * 6. Hash-linked blockchain.
 * 7. Block integrity verification.
 *
 * Educational implementation.
 * Production systems should use a vetted cryptographic library.
 */

namespace crypto {

using Bytes = std::vector<uint8_t>;

constexpr std::array<uint32_t, 64> K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

uint32_t rotateRight(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

class SHA256 {

    std::array<uint32_t, 8> state = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    uint64_t totalBits = 0;
    Bytes buffer;

    void transform(const uint8_t* data) {
        uint32_t w[64];

        for (int i = 0; i < 16; ++i) {
            w[i] =
                (uint32_t(data[i * 4]) << 24) |
                (uint32_t(data[i * 4 + 1]) << 16) |
                (uint32_t(data[i * 4 + 2]) << 8) |
                uint32_t(data[i * 4 + 3]);
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

            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        auto a = state[0];
        auto b = state[1];
        auto c = state[2];
        auto d = state[3];
        auto e = state[4];
        auto f = state[5];
        auto g = state[6];
        auto h = state[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 =
                rotateRight(e, 6) ^
                rotateRight(e, 11) ^
                rotateRight(e, 25);

            uint32_t ch = (e & f) ^ (~e & g);

            uint32_t temp1 = h + S1 + ch + K[i] + w[i];

            uint32_t S0 =
                rotateRight(a, 2) ^
                rotateRight(a, 13) ^
                rotateRight(a, 22);

            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);

            uint32_t temp2 = S0 + maj;

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

public:

    void update(const Bytes& input) {
        if (input.size() >
            (UINT64_MAX - totalBits) / 8) {
            throw std::length_error("SHA-256 input too large.");
        }

        totalBits += static_cast<uint64_t>(input.size()) * 8;

        for (uint8_t byte : input) {
            buffer.push_back(byte);

            if (buffer.size() == 64) {
                transform(buffer.data());
                buffer.clear();
            }
        }
    }

    Bytes finish() {
        uint64_t originalBits = totalBits;

        buffer.push_back(0x80);

        while (buffer.size() % 64 != 56) {
            buffer.push_back(0x00);
        }

        for (int i = 7; i >= 0; --i) {
            buffer.push_back(
                static_cast<uint8_t>(
                    originalBits >> (i * 8)
                )
            );
        }

        for (size_t i = 0; i < buffer.size(); i += 64) {
            transform(buffer.data() + i);
        }

        Bytes output;

        for (uint32_t value : state) {
            for (int i = 3; i >= 0; --i) {
                output.push_back(
                    static_cast<uint8_t>(value >> (i * 8))
                );
            }
        }

        return output;
    }
};

Bytes sha256(const Bytes& data) {
    SHA256 hash;
    hash.update(data);
    return hash.finish();
}

std::string toHex(const Bytes& bytes) {
    std::ostringstream out;

    out << std::hex << std::setfill('0');

    for (uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }

    return out.str();
}

Bytes fromString(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

Bytes hmacSha256(const Bytes& key, const Bytes& message) {
    constexpr size_t BLOCK_SIZE = 64;

    if (key.size() < 32) {
        throw std::invalid_argument(
            "HMAC key must contain at least 32 bytes."
        );
    }

    Bytes normalized = key;

    if (normalized.size() > BLOCK_SIZE) {
        normalized = sha256(normalized);
    }

    normalized.resize(BLOCK_SIZE, 0);

    Bytes innerPad(BLOCK_SIZE);
    Bytes outerPad(BLOCK_SIZE);

    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        innerPad[i] = normalized[i] ^ 0x36;
        outerPad[i] = normalized[i] ^ 0x5c;
    }

    Bytes inner = innerPad;
    inner.insert(inner.end(), message.begin(), message.end());

    Bytes innerHash = sha256(inner);

    Bytes outer = outerPad;
    outer.insert(outer.end(), innerHash.begin(), innerHash.end());

    return sha256(outer);
}

bool constantTimeEqual(const std::string& a, const std::string& b) {
    size_t maximum = std::max(a.size(), b.size());
    unsigned difference =
        static_cast<unsigned>(a.size() ^ b.size());

    for (size_t i = 0; i < maximum; ++i) {
        unsigned char x = i < a.size() ? a[i] : 0;
        unsigned char y = i < b.size() ? b[i] : 0;

        difference |= x ^ y;
    }

    return difference == 0;
}

bool verifyHmac(
    const Bytes& key,
    const Bytes& message,
    const std::string& supplied
) {
    return constantTimeEqual(
        toHex(hmacSha256(key, message)),
        supplied
    );
}

} // namespace crypto

// ============================================================
// 1. DOMAIN MODEL
// ============================================================

enum class KeyStatus {
    ACTIVE,
    RETIRED,
    REVOKED
};

struct KeyRecord {
    crypto::Bytes secret;
    KeyStatus status;
};

struct Transaction {
    std::string id;
    std::string sender;
    std::string receiver;
    int64_t amount;
    uint64_t nonce;
    std::string keyId;
    std::string signature;

    std::string payload() const {
        // Fixed field order gives deterministic serialization.
        std::ostringstream out;

        out << id << '|'
            << sender << '|'
            << receiver << '|'
            << amount << '|'
            << nonce << '|'
            << keyId;

        return out.str();
    }
};

struct Block {
    uint64_t index;
    std::string previousHash;
    std::vector<Transaction> transactions;
    std::string hash;

    std::string payload() const {
        std::ostringstream out;

        out << index << '|'
            << previousHash << '|'
            << transactions.size();

        for (const auto& tx : transactions) {
            out << '|'
                << tx.payload()
                << '|'
                << tx.signature;
        }

        return out.str();
    }

    void calculateHash() {
        hash = crypto::toHex(
            crypto::sha256(crypto::fromString(payload()))
        );
    }
};

// ============================================================
// 2. KEY MANAGEMENT
// ============================================================

class KeyVault {

    std::map<std::string, KeyRecord> keys;

public:

    void add(
        const std::string& id,
        const crypto::Bytes& secret
    ) {
        if (id.empty() || keys.count(id)) {
            throw std::invalid_argument(
                "Invalid or duplicate key ID."
            );
        }

        if (secret.size() < 32) {
            throw std::invalid_argument(
                "Key must contain at least 32 bytes."
            );
        }

        keys.emplace(
            id,
            KeyRecord{secret, KeyStatus::ACTIVE}
        );
    }

    const KeyRecord& get(const std::string& id) const {
        auto it = keys.find(id);

        if (it == keys.end() ||
            it->second.status == KeyStatus::REVOKED) {
            throw std::runtime_error(
                "Key unavailable or revoked."
            );
        }

        return it->second;
    }

    void rotate(
        const std::string& oldId,
        const std::string& newId,
        const crypto::Bytes& newSecret
    ) {
        const auto& old = get(oldId);

        if (old.status != KeyStatus::ACTIVE) {
            throw std::runtime_error("Old key is not active.");
        }

        add(newId, newSecret);

        keys.at(oldId).status = KeyStatus::RETIRED;
    }

    std::string sign(
        const std::string& keyId,
        const std::string& payload
    ) const {
        const auto& record = get(keyId);

        if (record.status != KeyStatus::ACTIVE) {
            throw std::runtime_error(
                "Retired keys cannot sign."
            );
        }

        return crypto::toHex(
            crypto::hmacSha256(
                record.secret,
                crypto::fromString(payload)
            )
        );
    }

    bool verify(
        const std::string& keyId,
        const std::string& payload,
        const std::string& signature
    ) const {
        const auto& record = get(keyId);

        return crypto::verifyHmac(
            record.secret,
            crypto::fromString(payload),
            signature
        );
    }
};

// ============================================================
// 3. TRANSACTION FACTORY
// ============================================================

class TransactionFactory {

public:

    static Transaction create(
        const std::string& id,
        const std::string& sender,
        const std::string& receiver,
        int64_t amount,
        uint64_t nonce,
        const std::string& keyId,
        const KeyVault& vault
    ) {
        if (
            id.empty() ||
            sender.empty() ||
            receiver.empty() ||
            sender == receiver
        ) {
            throw std::invalid_argument(
                "Invalid transaction identity."
            );
        }

        if (amount <= 0) {
            throw std::invalid_argument(
                "Amount must be positive."
            );
        }

        Transaction tx{
            id,
            sender,
            receiver,
            amount,
            nonce,
            keyId,
            ""
        };

        tx.signature = vault.sign(keyId, tx.payload());

        return tx;
    }
};

// ============================================================
// 4. BLOCKCHAIN ENGINE
// ============================================================

class Blockchain {

    const KeyVault& vault;

    std::vector<Block> chain;
    std::vector<Transaction> pending;

    std::map<std::string, std::set<uint64_t>> usedNonces;
    std::set<std::string> transactionIds;

public:

    explicit Blockchain(const KeyVault& keyVault)
        : vault(keyVault) {

        Block genesis{
            0,
            std::string(64, '0'),
            {},
            ""
        };

        genesis.calculateHash();
        chain.push_back(genesis);
    }

    void submit(const Transaction& tx) {
        if (tx.amount <= 0) {
            throw std::invalid_argument("Invalid amount.");
        }

        if (!vault.verify(
            tx.keyId,
            tx.payload(),
            tx.signature
        )) {
            throw std::runtime_error(
                "HMAC authentication failed."
            );
        }

        if (transactionIds.count(tx.id)) {
            throw std::runtime_error(
                "Duplicate transaction ID."
            );
        }

        auto& nonces = usedNonces[tx.sender];

        if (nonces.count(tx.nonce)) {
            throw std::runtime_error(
                "Replay attack detected."
            );
        }

        for (const auto& item : pending) {
            if (
                item.id == tx.id ||
                (
                    item.sender == tx.sender &&
                    item.nonce == tx.nonce
                )
            ) {
                throw std::runtime_error(
                    "Duplicate pending transaction."
                );
            }
        }

        pending.push_back(tx);
    }

    const Block& mine() {
        if (pending.empty()) {
            throw std::runtime_error(
                "No pending transactions."
            );
        }

        // Validate the complete batch before modifying ledger state.
        std::map<std::string, std::set<uint64_t>> batchNonces;
        std::set<std::string> batchIds;

        for (const auto& tx : pending) {
            if (!vault.verify(
                tx.keyId,
                tx.payload(),
                tx.signature
            )) {
                throw std::runtime_error(
                    "Invalid transaction signature."
                );
            }

            if (
                usedNonces[tx.sender].count(tx.nonce) ||
                !batchNonces[tx.sender].insert(tx.nonce).second
            ) {
                throw std::runtime_error(
                    "Nonce conflict during block construction."
                );
            }

            if (
                transactionIds.count(tx.id) ||
                !batchIds.insert(tx.id).second
            ) {
                throw std::runtime_error(
                    "Transaction ID conflict."
                );
            }
        }

        Block block{
            chain.size(),
            chain.back().hash,
            pending,
            ""
        };

        block.calculateHash();

        // Commit after successful validation.
        chain.push_back(block);

        for (const auto& tx : pending) {
            usedNonces[tx.sender].insert(tx.nonce);
            transactionIds.insert(tx.id);
        }

        pending.clear();

        return chain.back();
    }

    bool validate() const {
        if (chain.empty()) {
            return false;
        }

        for (size_t i = 0; i < chain.size(); ++i) {
            const auto& block = chain[i];

            Block copy = block;
            copy.calculateHash();

            if (copy.hash != block.hash) {
                return false;
            }

            if (i == 0) {
                if (block.previousHash != std::string(64, '0')) {
                    return false;
                }
            } else if (
                block.previousHash != chain[i - 1].hash
            ) {
                return false;
            }

            for (const auto& tx : block.transactions) {
                try {
                    if (!vault.verify(
                        tx.keyId,
                        tx.payload(),
                        tx.signature
                    )) {
                        return false;
                    }
                } catch (...) {
                    return false;
                }
            }
        }

        return true;
    }

    int64_t balance(const std::string& address) const {
        int64_t result = 0;

        for (const auto& block : chain) {
            for (const auto& tx : block.transactions) {
                if (tx.sender == address) {
                    result -= tx.amount;
                }

                if (tx.receiver == address) {
                    result += tx.amount;
                }
            }
        }

        return result;
    }

    const std::vector<Block>& blocks() const {
        return chain;
    }
};

// ============================================================
// 5. DEMONSTRATION AND TESTS
// ============================================================

int main() {
    try {
        std::cout
            << "HMAC-SHA256 AND BLOCKCHAIN ENGINE\n"
            << "=================================\n\n";

        // SHA-256 known-answer test.
        auto digest = crypto::sha256(
            crypto::fromString("abc")
        );

        const std::string expected =
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad";

        if (crypto::toHex(digest) != expected) {
            throw std::runtime_error(
                "SHA-256 test failed."
            );
        }

        std::cout << "SHA-256 test: PASSED\n";

        // HMAC known-answer test.
        crypto::Bytes testKey(20, 0x0b);

        auto testTag = crypto::hmacSha256(
            testKey,
            crypto::fromString("Hi There")
        );

        const std::string expectedHmac =
            "b0344c61d8db38535ca8afceaf0bf12b"
            "881dc200c9833da726e9376c2e32cff7";

        if (crypto::toHex(testTag) != expectedHmac) {
            throw std::runtime_error(
                "HMAC known-answer test failed."
            );
        }

        std::cout << "HMAC-SHA256 test: PASSED\n\n";

        KeyVault vault;

        crypto::Bytes secret(32, 0x42);

        vault.add("wallet-v1", secret);

        Blockchain ledger(vault);

        Transaction first = TransactionFactory::create(
            "TX-001",
            "ALICE",
            "BOB",
            500,
            1,
            "wallet-v1",
            vault
        );

        Transaction second = TransactionFactory::create(
            "TX-002",
            "BOB",
            "CHARLIE",
            150,
            1,
            "wallet-v1",
            vault
        );

        std::cout << "TRANSACTION AUTHENTICATION\n";

        std::cout << "TX-001: "
                  << vault.verify(
                      first.keyId,
                      first.payload(),
                      first.signature
                  )
                  << '\n';

        ledger.submit(first);
        ledger.submit(second);

        std::cout << "\nBLOCK CREATION\n";

        const Block& block = ledger.mine();

        std::cout << "Block index: "
                  << block.index << '\n';

        std::cout << "Block hash: "
                  << block.hash << '\n';

        std::cout << "\nACCOUNT BALANCES\n";

        std::cout << "Alice: "
                  << ledger.balance("ALICE") << '\n';

        std::cout << "Bob: "
                  << ledger.balance("BOB") << '\n';

        std::cout << "Charlie: "
                  << ledger.balance("CHARLIE") << '\n';

        std::cout << "\nREPLAY PROTECTION\n";

        try {
            ledger.submit(first);
        } catch (const std::exception& e) {
            std::cout << "Rejected: "
                      << e.what() << '\n';
        }

        std::cout << "\nTAMPERING DETECTION\n";

        Transaction modified = first;
        modified.amount = 9999;

        std::cout << "Modified HMAC valid: "
                  << vault.verify(
                      modified.keyId,
                      modified.payload(),
                      modified.signature
                  )
                  << '\n';

        std::cout << "\nCHAIN INTEGRITY\n";

        std::cout << "Valid: "
                  << ledger.validate() << '\n';

        // Key rotation.
        std::cout << "\nKEY ROTATION\n";

        vault.rotate(
            "wallet-v1",
            "wallet-v2",
            crypto::Bytes(32, 0x33)
        );

        Transaction third = TransactionFactory::create(
            "TX-003",
            "CHARLIE",
            "DAVID",
            50,
            2,
            "wallet-v2",
            vault
        );

        ledger.submit(third);
        ledger.mine();

        std::cout << "Post-rotation chain valid: "
                  << ledger.validate() << '\n';

        // Historical signatures remain verifiable using retired keys.
        std::cout << "Historical signature valid: "
                  << vault.verify(
                      first.keyId,
                      first.payload(),
                      first.signature
                  )
                  << '\n';

        std::cout << "\nALL CRYPTOGRAPHIC TESTS PASSED\n";

    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
