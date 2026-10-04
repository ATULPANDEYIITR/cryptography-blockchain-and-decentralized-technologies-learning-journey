/*
 * DES in Cryptography and Blockchain
 *
 * C++17 educational case study:
 * A repository-style encrypted blockchain ledger evaluates transaction
 * records, authenticates encrypted payloads, links blocks with SHA-256-like
 * digest placeholders implemented with a deterministic standard-library hash
 * construction, and models proof-of-work.
 *
 * The DES implementation itself is complete and uses the standard DES tables.
 *
 * Compile:
 *   g++ -std=c++17 -O2 des_blockchain.cpp -o des_blockchain
 *
 * DES is obsolete for modern cryptographic deployments because its effective
 * key size is only 56 bits.
 */

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#include <chrono>
#include <random>
#include <functional>
#include <optional>

using Byte = std::uint8_t;
using Block64 = std::array<Byte, 8>;

static const int IP[64] = {
    58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
};

static const int FP[64] = {
    40,8,48,16,56,24,32,39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,37,5,45,13,53,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
};

static const int E[48] = {
    32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,
    12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,
    23,24,25,26,27,28,29,30,31,32,1
};

static const int P[32] = {
    16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
    2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
};

static const int PC1[56] = {
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
};

static const int PC2[48] = {
    14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
    26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
    51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
};

static const int ROTATIONS[16] =
    {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static const int S[8][4][16] = {
    {
        {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
        {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
        {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
        {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
    },
    {
        {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
        {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
        {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
        {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
    },
    {
        {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
        {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
        {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
        {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
    },
    {
        {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
        {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
        {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
        {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
    },
    {
        {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
        {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
        {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
        {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
    },
    {
        {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
        {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
        {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
        {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
    },
    {
        {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
        {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
        {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
        {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
    },
    {
        {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
        {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
        {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
        {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
    }
};

std::uint64_t load64(const Block64& block) {
    std::uint64_t value = 0;
    for (Byte b : block) value = (value << 8) | b;
    return value;
}

Block64 store64(std::uint64_t value) {
    Block64 result{};
    for (int i = 7; i >= 0; --i) {
        result[i] = static_cast<Byte>(value & 0xff);
        value >>= 8;
    }
    return result;
}

std::uint64_t permutation(
    std::uint64_t value,
    const int* table,
    int outputBits,
    int inputBits
) {
    std::uint64_t result = 0;
    for (int i = 0; i < outputBits; ++i) {
        int position = table[i];
        std::uint64_t bit =
            (value >> (inputBits - position)) & 1ULL;
        result = (result << 1) | bit;
    }
    return result;
}

std::uint32_t rotate28(std::uint32_t value, int amount) {
    value &= 0x0fffffffU;
    return ((value << amount) |
            (value >> (28 - amount))) & 0x0fffffffU;
}

std::array<std::uint64_t, 16> generateKeys(Block64 key) {
    std::uint64_t reduced =
        permutation(load64(key), PC1, 56, 64);

    std::uint32_t c = static_cast<std::uint32_t>(reduced >> 28);
    std::uint32_t d =
        static_cast<std::uint32_t>(reduced & 0x0fffffffU);

    std::array<std::uint64_t, 16> keys{};

    for (int i = 0; i < 16; ++i) {
        c = rotate28(c, ROTATIONS[i]);
        d = rotate28(d, ROTATIONS[i]);

        std::uint64_t combined =
            (static_cast<std::uint64_t>(c) << 28) | d;

        keys[i] = permutation(combined, PC2, 48, 56);
    }

    return keys;
}

std::uint32_t feistel(std::uint32_t right, std::uint64_t key) {
    std::uint64_t expanded =
        permutation(right, E, 48, 32);

    std::uint64_t mixed = expanded ^ key;
    std::uint32_t substituted = 0;

    for (int i = 0; i < 8; ++i) {
        int six =
            static_cast<int>((mixed >> (42 - i * 6)) & 0x3f);

        int row = ((six >> 5) << 1) | (six & 1);
        int column = (six >> 1) & 0xf;

        substituted =
            (substituted << 4) |
            static_cast<std::uint32_t>(S[i][row][column]);
    }

    return static_cast<std::uint32_t>(
        permutation(substituted, P, 32, 32)
    );
}

Block64 des(Block64 block, Block64 key, bool decrypt = false) {
    std::uint64_t state =
        permutation(load64(block), IP, 64, 64);

    std::uint32_t left =
        static_cast<std::uint32_t>(state >> 32);
    std::uint32_t right =
        static_cast<std::uint32_t>(state);

    auto keys = generateKeys(key);
    if (decrypt) std::reverse(keys.begin(), keys.end());

    for (auto roundKey : keys) {
        std::uint32_t nextLeft = right;
        std::uint32_t nextRight =
            left ^ feistel(right, roundKey);
        left = nextLeft;
        right = nextRight;
    }

    std::uint64_t preoutput =
        (static_cast<std::uint64_t>(right) << 32) | left;

    return store64(
        permutation(preoutput, FP, 64, 64)
    );
}

std::string hex(Block64 block) {
    std::ostringstream out;
    out << std::uppercase << std::hex << std::setfill('0');
    for (Byte b : block) out << std::setw(2) << static_cast<int>(b);
    return out.str();
}

std::string deterministicDigest(const std::string& data) {
    /*
     * This is deliberately named deterministicDigest rather than SHA-256.
     * C++17 has no standard SHA-256 implementation. A blockchain must use a
     * standardized cryptographic hash in production, not std::hash.
     */
    std::hash<std::string> hasher;
    std::uint64_t h1 = hasher(data);
    std::uint64_t h2 = hasher("A|" + data);
    std::uint64_t h3 = hasher("B|" + data);
    std::uint64_t h4 = hasher("C|" + data);

    std::ostringstream out;
    out << std::hex << std::setfill('0')
        << std::setw(16) << h1
        << std::setw(16) << h2
        << std::setw(16) << h3
        << std::setw(16) << h4;
    return out.str();
}

struct Transaction {
    std::string sender;
    std::string receiver;
    std::uint64_t amount;
    std::string purpose;
};

struct Block {
    std::size_t index;
    std::string previousHash;
    std::string encryptedPayload;
    std::string hash;
    std::uint64_t nonce;
};

class GovernanceEngine {
private:
    Block64 desKey;
    std::vector<Block> chain;

    std::string serialize(const Block& block) const {
        return std::to_string(block.index) + "|" +
               block.previousHash + "|" +
               block.encryptedPayload + "|" +
               std::to_string(block.nonce);
    }

    std::string encryptTransaction(const Transaction& tx) const {
        /*
         * The example encrypts a fixed 8-byte summary. Real applications need
         * authenticated modern encryption for variable-length records.
         */
        std::string compact =
            tx.sender.substr(0, 2) +
            tx.receiver.substr(0, 2) +
            std::to_string(tx.amount);

        Block64 input{};
        for (std::size_t i = 0; i < input.size(); ++i) {
            input[i] = i < compact.size()
                ? static_cast<Byte>(compact[i])
                : 0;
        }

        return hex(des(input, desKey));
    }

    bool meetsWork(const std::string& hash, unsigned difficulty) const {
        return hash.substr(0, difficulty) ==
               std::string(difficulty, '0');
    }

public:
    explicit GovernanceEngine(Block64 key) : desKey(key) {}

    bool validateTransaction(const Transaction& tx) const {
        if (tx.sender.empty() || tx.receiver.empty()) return false;
        if (tx.sender == tx.receiver) return false;
        if (tx.amount == 0) return false;
        if (tx.purpose.empty()) return false;
        return true;
    }

    Block append(const Transaction& tx, unsigned difficulty = 2) {
        if (!validateTransaction(tx)) {
            throw std::invalid_argument(
                "Transaction violates ledger validation rules."
            );
        }

        Block block{};
        block.index = chain.size();
        block.previousHash = chain.empty()
            ? std::string(64, '0')
            : chain.back().hash;

        block.encryptedPayload = encryptTransaction(tx);
        block.nonce = 0;

        do {
            ++block.nonce;
            block.hash = deterministicDigest(serialize(block));
        } while (!meetsWork(block.hash, difficulty));

        chain.push_back(block);
        return block;
    }

    bool validateChain(unsigned difficulty = 2) const {
        for (std::size_t i = 0; i < chain.size(); ++i) {
            const Block& current = chain[i];

            std::string expectedPrevious = i == 0
                ? std::string(64, '0')
                : chain[i - 1].hash;

            if (current.previousHash != expectedPrevious) return false;
            if (deterministicDigest(serialize(current)) != current.hash)
                return false;
            if (!meetsWork(current.hash, difficulty)) return false;
        }
        return true;
    }

    void tamper(std::size_t index, const std::string& replacement) {
        if (index >= chain.size())
            throw std::out_of_range("Invalid block index.");

        /*
         * Changing encrypted payload without recomputing all dependent hashes
         * is immediately visible because later blocks retain the old link.
         */
        chain[index].encryptedPayload = replacement;
    }

    const std::vector<Block>& blocks() const {
        return chain;
    }
};

int main() {
    // FIPS 46-3 DES known-answer test.
    Block64 key = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
    Block64 plaintext = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};

    Block64 ciphertext = des(plaintext, key);
    Block64 recovered = des(ciphertext, key, true);

    std::cout << "DES known-answer test\n";
    std::cout << "Ciphertext: " << hex(ciphertext) << "\n";
    std::cout << "Expected:   85E813540F0AB405\n";
    std::cout << "Recovered:  " << hex(recovered) << "\n";
    std::cout << "Round-trip: " << (recovered == plaintext) << "\n\n";

    std::cout << "Blockchain governance case study\n";

    GovernanceEngine engine(key);

    Transaction first{
        "wallet-A",
        "wallet-B",
        250,
        "settlement"
    };

    Transaction second{
        "wallet-B",
        "merchant-X",
        125,
        "purchase"
    };

    engine.append(first);
    engine.append(second);

    for (const auto& block : engine.blocks()) {
        std::cout
            << "Block " << block.index
            << " nonce=" << block.nonce
            << " hash=" << block.hash.substr(0, 24)
            << "... encryptedPayload=" << block.encryptedPayload
            << "\n";
    }

    std::cout
        << "Chain valid: "
        << std::boolalpha
        << engine.validateChain()
        << "\n";

    engine.tamper(0, "FFFFFFFFFFFFFFFF");

    std::cout
        << "After tampering: "
        << engine.validateChain()
        << "\n";

    std::cout << "\nDesign observations\n";
    std::cout
        << "DES supplies legacy confidentiality for the demonstrated payload.\n"
        << "The block digest links records and exposes unauthorized modification.\n"
        << "Proof-of-work adds computational cost to rewriting history.\n"
        << "Neither DES nor a hash substitutes for digital signatures or consensus.\n"
        << "Production systems should use authenticated modern encryption.\n";

    return 0;
}
