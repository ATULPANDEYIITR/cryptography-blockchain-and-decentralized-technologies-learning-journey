#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Cryptographic hash properties case study.
 *
 * This program implements a compact educational SHA-256 engine and uses it
 * to model repository artifact integrity, avalanche behavior, hash chains,
 * Merkle-style aggregation, and truncated-digest collision behavior.
 *
 * SHA-256 is implemented here so the program has no external dependencies.
 * Production cryptographic systems should use a reviewed cryptographic
 * library rather than a custom implementation.
 */

class SHA256 {
private:
    std::array<uint32_t, 8> state_{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    static constexpr std::array<uint32_t, 64> K{
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

    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
        return (e & f) ^ (~e & g);
    }

    static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
        return (a & b) ^ (a & c) ^ (b & c);
    }

    static uint32_t bigSigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static uint32_t bigSigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static uint32_t smallSigma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static uint32_t smallSigma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    void processBlock(const uint8_t* block) {
        std::array<uint32_t, 64> w{};

        for (int i = 0; i < 16; ++i) {
            w[i] =
                (static_cast<uint32_t>(block[i * 4]) << 24) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; ++i) {
            w[i] = smallSigma1(w[i - 2]) + w[i - 7]
                 + smallSigma0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = state_[0];
        uint32_t b = state_[1];
        uint32_t c = state_[2];
        uint32_t d = state_[3];
        uint32_t e = state_[4];
        uint32_t f = state_[5];
        uint32_t g = state_[6];
        uint32_t h = state_[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + bigSigma1(e) + choose(e, f, g) + K[i] + w[i];
            uint32_t t2 = bigSigma0(a) + majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
        state_[5] += f;
        state_[6] += g;
        state_[7] += h;
    }

public:
    std::array<uint8_t, 32> digest(const std::string& input) {
        std::vector<uint8_t> data(input.begin(), input.end());

        const uint64_t bitLength =
            static_cast<uint64_t>(data.size()) * 8;

        data.push_back(0x80);

        while ((data.size() % 64) != 56) {
            data.push_back(0);
        }

        for (int i = 7; i >= 0; --i) {
            data.push_back(
                static_cast<uint8_t>((bitLength >> (i * 8)) & 0xff)
            );
        }

        for (std::size_t offset = 0; offset < data.size(); offset += 64) {
            processBlock(data.data() + offset);
        }

        std::array<uint8_t, 32> output{};

        for (int i = 0; i < 8; ++i) {
            output[i * 4] =
                static_cast<uint8_t>((state_[i] >> 24) & 0xff);
            output[i * 4 + 1] =
                static_cast<uint8_t>((state_[i] >> 16) & 0xff);
            output[i * 4 + 2] =
                static_cast<uint8_t>((state_[i] >> 8) & 0xff);
            output[i * 4 + 3] =
                static_cast<uint8_t>(state_[i] & 0xff);
        }

        return output;
    }

    std::string hexDigest(const std::string& input) {
        auto bytes = digest(input);
        std::ostringstream output;

        for (uint8_t byte : bytes) {
            output << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<int>(byte);
        }

        return output.str();
    }
};

static int differingBits(
    const std::array<uint8_t, 32>& left,
    const std::array<uint8_t, 32>& right
) {
    int result = 0;

    for (std::size_t i = 0; i < left.size(); ++i) {
        result += __builtin_popcount(
            static_cast<unsigned int>(left[i] ^ right[i])
        );
    }

    return result;
}

static std::string truncatedDigest(
    SHA256& hasher,
    const std::string& input
) {
    return hasher.hexDigest(input).substr(0, 4);
}

struct RepositoryBlock {
    int index;
    std::string previousHash;
    std::string payload;
    std::string hash;
};

static RepositoryBlock createBlock(
    SHA256& hasher,
    int index,
    const std::string& previousHash,
    const std::string& payload
) {
    std::string material =
        std::to_string(index) + "|" + previousHash + "|" + payload;

    return {
        index,
        previousHash,
        payload,
        hasher.hexDigest(material)
    };
}

static bool validateChain(
    SHA256& hasher,
    const std::vector<RepositoryBlock>& chain
) {
    if (chain.empty()) {
        return false;
    }

    for (std::size_t i = 0; i < chain.size(); ++i) {
        const std::string expectedPrevious =
            i == 0
                ? std::string(64, '0')
                : chain[i - 1].hash;

        if (chain[i].previousHash != expectedPrevious) {
            return false;
        }

        const auto rebuilt = createBlock(
            hasher,
            chain[i].index,
            chain[i].previousHash,
            chain[i].payload
        );

        if (rebuilt.hash != chain[i].hash) {
            return false;
        }
    }

    return true;
}

static std::string merkleRoot(
    SHA256& hasher,
    std::vector<std::string> values
) {
    if (values.empty()) {
        throw std::invalid_argument("Merkle tree requires at least one value");
    }

    std::vector<std::string> level;

    for (const auto& value : values) {
        level.push_back(hasher.hexDigest(value));
    }

    while (level.size() > 1) {
        std::vector<std::string> next;

        for (std::size_t i = 0; i < level.size(); i += 2) {
            const std::string& right =
                i + 1 < level.size() ? level[i + 1] : level[i];

            next.push_back(
                hasher.hexDigest(level[i] + right)
            );
        }

        level = std::move(next);
    }

    return level.front();
}

int main() {
    try {
        SHA256 hasher;

        std::cout << "Cryptographic hash properties\n\n";

        const std::string message = "repository artifact: build-1842";
        const std::string first = hasher.hexDigest(message);
        const std::string second = hasher.hexDigest(message);

        std::cout << "Determinism\n";
        std::cout << "  equal: " << std::boolalpha << (first == second) << "\n";
        std::cout << "  SHA-256: " << first << "\n";

        const auto original = hasher.digest("amount=1000;account=42");
        const auto modified = hasher.digest("amount=1001;account=42");

        const int changed = differingBits(original, modified);

        std::cout << "\nAvalanche effect\n";
        std::cout << "  changed bits: " << changed << "/256\n";
        std::cout << "  percentage: " << (changed / 256.0 * 100.0) << "%\n";

        std::cout << "\nFixed output size\n";
        for (const auto& input : {
            std::string(""),
            std::string("a"),
            std::string(1000, 'x')
        }) {
            std::cout
                << "  input bytes=" << input.size()
                << " -> digest bytes=32\n";
        }

        std::cout << "\nDomain separation\n";
        const auto registration =
            hasher.hexDigest("registration:user=42");
        const auto audit =
            hasher.hexDigest("audit:user=42");

        std::cout << "  registration: " << registration << "\n";
        std::cout << "  audit:        " << audit << "\n";

        std::cout << "\nTruncated collision experiment\n";

        std::map<std::string, std::string> seen;
        bool collisionFound = false;

        for (int i = 0; i < 1'000'000; ++i) {
            const std::string candidate = "record-" + std::to_string(i);
            const std::string shortDigest =
                truncatedDigest(hasher, candidate);

            auto [it, inserted] = seen.emplace(shortDigest, candidate);

            if (!inserted && it->second != candidate) {
                std::cout << "  prefix: " << shortDigest << "\n";
                std::cout << "  first:  " << it->second << "\n";
                std::cout << "  second: " << candidate << "\n";
                collisionFound = true;
                break;
            }
        }

        if (!collisionFound) {
            std::cout << "  no collision found within limit\n";
        }

        std::vector<RepositoryBlock> chain;
        std::string previous(64, '0');

        for (int i = 0; i < 3; ++i) {
            const std::string payload =
                i == 0 ? "commit:8f42" :
                i == 1 ? "review:approved" :
                         "merge:main";

            chain.push_back(
                createBlock(hasher, i, previous, payload)
            );

            previous = chain.back().hash;
        }

        std::cout << "\nRepository artifact hash chain\n";
        std::cout << "  valid: " << validateChain(hasher, chain) << "\n";

        chain[1].payload = "review:rejected";

        std::cout << "  after tampering: "
                  << validateChain(hasher, chain) << "\n";

        std::cout << "\nMerkle-style aggregation\n";
        std::cout << "  root: "
                  << merkleRoot(hasher, {
                         "commit:8f42",
                         "commit:19bc",
                         "commit:a71e",
                         "commit:f004"
                     })
                  << "\n";

        std::cout << "\nSecurity considerations\n";
        std::cout << "  SHA-256 provides a 256-bit digest.\n";
        std::cout << "  Collision resistance is not the same as preimage resistance.\n";
        std::cout << "  Hashing does not encrypt data.\n";
        std::cout << "  A custom SHA-256 implementation is suitable for study, not production cryptography.\n";
        std::cout << "  Authentication requires a keyed construction such as HMAC or a digital signature.\n";

    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
