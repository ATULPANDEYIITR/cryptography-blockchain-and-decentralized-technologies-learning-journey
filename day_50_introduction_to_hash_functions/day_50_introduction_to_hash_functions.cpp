#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * Introduction to Hash Functions
 *
 * This C++17 case study implements a compact educational SHA-256 engine
 * rather than relying on a third-party cryptographic library.
 *
 * The program demonstrates:
 * - deterministic cryptographic hashing
 * - SHA-256 message padding
 * - compression rounds
 * - avalanche behavior
 * - digest-based artifact identification
 * - collision-aware unordered containers
 * - Merkle-tree construction
 * - integrity verification
 *
 * Security note:
 * This implementation is educational. Production cryptographic software
 * should normally use a reviewed cryptographic library rather than
 * application-level cryptographic primitives.
 */

class Sha256 {
private:
    std::array<std::uint32_t, 8> state_{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    static constexpr std::array<std::uint32_t, 64> K{
        0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
        0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
        0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
        0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
        0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
        0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
        0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
        0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
        0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
        0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
        0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
        0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
        0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
        0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
        0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
        0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
    };

    static std::uint32_t rotateRight(std::uint32_t x, unsigned n) {
        return (x >> n) | (x << (32U - n));
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

    static std::uint32_t bigSigma0(std::uint32_t x) {
        return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
    }

    static std::uint32_t bigSigma1(std::uint32_t x) {
        return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
    }

    static std::uint32_t smallSigma0(std::uint32_t x) {
        return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
    }

    static std::uint32_t smallSigma1(std::uint32_t x) {
        return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
    }

    void compress(const std::array<std::uint8_t, 64>& block) {
        std::array<std::uint32_t, 64> w{};

        for (std::size_t i = 0; i < 16; ++i) {
            std::size_t p = i * 4;
            w[i] =
                (static_cast<std::uint32_t>(block[p]) << 24) |
                (static_cast<std::uint32_t>(block[p + 1]) << 16) |
                (static_cast<std::uint32_t>(block[p + 2]) << 8) |
                static_cast<std::uint32_t>(block[p + 3]);
        }

        for (std::size_t i = 16; i < 64; ++i) {
            w[i] =
                smallSigma1(w[i - 2]) +
                w[i - 7] +
                smallSigma0(w[i - 15]) +
                w[i - 16];
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];
        std::uint32_t f = state_[5];
        std::uint32_t g = state_[6];
        std::uint32_t h = state_[7];

        for (std::size_t i = 0; i < 64; ++i) {
            std::uint32_t temp1 =
                h + bigSigma1(e) + choose(e, f, g) + K[i] + w[i];

            std::uint32_t temp2 =
                bigSigma0(a) + majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
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
    static std::string hash(const std::string& message) {
        Sha256 sha;

        std::vector<std::uint8_t> data(
            message.begin(),
            message.end()
        );

        const std::uint64_t bitLength =
            static_cast<std::uint64_t>(data.size()) * 8ULL;

        data.push_back(0x80U);

        while ((data.size() % 64U) != 56U) {
            data.push_back(0x00U);
        }

        for (int shift = 56; shift >= 0; shift -= 8) {
            data.push_back(
                static_cast<std::uint8_t>((bitLength >> shift) & 0xffU)
            );
        }

        for (std::size_t offset = 0; offset < data.size(); offset += 64) {
            std::array<std::uint8_t, 64> block{};

            std::copy_n(
                data.begin() + static_cast<std::ptrdiff_t>(offset),
                64,
                block.begin()
            );

            sha.compress(block);
        }

        std::ostringstream output;
        output << std::hex << std::setfill('0');

        for (std::uint32_t word : sha.state_) {
            output << std::setw(8) << word;
        }

        return output.str();
    }
};

class ArtifactIndex {
private:
    struct Artifact {
        std::string identifier;
        std::string branch;
        std::string author;
    };

    std::unordered_map<std::string, Artifact> artifacts_;

public:
    void add(const Artifact& artifact) {
        if (artifact.identifier.empty()) {
            throw std::invalid_argument("Artifact identifier cannot be empty");
        }

        artifacts_[artifact.identifier] = artifact;
    }

    std::optional<Artifact> find(const std::string& identifier) const {
        auto iterator = artifacts_.find(identifier);

        if (iterator == artifacts_.end()) {
            return std::nullopt;
        }

        return iterator->second;
    }

    std::size_t size() const {
        return artifacts_.size();
    }
};

class MerkleTree {
public:
    static std::string root(std::vector<std::string> leaves) {
        if (leaves.empty()) {
            throw std::invalid_argument(
                "Merkle tree requires at least one leaf"
            );
        }

        std::vector<std::string> level;

        for (const auto& leaf : leaves) {
            level.push_back(Sha256::hash(leaf));
        }

        while (level.size() > 1) {
            if (level.size() % 2 != 0) {
                level.push_back(level.back());
            }

            std::vector<std::string> next;

            for (std::size_t i = 0; i < level.size(); i += 2) {
                next.push_back(
                    Sha256::hash(level[i] + level[i + 1])
                );
            }

            level = std::move(next);
        }

        return level.front();
    }
};

std::size_t differingCharacters(const std::string& a,
                                const std::string& b) {
    if (a.size() != b.size()) {
        throw std::invalid_argument("Digest lengths must match");
    }

    std::size_t count = 0;

    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            ++count;
        }
    }

    return count;
}

bool constantTimeEqual(const std::string& a, const std::string& b) {
    /*
     * Prevent early exit so the comparison does not immediately reveal
     * the position of the first differing byte through timing.
     */
    if (a.size() != b.size()) {
        return false;
    }

    unsigned char difference = 0;

    for (std::size_t i = 0; i < a.size(); ++i) {
        difference |=
            static_cast<unsigned char>(a[i]) ^
            static_cast<unsigned char>(b[i]);
    }

    return difference == 0;
}

int main() {
    try {
        std::cout << "=== SHA-256 Determinism ===\n";

        const std::string digest1 =
            Sha256::hash("repository artifact");

        const std::string digest2 =
            Sha256::hash("repository artifact");

        std::cout << digest1 << '\n';
        std::cout
            << "Deterministic: "
            << std::boolalpha
            << constantTimeEqual(digest1, digest2)
            << "\n\n";

        std::cout << "=== Avalanche Behavior ===\n";

        const std::string original =
            Sha256::hash("hash-function");

        const std::string changed =
            Sha256::hash("hash-functions");

        std::cout << "Original: " << original << '\n';
        std::cout << "Changed : " << changed << '\n';
        std::cout
            << "Different hexadecimal positions: "
            << differingCharacters(original, changed)
            << "\n\n";

        std::cout << "=== Artifact Index ===\n";

        ArtifactIndex index;

        const std::string artifactDigest =
            Sha256::hash("commit-001");

        index.add({
            artifactDigest,
            "main",
            "developer@example.com"
        });

        const auto artifact = index.find(artifactDigest);

        if (artifact) {
            std::cout
                << "Branch: "
                << artifact->branch
                << ", Author: "
                << artifact->author
                << '\n';
        }

        std::cout
            << "Indexed artifacts: "
            << index.size()
            << "\n\n";

        std::cout << "=== Integrity Verification ===\n";

        const std::string expected =
            Sha256::hash("release artifact v1");

        const bool unchanged =
            constantTimeEqual(
                expected,
                Sha256::hash("release artifact v1")
            );

        const bool modified =
            constantTimeEqual(
                expected,
                Sha256::hash("release artifact v2")
            );

        std::cout << "Unchanged artifact: " << unchanged << '\n';
        std::cout << "Modified artifact: " << modified << "\n\n";

        std::cout << "=== Merkle Tree ===\n";

        const std::vector<std::string> transactions{
            "TX-001 Alice -> Bob 10",
            "TX-002 Bob -> Carol 5",
            "TX-003 Carol -> Dave 2",
            "TX-004 Dave -> Erin 1"
        };

        std::cout
            << "Merkle root: "
            << MerkleTree::root(transactions)
            << "\n\n";

        std::cout << "=== Hashing Properties ===\n";
        std::cout << "Fixed SHA-256 output: 256 bits / 32 bytes\n";
        std::cout << "Typical software lookup: expected O(1) average\n";
        std::cout << "Cryptographic collision resistance is not the same as "
                     "ordinary hash-table collision handling.\n";
    }
    catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
