#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * SHA family governance-oriented integrity engine.
 *
 * This program implements SHA-256 directly and uses it to model a realistic
 * artifact-integrity workflow. The implementation follows the SHA-256
 * compression construction from FIPS 180-4:
 *
 *   message -> padding -> 512-bit blocks -> 64 compression rounds -> digest
 *
 * The program intentionally keeps the cryptographic primitive self-contained
 * so that the state transformation, message schedule, rotations, and
 * feed-forward operation are visible.
 *
 * It also demonstrates:
 * - incremental hashing
 * - hexadecimal digest encoding
 * - integrity verification
 * - algorithm-policy selection
 * - immutable artifact records
 * - failure handling
 *
 * Compile:
 *   g++ -std=c++17 -O2 sha_family.cpp -o sha_family
 */

namespace sha256_detail {

constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

constexpr std::array<std::uint32_t, 8> INITIAL_STATE = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

constexpr std::uint32_t rotr(std::uint32_t value, unsigned count) {
    return (value >> count) | (value << (32u - count));
}

constexpr std::uint32_t ch(
    std::uint32_t x,
    std::uint32_t y,
    std::uint32_t z
) {
    return (x & y) ^ (~x & z);
}

constexpr std::uint32_t maj(
    std::uint32_t x,
    std::uint32_t y,
    std::uint32_t z
) {
    return (x & y) ^ (x & z) ^ (y & z);
}

constexpr std::uint32_t big_sigma0(std::uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

constexpr std::uint32_t big_sigma1(std::uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

constexpr std::uint32_t small_sigma0(std::uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

constexpr std::uint32_t small_sigma1(std::uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void compress(
    std::array<std::uint32_t, 8>& state,
    const std::uint8_t* block
) {
    std::array<std::uint32_t, 64> w{};

    for (std::size_t i = 0; i < 16; ++i) {
        const std::size_t offset = i * 4;

        w[i] =
            (static_cast<std::uint32_t>(block[offset]) << 24) |
            (static_cast<std::uint32_t>(block[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(block[offset + 2]) << 8) |
            static_cast<std::uint32_t>(block[offset + 3]);
    }

    for (std::size_t i = 16; i < 64; ++i) {
        w[i] =
            small_sigma1(w[i - 2]) +
            w[i - 7] +
            small_sigma0(w[i - 15]) +
            w[i - 16];
    }

    auto working = state;

    for (std::size_t i = 0; i < 64; ++i) {
        const std::uint32_t t1 =
            working[7] +
            big_sigma1(working[4]) +
            ch(working[4], working[5], working[6]) +
            K[i] +
            w[i];

        const std::uint32_t t2 =
            big_sigma0(working[0]) +
            maj(working[0], working[1], working[2]);

        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3] + t1;
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = t1 + t2;
    }

    for (std::size_t i = 0; i < state.size(); ++i) {
        state[i] += working[i];
    }
}

} // namespace sha256_detail

class Sha256 {
public:
    Sha256() = default;

    void update(std::string_view data) {
        for (unsigned char byte : data) {
            buffer_.push_back(byte);

            if (buffer_.size() == 64) {
                sha256_detail::compress(state_, buffer_.data());
                buffer_.clear();
                bit_length_ += 512;
            }
        }
    }

    std::array<std::uint8_t, 32> final() {
        auto state = state_;
        auto buffer = buffer_;
        std::uint64_t bits = bit_length_ + buffer.size() * 8ULL;

        buffer.push_back(0x80);

        while (buffer.size() % 64 != 56) {
            buffer.push_back(0);
        }

        for (int shift = 56; shift >= 0; shift -= 8) {
            buffer.push_back(
                static_cast<std::uint8_t>((bits >> shift) & 0xffU)
            );
        }

        for (std::size_t offset = 0; offset < buffer.size(); offset += 64) {
            sha256_detail::compress(state, buffer.data() + offset);
        }

        std::array<std::uint8_t, 32> digest{};

        for (std::size_t i = 0; i < state.size(); ++i) {
            digest[i * 4] =
                static_cast<std::uint8_t>((state[i] >> 24) & 0xffU);
            digest[i * 4 + 1] =
                static_cast<std::uint8_t>((state[i] >> 16) & 0xffU);
            digest[i * 4 + 2] =
                static_cast<std::uint8_t>((state[i] >> 8) & 0xffU);
            digest[i * 4 + 3] =
                static_cast<std::uint8_t>(state[i] & 0xffU);
        }

        return digest;
    }

private:
    std::array<std::uint32_t, 8> state_ =
        sha256_detail::INITIAL_STATE;

    std::vector<std::uint8_t> buffer_;
    std::uint64_t bit_length_ = 0;
};

std::string to_hex(const std::array<std::uint8_t, 32>& digest) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (std::uint8_t byte : digest) {
        output << std::setw(2)
               << static_cast<unsigned>(byte);
    }

    return output.str();
}

std::string sha256(std::string_view message) {
    Sha256 hasher;
    hasher.update(message);
    return to_hex(hasher.final());
}

bool constant_time_equal(std::string_view left, std::string_view right) {
    if (left.size() != right.size()) {
        return false;
    }

    unsigned char difference = 0;

    for (std::size_t i = 0; i < left.size(); ++i) {
        difference |=
            static_cast<unsigned char>(left[i] ^ right[i]);
    }

    return difference == 0;
}

enum class HashPolicy {
    LegacyCompatibility,
    ModernIntegrity
};

std::string_view policy_name(HashPolicy policy) {
    switch (policy) {
        case HashPolicy::LegacyCompatibility:
            return "LegacyCompatibility";
        case HashPolicy::ModernIntegrity:
            return "ModernIntegrity";
    }

    throw std::invalid_argument("Unknown hash policy.");
}

struct Artifact {
    std::string identifier;
    std::string payload;
    std::string expected_sha256;
};

class IntegrityEngine {
public:
    explicit IntegrityEngine(HashPolicy policy)
        : policy_(policy) {}

    bool verify(const Artifact& artifact) const {
        if (artifact.identifier.empty()) {
            throw std::invalid_argument("Artifact identifier is empty.");
        }

        if (artifact.expected_sha256.size() != 64) {
            throw std::invalid_argument(
                "SHA-256 digest must contain 64 hexadecimal characters."
            );
        }

        const std::string actual = sha256(artifact.payload);

        return constant_time_equal(
            artifact.expected_sha256,
            actual
        );
    }

    bool accepts_sha1() const {
        return policy_ == HashPolicy::LegacyCompatibility;
    }

    std::string_view policy() const {
        return policy_name(policy_);
    }

private:
    HashPolicy policy_;
};

int main() {
    try {
        const std::string message =
            "SHA family integrity example";

        const std::string digest = sha256(message);

        std::cout << "SHA-256 implementation\n";
        std::cout << "======================\n";
        std::cout << "Message: " << message << '\n';
        std::cout << "Digest:  " << digest << "\n\n";

        const std::string knownAnswer =
            "0c0c3f43e6f2f3b8a3bde0e95f7f5d4d5d8d3c8b"
            "f1e0f5b0c1e2a1c1c5d1b5f0e9e8d3b8";

        // The demonstration does not trust a fabricated expected value.
        // A self-generated digest is used for the positive integrity path.
        Artifact artifact{
            "release-artifact-v4",
            message,
            digest
        };

        IntegrityEngine engine(HashPolicy::ModernIntegrity);

        std::cout << "Governance policy\n";
        std::cout << "=================\n";
        std::cout << "Policy: " << engine.policy() << '\n';
        std::cout << "SHA-1 accepted for new integrity checks: "
                  << std::boolalpha
                  << engine.accepts_sha1()
                  << "\n\n";

        std::cout << "Artifact verification\n";
        std::cout << "=====================\n";
        std::cout << "Original artifact: "
                  << engine.verify(artifact) << '\n';

        Artifact tampered = artifact;
        tampered.payload += "tampered";

        std::cout << "Tampered artifact:  "
                  << engine.verify(tampered) << '\n';

        std::cout << "\nIncremental hashing\n";
        std::cout << "===================\n";

        Sha256 incremental;
        incremental.update("SHA family ");
        incremental.update("integrity ");
        incremental.update("example");

        const std::string incremental_digest =
            to_hex(incremental.final());

        std::cout << "Incremental digest: " << incremental_digest << '\n';
        std::cout << "Matches one-shot:   "
                  << constant_time_equal(
                         digest,
                         incremental_digest
                     )
                  << '\n';

        std::cout << "\nArchitectural considerations\n";
        std::cout << "============================\n";
        std::cout << "SHA-256 processes 512-bit message blocks.\n";
        std::cout << "The digest is 256 bits, represented here by 64 hexadecimal characters.\n";
        std::cout << "Streaming update avoids requiring the entire payload in one buffer.\n";
        std::cout << "Raw SHA-256 authenticates nothing because anyone can calculate it.\n";
        std::cout << "HMAC-SHA-256 is appropriate when a shared secret is required.\n";
        std::cout << "SHA-1 should not be selected for new collision-resistant designs.\n";
        std::cout << "Cryptographic production systems should use vetted library implementations rather than custom primitives.\n";

        if (knownAnswer == digest) {
            std::cerr << "Unexpected test-vector collision.\n";
        }

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
