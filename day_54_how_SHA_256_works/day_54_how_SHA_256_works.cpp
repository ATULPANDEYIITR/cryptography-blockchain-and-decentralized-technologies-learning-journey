#include <array>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

class SHA256 {
public:
    static constexpr std::size_t BlockSize = 64;
    static constexpr std::size_t DigestSize = 32;

    SHA256() {
        reset();
    }

    void update(const std::vector<std::uint8_t>& data) {
        for (std::uint8_t byte : data) {
            buffer_.push_back(byte);

            if (buffer_.size() == BlockSize) {
                compress(buffer_.data());
                totalBytes_ += BlockSize;
                buffer_.clear();
            }
        }
    }

    void update(const std::string& text) {
        update(std::vector<std::uint8_t>(text.begin(), text.end()));
    }

    std::array<std::uint8_t, DigestSize> final() {
        std::vector<std::uint8_t> tail = buffer_;

        const std::uint64_t totalBits =
            (totalBytes_ + tail.size()) * 8ULL;

        // Append the mandatory one bit followed by zero bits.
        tail.push_back(0x80);

        while ((tail.size() % BlockSize) != 56) {
            tail.push_back(0);
        }

        // SHA-256 uses a 64-bit big-endian message length.
        for (int shift = 56; shift >= 0; shift -= 8) {
            tail.push_back(
                static_cast<std::uint8_t>((totalBits >> shift) & 0xff)
            );
        }

        for (std::size_t offset = 0; offset < tail.size(); offset += BlockSize) {
            compress(tail.data() + offset);
        }

        std::array<std::uint8_t, DigestSize> digest{};

        for (std::size_t i = 0; i < state_.size(); ++i) {
            digest[i * 4] =
                static_cast<std::uint8_t>((state_[i] >> 24) & 0xff);
            digest[i * 4 + 1] =
                static_cast<std::uint8_t>((state_[i] >> 16) & 0xff);
            digest[i * 4 + 2] =
                static_cast<std::uint8_t>((state_[i] >> 8) & 0xff);
            digest[i * 4 + 3] =
                static_cast<std::uint8_t>(state_[i] & 0xff);
        }

        return digest;
    }

    void reset() {
        state_ = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        buffer_.clear();
        totalBytes_ = 0;
    }

    static std::string hex(const std::array<std::uint8_t, DigestSize>& digest) {
        std::ostringstream output;
        output << std::hex << std::setfill('0');

        for (std::uint8_t byte : digest) {
            output << std::setw(2) << static_cast<unsigned>(byte);
        }

        return output.str();
    }

    static std::string digest(const std::string& text) {
        SHA256 hasher;
        hasher.update(text);
        return hex(hasher.final());
    }

private:
    static constexpr std::array<std::uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x766a0abb,
        0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624,
        0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f,
        0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
        0xbef9a3f7, 0xc67178f2
    };

    std::array<std::uint32_t, 8> state_{};
    std::vector<std::uint8_t> buffer_;
    std::uint64_t totalBytes_ = 0;

    static std::uint32_t rotr(std::uint32_t x, unsigned n) {
        return (x >> n) | (x << (32 - n));
    }

    static std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static std::uint32_t bigSigma0(std::uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static std::uint32_t bigSigma1(std::uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    static std::uint32_t smallSigma0(std::uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static std::uint32_t smallSigma1(std::uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    static std::uint32_t readBigEndian(const std::uint8_t* data) {
        return (static_cast<std::uint32_t>(data[0]) << 24)
             | (static_cast<std::uint32_t>(data[1]) << 16)
             | (static_cast<std::uint32_t>(data[2]) << 8)
             | static_cast<std::uint32_t>(data[3]);
    }

    void compress(const std::uint8_t* block) {
        std::array<std::uint32_t, 64> w{};

        for (std::size_t i = 0; i < 16; ++i) {
            w[i] = readBigEndian(block + i * 4);
        }

        for (std::size_t i = 16; i < 64; ++i) {
            w[i] = smallSigma1(w[i - 2])
                 + w[i - 7]
                 + smallSigma0(w[i - 15])
                 + w[i - 16];
        }

        auto working = state_;

        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t temp1 =
                working[7]
                + bigSigma1(working[4])
                + ch(working[4], working[5], working[6])
                + K[i]
                + w[i];

            const std::uint32_t temp2 =
                bigSigma0(working[0])
                + maj(working[0], working[1], working[2]);

            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3] + temp1;
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1 + temp2;
        }

        for (std::size_t i = 0; i < 8; ++i) {
            state_[i] += working[i];
        }
    }
};

constexpr std::array<std::uint32_t, 64> SHA256::K;

std::size_t hammingDistance(
    const std::array<std::uint8_t, SHA256::DigestSize>& a,
    const std::array<std::uint8_t, SHA256::DigestSize>& b
) {
    std::size_t distance = 0;

    for (std::size_t i = 0; i < a.size(); ++i) {
        std::uint8_t value = a[i] ^ b[i];

        while (value != 0) {
            value &= static_cast<std::uint8_t>(value - 1);
            ++distance;
        }
    }

    return distance;
}

void knownAnswerTests() {
    struct Vector {
        std::string input;
        std::string expected;
    };

    const std::vector<Vector> vectors = {
        {
            "",
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        },
        {
            "abc",
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad"
        },
        {
            "The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f"
            "8d5651e46d3cdb762d02d0bf37c9e592"
        }
    };

    for (const auto& vector : vectors) {
        const std::string actual = SHA256::digest(vector.input);
        assert(actual == vector.expected);
    }

    std::cout << "Known-answer tests: PASS\n";
}

void avalancheExperiment(const std::string& text) {
    if (text.empty()) {
        throw std::invalid_argument("Avalanche input cannot be empty");
    }

    std::string modified = text;
    modified[0] ^= 0x01;

    SHA256 first;
    first.update(text);

    SHA256 second;
    second.update(modified);

    const auto firstDigest = first.final();
    const auto secondDigest = second.final();

    std::cout << "\nAvalanche experiment\n";
    std::cout << "Original:        " << text << '\n';
    std::cout << "Modified first byte by one bit\n";
    std::cout << "Original digest: " << SHA256::hex(firstDigest) << '\n';
    std::cout << "Modified digest: " << SHA256::hex(secondDigest) << '\n';
    std::cout << "Differing bits:  "
              << hammingDistance(firstDigest, secondDigest)
              << " / 256\n";
}

int main() {
    try {
        knownAnswerTests();

        std::cout << "\nDigest demonstration\n";
        std::cout << "Input: Hello, SHA-256!\n";
        std::cout << "SHA-256: "
                  << SHA256::digest("Hello, SHA-256!")
                  << '\n';

        avalancheExperiment("security");

        std::cout << "\nEngineering characteristics\n";
        std::cout << "- Input is divided into 512-bit blocks.\n";
        std::cout << "- Each block expands into 64 32-bit schedule words.\n";
        std::cout << "- Every block executes 64 compression rounds.\n";
        std::cout << "- The final digest contains eight 32-bit words.\n";
        std::cout << "- Arithmetic intentionally wraps modulo 2^32.\n";
        std::cout << "- SHA-256 is a hash function, not encryption.\n";
        std::cout << "- Passwords should use a dedicated password-hashing scheme.\n";
    }
    catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
