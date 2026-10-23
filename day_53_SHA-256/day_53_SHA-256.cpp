#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

class SHA256 {
public:
    SHA256() {
        reset();
    }

    void update(const std::string& input) {
        update(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    }

    void update(const std::vector<std::uint8_t>& input) {
        update(input.data(), input.size());
    }

    void update(const std::uint8_t* data, std::size_t length) {
        if (finalized_) {
            throw std::logic_error("Cannot update a finalized SHA-256 object.");
        }

        totalBytes_ += length;

        while (length > 0) {
            const std::size_t available = 64 - bufferSize_;
            const std::size_t take = std::min(available, length);

            std::copy_n(data, take, buffer_.begin() + bufferSize_);

            bufferSize_ += take;
            data += take;
            length -= take;

            if (bufferSize_ == 64) {
                transform(buffer_);
                bufferSize_ = 0;
            }
        }
    }

    std::array<std::uint8_t, 32> finalize() {
        if (finalized_) {
            return digest_;
        }

        const std::uint64_t bitLength = totalBytes_ * 8ULL;

        buffer_[bufferSize_++] = 0x80;

        if (bufferSize_ > 56) {
            while (bufferSize_ < 64) {
                buffer_[bufferSize_++] = 0;
            }

            transform(buffer_);
            bufferSize_ = 0;
        }

        while (bufferSize_ < 56) {
            buffer_[bufferSize_++] = 0;
        }

        for (int i = 7; i >= 0; --i) {
            buffer_[bufferSize_++] =
                static_cast<std::uint8_t>((bitLength >> (i * 8)) & 0xff);
        }

        transform(buffer_);

        for (std::size_t i = 0; i < state_.size(); ++i) {
            digest_[i * 4]     = static_cast<std::uint8_t>(state_[i] >> 24);
            digest_[i * 4 + 1] = static_cast<std::uint8_t>(state_[i] >> 16);
            digest_[i * 4 + 2] = static_cast<std::uint8_t>(state_[i] >> 8);
            digest_[i * 4 + 3] = static_cast<std::uint8_t>(state_[i]);
        }

        finalized_ = true;
        return digest_;
    }

    static std::string toHex(const std::array<std::uint8_t, 32>& digest) {
        std::ostringstream output;

        for (std::uint8_t byte : digest) {
            output << std::hex << std::setw(2) << std::setfill('0')
                   << static_cast<unsigned int>(byte);
        }

        return output.str();
    }

private:
    static constexpr std::array<std::uint32_t, 8> INITIAL = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    static constexpr std::array<std::uint32_t, 64> K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x27b70a85, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bc5b,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::array<std::uint8_t, 32> digest_{};
    std::size_t bufferSize_ = 0;
    std::uint64_t totalBytes_ = 0;
    bool finalized_ = false;

    static std::uint32_t rotr(std::uint32_t x, unsigned n) {
        return (x >> n) | (x << (32 - n));
    }

    static std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static std::uint32_t sigma0(std::uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }

    static std::uint32_t sigma1(std::uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    static std::uint32_t Sigma0(std::uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    static std::uint32_t Sigma1(std::uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    void reset() {
        state_ = INITIAL;
        buffer_.fill(0);
        digest_.fill(0);
        bufferSize_ = 0;
        totalBytes_ = 0;
        finalized_ = false;
    }

    void transform(const std::array<std::uint8_t, 64>& block) {
        std::array<std::uint32_t, 64> w{};

        for (std::size_t i = 0; i < 16; ++i) {
            w[i] =
                (static_cast<std::uint32_t>(block[i * 4]) << 24) |
                (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<std::uint32_t>(block[i * 4 + 3]);
        }

        for (std::size_t i = 16; i < 64; ++i) {
            w[i] = sigma1(w[i - 2]) + w[i - 7] +
                   sigma0(w[i - 15]) + w[i - 16];
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
            const std::uint32_t t1 =
                h + Sigma1(e) + ch(e, f, g) + K[i] + w[i];

            const std::uint32_t t2 =
                Sigma0(a) + maj(a, b, c);

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
};

std::string hashString(const std::string& value) {
    SHA256 sha;
    sha.update(value);
    return SHA256::toHex(sha.finalize());
}

bool verify(const std::string& value, const std::string& expected) {
    const std::string actual = hashString(value);

    if (actual.size() != expected.size()) {
        return false;
    }

    // Constant-time comparison avoids an early mismatch return.
    std::uint8_t difference = 0;

    for (std::size_t i = 0; i < actual.size(); ++i) {
        difference |= static_cast<std::uint8_t>(actual[i] ^ expected[i]);
    }

    return difference == 0;
}

void runKnownVectors() {
    const std::vector<std::pair<std::string, std::string>> vectors = {
        {
            "",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        {
            "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        },
        {
            "hello world",
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        }
    };

    for (const auto& [input, expected] : vectors) {
        const auto actual = hashString(input);

        if (actual != expected) {
            throw std::runtime_error("Known SHA-256 vector failed.");
        }
    }

    std::cout << "Known SHA-256 vectors: PASS\n";
}

int main() {
    try {
        runKnownVectors();

        const std::vector<std::string> examples = {
            "repository artifact",
            "SHA-256 is deterministic",
            "integrity verification"
        };

        for (const auto& value : examples) {
            const std::string digest = hashString(value);

            std::cout << "\nInput: " << value << '\n';
            std::cout << "SHA-256: " << digest << '\n';
            std::cout << "Verification: " << std::boolalpha
                      << verify(value, digest) << '\n';
        }

        std::cout << "\nStreaming behavior:\n";

        SHA256 streaming;
        streaming.update("SHA-");
        streaming.update("256 ");
        streaming.update("streaming ");
        streaming.update("input");

        std::cout << "Digest: "
                  << SHA256::toHex(streaming.finalize())
                  << '\n';

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "SHA-256 workflow failed: "
                  << error.what() << '\n';
        return 1;
    }
}
