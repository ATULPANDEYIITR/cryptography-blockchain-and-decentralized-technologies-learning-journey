#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Hash Functions Practice Project - C++17
 *
 * Implements SHA-256 and HMAC-SHA256 without external libraries.
 *
 * This implementation is intended for studying hash mechanics.
 * Production applications should use a maintained cryptographic library.
 *
 * Run:
 *   ./hash_lab_cpp
 *   ./hash_lab_cpp --file artifact.bin
 *   ./hash_lab_cpp --hmac secret-key "release manifest"
 */

class Sha256 {
public:
    using Digest = std::array<std::uint8_t, 32>;

    Sha256() {
        reset();
    }

    void reset() {
        state_ = {
            0x6a09e667U,
            0xbb67ae85U,
            0x3c6ef372U,
            0xa54ff53aU,
            0x510e527fU,
            0x9b05688cU,
            0x1f83d9abU,
            0x5be0cd19U
        };

        buffer_.fill(0);
        bufferLength_ = 0;
        totalBytes_ = 0;
        finished_ = false;
        cachedDigest_.fill(0);
    }

    void update(const std::uint8_t* data, std::size_t length) {
        if (finished_) {
            throw std::logic_error("Cannot update a finalized SHA-256 context");
        }

        if (length > 0 && data == nullptr) {
            throw std::invalid_argument("Input pointer cannot be null");
        }

        const std::uint64_t maximumBytes =
            std::numeric_limits<std::uint64_t>::max() / 8U;

        if (length > maximumBytes - totalBytes_) {
            throw std::length_error("SHA-256 input exceeds the supported length");
        }

        totalBytes_ += static_cast<std::uint64_t>(length);

        while (length > 0) {
            const std::size_t available = 64U - bufferLength_;
            const std::size_t amount = std::min(available, length);

            std::memcpy(
                buffer_.data() + bufferLength_,
                data,
                amount
            );

            bufferLength_ += amount;
            data += amount;
            length -= amount;

            if (bufferLength_ == 64U) {
                transform(buffer_.data());
                bufferLength_ = 0;
            }
        }
    }

    void update(const std::string& text) {
        update(
            reinterpret_cast<const std::uint8_t*>(text.data()),
            text.size()
        );
    }

    Digest finish() {
        if (finished_) {
            return cachedDigest_;
        }

        const std::uint64_t bitLength = totalBytes_ * 8U;

        buffer_[bufferLength_++] = 0x80U;

        if (bufferLength_ > 56U) {
            while (bufferLength_ < 64U) {
                buffer_[bufferLength_++] = 0U;
            }

            transform(buffer_.data());
            bufferLength_ = 0;
        }

        while (bufferLength_ < 56U) {
            buffer_[bufferLength_++] = 0U;
        }

        for (int shift = 56; shift >= 0; shift -= 8) {
            buffer_[bufferLength_++] =
                static_cast<std::uint8_t>((bitLength >> shift) & 0xffU);
        }

        transform(buffer_.data());

        for (std::size_t i = 0; i < state_.size(); ++i) {
            cachedDigest_[i * 4] =
                static_cast<std::uint8_t>(state_[i] >> 24);

            cachedDigest_[i * 4 + 1] =
                static_cast<std::uint8_t>(state_[i] >> 16);

            cachedDigest_[i * 4 + 2] =
                static_cast<std::uint8_t>(state_[i] >> 8);

            cachedDigest_[i * 4 + 3] =
                static_cast<std::uint8_t>(state_[i]);
        }

        finished_ = true;
        return cachedDigest_;
    }

    static Digest hash(const std::string& text) {
        Sha256 context;
        context.update(text);
        return context.finish();
    }

private:
    static constexpr std::array<std::uint32_t, 64> K = {
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

    static std::uint32_t rotateRight(std::uint32_t value, unsigned int count) {
        return (value >> count) | (value << (32U - count));
    }

    static std::uint32_t choose(
        std::uint32_t x,
        std::uint32_t y,
        std::uint32_t z
    ) {
        return (x & y) ^ (~x & z);
    }

    static std::uint32_t majority(
        std::uint32_t x,
        std::uint32_t y,
        std::uint32_t z
    ) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    void transform(const std::uint8_t* block) {
        std::array<std::uint32_t, 64> words{};

        for (std::size_t i = 0; i < 16; ++i) {
            const std::size_t offset = i * 4;

            words[i] =
                (static_cast<std::uint32_t>(block[offset]) << 24) |
                (static_cast<std::uint32_t>(block[offset + 1]) << 16) |
                (static_cast<std::uint32_t>(block[offset + 2]) << 8) |
                static_cast<std::uint32_t>(block[offset + 3]);
        }

        for (std::size_t i = 16; i < 64; ++i) {
            const std::uint32_t s0 =
                rotateRight(words[i - 15], 7) ^
                rotateRight(words[i - 15], 18) ^
                (words[i - 15] >> 3);

            const std::uint32_t s1 =
                rotateRight(words[i - 2], 17) ^
                rotateRight(words[i - 2], 19) ^
                (words[i - 2] >> 10);

            words[i] =
                words[i - 16] + s0 + words[i - 7] + s1;
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
            const std::uint32_t sum1 =
                rotateRight(e, 6) ^
                rotateRight(e, 11) ^
                rotateRight(e, 25);

            const std::uint32_t temp1 =
                h + sum1 + choose(e, f, g) + K[i] + words[i];

            const std::uint32_t sum0 =
                rotateRight(a, 2) ^
                rotateRight(a, 13) ^
                rotateRight(a, 22);

            const std::uint32_t temp2 =
                sum0 + majority(a, b, c);

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

    std::array<std::uint32_t, 8> state_{};
    std::array<std::uint8_t, 64> buffer_{};
    std::size_t bufferLength_ = 0;
    std::uint64_t totalBytes_ = 0;
    bool finished_ = false;
    Digest cachedDigest_{};
};

std::string toHex(const Sha256::Digest& digest) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (std::uint8_t value : digest) {
        output << std::setw(2) << static_cast<unsigned int>(value);
    }

    return output.str();
}

Sha256::Digest sha256(const std::string& text) {
    return Sha256::hash(text);
}

Sha256::Digest hmacSha256(
    const std::vector<std::uint8_t>& originalKey,
    const std::string& message
) {
    constexpr std::size_t BLOCK_SIZE = 64;

    std::vector<std::uint8_t> key = originalKey;

    if (key.empty()) {
        throw std::invalid_argument("HMAC key cannot be empty");
    }

    if (key.size() > BLOCK_SIZE) {
        Sha256 keyHasher;
        keyHasher.update(key.data(), key.size());

        const auto keyDigest = keyHasher.finish();
        key.assign(keyDigest.begin(), keyDigest.end());
    }

    std::array<std::uint8_t, BLOCK_SIZE> innerPad{};
    std::array<std::uint8_t, BLOCK_SIZE> outerPad{};

    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        const std::uint8_t keyByte =
            i < key.size() ? key[i] : static_cast<std::uint8_t>(0);

        innerPad[i] = keyByte ^ 0x36U;
        outerPad[i] = keyByte ^ 0x5cU;
    }

    Sha256 inner;
    inner.update(innerPad.data(), innerPad.size());
    inner.update(message);

    const auto innerDigest = inner.finish();

    Sha256 outer;
    outer.update(outerPad.data(), outerPad.size());
    outer.update(innerDigest.data(), innerDigest.size());

    return outer.finish();
}

std::string hmacHex(
    const std::string& key,
    const std::string& message
) {
    std::vector<std::uint8_t> keyBytes(
        key.begin(),
        key.end()
    );

    return toHex(hmacSha256(keyBytes, message));
}

bool constantTimeEqual(
    const std::string& left,
    const std::string& right
) {
    const std::size_t maximumLength =
        std::max(left.size(), right.size());

    volatile unsigned int difference =
        static_cast<unsigned int>(left.size() ^ right.size());

    for (std::size_t i = 0; i < maximumLength; ++i) {
        const unsigned char a =
            i < left.size()
                ? static_cast<unsigned char>(left[i])
                : 0U;

        const unsigned char b =
            i < right.size()
                ? static_cast<unsigned char>(right[i])
                : 0U;

        difference |= static_cast<unsigned int>(a ^ b);
    }

    return difference == 0U;
}

std::string hashFile(const std::string& filePath) {
    std::ifstream input(filePath, std::ios::binary);

    if (!input.is_open()) {
        throw std::runtime_error("Unable to open file: " + filePath);
    }

    Sha256 hasher;
    std::array<char, 8192> buffer{};

    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));

        const std::streamsize count = input.gcount();

        if (count > 0) {
            hasher.update(
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                static_cast<std::size_t>(count)
            );
        }
    }

    if (!input.eof()) {
        throw std::runtime_error("Error while reading file: " + filePath);
    }

    return toHex(hasher.finish());
}

void runSelfTests() {
    const std::string expectedEmpty =
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855";

    const std::string expectedAbc =
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad";

    if (toHex(sha256("")) != expectedEmpty) {
        throw std::runtime_error("SHA-256 empty-input test failed");
    }

    if (toHex(sha256("abc")) != expectedAbc) {
        throw std::runtime_error("SHA-256 abc test failed");
    }

    const std::vector<std::uint8_t> testKey(20, 0x0b);

    const std::string expectedHmac =
        "b0344c61d8db38535ca8afceaf0bf12b"
        "881dc200c9833da726e9376c2e32cff7";

    const std::string actualHmac =
        toHex(hmacSha256(testKey, "Hi There"));

    if (actualHmac != expectedHmac) {
        throw std::runtime_error("HMAC-SHA256 test failed");
    }
}

void runDemo() {
    runSelfTests();

    std::cout << "Hash Functions Practice Project\n";
    std::cout << "================================\n";

    const std::string releaseManifest =
        "release=2.4.0;component=payment-service";

    const std::string originalDigest =
        toHex(sha256(releaseManifest));

    const std::string modifiedManifest =
        releaseManifest + ";status=modified";

    const std::string modifiedDigest =
        toHex(sha256(modifiedManifest));

    std::cout << "\nRelease integrity example:\n";
    std::cout << "Original SHA-256: " << originalDigest << '\n';
    std::cout << "Modified SHA-256: " << modifiedDigest << '\n';

    std::cout << "Original verification: "
              << (constantTimeEqual(originalDigest, originalDigest)
                      ? "PASS"
                      : "FAIL")
              << '\n';

    std::cout << "Modified verification: "
              << (constantTimeEqual(originalDigest, modifiedDigest)
                      ? "PASS"
                      : "FAIL")
              << '\n';

    std::cout << "\nHMAC-SHA256 example:\n";

    const std::string secret = "demo-key-replace-in-production";
    const std::string signature =
        hmacHex(secret, releaseManifest);

    const std::string validSignature =
        hmacHex(secret, releaseManifest);

    const std::string invalidSignature =
        hmacHex(secret, modifiedManifest);

    std::cout << "Signature: " << signature << '\n';

    std::cout << "Original message authenticated: "
              << (constantTimeEqual(signature, validSignature)
                      ? "YES"
                      : "NO")
              << '\n';

    std::cout << "Modified message authenticated: "
              << (constantTimeEqual(signature, invalidSignature)
                      ? "YES"
                      : "NO")
              << '\n';

    std::cout << "\nAll known-answer tests passed.\n";
}

int main(int argc, char* argv[]) {
    try {
        if (argc == 1) {
            runDemo();
            return 0;
        }

        const std::string command = argv[1];

        if (command == "--file" && argc == 3) {
            const std::string result = hashFile(argv[2]);

            std::cout << "Algorithm: SHA-256\n";
            std::cout << "File: " << argv[2] << '\n';
            std::cout << "Digest: " << result << '\n';

            return 0;
        }

        if (command == "--hmac" && argc == 4) {
            const std::string result =
                hmacHex(argv[2], argv[3]);

            std::cout << "Algorithm: HMAC-SHA256\n";
            std::cout << "Signature: " << result << '\n';

            return 0;
        }

        std::cerr
            << "Usage:\n"
            << "  hash_lab_cpp\n"
            << "  hash_lab_cpp --file <path>\n"
            << "  hash_lab_cpp --hmac <key> <message>\n";

        return 2;

    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
