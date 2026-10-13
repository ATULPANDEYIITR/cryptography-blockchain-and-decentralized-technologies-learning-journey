#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/*
 * Repository-independent technical case study:
 * A secure record transport service uses CTR stream encryption to protect
 * binary inspection records before transfer between two services.
 *
 * The standard library does not implement AES. This program therefore
 * models the CTR mechanics with a deterministic educational block primitive.
 * It is NOT cryptographically secure and must never protect real data.
 *
 * The purpose is to make counter allocation, keystream alignment, random
 * access, counter exhaustion, and the operational consequences of nonce
 * reuse explicit. Production software must replace EducationalBlockCipher
 * with a vetted AES implementation and an authenticated-encryption design.
 */

constexpr std::size_t BLOCK_SIZE = 16;
constexpr std::uint64_t COUNTER_LIMIT = 256;

using Block = std::array<std::uint8_t, BLOCK_SIZE>;
using Bytes = std::vector<std::uint8_t>;

std::string toHex(const Bytes& bytes) {
    std::string result;
    const char* digits = "0123456789abcdef";

    for (std::uint8_t value : bytes) {
        result.push_back(digits[value >> 4]);
        result.push_back(digits[value & 0x0f]);
    }

    return result;
}

Bytes fromString(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

std::string toString(const Bytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

Block makeCounter(std::uint64_t value) {
    Block block{};

    // Store the educational counter in the last byte. The restricted
    // eight-bit counter is intentional so exhaustion can be demonstrated.
    if (value >= COUNTER_LIMIT) {
        throw std::overflow_error("Educational counter is exhausted.");
    }

    block[BLOCK_SIZE - 1] = static_cast<std::uint8_t>(value);
    return block;
}

std::uint64_t readCounter(const Block& block) {
    for (std::size_t i = 0; i < BLOCK_SIZE - 1; ++i) {
        if (block[i] != 0) {
            throw std::invalid_argument(
                "This case study supports only an eight-bit counter field."
            );
        }
    }
    return block.back();
}

class EducationalBlockCipher {
public:
    explicit EducationalBlockCipher(std::uint32_t key) : key_(key) {}

    Block encryptBlock(const Block& input) const {
        // A reversible-looking demonstration mapping is not a secure
        // pseudorandom permutation. Never substitute it for AES.
        Block output{};
        std::uint32_t state = key_ ^ 0x9e3779b9U;

        for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
            state ^= static_cast<std::uint32_t>(input[i]) + 0x7f4a7c15U;
            state = (state << 7) | (state >> 25);
            state *= 0x85ebca6bU;
            output[i] = static_cast<std::uint8_t>(
                (state >> ((i % 4) * 8)) & 0xffU
            );
            state ^= state >> 13;
        }

        return output;
    }

private:
    std::uint32_t key_;
};

class EducationalCTR {
public:
    EducationalCTR(std::uint32_t key, std::uint64_t initialCounter)
        : primitive_(key), initialCounter_(initialCounter) {
        if (initialCounter >= COUNTER_LIMIT) {
            throw std::invalid_argument("Initial counter is out of range.");
        }
    }

    Bytes transformAt(const Bytes& input, std::size_t offset = 0) const {
        if (input.empty()) return {};

        const std::size_t firstBlock = offset / BLOCK_SIZE;
        const std::size_t intraBlock = offset % BLOCK_SIZE;
        const std::size_t blockCount =
            (intraBlock + input.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;

        if (initialCounter_ + firstBlock + blockCount > COUNTER_LIMIT) {
            throw std::overflow_error("CTR request exceeds counter space.");
        }

        Bytes output;
        output.reserve(input.size());

        std::size_t consumed = 0;
        std::uint64_t counter = initialCounter_ + firstBlock;
        std::size_t skip = intraBlock;

        while (consumed < input.size()) {
            const Block counterBlock = makeCounter(counter);
            const Block stream = primitive_.encryptBlock(counterBlock);

            for (std::size_t j = skip;
                 j < BLOCK_SIZE && consumed < input.size();
                 ++j, ++consumed) {
                output.push_back(input[consumed] ^ stream[j]);
            }

            skip = 0;
            ++counter;
        }

        return output;
    }

    Bytes encrypt(const Bytes& plaintext) const {
        return transformAt(plaintext);
    }

    Bytes decrypt(const Bytes& ciphertext) const {
        return transformAt(ciphertext);
    }

private:
    EducationalBlockCipher primitive_;
    std::uint64_t initialCounter_;
};

class NonceAllocationService {
public:
    void reserve(std::uint32_t keyId, const std::string& nonce) {
        if (nonce.empty()) {
            throw std::invalid_argument("Nonce cannot be empty.");
        }

        auto& nonces = allocated_[keyId];
        if (!nonces.insert(nonce).second) {
            throw std::runtime_error("Nonce reuse detected for key ID.");
        }
    }

private:
    std::map<std::uint32_t, std::set<std::string>> allocated_;
};

struct TransferRecord {
    std::string recordId;
    std::string classification;
    Bytes payload;
};

class RecordTransport {
public:
    explicit RecordTransport(std::uint32_t key)
        : cipher_(key, 10), keyId_(key) {}

    Bytes protect(const TransferRecord& record) {
        if (record.recordId.empty()) {
            throw std::invalid_argument("Record ID is required.");
        }
        if (record.payload.empty()) {
            throw std::invalid_argument("Record payload cannot be empty.");
        }

        // The record metadata identifies the transfer. It is not
        // cryptographically authenticated by this educational CTR model.
        const std::string nonce = "session-42-counter-10";
        nonces_.reserve(keyId_, nonce);
        return cipher_.encrypt(record.payload);
    }

    Bytes recover(const Bytes& ciphertext) const {
        return cipher_.decrypt(ciphertext);
    }

private:
    EducationalCTR cipher_;
    std::uint32_t keyId_;
    NonceAllocationService nonces_;
};

void demonstrateStreamProperties() {
    std::cout << "\nCTR stream properties\n";

    EducationalCTR cipher(0x12345678U, 20);
    const Bytes message = fromString(
        "Pump station inspection: vibration threshold exceeded."
    );

    const Bytes ciphertext = cipher.encrypt(message);
    const Bytes recovered = cipher.decrypt(ciphertext);

    if (recovered != message) {
        throw std::runtime_error("CTR round trip failed.");
    }

    const std::size_t offset = 7;
    Bytes segment(ciphertext.begin() + offset, ciphertext.begin() + 22);
    const Bytes restoredSegment = cipher.decrypt(segment, offset);
    Bytes expected(message.begin() + offset, message.begin() + 22);

    if (restoredSegment != expected) {
        throw std::runtime_error("Random-access transformation failed.");
    }

    std::cout << "Ciphertext: " << toHex(ciphertext) << '\n';
    std::cout << "Recovered: " << toString(recovered) << '\n';
    std::cout << "Random-access segment: "
              << toString(restoredSegment) << '\n';
}

void demonstrateCounterExhaustion() {
    std::cout << "\nCounter exhaustion\n";

    try {
        EducationalCTR cipher(7, 255);
        cipher.encrypt(Bytes(17, 0x41));
        throw std::runtime_error("Expected counter exhaustion.");
    } catch (const std::overflow_error& error) {
        std::cout << "Request rejected: " << error.what() << '\n';
    }
}

void demonstrateNonceAllocation() {
    std::cout << "\nNonce allocation\n";

    NonceAllocationService allocator;
    allocator.reserve(17, "unique-session-nonce");

    try {
        allocator.reserve(17, "unique-session-nonce");
    } catch (const std::runtime_error& error) {
        std::cout << "Duplicate rejected: " << error.what() << '\n';
    }

    // Reusing the same nonce under a different key ID is permitted by
    // this registry. A production system must make key identity reliable.
    allocator.reserve(18, "unique-session-nonce");
    std::cout << "Different key ID accepted the nonce.\n";
}

void demonstrateRecordTransport() {
    std::cout << "\nInspection record transport\n";

    RecordTransport transport(91);
    TransferRecord record{
        "INS-2026-0008",
        "internal",
        fromString("Bearing temperature: 84 C")
    };

    const Bytes encrypted = transport.protect(record);
    const Bytes recovered = transport.recover(encrypted);

    std::cout << "Record: " << record.recordId << '\n';
    std::cout << "Encrypted bytes: " << encrypted.size() << '\n';
    std::cout << "Recovered payload: " << toString(recovered) << '\n';
}

int main() {
    try {
        demonstrateStreamProperties();
        demonstrateCounterExhaustion();
        demonstrateNonceAllocation();
        demonstrateRecordTransport();

        std::cout << "\nAll educational case-study checks passed.\n";
        std::cout
            << "Production systems require real AES and authenticated encryption.\n";
    } catch (const std::exception& error) {
        std::cerr << "Case-study failure: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
