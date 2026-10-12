#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Repository Governance Encryption Case Study
 *
 * The program models a repository-policy service that stores fixed-size
 * sensitive configuration records. It implements ECB and CBC mechanics with
 * a small educational Feistel block cipher so that the mode behavior is
 * inspectable without third-party cryptographic libraries.
 *
 * The cipher is NOT cryptographically secure.
 *
 * The technical focus is the distinction between:
 *   ECB: C_i = E_K(P_i)
 *   CBC: C_i = E_K(P_i XOR C_(i-1))
 *
 * Real systems should use a vetted cryptographic library and an authenticated
 * encryption mode such as AES-GCM or ChaCha20-Poly1305.
 */

constexpr std::size_t BLOCK_SIZE = 8;
constexpr std::uint32_t WORD_MASK = 0xFFFFFFFFu;

using Block = std::array<std::uint8_t, BLOCK_SIZE>;

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message)
        : std::runtime_error(message) {}
};

Block xorBlock(const Block& a, const Block& b) {
    Block result{};

    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        result[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }

    return result;
}

std::uint32_t readWord(const std::uint8_t* bytes) {
    return (static_cast<std::uint32_t>(bytes[0]) << 24)
         | (static_cast<std::uint32_t>(bytes[1]) << 16)
         | (static_cast<std::uint32_t>(bytes[2]) << 8)
         | static_cast<std::uint32_t>(bytes[3]);
}

void writeWord(std::uint32_t value, std::uint8_t* bytes) {
    bytes[0] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
    bytes[1] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    bytes[2] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    bytes[3] = static_cast<std::uint8_t>(value & 0xFF);
}

class EducationalFeistel {
private:
    std::array<std::uint8_t, 16> key_;

    std::uint32_t roundKey(std::uint32_t round) const {
        std::uint32_t value = 0x9E3779B9u ^ round;

        for (std::uint8_t byte : key_) {
            value ^= byte;
            value = (value * 0x45D9F3Bu) & WORD_MASK;
            value ^= value >> 16;
        }

        return value;
    }

    std::uint32_t roundFunction(
        std::uint32_t right,
        std::uint32_t round
    ) const {
        std::uint32_t value = right + roundKey(round);
        value ^= value << 7;
        value ^= value >> 9;
        value *= 0x45D9F3Bu;
        value ^= value >> 16;
        return value;
    }

public:
    explicit EducationalFeistel(const std::array<std::uint8_t, 16>& key)
        : key_(key) {}

    Block encrypt(const Block& input) const {
        std::uint32_t left = readWord(input.data());
        std::uint32_t right = readWord(input.data() + 4);

        for (std::uint32_t round = 0; round < 8; ++round) {
            const std::uint32_t nextLeft = right;
            const std::uint32_t nextRight =
                left ^ roundFunction(right, round);

            left = nextLeft;
            right = nextRight;
        }

        Block output{};
        writeWord(left, output.data());
        writeWord(right, output.data() + 4);
        return output;
    }

    Block decrypt(const Block& input) const {
        std::uint32_t left = readWord(input.data());
        std::uint32_t right = readWord(input.data() + 4);

        for (int round = 7; round >= 0; --round) {
            const std::uint32_t previousRight = left;
            const std::uint32_t previousLeft =
                right ^ roundFunction(left, static_cast<std::uint32_t>(round));

            left = previousLeft;
            right = previousRight;
        }

        Block output{};
        writeWord(left, output.data());
        writeWord(right, output.data() + 4);
        return output;
    }
};

std::vector<Block> padAndSplit(const std::string& text) {
    std::vector<std::uint8_t> bytes(text.begin(), text.end());

    std::size_t padding = BLOCK_SIZE - (bytes.size() % BLOCK_SIZE);

    if (padding == 0) {
        padding = BLOCK_SIZE;
    }

    bytes.insert(bytes.end(), padding, static_cast<std::uint8_t>(padding));

    std::vector<Block> blocks;

    for (std::size_t offset = 0; offset < bytes.size(); offset += BLOCK_SIZE) {
        Block block{};

        std::copy_n(
            bytes.begin() + static_cast<std::ptrdiff_t>(offset),
            BLOCK_SIZE,
            block.begin()
        );

        blocks.push_back(block);
    }

    return blocks;
}

std::string removePadding(const std::vector<Block>& blocks) {
    std::vector<std::uint8_t> bytes;

    for (const auto& block : blocks) {
        bytes.insert(bytes.end(), block.begin(), block.end());
    }

    if (bytes.empty()) {
        throw CryptoError("No plaintext blocks");
    }

    const std::uint8_t padding = bytes.back();

    if (padding == 0 || padding > BLOCK_SIZE || padding > bytes.size()) {
        throw CryptoError("Invalid padding");
    }

    for (std::size_t i = 0; i < padding; ++i) {
        if (bytes[bytes.size() - 1 - i] != padding) {
            throw CryptoError("Invalid padding bytes");
        }
    }

    bytes.resize(bytes.size() - padding);

    return std::string(bytes.begin(), bytes.end());
}

std::vector<Block> encryptECB(
    const EducationalFeistel& cipher,
    const std::string& plaintext
) {
    const auto blocks = padAndSplit(plaintext);
    std::vector<Block> ciphertext;

    ciphertext.reserve(blocks.size());

    for (const Block& block : blocks) {
        ciphertext.push_back(cipher.encrypt(block));
    }

    return ciphertext;
}

std::vector<Block> decryptECB(
    const EducationalFeistel& cipher,
    const std::vector<Block>& ciphertext
) {
    std::vector<Block> plaintext;

    for (const Block& block : ciphertext) {
        plaintext.push_back(cipher.decrypt(block));
    }

    return plaintext;
}

std::vector<Block> encryptCBC(
    const EducationalFeistel& cipher,
    const std::string& plaintext,
    const Block& iv
) {
    const auto blocks = padAndSplit(plaintext);
    std::vector<Block> ciphertext;

    Block previous = iv;

    for (const Block& plaintextBlock : blocks) {
        Block mixed = xorBlock(plaintextBlock, previous);
        Block encrypted = cipher.encrypt(mixed);

        ciphertext.push_back(encrypted);
        previous = encrypted;
    }

    return ciphertext;
}

std::vector<Block> decryptCBC(
    const EducationalFeistel& cipher,
    const std::vector<Block>& ciphertext,
    const Block& iv
) {
    std::vector<Block> plaintext;

    Block previous = iv;

    for (const Block& ciphertextBlock : ciphertext) {
        Block decrypted = cipher.decrypt(ciphertextBlock);
        Block recovered = xorBlock(decrypted, previous);

        plaintext.push_back(recovered);
        previous = ciphertextBlock;
    }

    return plaintext;
}

std::string blockHex(const Block& block) {
    std::ostringstream output;

    output << std::hex << std::setfill('0');

    for (std::uint8_t byte : block) {
        output << std::setw(2)
               << static_cast<unsigned int>(byte);
    }

    return output.str();
}

void printBlocks(const std::vector<Block>& blocks) {
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        if (i > 0) {
            std::cout << " | ";
        }

        std::cout << blockHex(blocks[i]);
    }

    std::cout << '\n';
}

std::size_t distinctBlockCount(const std::vector<Block>& blocks) {
    std::map<std::string, std::size_t> frequencies;

    for (const Block& block : blocks) {
        ++frequencies[blockHex(block)];
    }

    return frequencies.size();
}

void runRepeatedRecordCase(const EducationalFeistel& cipher) {
    /*
     * A repository policy system might encounter repeated fixed-size records,
     * such as repeated flags or configuration values. ECB exposes the
     * repetition because identical plaintext blocks map to identical
     * ciphertext blocks.
     */
    const std::string repeated =
        "POLICY01POLICY01POLICY01POLICY01";

    const auto ecb = encryptECB(cipher, repeated);

    Block iv{};
    iv.fill(0x42);

    const auto cbc = encryptCBC(cipher, repeated, iv);

    std::cout << "=== Repeated policy records ===\n";
    std::cout << "ECB blocks:\n";
    printBlocks(ecb);

    std::cout << "ECB distinct blocks: "
              << distinctBlockCount(ecb) << '\n';

    std::cout << "CBC blocks:\n";
    printBlocks(cbc);

    std::cout << "CBC distinct blocks: "
              << distinctBlockCount(cbc) << '\n';

    std::cout << '\n';
}

void runGovernanceRecordCase(const EducationalFeistel& cipher) {
    /*
     * This record represents policy metadata that could be sensitive in a
     * hypothetical system. The application layer must still treat the mode
     * separately from authorization. Encryption does not decide whether a
     * branch may be merged.
     */
    const std::string policyRecord =
        "reviews=2;checks=4;linear=true;";

    Block iv{};
    iv.fill(0xA5);

    const auto ciphertext = encryptCBC(cipher, policyRecord, iv);
    const auto recoveredBlocks = decryptCBC(cipher, ciphertext, iv);
    const std::string recovered = removePadding(recoveredBlocks);

    std::cout << "=== CBC policy record ===\n";
    std::cout << "Ciphertext:\n";
    printBlocks(ciphertext);

    std::cout << "Recovered record: "
              << recovered << '\n';

    std::cout << '\n';
}

void runTamperCase(const EducationalFeistel& cipher) {
    /*
     * CBC permits controlled modification of the next plaintext block by
     * modifying the corresponding bit in the previous ciphertext block.
     * The earlier plaintext block is generally corrupted unpredictably.
     *
     * This is a confidentiality-only construction and is not sufficient for
     * authenticated application data.
     */
    const std::string message =
        "ROLE=REVIEWER;ACTION=APPROVE;";

    Block iv{};
    iv.fill(0x33);

    auto ciphertext = encryptCBC(cipher, message, iv);

    if (ciphertext.size() < 2) {
        throw CryptoError("Tamper demonstration requires multiple blocks");
    }

    ciphertext[0][0] ^= 0x01;

    try {
        const auto modifiedPlaintext =
            decryptCBC(cipher, ciphertext, iv);

        std::cout << "=== CBC tampering ===\n";
        std::cout << "Decryption completed after ciphertext modification.\n";
        std::cout << "Modified plaintext may contain corrupted bytes.\n";

        for (const auto& block : modifiedPlaintext) {
            std::cout << blockHex(block) << ' ';
        }

        std::cout << "\n\n";
    } catch (const std::exception& error) {
        std::cout << "Tampering caused rejection: "
                  << error.what() << "\n\n";
    }
}

void runModeComparison() {
    struct ModeProperties {
        std::string name;
        bool independentEncryption;
        bool requiresIV;
        bool hidesRepeatedBlocks;
        bool providesAuthentication;
    };

    const std::vector<ModeProperties> modes = {
        {"ECB", true, false, false, false},
        {"CBC", false, true, true, false}
    };

    std::cout << "=== Architectural comparison ===\n";

    for (const auto& mode : modes) {
        std::cout << mode.name << '\n'
                  << "  independent encryption: "
                  << std::boolalpha << mode.independentEncryption << '\n'
                  << "  requires IV: "
                  << mode.requiresIV << '\n'
                  << "  hides repeated blocks: "
                  << mode.hidesRepeatedBlocks << '\n'
                  << "  provides authentication: "
                  << mode.providesAuthentication << "\n\n";
    }
}

int main() {
    try {
        const std::array<std::uint8_t, 16> key = {
            0x10, 0x21, 0x32, 0x43,
            0x54, 0x65, 0x76, 0x87,
            0x98, 0xA9, 0xBA, 0xCB,
            0xDC, 0xED, 0xFE, 0x0F
        };

        EducationalFeistel cipher(key);

        runRepeatedRecordCase(cipher);
        runGovernanceRecordCase(cipher);
        runTamperCase(cipher);
        runModeComparison();

        std::cout
            << "Case study completed using an educational block cipher.\n"
            << "Do not use the cipher or unauthenticated ECB/CBC in production.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
