#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Repository artifact protection: AES key-schedule and merge-artifact case study.
 *
 * This program models the AES block algorithm, key expansion, and a release
 * manifest's encryption eligibility checks. It intentionally does not claim
 * that unauthenticated AES blocks constitute a secure file-encryption format.
 *
 * Compile:
 *   g++ -std=c++17 -O2 aes_keys_rounds.cpp -o aes_keys_rounds
 */

namespace aes {

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;
using Word = std::array<Byte, 4>;
using State = std::array<std::array<Byte, 4>, 4>;

struct Parameters {
    std::size_t keyBytes;
    int rounds;
};

Parameters parametersForKeySize(std::size_t size) {
    switch (size) {
        case 16: return {16, 10};
        case 24: return {24, 12};
        case 32: return {32, 14};
        default:
            throw std::invalid_argument(
                "AES requires a 16-, 24-, or 32-byte key."
            );
    }
}

Byte xtime(Byte value) {
    const unsigned int shifted = static_cast<unsigned int>(value) << 1U;
    return static_cast<Byte>(
        (shifted ^ ((value & 0x80U) ? 0x11bU : 0U)) & 0xffU
    );
}

Byte multiply(Byte left, Byte right) {
    Byte result = 0;

    while (right != 0) {
        if ((right & 1U) != 0) {
            result ^= left;
        }

        left = xtime(left);
        right = static_cast<Byte>(right >> 1U);
    }

    return result;
}

Byte power(Byte value, unsigned int exponent) {
    Byte result = 1;

    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = multiply(result, value);
        }

        value = multiply(value, value);
        exponent >>= 1U;
    }

    return result;
}

Byte rotateLeft(Byte value, unsigned int count) {
    const unsigned int x = value;
    return static_cast<Byte>(
        ((x << count) | (x >> (8U - count))) & 0xffU
    );
}

std::array<Byte, 256> createSBox() {
    std::array<Byte, 256> table{};

    for (unsigned int value = 0; value < 256; ++value) {
        const Byte inverse = value == 0
            ? 0
            : power(static_cast<Byte>(value), 254);

        table[value] = static_cast<Byte>(
            inverse ^
            rotateLeft(inverse, 1) ^
            rotateLeft(inverse, 2) ^
            rotateLeft(inverse, 3) ^
            rotateLeft(inverse, 4) ^
            0x63U
        );
    }

    return table;
}

const std::array<Byte, 256> SBOX = createSBox();

Word rotateWord(const Word& word) {
    return {word[1], word[2], word[3], word[0]};
}

Word substituteWord(const Word& word) {
    return {
        SBOX[word[0]],
        SBOX[word[1]],
        SBOX[word[2]],
        SBOX[word[3]]
    };
}

class AES {
public:
    explicit AES(const std::vector<Byte>& key)
        : parameters_(parametersForKeySize(key.size())),
          roundKeys_(expandKey(key)) {}

    const Parameters& parameters() const {
        return parameters_;
    }

    const std::vector<Block>& roundKeys() const {
        return roundKeys_;
    }

    Block encryptBlock(const Block& plaintext) const {
        State state = toState(plaintext);
        addRoundKey(state, roundKeys_[0]);

        for (int round = 1; round < parameters_.rounds; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys_[round]);
        }

        // The final round omits MixColumns in the AES specification.
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys_.back());

        return fromState(state);
    }

private:
    Parameters parameters_;
    std::vector<Block> roundKeys_;

    std::vector<Block> expandKey(const std::vector<Byte>& key) const {
        const std::size_t nk = key.size() / 4;
        const std::size_t wordCount =
            4U * static_cast<std::size_t>(parameters_.rounds + 1);

        std::vector<Word> words;
        words.reserve(wordCount);

        for (std::size_t offset = 0; offset < key.size(); offset += 4) {
            words.push_back({
                key[offset],
                key[offset + 1],
                key[offset + 2],
                key[offset + 3]
            });
        }

        Byte rcon = 1;

        for (std::size_t index = nk; index < wordCount; ++index) {
            Word temporary = words[index - 1];

            if (index % nk == 0) {
                temporary = substituteWord(rotateWord(temporary));
                temporary[0] ^= rcon;
                rcon = xtime(rcon);
            } else if (nk > 6 && index % nk == 4) {
                temporary = substituteWord(temporary);
            }

            Word next{};
            for (std::size_t byte = 0; byte < 4; ++byte) {
                next[byte] = words[index - nk][byte] ^ temporary[byte];
            }

            words.push_back(next);
        }

        std::vector<Block> keys;
        keys.reserve(static_cast<std::size_t>(parameters_.rounds + 1));

        for (std::size_t index = 0; index < words.size(); index += 4) {
            Block roundKey{};

            for (std::size_t word = 0; word < 4; ++word) {
                for (std::size_t byte = 0; byte < 4; ++byte) {
                    roundKey[word * 4 + byte] = words[index + word][byte];
                }
            }

            keys.push_back(roundKey);
        }

        return keys;
    }

    static State toState(const Block& block) {
        State state{};

        for (std::size_t column = 0; column < 4; ++column) {
            for (std::size_t row = 0; row < 4; ++row) {
                state[row][column] = block[column * 4 + row];
            }
        }

        return state;
    }

    static Block fromState(const State& state) {
        Block block{};

        for (std::size_t column = 0; column < 4; ++column) {
            for (std::size_t row = 0; row < 4; ++row) {
                block[column * 4 + row] = state[row][column];
            }
        }

        return block;
    }

    static void addRoundKey(State& state, const Block& key) {
        for (std::size_t column = 0; column < 4; ++column) {
            for (std::size_t row = 0; row < 4; ++row) {
                state[row][column] ^= key[column * 4 + row];
            }
        }
    }

    static void subBytes(State& state) {
        for (auto& row : state) {
            for (Byte& value : row) {
                value = SBOX[value];
            }
        }
    }

    static void shiftRows(State& state) {
        for (std::size_t row = 1; row < 4; ++row) {
            std::array<Byte, 4> original = state[row];

            for (std::size_t column = 0; column < 4; ++column) {
                state[row][column] = original[(column + row) % 4];
            }
        }
    }

    static void mixColumns(State& state) {
        for (std::size_t column = 0; column < 4; ++column) {
            const Byte a = state[0][column];
            const Byte b = state[1][column];
            const Byte c = state[2][column];
            const Byte d = state[3][column];

            state[0][column] = multiply(a, 2) ^ multiply(b, 3) ^ c ^ d;
            state[1][column] = a ^ multiply(b, 2) ^ multiply(c, 3) ^ d;
            state[2][column] = a ^ b ^ multiply(c, 2) ^ multiply(d, 3);
            state[3][column] = multiply(a, 3) ^ b ^ c ^ multiply(d, 2);
        }
    }
};

std::vector<Byte> parseHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hexadecimal input has odd length.");
    }

    std::vector<Byte> result;
    result.reserve(hex.size() / 2);

    for (std::size_t index = 0; index < hex.size(); index += 2) {
        const auto nibble = [](char character) -> unsigned int {
            if (character >= '0' && character <= '9') {
                return static_cast<unsigned int>(character - '0');
            }
            if (character >= 'a' && character <= 'f') {
                return static_cast<unsigned int>(character - 'a' + 10);
            }
            if (character >= 'A' && character <= 'F') {
                return static_cast<unsigned int>(character - 'A' + 10);
            }
            throw std::invalid_argument("Invalid hexadecimal character.");
        };

        result.push_back(static_cast<Byte>(
            (nibble(hex[index]) << 4U) | nibble(hex[index + 1])
        ));
    }

    return result;
}

std::string toHex(const std::vector<Byte>& bytes) {
    std::string result;
    result.reserve(bytes.size() * 2);

    constexpr char digits[] = "0123456789abcdef";
    for (Byte byte : bytes) {
        result.push_back(digits[byte >> 4U]);
        result.push_back(digits[byte & 0x0fU]);
    }

    return result;
}

std::string toHex(const Block& block) {
    return toHex(std::vector<Byte>(block.begin(), block.end()));
}

struct ReleaseArtifact {
    std::string repository;
    std::string sourceBranch;
    std::string targetBranch;
    std::string pullRequest;
    std::string commit;
    bool reviewApproved;
    bool ciPassed;
    bool protectionEnabled;
};

class ReleaseGovernance {
public:
    bool eligible(const ReleaseArtifact& artifact) const {
        if (artifact.repository.empty() ||
            artifact.sourceBranch.empty() ||
            artifact.targetBranch.empty() ||
            artifact.pullRequest.empty() ||
            artifact.commit.empty()) {
            return false;
        }

        if (artifact.sourceBranch == artifact.targetBranch) {
            return false;
        }

        return artifact.reviewApproved &&
               artifact.ciPassed &&
               artifact.protectionEnabled;
    }

    void requireEligible(const ReleaseArtifact& artifact) const {
        if (!eligible(artifact)) {
            throw std::runtime_error(
                "Artifact rejected: governance requirements are not satisfied."
            );
        }
    }
};

void printRoundKeys(const AES& cipher) {
    const auto& keys = cipher.roundKeys();

    for (std::size_t round = 0; round < keys.size(); ++round) {
        std::cout << "Round " << std::setw(2) << std::setfill('0')
                  << round << ": " << toHex(keys[round]) << '\n';
    }
}

void runKnownAnswerTest() {
    const auto keyBytes = parseHex("000102030405060708090a0b0c0d0e0f");
    const auto plaintextBytes = parseHex("00112233445566778899aabbccddeeff");

    if (keyBytes.size() != 16 || plaintextBytes.size() != 16) {
        throw std::runtime_error("Test vector has an invalid block or key size.");
    }

    Block plaintext{};
    std::copy(plaintextBytes.begin(), plaintextBytes.end(), plaintext.begin());

    AES cipher(keyBytes);
    const Block encrypted = cipher.encryptBlock(plaintext);

    const std::string expected = "69c4e0d86a7b0430d8cdb78070b4c55a";
    if (toHex(encrypted) != expected) {
        throw std::runtime_error("AES-128 known-answer test failed.");
    }

    std::cout << "AES-128 known-answer test passed.\n";
}

}  // namespace aes

int main() {
    try {
        using namespace aes;

        runKnownAnswerTest();

        const std::vector<Byte> key =
            parseHex("000102030405060708090a0b0c0d0e0f");

        AES cipher(key);

        std::cout << "\nAES key schedule\n";
        std::cout << "Key size: " << cipher.parameters().keyBytes * 8
                  << " bits\n";
        std::cout << "Rounds: " << cipher.parameters().rounds << '\n';
        printRoundKeys(cipher);

        const auto input = parseHex("00112233445566778899aabbccddeeff");
        Block plaintext{};
        std::copy(input.begin(), input.end(), plaintext.begin());

        std::cout << "\nEncrypted block: "
                  << toHex(cipher.encryptBlock(plaintext)) << '\n';

        ReleaseGovernance governance;

        const ReleaseArtifact release{
            "payments-api",
            "feature/aes-key-rotation",
            "main",
            "PR-842",
            "a91d42f",
            true,
            true,
            true
        };

        if (governance.eligible(release)) {
            governance.requireEligible(release);
            std::cout << "\nRelease " << release.pullRequest
                      << " passed governance checks.\n";
        }

        ReleaseArtifact rejected = release;
        rejected.reviewApproved = false;

        if (!governance.eligible(rejected)) {
            std::cout << "Release rejected because approval is missing.\n";
        }

        for (std::size_t length : {16U, 24U, 32U}) {
            const auto parameters = parametersForKeySize(length);
            std::cout << "AES-" << length * 8 << ": "
                      << parameters.rounds << " rounds, "
                      << parameters.rounds + 1 << " round keys\n";
        }

        try {
            parametersForKeySize(20);
        } catch (const std::invalid_argument& error) {
            std::cout << "Invalid key rejected: " << error.what() << '\n';
        }

    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
