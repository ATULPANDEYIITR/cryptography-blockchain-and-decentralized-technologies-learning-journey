#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * AES Structure and Working
 *
 * Technical case study:
 * A secure repository artifact service receives a 128-bit AES key and
 * fixed-size data blocks. The service exposes the AES-128 transformation
 * pipeline as an auditable engine.
 *
 * The case study emphasizes the relationship between:
 *   - the 4x4 byte state
 *   - round keys
 *   - SubBytes
 *   - ShiftRows
 *   - MixColumns
 *   - AddRoundKey
 *   - the final-round exception
 *
 * C++17 is sufficient. No external library is required.
 */

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;
using State = std::array<std::array<Byte, 4>, 4>;

static constexpr std::array<Byte, 256> SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static constexpr std::array<Byte, 11> RCON = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

Byte xtime(Byte value) {
    Byte shifted = static_cast<Byte>(value << 1);
    if (value & 0x80) {
        shifted ^= 0x1B;
    }
    return shifted;
}

Byte gmul(Byte a, Byte b) {
    Byte result = 0;

    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }

        a = xtime(a);
        b >>= 1;
    }

    return result;
}

State toState(const Block& block) {
    State state{};

    for (std::size_t column = 0; column < 4; ++column) {
        for (std::size_t row = 0; row < 4; ++row) {
            state[row][column] = block[column * 4 + row];
        }
    }

    return state;
}

Block fromState(const State& state) {
    Block block{};

    for (std::size_t column = 0; column < 4; ++column) {
        for (std::size_t row = 0; row < 4; ++row) {
            block[column * 4 + row] = state[row][column];
        }
    }

    return block;
}

State addRoundKey(const State& state, const Block& key) {
    const State keyState = toState(key);
    State result = state;

    for (std::size_t row = 0; row < 4; ++row) {
        for (std::size_t column = 0; column < 4; ++column) {
            result[row][column] ^= keyState[row][column];
        }
    }

    return result;
}

State subBytes(const State& state) {
    State result = state;

    for (auto& row : result) {
        for (Byte& value : row) {
            value = SBOX[value];
        }
    }

    return result;
}

State shiftRows(const State& state) {
    State result{};

    for (std::size_t row = 0; row < 4; ++row) {
        for (std::size_t column = 0; column < 4; ++column) {
            result[row][column] = state[row][(column + row) % 4];
        }
    }

    return result;
}

State mixColumns(const State& state) {
    State result = state;

    for (std::size_t column = 0; column < 4; ++column) {
        const Byte a0 = state[0][column];
        const Byte a1 = state[1][column];
        const Byte a2 = state[2][column];
        const Byte a3 = state[3][column];

        result[0][column] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
        result[1][column] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
        result[2][column] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
        result[3][column] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
    }

    return result;
}

std::array<Byte, 4> rotWord(std::array<Byte, 4> word) {
    return {word[1], word[2], word[3], word[0]};
}

std::array<Byte, 4> subWord(std::array<Byte, 4> word) {
    for (Byte& value : word) {
        value = SBOX[value];
    }
    return word;
}

std::array<Block, 11> expandKey(const Block& key) {
    std::array<std::array<Byte, 4>, 44> words{};

    for (std::size_t word = 0; word < 4; ++word) {
        for (std::size_t byte = 0; byte < 4; ++byte) {
            words[word][byte] = key[word * 4 + byte];
        }
    }

    for (std::size_t index = 4; index < 44; ++index) {
        auto temp = words[index - 1];

        if (index % 4 == 0) {
            temp = subWord(rotWord(temp));
            temp[0] ^= RCON[index / 4];
        }

        for (std::size_t byte = 0; byte < 4; ++byte) {
            words[index][byte] = words[index - 4][byte] ^ temp[byte];
        }
    }

    std::array<Block, 11> roundKeys{};

    for (std::size_t round = 0; round < 11; ++round) {
        for (std::size_t word = 0; word < 4; ++word) {
            for (std::size_t byte = 0; byte < 4; ++byte) {
                roundKeys[round][word * 4 + byte] =
                    words[round * 4 + word][byte];
            }
        }
    }

    return roundKeys;
}

std::string hex(const Block& block) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (Byte value : block) {
        output << std::setw(2) << static_cast<int>(value);
    }

    return output.str();
}

void printState(const State& state) {
    std::cout << std::hex << std::setfill('0');

    for (const auto& row : state) {
        for (Byte value : row) {
            std::cout << std::setw(2) << static_cast<int>(value) << ' ';
        }
        std::cout << '\n';
    }

    std::cout << std::dec;
}

struct RoundEvent {
    int round;
    std::string operation;
    Block state;
};

class AES128Engine {
public:
    explicit AES128Engine(const Block& key)
        : roundKeys_(expandKey(key)) {}

    std::pair<Block, std::vector<RoundEvent>>
    encrypt(const Block& plaintext) const {
        State state = toState(plaintext);
        std::vector<RoundEvent> events;

        state = addRoundKey(state, roundKeys_[0]);
        events.push_back({0, "AddRoundKey", fromState(state)});

        for (int round = 1; round <= 10; ++round) {
            state = subBytes(state);
            events.push_back({round, "SubBytes", fromState(state)});

            state = shiftRows(state);
            events.push_back({round, "ShiftRows", fromState(state)});

            // AES deliberately omits MixColumns in the final round.
            if (round != 10) {
                state = mixColumns(state);
                events.push_back({round, "MixColumns", fromState(state)});
            }

            state = addRoundKey(state, roundKeys_[round]);
            events.push_back({round, "AddRoundKey", fromState(state)});
        }

        return {fromState(state), events};
    }

    const std::array<Block, 11>& roundKeys() const {
        return roundKeys_;
    }

private:
    std::array<Block, 11> roundKeys_;
};

class ArtifactEncryptionCaseStudy {
public:
    struct Artifact {
        std::string identifier;
        std::string classification;
        Block plaintext;
        Block key;
    };

    struct AuditRecord {
        std::string artifactId;
        std::string classification;
        std::string ciphertext;
        std::size_t roundsExecuted;
        bool finalRoundOmittedMixColumns;
    };

    explicit ArtifactEncryptionCaseStudy(const Block& key)
        : engine_(key) {}

    AuditRecord process(const Artifact& artifact) {
        if (artifact.identifier.empty()) {
            throw std::invalid_argument("Artifact identifier cannot be empty.");
        }

        if (artifact.classification != "internal" &&
            artifact.classification != "restricted") {
            throw std::invalid_argument(
                "Only internal and restricted artifacts are accepted."
            );
        }

        const auto [ciphertext, events] = engine_.encrypt(artifact.plaintext);

        return {
            artifact.identifier,
            artifact.classification,
            hex(ciphertext),
            10,
            true
        };
    }

private:
    AES128Engine engine_;
};

Block blockFromHex(const std::string& value) {
    if (value.size() != 32) {
        throw std::invalid_argument("A hexadecimal AES block must contain 32 characters.");
    }

    Block result{};

    for (std::size_t index = 0; index < 16; ++index) {
        const auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::invalid_argument("Invalid hexadecimal character.");
        };

        result[index] = static_cast<Byte>(
            (nibble(value[index * 2]) << 4) | nibble(value[index * 2 + 1])
        );
    }

    return result;
}

void runKnownAnswerTest() {
    const Block key = blockFromHex("000102030405060708090a0b0c0d0e0f");
    const Block plaintext = blockFromHex("00112233445566778899aabbccddeeff");
    const Block expected = blockFromHex("69c4e0d86a7b0430d8cdb78070b4c55a");

    AES128Engine engine(key);
    const auto [ciphertext, events] = engine.encrypt(plaintext);

    if (ciphertext != expected) {
        throw std::runtime_error(
            "AES-128 known-answer test failed: " + hex(ciphertext)
        );
    }

    std::cout << "FIPS-197 known-answer test: PASS\n";
    std::cout << "Ciphertext: " << hex(ciphertext) << "\n";
    std::cout << "Trace events: " << events.size() << "\n";
}

void demonstrateCaseStudy() {
    const Block key = blockFromHex("000102030405060708090a0b0c0d0e0f");

    ArtifactEncryptionCaseStudy system(key);

    ArtifactEncryptionCaseStudy::Artifact artifact{
        "ART-SEC-042",
        "restricted",
        blockFromHex("00112233445566778899aabbccddeeff"),
        key
    };

    const auto record = system.process(artifact);

    std::cout << "\nRepository artifact encryption case study\n";
    std::cout << "=========================================\n";
    std::cout << "Artifact       : " << record.artifactId << '\n';
    std::cout << "Classification : " << record.classification << '\n';
    std::cout << "Ciphertext     : " << record.ciphertext << '\n';
    std::cout << "AES rounds     : " << record.roundsExecuted << '\n';
    std::cout << "Final MixCols  : "
              << (record.finalRoundOmittedMixColumns ? "omitted by AES specification" : "present")
              << '\n';
}

void demonstrateStateAndFieldArithmetic() {
    const Block sample = blockFromHex("00112233445566778899aabbccddeeff");
    const State state = toState(sample);

    std::cout << "\nAES state matrix\n";
    std::cout << "================\n";
    printState(state);

    std::cout << "\nGF(2^8) multiplication\n";
    std::cout << "0x57 * 0x13 = "
              << std::hex << std::setw(2) << std::setfill('0')
              << static_cast<int>(gmul(0x57, 0x13))
              << std::dec << '\n';
}

void demonstrateFailureHandling() {
    std::cout << "\nValidation behavior\n";
    std::cout << "===================\n";

    try {
        blockFromHex("1234");
    } catch (const std::exception& error) {
        std::cout << "Rejected malformed block: " << error.what() << '\n';
    }

    try {
        const Block key = blockFromHex("000102030405060708090a0b0c0d0e0f");
        ArtifactEncryptionCaseStudy system(key);

        ArtifactEncryptionCaseStudy::Artifact invalid{
            "",
            "restricted",
            blockFromHex("00112233445566778899aabbccddeeff"),
            key
        };

        system.process(invalid);
    } catch (const std::exception& error) {
        std::cout << "Rejected invalid artifact: " << error.what() << '\n';
    }
}

int main() {
    try {
        std::cout << "AES Structure and Working\n";
        std::cout << "=========================\n";

        demonstrateStateAndFieldArithmetic();
        runKnownAnswerTest();
        demonstrateCaseStudy();
        demonstrateFailureHandling();

        std::cout << "\nArchitecture note\n";
        std::cout
            << "The primitive operates on one 128-bit block at a time. "
            << "Real applications need a complete cryptographic construction, "
            << "including a suitable authenticated mode, nonce management, "
            << "secure key lifecycle, and protected implementation.\n";
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
