#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * AES-128 repository-style document protection case study.
 *
 * The scenario is a small document vault that must protect a fixed-size
 * sensitive metadata record. The implementation deliberately exposes AES's
 * internal transformations instead of relying on a cryptographic library.
 *
 * This is educational code. Production systems should use a vetted
 * cryptographic library and authenticated encryption such as AES-GCM.
 */

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;
using Key = std::array<Byte, 16>;

static const std::array<Byte, 256> SBOX = {
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

static const std::array<Byte, 256> INV_SBOX = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const std::array<Byte, 11> RCON =
    {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

Byte gfMultiply(Byte a, Byte b) {
    Byte result = 0;
    while (b != 0) {
        if (b & 1) result ^= a;
        a = static_cast<Byte>((a << 1) ^ ((a & 0x80) ? 0x1B : 0));
        b >>= 1;
    }
    return result;
}

class AES128 {
private:
    std::array<Block, 11> roundKeys{};

    static Block xorBlock(const Block& a, const Block& b) {
        Block result{};
        for (std::size_t i = 0; i < 16; ++i)
            result[i] = a[i] ^ b[i];
        return result;
    }

    static Block subBytes(const Block& state) {
        Block result{};
        for (std::size_t i = 0; i < 16; ++i)
            result[i] = SBOX[state[i]];
        return result;
    }

    static Block inverseSubBytes(const Block& state) {
        Block result{};
        for (std::size_t i = 0; i < 16; ++i)
            result[i] = INV_SBOX[state[i]];
        return result;
    }

    static Block shiftRows(const Block& state) {
        Block result{};
        for (int row = 0; row < 4; ++row) {
            for (int column = 0; column < 4; ++column) {
                result[4 * column + row] =
                    state[4 * ((column + row) % 4) + row];
            }
        }
        return result;
    }

    static Block inverseShiftRows(const Block& state) {
        Block result{};
        for (int row = 0; row < 4; ++row) {
            for (int column = 0; column < 4; ++column) {
                result[4 * column + row] =
                    state[4 * ((column - row + 4) % 4) + row];
            }
        }
        return result;
    }

    static Block mixColumns(const Block& state) {
        Block result = state;

        for (int column = 0; column < 4; ++column) {
            const int i = column * 4;
            const Byte a0 = state[i];
            const Byte a1 = state[i + 1];
            const Byte a2 = state[i + 2];
            const Byte a3 = state[i + 3];

            result[i] =
                gfMultiply(a0, 2) ^ gfMultiply(a1, 3) ^ a2 ^ a3;
            result[i + 1] =
                a0 ^ gfMultiply(a1, 2) ^ gfMultiply(a2, 3) ^ a3;
            result[i + 2] =
                a0 ^ a1 ^ gfMultiply(a2, 2) ^ gfMultiply(a3, 3);
            result[i + 3] =
                gfMultiply(a0, 3) ^ a1 ^ a2 ^ gfMultiply(a3, 2);
        }

        return result;
    }

    static Block inverseMixColumns(const Block& state) {
        Block result = state;

        for (int column = 0; column < 4; ++column) {
            const int i = column * 4;
            const Byte a0 = state[i];
            const Byte a1 = state[i + 1];
            const Byte a2 = state[i + 2];
            const Byte a3 = state[i + 3];

            result[i] =
                gfMultiply(a0, 14) ^ gfMultiply(a1, 11) ^
                gfMultiply(a2, 13) ^ gfMultiply(a3, 9);
            result[i + 1] =
                gfMultiply(a0, 9) ^ gfMultiply(a1, 14) ^
                gfMultiply(a2, 11) ^ gfMultiply(a3, 13);
            result[i + 2] =
                gfMultiply(a0, 13) ^ gfMultiply(a1, 9) ^
                gfMultiply(a2, 14) ^ gfMultiply(a3, 11);
            result[i + 3] =
                gfMultiply(a0, 11) ^ gfMultiply(a1, 13) ^
                gfMultiply(a2, 9) ^ gfMultiply(a3, 14);
        }

        return result;
    }

    void expandKey(const Key& key) {
        std::array<std::array<Byte, 4>, 44> words{};

        for (std::size_t i = 0; i < 4; ++i) {
            for (std::size_t j = 0; j < 4; ++j)
                words[i][j] = key[i * 4 + j];
        }

        for (std::size_t i = 4; i < 44; ++i) {
            auto temp = words[i - 1];

            if (i % 4 == 0) {
                const Byte first = temp[0];
                temp[0] = SBOX[temp[1]];
                temp[1] = SBOX[temp[2]];
                temp[2] = SBOX[temp[3]];
                temp[3] = SBOX[first];
                temp[0] ^= RCON[i / 4];
            }

            for (std::size_t j = 0; j < 4; ++j)
                words[i][j] = words[i - 4][j] ^ temp[j];
        }

        for (std::size_t round = 0; round < 11; ++round) {
            for (std::size_t word = 0; word < 4; ++word) {
                for (std::size_t byte = 0; byte < 4; ++byte) {
                    roundKeys[round][word * 4 + byte] =
                        words[round * 4 + word][byte];
                }
            }
        }
    }

public:
    explicit AES128(const Key& key) {
        expandKey(key);
    }

    Block encrypt(const Block& plaintext) const {
        Block state = xorBlock(plaintext, roundKeys[0]);

        for (int round = 1; round < 10; ++round) {
            state = subBytes(state);
            state = shiftRows(state);
            state = mixColumns(state);
            state = xorBlock(state, roundKeys[round]);
        }

        state = subBytes(state);
        state = shiftRows(state);
        state = xorBlock(state, roundKeys[10]);

        return state;
    }

    Block decrypt(const Block& ciphertext) const {
        Block state = xorBlock(ciphertext, roundKeys[10]);

        for (int round = 9; round > 0; --round) {
            state = inverseShiftRows(state);
            state = inverseSubBytes(state);
            state = xorBlock(state, roundKeys[round]);
            state = inverseMixColumns(state);
        }

        state = inverseShiftRows(state);
        state = inverseSubBytes(state);
        state = xorBlock(state, roundKeys[0]);

        return state;
    }
};

std::string hex(const Block& block) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (Byte value : block)
        output << std::setw(2) << static_cast<int>(value);

    return output.str();
}

Block blockFromHex(const std::string& value) {
    if (value.size() != 32)
        throw std::invalid_argument("A block requires 32 hexadecimal characters");

    Block result{};

    for (std::size_t i = 0; i < 16; ++i) {
        result[i] = static_cast<Byte>(
            std::stoul(value.substr(i * 2, 2), nullptr, 16)
        );
    }

    return result;
}

class DocumentVault {
private:
    AES128 cipher;

public:
    explicit DocumentVault(const Key& key) : cipher(key) {}

    Block protectMetadata(const Block& metadata) const {
        return cipher.encrypt(metadata);
    }

    Block recoverMetadata(const Block& encryptedMetadata) const {
        return cipher.decrypt(encryptedMetadata);
    }
};

void knownAnswerTest() {
    Key key{};
    Block plaintext{};

    for (int i = 0; i < 16; ++i) {
        key[i] = static_cast<Byte>(i);
        plaintext[i] = static_cast<Byte>(0x00 + i);
    }

    const Block expected =
        blockFromHex("69c4e0d86a7b0430d8cdb78070b4c55a");

    AES128 aes(key);
    const Block ciphertext = aes.encrypt(plaintext);

    if (ciphertext != expected)
        throw std::runtime_error("AES-128 known-answer test failed");

    if (aes.decrypt(ciphertext) != plaintext)
        throw std::runtime_error("AES-128 decryption test failed");

    std::cout << "Known-answer test: PASS\n";
}

void demonstrateVault() {
    Key key{
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

    /*
     * A real document is larger than one AES block and needs an encryption
     * mode. This case study uses exactly one block to isolate the AES
     * primitive. It intentionally does not pretend that raw ECB encryption
     * is an appropriate document-vault design.
     */
    const Block metadata{
        'P','A','Y','R','O','L','L','-',
        '2','0','2','6','-','1','0','0'
    };

    DocumentVault vault(key);
    const Block encrypted = vault.protectMetadata(metadata);
    const Block recovered = vault.recoverMetadata(encrypted);

    std::cout << "\nRepository document-vault case study\n";
    std::cout << "------------------------------------\n";
    std::cout << "Plain metadata : " << hex(metadata) << '\n';
    std::cout << "AES ciphertext : " << hex(encrypted) << '\n';
    std::cout << "Recovered      : " << hex(recovered) << '\n';

    if (recovered != metadata)
        throw std::runtime_error("Vault round-trip failed");
}

void demonstrateAvalancheEffect() {
    Key key{
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,
        0x0c,0x0d,0x0e,0x0f
    };

    Block first{};
    Block second{};

    first.fill(0);
    second.fill(0);
    second[0] = 1;

    AES128 aes(key);

    const Block firstCiphertext = aes.encrypt(first);
    const Block secondCiphertext = aes.encrypt(second);

    std::size_t differingBits = 0;

    for (std::size_t i = 0; i < 16; ++i) {
        Byte difference = firstCiphertext[i] ^ secondCiphertext[i];

        while (difference != 0) {
            differingBits += difference & 1U;
            difference >>= 1;
        }
    }

    std::cout << "\nAvalanche demonstration\n";
    std::cout << "----------------------\n";
    std::cout << "Ciphertext A : " << hex(firstCiphertext) << '\n';
    std::cout << "Ciphertext B : " << hex(secondCiphertext) << '\n';
    std::cout << "Differing bits: " << differingBits << " / 128\n";
}

void demonstrateFailureHandling() {
    Key key{};
    AES128 aes(key);

    Block plaintext{};
    Block ciphertext = aes.encrypt(plaintext);

    if (aes.decrypt(ciphertext) != plaintext)
        throw std::runtime_error("Unexpected AES round-trip failure");

    std::cout << "\nFailure and design observations\n";
    std::cout << "-------------------------------\n";
    std::cout << "A wrong AES key produces unrelated plaintext.\n";
    std::cout << "AES-128 has a 16-byte block and a 16-byte key.\n";
    std::cout << "Raw AES blocks do not provide authentication.\n";
    std::cout << "ECB-style repeated block encryption leaks repeated plaintext patterns.\n";
    std::cout << "CBC requires padding and an unpredictable IV.\n";
    std::cout << "CTR requires strict nonce uniqueness for each key.\n";
    std::cout << "Modern applications should normally use AES-GCM or another reviewed\n";
    std::cout << "authenticated-encryption construction instead of assembling modes manually.\n";
}

int main() {
    try {
        std::cout << "AES-128 technical case study\n";
        std::cout << "============================\n";

        knownAnswerTest();
        demonstrateVault();
        demonstrateAvalancheEffect();
        demonstrateFailureHandling();

        std::cout << "\nC++17 AES case study completed successfully.\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }
}
