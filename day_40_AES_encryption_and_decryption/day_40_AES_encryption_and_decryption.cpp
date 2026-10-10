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
#include <vector>

/*
 * AES-128 repository-governance case study.
 *
 * This program implements the AES-128 block cipher and uses it in CTR mode
 * to encrypt sensitive repository policy records.
 *
 * The example intentionally keeps the cryptographic primitive visible so that
 * the relationship between a block cipher and a higher-level mode is clear.
 *
 * Production systems should normally use a vetted cryptographic library and
 * an authenticated mode such as AES-GCM rather than maintaining cryptography
 * code manually.
 */

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;

class AES128 {
private:
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

    std::array<Block, 11> roundKeys{};

    static Byte xtime(Byte x) {
        return static_cast<Byte>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
    }

    static Byte multiply(Byte a, Byte b) {
        Byte result = 0;
        while (b) {
            if (b & 1) result ^= a;
            a = xtime(a);
            b >>= 1;
        }
        return result;
    }

    void expandKey(const Block& key) {
        roundKeys[0] = key;
        const std::array<Byte, 10> rcon =
            {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

        for (int round = 1; round <= 10; ++round) {
            Block previous = roundKeys[round - 1];
            Block current{};

            current[0] = SBOX[previous[13]] ^ rcon[round - 1] ^ previous[0];
            current[1] = SBOX[previous[14]] ^ previous[1];
            current[2] = SBOX[previous[15]] ^ previous[2];
            current[3] = SBOX[previous[12]] ^ previous[3];

            for (int i = 4; i < 16; ++i)
                current[i] = previous[i] ^ current[i - 4];

            roundKeys[round] = current;
        }
    }

    static void addRoundKey(Block& state, const Block& key) {
        for (int i = 0; i < 16; ++i) state[i] ^= key[i];
    }

    static void subBytes(Block& state) {
        for (auto& byte : state) byte = SBOX[byte];
    }

    static void shiftRows(Block& state) {
        Block copy = state;
        for (int row = 0; row < 4; ++row)
            for (int col = 0; col < 4; ++col)
                state[4 * col + row] =
                    copy[4 * ((col + row) % 4) + row];
    }

    static void mixColumns(Block& state) {
        for (int col = 0; col < 4; ++col) {
            int i = col * 4;
            Byte a0 = state[i], a1 = state[i + 1];
            Byte a2 = state[i + 2], a3 = state[i + 3];

            state[i]     = multiply(a0,2) ^ multiply(a1,3) ^ a2 ^ a3;
            state[i + 1] = a0 ^ multiply(a1,2) ^ multiply(a2,3) ^ a3;
            state[i + 2] = a0 ^ a1 ^ multiply(a2,2) ^ multiply(a3,3);
            state[i + 3] = multiply(a0,3) ^ a1 ^ a2 ^ multiply(a3,2);
        }
    }

public:
    explicit AES128(const Block& key) {
        expandKey(key);
    }

    Block encryptBlock(Block state) const {
        addRoundKey(state, roundKeys[0]);

        for (int round = 1; round <= 9; ++round) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[10]);

        return state;
    }
};

struct RepositoryPolicyRecord {
    std::string repository;
    std::string branch;
    int requiredApprovals;
    bool forcePushAllowed;
};

class GovernanceCipher {
private:
    AES128 aes;
    Block counter;

    static void increment(Block& block) {
        for (int i = 15; i >= 0; --i) {
            ++block[i];
            if (block[i] != 0) return;
        }
        throw std::overflow_error("CTR counter exhausted.");
    }

public:
    GovernanceCipher(const Block& key, const Block& initialCounter)
        : aes(key), counter(initialCounter) {}

    std::vector<Byte> crypt(const std::vector<Byte>& input) {
        std::vector<Byte> output;
        output.reserve(input.size());

        Block localCounter = counter;

        for (std::size_t offset = 0; offset < input.size(); offset += 16) {
            Block keystream = aes.encryptBlock(localCounter);
            std::size_t remaining = std::min<std::size_t>(16, input.size() - offset);

            for (std::size_t i = 0; i < remaining; ++i)
                output.push_back(input[offset + i] ^ keystream[i]);

            increment(localCounter);
        }

        return output;
    }
};

std::vector<Byte> toBytes(const std::string& text) {
    return std::vector<Byte>(text.begin(), text.end());
}

std::string fromBytes(const std::vector<Byte>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

std::string hex(const std::vector<Byte>& bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (Byte value : bytes)
        output << std::setw(2) << static_cast<int>(value);

    return output.str();
}

std::string policyToText(const RepositoryPolicyRecord& policy) {
    std::ostringstream result;
    result << "repository=" << policy.repository
           << ";branch=" << policy.branch
           << ";required_approvals=" << policy.requiredApprovals
           << ";force_push_allowed="
           << (policy.forcePushAllowed ? "true" : "false");
    return result.str();
}

bool canMerge(
    int approvals,
    bool checksPassed,
    bool protectedBranch,
    bool hasConflict
) {
    if (approvals < 0) throw std::invalid_argument("Approval count cannot be negative.");

    return approvals >= 2 &&
           checksPassed &&
           protectedBranch &&
           !hasConflict;
}

int main() {
    try {
        const Block key = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };

        const Block counter = {
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };

        RepositoryPolicyRecord policy{
            "security-platform",
            "main",
            2,
            false
        };

        std::string cleartext = policyToText(policy);
        auto plaintext = toBytes(cleartext);

        GovernanceCipher cipher(key, counter);

        auto encrypted = cipher.crypt(plaintext);

        // CTR encryption and decryption use the same XOR operation. Recreating
        // the cipher with the same key and initial counter reverses the process.
        GovernanceCipher decipher(key, counter);
        auto recovered = decipher.crypt(encrypted);

        std::cout << "Repository governance encryption\n";
        std::cout << "--------------------------------\n";
        std::cout << "Plaintext : " << cleartext << "\n";
        std::cout << "Ciphertext: " << hex(encrypted) << "\n";
        std::cout << "Recovered : " << fromBytes(recovered) << "\n";
        std::cout << "Round trip: "
                  << (recovered == plaintext ? "successful" : "failed")
                  << "\n";

        std::cout << "\nMerge eligibility policy\n";
        std::cout << "------------------------\n";

        const bool eligible = canMerge(
            2,
            true,
            true,
            false
        );

        std::cout << "Approvals: 2\n";
        std::cout << "Checks passed: true\n";
        std::cout << "Protected branch: true\n";
        std::cout << "Conflicts: false\n";
        std::cout << "Merge eligible: "
                  << (eligible ? "true" : "false") << "\n";

        std::cout << "\nPolicy failure example\n";
        std::cout << "----------------------\n";

        const bool blocked = canMerge(
            1,
            true,
            true,
            false
        );

        std::cout << "One approval with two required approvals: "
                  << (blocked ? "incorrectly accepted" : "blocked")
                  << "\n";

        std::cout << "\nAES-128 known-answer test\n";
        std::cout << "-------------------------\n";

        Block testPlaintext = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
        };

        AES128 testCipher(key);
        Block testCiphertext = testCipher.encryptBlock(testPlaintext);

        std::vector<Byte> known(testCiphertext.begin(), testCiphertext.end());

        std::cout << "Expected: 69c4e0d86a7b0430d8cdb78070b4c55a\n";
        std::cout << "Actual  : " << hex(known) << "\n";
        std::cout << "Result  : "
                  << (hex(known) == "69c4e0d86a7b0430d8cdb78070b4c55a"
                      ? "passed" : "failed")
                  << "\n";

        std::cout << "\nSecurity limitation\n";
        std::cout << "-------------------\n";
        std::cout << "This educational CTR construction provides confidentiality only.\n";
        std::cout << "Production systems should use authenticated encryption such as AES-GCM.\n";

    } catch (const std::exception& error) {
        std::cerr << "Failure: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
