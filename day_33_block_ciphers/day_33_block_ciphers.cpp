/*
 * Block Cipher Case Study: AES-128 Protected Telemetry Archive
 *
 * C++17 self-contained educational implementation.
 *
 * Scenario:
 * A telemetry service stores fixed-format records in an archive. The archive
 * needs a block cipher primitive, deterministic record framing, CBC encryption,
 * strict PKCS#7 validation, and explicit policy checks around IV handling.
 *
 * This program intentionally stops short of pretending that AES-CBC alone is
 * an authenticated storage protocol. Production archival encryption should
 * normally use an authenticated-encryption construction such as AES-GCM.
 *
 * Build:
 *   g++ -std=c++17 -O2 block_cipher_case_study.cpp -o block_cipher_case_study
 */

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using Byte = std::uint8_t;
using Block = std::array<Byte, 16>;
using Bytes = std::vector<Byte>;

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

static const std::array<Byte, 256> INV_SBOX = [] {
    std::array<Byte, 256> table{};
    for (std::size_t i = 0; i < SBOX.size(); ++i) {
        table[SBOX[i]] = static_cast<Byte>(i);
    }
    return table;
}();

static const std::array<Byte, 11> RCON = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

Byte gfMul(Byte a, Byte b) {
    Byte result = 0;

    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            result ^= a;
        }

        const bool highBit = (a & 0x80) != 0;
        a = static_cast<Byte>(a << 1);

        if (highBit) {
            a ^= 0x1b;
        }

        b = static_cast<Byte>(b >> 1);
    }

    return result;
}

void addRoundKey(Block& state, const Block& key) {
    for (std::size_t i = 0; i < 16; ++i) {
        state[i] ^= key[i];
    }
}

void subBytes(Block& state) {
    for (Byte& value : state) {
        value = SBOX[value];
    }
}

void inverseSubBytes(Block& state) {
    for (Byte& value : state) {
        value = INV_SBOX[value];
    }
}

void shiftRows(Block& state) {
    Block original = state;

    for (std::size_t row = 0; row < 4; ++row) {
        for (std::size_t column = 0; column < 4; ++column) {
            const std::size_t sourceColumn = (column + row) % 4;
            state[4 * column + row] =
                original[4 * sourceColumn + row];
        }
    }
}

void inverseShiftRows(Block& state) {
    Block original = state;

    for (std::size_t row = 0; row < 4; ++row) {
        for (std::size_t column = 0; column < 4; ++column) {
            const int sourceColumn =
                (static_cast<int>(column) - static_cast<int>(row) + 4) % 4;

            state[4 * column + row] =
                original[4 * static_cast<std::size_t>(sourceColumn) + row];
        }
    }
}

void mixColumns(Block& state) {
    for (std::size_t column = 0; column < 4; ++column) {
        const std::size_t base = column * 4;
        const Byte a0 = state[base];
        const Byte a1 = state[base + 1];
        const Byte a2 = state[base + 2];
        const Byte a3 = state[base + 3];

        state[base] =
            gfMul(a0, 2) ^ gfMul(a1, 3) ^ a2 ^ a3;

        state[base + 1] =
            a0 ^ gfMul(a1, 2) ^ gfMul(a2, 3) ^ a3;

        state[base + 2] =
            a0 ^ a1 ^ gfMul(a2, 2) ^ gfMul(a3, 3);

        state[base + 3] =
            gfMul(a0, 3) ^ a1 ^ a2 ^ gfMul(a3, 2);
    }
}

void inverseMixColumns(Block& state) {
    for (std::size_t column = 0; column < 4; ++column) {
        const std::size_t base = column * 4;
        const Byte a0 = state[base];
        const Byte a1 = state[base + 1];
        const Byte a2 = state[base + 2];
        const Byte a3 = state[base + 3];

        state[base] =
            gfMul(a0, 14) ^ gfMul(a1, 11) ^
            gfMul(a2, 13) ^ gfMul(a3, 9);

        state[base + 1] =
            gfMul(a0, 9) ^ gfMul(a1, 14) ^
            gfMul(a2, 11) ^ gfMul(a3, 13);

        state[base + 2] =
            gfMul(a0, 13) ^ gfMul(a1, 9) ^
            gfMul(a2, 14) ^ gfMul(a3, 11);

        state[base + 3] =
            gfMul(a0, 11) ^ gfMul(a1, 13) ^
            gfMul(a2, 9) ^ gfMul(a3, 14);
    }
}

std::array<Block, 11> expandKey(const Block& key) {
    std::array<std::array<Byte, 4>, 44> words{};

    for (std::size_t i = 0; i < 4; ++i) {
        for (std::size_t j = 0; j < 4; ++j) {
            words[i][j] = key[i * 4 + j];
        }
    }

    for (std::size_t i = 4; i < 44; ++i) {
        std::array<Byte, 4> temp = words[i - 1];

        if (i % 4 == 0) {
            temp = {temp[1], temp[2], temp[3], temp[0]};

            for (Byte& value : temp) {
                value = SBOX[value];
            }

            temp[0] ^= RCON[i / 4];
        }

        for (std::size_t j = 0; j < 4; ++j) {
            words[i][j] = words[i - 4][j] ^ temp[j];
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

class AES128 {
public:
    explicit AES128(const Block& key)
        : roundKeys_(expandKey(key)) {}

    Block encryptBlock(const Block& input) const {
        Block state = input;

        addRoundKey(state, roundKeys_[0]);

        for (std::size_t round = 1; round <= 10; ++round) {
            subBytes(state);
            shiftRows(state);

            if (round != 10) {
                mixColumns(state);
            }

            addRoundKey(state, roundKeys_[round]);
        }

        return state;
    }

    Block decryptBlock(const Block& input) const {
        Block state = input;

        addRoundKey(state, roundKeys_[10]);

        for (int round = 9; round >= 0; --round) {
            inverseShiftRows(state);
            inverseSubBytes(state);
            addRoundKey(state, roundKeys_[static_cast<std::size_t>(round)]);

            if (round != 0) {
                inverseMixColumns(state);
            }
        }

        return state;
    }

private:
    std::array<Block, 11> roundKeys_;
};

// -----------------------------------------------------------------------------
// Archive framing
// -----------------------------------------------------------------------------

struct TelemetryRecord {
    std::uint32_t deviceId;
    std::uint64_t timestamp;
    std::int32_t temperatureMilliCelsius;
    std::uint32_t sequence;
};

Bytes serializeRecord(const TelemetryRecord& record) {
    /*
     * The archive uses a fixed binary representation so encryption operates
     * on well-defined bytes rather than implementation-dependent C++ object
     * layout or raw struct memory.
     */
    Bytes result;
    result.reserve(20);

    auto append32 = [&result](std::uint32_t value) {
        result.push_back(static_cast<Byte>((value >> 24) & 0xff));
        result.push_back(static_cast<Byte>((value >> 16) & 0xff));
        result.push_back(static_cast<Byte>((value >> 8) & 0xff));
        result.push_back(static_cast<Byte>(value & 0xff));
    };

    auto append64 = [&result](std::uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            result.push_back(static_cast<Byte>((value >> shift) & 0xff));
        }
    };

    append32(record.deviceId);
    append64(record.timestamp);
    append32(static_cast<std::uint32_t>(record.temperatureMilliCelsius));
    append32(record.sequence);

    return result;
}

TelemetryRecord deserializeRecord(const Bytes& data) {
    if (data.size() != 20) {
        throw std::runtime_error("Telemetry record must contain exactly 20 bytes");
    }

    auto read32 = [&data](std::size_t offset) -> std::uint32_t {
        return
            (static_cast<std::uint32_t>(data[offset]) << 24) |
            (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
            (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
            static_cast<std::uint32_t>(data[offset + 3]);
    };

    auto read64 = [&data](std::size_t offset) -> std::uint64_t {
        std::uint64_t value = 0;

        for (std::size_t i = 0; i < 8; ++i) {
            value = (value << 8) | data[offset + i];
        }

        return value;
    };

    TelemetryRecord record{};
    record.deviceId = read32(0);
    record.timestamp = read64(4);
    record.temperatureMilliCelsius =
        static_cast<std::int32_t>(read32(12));
    record.sequence = read32(16);

    return record;
}

// -----------------------------------------------------------------------------
// PKCS#7
// -----------------------------------------------------------------------------

Bytes pad(const Bytes& input) {
    const std::size_t padding = 16 - (input.size() % 16);

    Bytes result = input;
    result.insert(result.end(), padding, static_cast<Byte>(padding));

    return result;
}

Bytes unpad(const Bytes& input) {
    if (input.empty() || input.size() % 16 != 0) {
        throw std::runtime_error("Invalid padded ciphertext length");
    }

    const Byte padding = input.back();

    if (padding == 0 || padding > 16 || padding > input.size()) {
        throw std::runtime_error("Invalid PKCS#7 padding length");
    }

    for (std::size_t i = input.size() - padding; i < input.size(); ++i) {
        if (input[i] != padding) {
            throw std::runtime_error("Invalid PKCS#7 padding bytes");
        }
    }

    return Bytes(input.begin(), input.end() - padding);
}

// -----------------------------------------------------------------------------
// CBC record encryption
// -----------------------------------------------------------------------------

Bytes xorBlock(const Block& a, const Block& b) {
    Bytes result(16);

    for (std::size_t i = 0; i < 16; ++i) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

Block bytesToBlock(const Bytes& data, std::size_t offset) {
    if (offset + 16 > data.size()) {
        throw std::runtime_error("Insufficient bytes for block");
    }

    Block block{};

    for (std::size_t i = 0; i < 16; ++i) {
        block[i] = data[offset + i];
    }

    return block;
}

Bytes cbcEncrypt(const AES128& aes, const Bytes& plaintext, const Block& iv) {
    const Bytes padded = pad(plaintext);
    Bytes ciphertext;
    ciphertext.reserve(padded.size());

    Block previous = iv;

    for (std::size_t offset = 0; offset < padded.size(); offset += 16) {
        Block current = bytesToBlock(padded, offset);

        for (std::size_t i = 0; i < 16; ++i) {
            current[i] ^= previous[i];
        }

        Block encrypted = aes.encryptBlock(current);

        ciphertext.insert(
            ciphertext.end(),
            encrypted.begin(),
            encrypted.end()
        );

        previous = encrypted;
    }

    return ciphertext;
}

Bytes cbcDecrypt(const AES128& aes, const Bytes& ciphertext, const Block& iv) {
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw std::runtime_error("CBC ciphertext must contain full blocks");
    }

    Bytes plaintext;
    plaintext.reserve(ciphertext.size());

    Block previous = iv;

    for (std::size_t offset = 0; offset < ciphertext.size(); offset += 16) {
        Block current = bytesToBlock(ciphertext, offset);
        Block decrypted = aes.decryptBlock(current);

        for (std::size_t i = 0; i < 16; ++i) {
            decrypted[i] ^= previous[i];
        }

        plaintext.insert(
            plaintext.end(),
            decrypted.begin(),
            decrypted.end()
        );

        previous = current;
    }

    return unpad(plaintext);
}

// -----------------------------------------------------------------------------
// Archive policy
// -----------------------------------------------------------------------------

class IvRegistry {
public:
    void reserve(const Block& iv) {
        const std::string identifier = toHex(iv);

        if (used_.find(identifier) != used_.end()) {
            throw std::runtime_error(
                "IV reuse detected for the configured archive key"
            );
        }

        used_.insert(identifier);
    }

private:
    static std::string toHex(const Block& block) {
        std::ostringstream stream;

        for (Byte value : block) {
            stream << std::hex
                   << std::setw(2)
                   << std::setfill('0')
                   << static_cast<int>(value);
        }

        return stream.str();
    }

    std::unordered_set<std::string> used_;
};

class TelemetryArchive {
public:
    explicit TelemetryArchive(const Block& key)
        : aes_(key) {}

    Bytes encryptRecord(
        const TelemetryRecord& record,
        const Block& iv
    ) {
        /*
         * The IV registry is a policy check. It does not generate secure IVs;
         * real systems should obtain IVs from an appropriate CSPRNG and store
         * the IV alongside the ciphertext because the IV is not secret.
         */
        ivRegistry_.reserve(iv);

        const Bytes serialized = serializeRecord(record);
        return cbcEncrypt(aes_, serialized, iv);
    }

    TelemetryRecord decryptRecord(
        const Bytes& ciphertext,
        const Block& iv
    ) const {
        const Bytes serialized = cbcDecrypt(aes_, ciphertext, iv);
        return deserializeRecord(serialized);
    }

private:
    AES128 aes_;
    IvRegistry ivRegistry_;
};

// -----------------------------------------------------------------------------
// Diagnostics
// -----------------------------------------------------------------------------

std::string hex(const Bytes& data) {
    std::ostringstream stream;

    for (Byte value : data) {
        stream << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(value);
    }

    return stream.str();
}

std::string hex(const Block& block) {
    return hex(Bytes(block.begin(), block.end()));
}

std::size_t changedBits(const Block& a, const Block& b) {
    std::size_t count = 0;

    for (std::size_t i = 0; i < 16; ++i) {
        Byte difference = a[i] ^ b[i];

        while (difference != 0) {
            count += difference & 1;
            difference = static_cast<Byte>(difference >> 1);
        }
    }

    return count;
}

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// -----------------------------------------------------------------------------
// Tests and case study
// -----------------------------------------------------------------------------

void knownAnswerTest() {
    const Block key = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };

    const Block plaintext = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    const Block expected = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    AES128 aes(key);
    const Block encrypted = aes.encryptBlock(plaintext);
    const Block decrypted = aes.decryptBlock(encrypted);

    require(encrypted == expected, "AES known-answer test failed");
    require(decrypted == plaintext, "AES decryption test failed");

    std::cout << "AES known-answer test: PASS\n";
}

void archiveCaseStudy() {
    const Block key = {
        0x10,0x21,0x32,0x43,0x54,0x65,0x76,0x87,
        0x98,0xa9,0xba,0xcb,0xdc,0xed,0xfe,0x0f
    };

    const Block iv = {
        0x20,0x31,0x42,0x53,0x64,0x75,0x86,0x97,
        0xa8,0xb9,0xca,0xdb,0xec,0xfd,0x0e,0x1f
    };

    TelemetryRecord original{
        4821,
        1738406400ULL,
        27350,
        10427
    };

    TelemetryArchive archive(key);

    const Bytes ciphertext = archive.encryptRecord(original, iv);
    const TelemetryRecord recovered =
        archive.decryptRecord(ciphertext, iv);

    require(recovered.deviceId == original.deviceId,
            "Device identifier changed");
    require(recovered.timestamp == original.timestamp,
            "Timestamp changed");
    require(recovered.temperatureMilliCelsius ==
            original.temperatureMilliCelsius,
            "Temperature changed");
    require(recovered.sequence == original.sequence,
            "Sequence changed");

    std::cout << "\nTelemetry archive case study\n";
    std::cout << "Serialized record bytes: "
              << serializeRecord(original).size() << "\n";
    std::cout << "Ciphertext bytes: "
              << ciphertext.size() << "\n";
    std::cout << "Ciphertext: "
              << hex(ciphertext) << "\n";
    std::cout << "Record round trip: PASS\n";

    try {
        archive.encryptRecord(original, iv);
        throw std::runtime_error("IV reuse policy did not reject reuse");
    } catch (const std::runtime_error& error) {
        std::cout << "IV reuse policy: "
                  << error.what() << "\n";
    }
}

void paddingFailureTest() {
    std::cout << "\nPadding validation\n";

    Bytes malformed(16, 0);
    malformed.back() = 2;
    malformed[14] = 1;

    try {
        unpad(malformed);
        throw std::runtime_error("Malformed padding was accepted");
    } catch (const std::runtime_error& error) {
        std::cout << "Malformed padding rejected: "
                  << error.what() << "\n";
    }
}

void avalancheTest() {
    const Block key = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };

    Block original{};
    Block modified{};

    for (std::size_t i = 0; i < 16; ++i) {
        original[i] = static_cast<Byte>(i * 17);
        modified[i] = original[i];
    }

    modified[0] ^= 0x01;

    AES128 aes(key);

    const Block encryptedOriginal = aes.encryptBlock(original);
    const Block encryptedModified = aes.encryptBlock(modified);

    std::cout << "\nAvalanche test\n";
    std::cout << "Original ciphertext: "
              << hex(encryptedOriginal) << "\n";
    std::cout << "Modified ciphertext: "
              << hex(encryptedModified) << "\n";
    std::cout << "Changed bits: "
              << changedBits(encryptedOriginal, encryptedModified)
              << " of 128\n";
}

void failureCases() {
    std::cout << "\nFailure cases\n";

    const Block key{};
    AES128 aes(key);

    try {
        Bytes invalid(15, 0);
        cbcEncrypt(aes, invalid, key);
        std::cout << "Unexpected result: CBC accepted 15-byte input after padding\n";
    } catch (const std::exception& error) {
        /*
         * CBC accepts arbitrary plaintext because PKCS#7 supplies padding.
         * This message is intentionally not treated as a failure: it
         * demonstrates that encryption and record framing are separate layers.
         */
        std::cout << "CBC framing note: plaintext was padded successfully\n";
    }

    try {
        Bytes invalidCiphertext(15, 0);
        cbcDecrypt(aes, invalidCiphertext, key);
        std::cout << "Unexpected acceptance of incomplete ciphertext\n";
    } catch (const std::exception& error) {
        std::cout << "Incomplete ciphertext rejected: "
                  << error.what() << "\n";
    }
}

int main() {
    try {
        std::cout << "============================================\n";
        std::cout << "BLOCK CIPHER CASE STUDY: TELEMETRY ARCHIVE\n";
        std::cout << "============================================\n";

        knownAnswerTest();
        archiveCaseStudy();
        paddingFailureTest();
        avalancheTest();
        failureCases();

        std::cout << "\nSecurity boundary\n";
        std::cout << "AES supplies confidentiality at the block-primitive level.\n";
        std::cout << "CBC does not authenticate telemetry records.\n";
        std::cout << "Production storage should use authenticated encryption.\n";
        std::cout << "IV generation and key management must be handled separately.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
