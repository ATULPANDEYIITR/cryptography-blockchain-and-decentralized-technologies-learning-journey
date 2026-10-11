#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/*
 * Encryption-mode governance case study.
 *
 * Scenario:
 * A financial records service must select an encryption mode for different
 * workloads. The engine evaluates confidentiality, integrity, nonce rules,
 * padding behavior, and operational constraints.
 *
 * The block transformation used by this educational program is intentionally
 * not cryptographically secure. It exists to make mode behavior executable.
 * Production systems should use an audited cryptographic library.
 */

constexpr std::size_t BLOCK_SIZE = 16;

using Block = std::array<std::uint8_t, BLOCK_SIZE>;
using Bytes = std::vector<std::uint8_t>;

Block xor_block(const Block& a, const Block& b) {
    Block result{};

    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        result[i] = a[i] ^ b[i];
    }

    return result;
}

Block hash_like_block(const Block& input, std::uint8_t round) {
    Block result{};

    std::uint32_t state = 2166136261u;

    for (std::uint8_t byte : input) {
        state ^= byte;
        state *= 16777619u;
    }

    state ^= static_cast<std::uint32_t>(round) * 0x9E3779B9u;

    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        state ^= state >> 13;
        state *= 0x85EBCA6Bu;
        state ^= state >> 16;
        result[i] = static_cast<std::uint8_t>(state >> ((i % 4) * 8));
    }

    return result;
}

class EducationalBlockCipher {
public:
    explicit EducationalBlockCipher(Block key) : key_(key) {}

    Block encrypt_block(const Block& block) const {
        Block state = block;

        for (std::uint8_t round = 1; round <= 8; ++round) {
            state = xor_block(state, keyed_round(state, round));
        }

        return state;
    }

    Block decrypt_block(const Block& block) const {
        Block state = block;

        for (int round = 8; round >= 1; --round) {
            state = xor_block(
                state,
                keyed_round(state, static_cast<std::uint8_t>(round))
            );
        }

        return state;
    }

private:
    Block keyed_round(const Block& block, std::uint8_t round) const {
        Block mixed = block;

        for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
            mixed[i] ^= key_[i];
        }

        return hash_like_block(mixed, round);
    }

    Block key_;
};

Bytes pkcs7_pad(const Bytes& input) {
    std::size_t padding = BLOCK_SIZE - (input.size() % BLOCK_SIZE);

    Bytes output = input;
    output.insert(output.end(), padding, static_cast<std::uint8_t>(padding));

    return output;
}

Bytes pkcs7_unpad(const Bytes& input) {
    if (input.empty() || input.size() % BLOCK_SIZE != 0) {
        throw std::invalid_argument("Invalid padded data length");
    }

    const std::uint8_t padding = input.back();

    if (padding == 0 || padding > BLOCK_SIZE || padding > input.size()) {
        throw std::invalid_argument("Invalid PKCS#7 padding");
    }

    for (std::size_t i = input.size() - padding; i < input.size(); ++i) {
        if (input[i] != padding) {
            throw std::invalid_argument("Invalid PKCS#7 padding bytes");
        }
    }

    return Bytes(input.begin(), input.end() - padding);
}

Bytes ecb_encrypt(
    const EducationalBlockCipher& cipher,
    const Bytes& plaintext
) {
    const Bytes padded = pkcs7_pad(plaintext);
    Bytes output;

    for (std::size_t offset = 0; offset < padded.size(); offset += BLOCK_SIZE) {
        Block block{};

        std::copy_n(
            padded.begin() + static_cast<std::ptrdiff_t>(offset),
            BLOCK_SIZE,
            block.begin()
        );

        const Block encrypted = cipher.encrypt_block(block);
        output.insert(output.end(), encrypted.begin(), encrypted.end());
    }

    return output;
}

Bytes cbc_encrypt(
    const EducationalBlockCipher& cipher,
    const Bytes& plaintext,
    const Block& iv
) {
    const Bytes padded = pkcs7_pad(plaintext);
    Bytes output;
    Block previous = iv;

    for (std::size_t offset = 0; offset < padded.size(); offset += BLOCK_SIZE) {
        Block block{};

        std::copy_n(
            padded.begin() + static_cast<std::ptrdiff_t>(offset),
            BLOCK_SIZE,
            block.begin()
        );

        const Block chained = xor_block(block, previous);
        const Block encrypted = cipher.encrypt_block(chained);

        output.insert(output.end(), encrypted.begin(), encrypted.end());
        previous = encrypted;
    }

    return output;
}

Bytes ctr_crypt(
    const EducationalBlockCipher& cipher,
    const Bytes& input,
    const std::array<std::uint8_t, 8>& nonce
) {
    Bytes output(input.size());

    for (
        std::size_t offset = 0, counter = 0;
        offset < input.size();
        offset += BLOCK_SIZE, ++counter
    ) {
        Block counter_block{};

        std::copy(nonce.begin(), nonce.end(), counter_block.begin());

        for (int byte = 0; byte < 8; ++byte) {
            counter_block[15 - byte] =
                static_cast<std::uint8_t>(counter >> (byte * 8));
        }

        const Block keystream = cipher.encrypt_block(counter_block);

        const std::size_t chunk =
            std::min(BLOCK_SIZE, input.size() - offset);

        for (std::size_t i = 0; i < chunk; ++i) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
    }

    return output;
}

enum class Mode {
    ECB,
    CBC,
    CTR,
    AEAD
};

struct ModePolicy {
    Mode mode;
    bool authentication;
    bool padding;
    bool parallelEncryption;
    bool requiresUniqueNonce;
    std::string deploymentRisk;
};

std::string mode_name(Mode mode) {
    switch (mode) {
        case Mode::ECB:
            return "ECB";
        case Mode::CBC:
            return "CBC";
        case Mode::CTR:
            return "CTR";
        case Mode::AEAD:
            return "AEAD";
    }

    return "Unknown";
}

class MergeEligibilityEngine {
public:
    void add_policy(Mode mode, ModePolicy policy) {
        policies_[mode] = std::move(policy);
    }

    bool suitable_for_financial_record(Mode mode) const {
        const auto iterator = policies_.find(mode);

        if (iterator == policies_.end()) {
            return false;
        }

        const ModePolicy& policy = iterator->second;

        return policy.authentication &&
               !policy.padding &&
               policy.requiresUniqueNonce;
    }

    void print_assessment() const {
        for (const auto& [mode, policy] : policies_) {
            std::cout << mode_name(mode) << '\n';
            std::cout << "  authentication: "
                      << std::boolalpha
                      << policy.authentication << '\n';
            std::cout << "  padding: "
                      << policy.padding << '\n';
            std::cout << "  parallel encryption: "
                      << policy.parallelEncryption << '\n';
            std::cout << "  unique nonce required: "
                      << policy.requiresUniqueNonce << '\n';
            std::cout << "  deployment risk: "
                      << policy.deploymentRisk << "\n\n";
        }
    }

private:
    std::map<Mode, ModePolicy> policies_;
};

std::string bytes_to_hex(const Bytes& data) {
    std::ostringstream stream;

    for (std::uint8_t byte : data) {
        stream << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return stream.str();
}

Block random_block() {
    std::random_device device;
    std::mt19937 generator(device());
    std::uniform_int_distribution<int> distribution(0, 255);

    Block result{};

    for (auto& byte : result) {
        byte = static_cast<std::uint8_t>(distribution(generator));
    }

    return result;
}

std::array<std::uint8_t, 8> random_nonce() {
    std::random_device device;
    std::mt19937 generator(device());
    std::uniform_int_distribution<int> distribution(0, 255);

    std::array<std::uint8_t, 8> nonce{};

    for (auto& byte : nonce) {
        byte = static_cast<std::uint8_t>(distribution(generator));
    }

    return nonce;
}

Bytes text_bytes(std::string_view text) {
    return Bytes(text.begin(), text.end());
}

int main() {
    std::cout << "=== Encryption Mode Governance Case Study ===\n\n";

    MergeEligibilityEngine engine;

    engine.add_policy(
        Mode::ECB,
        {
            Mode::ECB,
            false,
            true,
            true,
            false,
            "Repeated blocks reveal structure"
        }
    );

    engine.add_policy(
        Mode::CBC,
        {
            Mode::CBC,
            false,
            true,
            false,
            false,
            "Unauthenticated ciphertext is malleable"
        }
    );

    engine.add_policy(
        Mode::CTR,
        {
            Mode::CTR,
            false,
            false,
            true,
            true,
            "Nonce reuse exposes plaintext relationships"
        }
    );

    engine.add_policy(
        Mode::AEAD,
        {
            Mode::AEAD,
            true,
            false,
            true,
            true,
            "Nonce misuse and key-management errors remain critical"
        }
    );

    engine.print_assessment();

    std::cout << "Suitable for financial records:\n";

    for (Mode mode : {Mode::ECB, Mode::CBC, Mode::CTR, Mode::AEAD}) {
        std::cout << "  " << mode_name(mode)
                  << ": "
                  << std::boolalpha
                  << engine.suitable_for_financial_record(mode)
                  << '\n';
    }

    std::cout << "\n=== CBC record processing ===\n";

    const Block key = random_block();
    const EducationalBlockCipher cipher(key);
    const Block iv = random_block();

    const Bytes financial_record = text_bytes(
        "account=AC-8821;amount=125000;currency=INR"
    );

    const Bytes cbc_ciphertext = cbc_encrypt(
        cipher,
        financial_record,
        iv
    );

    std::cout << "CBC ciphertext: "
              << bytes_to_hex(cbc_ciphertext)
              << '\n';

    std::cout << "\n=== CTR confidentiality behavior ===\n";

    const auto nonce = random_nonce();

    const Bytes original = text_bytes(
        "warehouse=LKO;quantity=840;status=verified"
    );

    const Bytes ctr_ciphertext = ctr_crypt(
        cipher,
        original,
        nonce
    );

    const Bytes recovered = ctr_crypt(
        cipher,
        ctr_ciphertext,
        nonce
    );

    std::cout << "CTR round trip successful: "
              << std::boolalpha
              << (recovered == original)
              << '\n';

    const Bytes second_message = text_bytes(
        "warehouse=LKO;quantity=120;status=pending"
    );

    const Bytes second_ciphertext = ctr_crypt(
        cipher,
        second_message,
        nonce
    );

    Bytes xor_ciphertexts;
    const std::size_t comparable =
        std::min(ctr_ciphertext.size(), second_ciphertext.size());

    xor_ciphertexts.reserve(comparable);

    for (std::size_t i = 0; i < comparable; ++i) {
        xor_ciphertexts.push_back(
            ctr_ciphertext[i] ^ second_ciphertext[i]
        );
    }

    std::cout << "Nonce reuse produces related ciphertexts: "
              << std::boolalpha
              << !xor_ciphertexts.empty()
              << '\n';

    std::cout << "\n=== ECB structural warning ===\n";

    const Bytes repeated = text_bytes(
        "BLOCK-REPEAT-16"
        "BLOCK-REPEAT-16"
        "BLOCK-REPEAT-16"
    );

    const Bytes ecb_ciphertext = ecb_encrypt(
        cipher,
        repeated
    );

    std::cout << "ECB ciphertext size: "
              << ecb_ciphertext.size()
              << " bytes\n";

    std::cout << "ECB processes blocks independently, so structured data can "
                 "leak repeated-block relationships.\n";

    std::cout << "\n=== Operational constraints ===\n";
    std::cout << "CBC needs correct IV generation and separate integrity "
                 "protection.\n";
    std::cout << "CTR needs strict nonce uniqueness under a key.\n";
    std::cout << "AEAD combines confidentiality and integrity but does not "
                 "remove nonce-management requirements.\n";
    std::cout << "Cryptographic primitives should come from audited libraries "
                 "rather than application code.\n";

    return 0;
}
