#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>

/*
 * Enterprise artifact transport case study using ChaCha20.
 *
 * The system models a service that encrypts repository build artifacts before
 * they are stored in an object store. The example deliberately implements the
 * RFC 8439 ChaCha20 primitive instead of using an external cryptographic
 * library, so the state layout, quarter rounds, counter, and serialization
 * remain inspectable.
 *
 * Raw ChaCha20 is a confidentiality primitive. The ArtifactEnvelope class
 * therefore marks the result as unauthenticated. A production protocol should
 * use an AEAD construction such as ChaCha20-Poly1305.
 */

using Byte = std::uint8_t;
using Word = std::uint32_t;

constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t BLOCK_SIZE = 64;
constexpr std::uint64_t MAX_COUNTER = 0xFFFFFFFFULL;

using Key = std::array<Byte, KEY_SIZE>;
using Nonce = std::array<Byte, NONCE_SIZE>;
using Block = std::array<Byte, BLOCK_SIZE>;

Word rotl32(Word value, unsigned amount) {
    return static_cast<Word>((value << amount) | (value >> (32U - amount)));
}

void quarter_round(std::array<Word, 16>& state,
                   std::size_t a,
                   std::size_t b,
                   std::size_t c,
                   std::size_t d) {
    state[a] = state[a] + state[b];
    state[d] ^= state[a];
    state[d] = rotl32(state[d], 16);

    state[c] = state[c] + state[d];
    state[b] ^= state[c];
    state[b] = rotl32(state[b], 12);

    state[a] = state[a] + state[b];
    state[d] ^= state[a];
    state[d] = rotl32(state[d], 8);

    state[c] = state[c] + state[d];
    state[b] ^= state[c];
    state[b] = rotl32(state[b], 7);
}

Word load32_le(const Byte* bytes) {
    return static_cast<Word>(bytes[0])
        | (static_cast<Word>(bytes[1]) << 8)
        | (static_cast<Word>(bytes[2]) << 16)
        | (static_cast<Word>(bytes[3]) << 24);
}

void store32_le(Byte* bytes, Word value) {
    bytes[0] = static_cast<Byte>(value);
    bytes[1] = static_cast<Byte>(value >> 8);
    bytes[2] = static_cast<Byte>(value >> 16);
    bytes[3] = static_cast<Byte>(value >> 24);
}

std::array<Word, 16> initial_state(
    const Key& key,
    std::uint32_t counter,
    const Nonce& nonce
) {
    static constexpr std::array<Byte, 16> constants{
        'e', 'x', 'p', 'a', 'n', 'd', ' ', '3',
        '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
    };

    std::array<Word, 16> state{};

    state[0] = load32_le(constants.data());
    state[1] = load32_le(constants.data() + 4);
    state[2] = load32_le(constants.data() + 8);
    state[3] = load32_le(constants.data() + 12);

    for (std::size_t i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key.data() + i * 4);
    }

    state[12] = counter;
    state[13] = load32_le(nonce.data());
    state[14] = load32_le(nonce.data() + 4);
    state[15] = load32_le(nonce.data() + 8);

    return state;
}

Block chacha20_block(
    const Key& key,
    std::uint32_t counter,
    const Nonce& nonce
) {
    auto original = initial_state(key, counter, nonce);
    auto working = original;

    for (int round = 0; round < 10; ++round) {
        quarter_round(working, 0, 4, 8, 12);
        quarter_round(working, 1, 5, 9, 13);
        quarter_round(working, 2, 6, 10, 14);
        quarter_round(working, 3, 7, 11, 15);

        quarter_round(working, 0, 5, 10, 15);
        quarter_round(working, 1, 6, 11, 12);
        quarter_round(working, 2, 7, 8, 13);
        quarter_round(working, 3, 4, 9, 14);
    }

    Block output{};

    for (std::size_t i = 0; i < 16; ++i) {
        const Word result = working[i] + original[i];
        store32_le(output.data() + i * 4, result);
    }

    return output;
}

std::vector<Byte> chacha20(
    const Key& key,
    const Nonce& nonce,
    const std::vector<Byte>& input,
    std::uint32_t initial_counter = 1
) {
    if (input.empty()) {
        return {};
    }

    const std::uint64_t block_count =
        (static_cast<std::uint64_t>(input.size()) + BLOCK_SIZE - 1) /
        BLOCK_SIZE;

    if (static_cast<std::uint64_t>(initial_counter) + block_count - 1 >
        MAX_COUNTER) {
        throw std::overflow_error("ChaCha20 counter space exhausted");
    }

    std::vector<Byte> output(input.size());

    for (std::uint64_t block = 0; block < block_count; ++block) {
        const auto stream = chacha20_block(
            key,
            static_cast<std::uint32_t>(initial_counter + block),
            nonce
        );

        const std::size_t offset =
            static_cast<std::size_t>(block * BLOCK_SIZE);

        const std::size_t length =
            std::min(BLOCK_SIZE, input.size() - offset);

        for (std::size_t i = 0; i < length; ++i) {
            output[offset + i] = input[offset + i] ^ stream[i];
        }
    }

    return output;
}

std::vector<Byte> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }

    std::vector<Byte> result;
    result.reserve(hex.size() / 2);

    auto value = [](char c) -> Byte {
        if (c >= '0' && c <= '9') return static_cast<Byte>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<Byte>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<Byte>(c - 'A' + 10);
        throw std::invalid_argument("Invalid hexadecimal character");
    };

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        result.push_back(
            static_cast<Byte>((value(hex[i]) << 4) | value(hex[i + 1]))
        );
    }

    return result;
}

std::string to_hex(const std::vector<Byte>& data) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (Byte value : data) {
        output << std::setw(2) << static_cast<unsigned>(value);
    }

    return output.str();
}

template <std::size_t N>
std::string to_hex(const std::array<Byte, N>& data) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (Byte value : data) {
        output << std::setw(2) << static_cast<unsigned>(value);
    }

    return output.str();
}

struct ArtifactEnvelope {
    std::uint8_t version;
    Nonce nonce;
    std::uint32_t initial_counter;
    std::vector<Byte> ciphertext;

    bool authenticated() const {
        return false;
    }
};

class SecureArtifactStore {
public:
    explicit SecureArtifactStore(Key key)
        : key_(key) {}

    ArtifactEnvelope encrypt(
        const std::vector<Byte>& artifact,
        const Nonce& nonce
    ) const {
        ArtifactEnvelope envelope{
            1,
            nonce,
            1,
            chacha20(key_, nonce, artifact, 1)
        };

        return envelope;
    }

    std::vector<Byte> decrypt(const ArtifactEnvelope& envelope) const {
        if (envelope.version != 1) {
            throw std::invalid_argument("Unsupported envelope version");
        }

        return chacha20(
            key_,
            envelope.nonce,
            envelope.ciphertext,
            envelope.initial_counter
        );
    }

private:
    Key key_;
};

Key deterministic_key() {
    Key key{};

    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<Byte>(i);
    }

    return key;
}

Nonce deterministic_nonce() {
    Nonce nonce{};
    nonce[0] = 0x00;
    nonce[1] = 0x00;
    nonce[2] = 0x00;
    nonce[3] = 0x09;
    nonce[4] = 0x00;
    nonce[5] = 0x00;
    nonce[6] = 0x00;
    nonce[7] = 0x4a;
    nonce[8] = 0x00;
    nonce[9] = 0x00;
    nonce[10] = 0x00;
    nonce[11] = 0x00;
    return nonce;
}

void verify_rfc_vector() {
    const Key key = deterministic_key();
    const Nonce nonce = deterministic_nonce();

    const std::string text =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, sunscreen would be it.";

    const std::vector<Byte> plaintext(text.begin(), text.end());

    const auto expected = from_hex(
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785a30"
        "7b5d6e5e6a0b"
    );

    const auto ciphertext = chacha20(key, nonce, plaintext, 1);

    if (ciphertext != expected) {
        throw std::runtime_error("RFC 8439 vector verification failed");
    }

    const auto recovered = chacha20(key, nonce, ciphertext, 1);

    if (recovered != plaintext) {
        throw std::runtime_error("ChaCha20 round-trip failed");
    }

    std::cout << "RFC 8439 vector: PASS\n";
    std::cout << "Round trip: PASS\n";
}

void demonstrate_large_artifact() {
    /*
     * A repository artifact may span many ChaCha20 blocks. The implementation
     * increments the 32-bit counter for each 64-byte block while retaining the
     * same key and nonce for that message.
     */
    Key key{};
    Nonce nonce{};

    std::random_device random_device;

    for (Byte& value : key) {
        value = static_cast<Byte>(random_device());
    }

    for (Byte& value : nonce) {
        value = static_cast<Byte>(random_device());
    }

    std::vector<Byte> artifact(4097);

    for (std::size_t i = 0; i < artifact.size(); ++i) {
        artifact[i] = static_cast<Byte>(i % 251);
    }

    SecureArtifactStore store(key);

    const auto envelope = store.encrypt(artifact, nonce);
    const auto recovered = store.decrypt(envelope);

    if (recovered != artifact) {
        throw std::runtime_error("Large artifact recovery failed");
    }

    std::cout << "Large artifact recovery: PASS\n";
    std::cout << "Artifact bytes: " << artifact.size() << '\n';
    std::cout << "Ciphertext bytes: " << envelope.ciphertext.size() << '\n';
    std::cout << "Authenticated: "
              << (envelope.authenticated() ? "yes" : "no") << '\n';
}

void demonstrate_nonce_reuse_hazard() {
    /*
     * Stream ciphers have C = P XOR K. Reusing a nonce with the same key
     * regenerates the same K, making C1 XOR C2 equal P1 XOR P2.
     */
    Key key = deterministic_key();
    Nonce nonce = deterministic_nonce();

    const std::string a = "artifact=release-A";
    const std::string b = "artifact=release-B";

    std::vector<Byte> plaintext_a(a.begin(), a.end());
    std::vector<Byte> plaintext_b(b.begin(), b.end());

    const auto ciphertext_a = chacha20(key, nonce, plaintext_a);
    const auto ciphertext_b = chacha20(key, nonce, plaintext_b);

    const std::size_t length =
        std::min(ciphertext_a.size(), ciphertext_b.size());

    std::vector<Byte> ciphertext_xor(length);
    std::vector<Byte> plaintext_xor(length);

    for (std::size_t i = 0; i < length; ++i) {
        ciphertext_xor[i] = ciphertext_a[i] ^ ciphertext_b[i];
        plaintext_xor[i] = plaintext_a[i] ^ plaintext_b[i];
    }

    if (ciphertext_xor != plaintext_xor) {
        throw std::runtime_error("Nonce-reuse demonstration failed");
    }

    std::cout << "Nonce-reuse XOR exposure: demonstrated\n";
}

int main() {
    try {
        std::cout << "ChaCha20 repository artifact case study\n";
        std::cout << "========================================\n";

        verify_rfc_vector();

        const auto key = deterministic_key();
        const auto nonce = deterministic_nonce();
        const auto block = chacha20_block(key, 1, nonce);

        std::cout << "First keystream block: "
                  << to_hex(block) << '\n';

        demonstrate_large_artifact();
        demonstrate_nonce_reuse_hazard();

        std::cout << "\nEngineering constraints\n";
        std::cout << "Raw ChaCha20 supplies confidentiality, not integrity.\n";
        std::cout << "Nonce uniqueness is mandatory for each key.\n";
        std::cout << "Production artifact storage should use authenticated encryption.\n";
        std::cout << "The key must never be stored beside the ciphertext.\n";
    }
    catch (const std::exception& error) {
        std::cerr << "Failure: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
