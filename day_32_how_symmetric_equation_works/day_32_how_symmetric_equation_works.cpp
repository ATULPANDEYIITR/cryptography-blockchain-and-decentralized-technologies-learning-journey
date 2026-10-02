#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

/*
 * Symmetric Encryption Case Study: Secure Message Gateway
 *
 * This C++17 program models the architecture of a service that receives
 * confidential messages from applications that share secret keys.
 *
 * The case study deliberately separates:
 *
 *   plaintext
 *       |
 *       v
 *   symmetric encryption
 *       |
 *       +--> ciphertext
 *       +--> nonce
 *       +--> authentication tag
 *       +--> visible protocol metadata
 *
 * The program implements a self-contained educational authenticated stream
 * construction based on a cryptographic-style hash mixer. It is NOT a
 * production cryptosystem. Its purpose is to make the mechanics of shared
 * secret encryption, nonce use, authentication, key selection, validation,
 * replay handling, and failure states visible in a realistic system.
 *
 * Production applications should use a reviewed cryptographic library and
 * standardized AEAD algorithms such as AES-GCM or ChaCha20-Poly1305 rather
 * than implementing cryptography themselves.
 */

namespace secure_gateway {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;

constexpr std::size_t KeySize = 32;
constexpr std::size_t NonceSize = 12;
constexpr std::size_t TagSize = 16;


/* -------------------------------------------------------------------------
 * Hexadecimal representation
 * ------------------------------------------------------------------------- */

std::string to_hex(const Bytes& bytes) {
    std::ostringstream output;

    for (Byte value : bytes) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(value);
    }

    return output.str();
}


/* -------------------------------------------------------------------------
 * Educational 64-bit mixing function
 * ------------------------------------------------------------------------- */

std::uint64_t rotate_left(
    std::uint64_t value,
    unsigned int amount
) {
    amount %= 64;

    if (amount == 0) {
        return value;
    }

    return (value << amount) | (value >> (64 - amount));
}


std::uint64_t mix_word(std::uint64_t value) {
    /*
     * The avalanche-oriented operations make small input differences spread
     * through the resulting state. This resembles the kind of diffusion
     * expected from cryptographic primitives, but this function is not itself
     * a cryptographic hash or cipher.
     */
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}


std::uint64_t load_word(
    const Bytes& data,
    std::size_t offset
) {
    std::uint64_t result = 0;

    for (std::size_t index = 0; index < 8; ++index) {
        result <<= 8;

        if (offset + index < data.size()) {
            result |= data[offset + index];
        }
    }

    return result;
}


/* -------------------------------------------------------------------------
 * Educational keyed digest
 * ------------------------------------------------------------------------- */

Bytes keyed_digest(
    const Bytes& key,
    const Bytes& input
) {
    if (key.empty()) {
        throw std::invalid_argument("authentication key must not be empty");
    }

    std::uint64_t state_a = 0x243f6a8885a308d3ULL;
    std::uint64_t state_b = 0x13198a2e03707344ULL;

    for (std::size_t index = 0; index < key.size(); ++index) {
        state_a = mix_word(
            state_a ^
            (static_cast<std::uint64_t>(key[index]) << (index % 8))
        );

        state_b = mix_word(
            state_b +
            static_cast<std::uint64_t>(key[index]) +
            index
        );
    }

    for (std::size_t offset = 0; offset < input.size(); offset += 8) {
        const std::uint64_t word = load_word(input, offset);

        state_a = mix_word(
            state_a ^
            word ^
            static_cast<std::uint64_t>(offset)
        );

        state_b = mix_word(
            state_b +
            rotate_left(word, static_cast<unsigned int>(offset % 63 + 1))
        );
    }

    Bytes result;
    result.reserve(32);

    for (int round = 0; round < 4; ++round) {
        state_a = mix_word(
            state_a ^
            rotate_left(state_b, static_cast<unsigned int>(round * 11 + 3))
        );

        state_b = mix_word(
            state_b ^
            rotate_left(state_a, static_cast<unsigned int>(round * 7 + 5))
        );

        for (int shift = 56; shift >= 0; shift -= 8) {
            result.push_back(
                static_cast<Byte>((state_a >> shift) & 0xff)
            );
        }

        for (int shift = 56; shift >= 0; shift -= 8) {
            result.push_back(
                static_cast<Byte>((state_b >> shift) & 0xff)
            );
        }
    }

    result.resize(32);
    return result;
}


/* -------------------------------------------------------------------------
 * Constant-time comparison
 * ------------------------------------------------------------------------- */

bool constant_time_equal(
    const Bytes& left,
    const Bytes& right
) {
    /*
     * Do not return immediately when a byte differs. Processing every byte
     * makes timing less dependent on the position of the first mismatch.
     */
    const std::size_t max_size = std::max(left.size(), right.size());
    std::uint8_t difference =
        static_cast<std::uint8_t>(left.size() ^ right.size());

    for (std::size_t index = 0; index < max_size; ++index) {
        const Byte left_byte =
            index < left.size() ? left[index] : 0;

        const Byte right_byte =
            index < right.size() ? right[index] : 0;

        difference |= static_cast<Byte>(left_byte ^ right_byte);
    }

    return difference == 0;
}


/* -------------------------------------------------------------------------
 * Shared-key representation
 * ------------------------------------------------------------------------- */

struct SecretKey {
    std::string key_id;
    Bytes material;
};


/* -------------------------------------------------------------------------
 * Random key and nonce generation
 * ------------------------------------------------------------------------- */

class RandomSource {
public:
    RandomSource()
        : engine_(
              std::random_device{}()
          ) {}

    Bytes bytes(std::size_t count) {
        Bytes result(count);

        /*
         * This example uses std::random_device to model entropy acquisition.
         * Cryptographic applications should obtain keys/nonces through the
         * operating system CSPRNG or a vetted cryptographic library.
         */
        std::uniform_int_distribution<unsigned int> distribution(0, 255);

        for (Byte& value : result) {
            value = static_cast<Byte>(distribution(engine_));
        }

        return result;
    }

private:
    std::mt19937_64 engine_;
};


/* -------------------------------------------------------------------------
 * Encrypted message
 * ------------------------------------------------------------------------- */

struct EncryptedMessage {
    std::string key_id;
    Bytes nonce;
    Bytes ciphertext;
    Bytes authentication_tag;
    Bytes associated_data;
};


/* -------------------------------------------------------------------------
 * Educational authenticated stream cipher
 * ------------------------------------------------------------------------- */

class EducationalAead {
public:
    explicit EducationalAead(RandomSource& random)
        : random_(random) {}

    EncryptedMessage encrypt(
        const SecretKey& key,
        const Bytes& plaintext,
        const Bytes& associated_data
    ) {
        validate_key(key);
        validate_data_size(plaintext);
        validate_data_size(associated_data);

        EncryptedMessage message;
        message.key_id = key.key_id;
        message.nonce = random_.bytes(NonceSize);
        message.associated_data = associated_data;

        const Bytes stream = generate_keystream(
            key.material,
            message.nonce,
            plaintext.size()
        );

        message.ciphertext = xor_bytes(plaintext, stream);

        /*
         * The tag covers protocol identity, nonce, AAD, and ciphertext.
         * Authenticating the nonce and metadata prevents an attacker from
         * changing those fields independently of the ciphertext.
         */
        const Bytes authentication_input = compose_authentication_input(
            key.key_id,
            message.nonce,
            message.associated_data,
            message.ciphertext
        );

        const Bytes full_tag = keyed_digest(
            key.material,
            authentication_input
        );

        message.authentication_tag.assign(
            full_tag.begin(),
            full_tag.begin() + TagSize
        );

        return message;
    }

    Bytes decrypt(
        const SecretKey& key,
        const EncryptedMessage& message
    ) const {
        validate_key(key);

        if (message.key_id != key.key_id) {
            throw std::runtime_error("message references a different key ID");
        }

        if (message.nonce.size() != NonceSize) {
            throw std::runtime_error("invalid nonce size");
        }

        if (message.authentication_tag.size() != TagSize) {
            throw std::runtime_error("invalid authentication tag size");
        }

        const Bytes authentication_input = compose_authentication_input(
            message.key_id,
            message.nonce,
            message.associated_data,
            message.ciphertext
        );

        const Bytes expected_full_tag = keyed_digest(
            key.material,
            authentication_input
        );

        const Bytes expected_tag(
            expected_full_tag.begin(),
            expected_full_tag.begin() + TagSize
        );

        /*
         * Authentication is checked before plaintext is released. This is the
         * critical security boundary for an AEAD-style message processor.
         */
        if (!constant_time_equal(
                expected_tag,
                message.authentication_tag
            )) {
            throw std::runtime_error(
                "authentication failed: ciphertext or metadata was modified"
            );
        }

        const Bytes stream = generate_keystream(
            key.material,
            message.nonce,
            message.ciphertext.size()
        );

        return xor_bytes(message.ciphertext, stream);
    }

private:
    static void validate_key(const SecretKey& key) {
        if (key.key_id.empty()) {
            throw std::invalid_argument("key ID must not be empty");
        }

        if (key.material.size() != KeySize) {
            throw std::invalid_argument(
                "educational gateway requires a 256-bit key"
            );
        }
    }

    static void validate_data_size(const Bytes& data) {
        constexpr std::size_t MaxMessageSize = 16 * 1024 * 1024;

        if (data.size() > MaxMessageSize) {
            throw std::length_error(
                "message exceeds configured maximum size"
            );
        }
    }

    static Bytes xor_bytes(
        const Bytes& left,
        const Bytes& right
    ) {
        if (left.size() != right.size()) {
            throw std::logic_error(
                "keystream and plaintext must have equal length"
            );
        }

        Bytes result(left.size());

        for (std::size_t index = 0; index < left.size(); ++index) {
            result[index] = left[index] ^ right[index];
        }

        return result;
    }

    static Bytes generate_keystream(
        const Bytes& key,
        const Bytes& nonce,
        std::size_t length
    ) {
        Bytes stream;
        stream.reserve(length);

        std::uint64_t counter = 0;

        while (stream.size() < length) {
            Bytes input = nonce;

            for (int shift = 56; shift >= 0; shift -= 8) {
                input.push_back(
                    static_cast<Byte>((counter >> shift) & 0xff)
                );
            }

            const Bytes block = keyed_digest(key, input);

            const std::size_t remaining =
                length - stream.size();

            const std::size_t take =
                std::min<std::size_t>(remaining, block.size());

            stream.insert(
                stream.end(),
                block.begin(),
                block.begin() + static_cast<std::ptrdiff_t>(take)
            );

            ++counter;
        }

        return stream;
    }

    static void append_length(
        Bytes& output,
        std::size_t length
    ) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            output.push_back(
                static_cast<Byte>(
                    (static_cast<std::uint64_t>(length) >> shift) & 0xff
                )
            );
        }
    }

    static Bytes compose_authentication_input(
        const std::string& key_id,
        const Bytes& nonce,
        const Bytes& associated_data,
        const Bytes& ciphertext
    ) {
        Bytes input;

        /*
         * Length-prefixing avoids ambiguity such as concatenating two fields
         * where different field boundaries could create identical byte
         * sequences.
         */
        append_length(input, key_id.size());
        input.insert(
            input.end(),
            key_id.begin(),
            key_id.end()
        );

        append_length(input, nonce.size());
        input.insert(
            input.end(),
            nonce.begin(),
            nonce.end()
        );

        append_length(input, associated_data.size());
        input.insert(
            input.end(),
            associated_data.begin(),
            associated_data.end()
        );

        append_length(input, ciphertext.size());
        input.insert(
            input.end(),
            ciphertext.begin(),
            ciphertext.end()
        );

        return input;
    }

    RandomSource& random_;
};


/* -------------------------------------------------------------------------
 * Replay protection
 * ------------------------------------------------------------------------- */

class ReplayGuard {
public:
    bool accept(
        const std::string& sender,
        const Bytes& nonce
    ) {
        const std::string fingerprint =
            sender + ":" + to_hex(nonce);

        /*
         * A nonce can be authenticated and still be replayed. Encryption does
         * not automatically provide freshness, so applications may need a
         * separate replay policy.
         */
        return seen_.insert(fingerprint).second;
    }

private:
    std::unordered_map<std::string, bool> seen_;
};


/* -------------------------------------------------------------------------
 * Gateway policy
 * ------------------------------------------------------------------------- */

struct GatewayRequest {
    std::string sender;
    std::string key_id;
    Bytes plaintext;
    Bytes associated_data;
};


class MessageGateway {
public:
    explicit MessageGateway(RandomSource& random)
        : cipher_(random) {}

    void register_key(SecretKey key) {
        if (key.key_id.empty()) {
            throw std::invalid_argument("cannot register empty key ID");
        }

        if (key.material.size() != KeySize) {
            throw std::invalid_argument(
                "gateway keys must be exactly 32 bytes"
            );
        }

        keys_[key.key_id] = std::move(key);
    }

    EncryptedMessage protect(
        const GatewayRequest& request
    ) {
        const SecretKey* key = find_key(request.key_id);

        if (key == nullptr) {
            throw std::runtime_error("unknown encryption key ID");
        }

        if (request.sender.empty()) {
            throw std::invalid_argument("sender identity is required");
        }

        return cipher_.encrypt(
            *key,
            request.plaintext,
            request.associated_data
        );
    }

    Bytes consume(
        const GatewayRequest& request,
        const EncryptedMessage& encrypted
    ) {
        const SecretKey* key = find_key(encrypted.key_id);

        if (key == nullptr) {
            throw std::runtime_error(
                "cannot decrypt: key ID is unavailable"
            );
        }

        /*
         * Replay checking happens before delivering plaintext to the
         * application. Authentication is still performed by the cipher.
         */
        if (!replay_guard_.accept(
                request.sender,
                encrypted.nonce
            )) {
            throw std::runtime_error(
                "replay rejected: nonce was already processed"
            );
        }

        return cipher_.decrypt(*key, encrypted);
    }

private:
    const SecretKey* find_key(
        const std::string& key_id
    ) const {
        const auto iterator = keys_.find(key_id);

        if (iterator == keys_.end()) {
            return nullptr;
        }

        return &iterator->second;
    }

    std::unordered_map<std::string, SecretKey> keys_;
    EducationalAead cipher_;
    ReplayGuard replay_guard_;
};


/* -------------------------------------------------------------------------
 * Demonstration helpers
 * ------------------------------------------------------------------------- */

Bytes bytes_from_string(std::string_view value) {
    return Bytes(value.begin(), value.end());
}


void print_message(
    const EncryptedMessage& message
) {
    std::cout << "Key ID: " << message.key_id << '\n';
    std::cout << "Nonce: " << to_hex(message.nonce) << '\n';
    std::cout << "Ciphertext: " << to_hex(message.ciphertext) << '\n';
    std::cout << "Authentication tag: "
              << to_hex(message.authentication_tag)
              << '\n';
    std::cout << "Associated data: "
              << std::string(
                     message.associated_data.begin(),
                     message.associated_data.end()
                 )
              << '\n';
}


/* -------------------------------------------------------------------------
 * Case study
 * ------------------------------------------------------------------------- */

void run_case_study() {
    std::cout << "SYMMETRIC ENCRYPTION CASE STUDY\n";
    std::cout << "============================================\n";

    RandomSource random;
    MessageGateway gateway(random);

    SecretKey finance_key{
        "finance-2026",
        random.bytes(KeySize)
    };

    SecretKey archive_key{
        "archive-2026",
        random.bytes(KeySize)
    };

    gateway.register_key(finance_key);
    gateway.register_key(archive_key);

    GatewayRequest request{
        "billing-service",
        "finance-2026",
        bytes_from_string(
            "Invoice INV-2048: transfer 12500 INR."
        ),
        bytes_from_string(
            "message-type=invoice;version=1"
        )
    };

    std::cout << "\nProtecting a financial message...\n";

    const EncryptedMessage encrypted =
        gateway.protect(request);

    print_message(encrypted);

    std::cout << "\nDecrypting authenticated message...\n";

    const Bytes recovered =
        gateway.consume(request, encrypted);

    std::cout << "Recovered plaintext: "
              << std::string(
                     recovered.begin(),
                     recovered.end()
                 )
              << '\n';


    /*
     * Tampering case:
     *
     * The attacker has access to the ciphertext and metadata but not the
     * shared secret. Changing one ciphertext byte invalidates the tag.
     */
    std::cout << "\nTesting ciphertext tampering...\n";

    EncryptedMessage tampered = encrypted;

    tampered.ciphertext[0] ^= 0x80;

    try {
        /*
         * A separate sender identity is used here so the replay guard does
         * not reject the message before the cryptographic authentication
         * check is reached.
         */
        GatewayRequest attacker_request = request;
        attacker_request.sender = "network-attacker";

        gateway.consume(attacker_request, tampered);

        std::cout << "ERROR: tampered ciphertext was accepted.\n";
    } catch (const std::exception& error) {
        std::cout << "Tampering rejected: "
                  << error.what()
                  << '\n';
    }


    /*
     * Metadata case:
     *
     * Associated data remains visible but is authenticated. Changing the
     * invoice classification therefore invalidates the message.
     */
    std::cout << "\nTesting associated-data tampering...\n";

    EncryptedMessage metadata_tampered = encrypted;
    metadata_tampered.associated_data =
        bytes_from_string(
            "message-type=admin;version=1"
        );

    try {
        GatewayRequest metadata_request = request;
        metadata_request.sender = "metadata-attacker";

        gateway.consume(
            metadata_request,
            metadata_tampered
        );

        std::cout << "ERROR: altered metadata was accepted.\n";
    } catch (const std::exception& error) {
        std::cout << "Metadata tampering rejected: "
                  << error.what()
                  << '\n';
    }


    /*
     * Wrong-key case:
     *
     * Symmetric encryption requires both parties to possess the same secret
     * key. A different legitimate key does not decrypt the message.
     */
    std::cout << "\nTesting wrong-key decryption...\n";

    EncryptedMessage wrong_key_message = encrypted;
    wrong_key_message.key_id = "archive-2026";

    try {
        GatewayRequest wrong_key_request = request;
        wrong_key_request.sender = "archive-service";

        gateway.consume(
            wrong_key_request,
            wrong_key_message
        );

        std::cout << "ERROR: wrong key was accepted.\n";
    } catch (const std::exception& error) {
        std::cout << "Wrong-key attempt rejected: "
                  << error.what()
                  << '\n';
    }


    /*
     * Replay case:
     *
     * The cryptographic tag proves that the message was created with the
     * secret key and that its protected fields were not modified. It does
     * not prove that the message is new. ReplayGuard adds application-level
     * freshness control using the nonce fingerprint.
     */
    std::cout << "\nTesting replay detection...\n";

    GatewayRequest replay_request = request;
    replay_request.sender = "replay-test-service";

    EncryptedMessage replay_message =
        gateway.protect(replay_request);

    gateway.consume(
        replay_request,
        replay_message
    );

    try {
        gateway.consume(
            replay_request,
            replay_message
        );

        std::cout << "ERROR: replay was accepted.\n";
    } catch (const std::exception& error) {
        std::cout << "Replay rejected: "
                  << error.what()
                  << '\n';
    }


    /*
     * Input validation case:
     *
     * A secure boundary rejects malformed keys rather than silently
     * truncating or extending them.
     */
    std::cout << "\nTesting key validation...\n";

    try {
        SecretKey invalid_key{
            "bad-key",
            Bytes(7, 0x41)
        };

        gateway.register_key(invalid_key);

        std::cout << "ERROR: malformed key was registered.\n";
    } catch (const std::exception& error) {
        std::cout << "Invalid key rejected: "
                  << error.what()
                  << '\n';
    }
}


/* -------------------------------------------------------------------------
 * Algorithmic and architectural observations
 * ------------------------------------------------------------------------- */

void run_invariant_checks() {
    std::cout << "\nSecurity invariants demonstrated by the case study\n";
    std::cout << "--------------------------------------------\n";

    RandomSource random;

    const Bytes key = random.bytes(KeySize);
    const Bytes nonce = random.bytes(NonceSize);

    if (key.size() != KeySize) {
        throw std::logic_error("key generation invariant failed");
    }

    if (nonce.size() != NonceSize) {
        throw std::logic_error("nonce generation invariant failed");
    }

    const Bytes original = bytes_from_string("same plaintext");
    const Bytes stream_a = keyed_digest(
        key,
        nonce
    );

    Bytes changed_nonce = nonce;
    changed_nonce[0] ^= 0x01;

    const Bytes stream_b = keyed_digest(
        key,
        changed_nonce
    );

    if (stream_a == stream_b) {
        throw std::logic_error(
            "nonce change did not change derived stream material"
        );
    }

    std::cout << "256-bit key size validated.\n";
    std::cout << "96-bit nonce size validated.\n";
    std::cout << "Changing nonce changes derived stream material.\n";
    std::cout << "Original sample size: "
              << original.size()
              << " bytes.\n";
}


/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

} // namespace secure_gateway


int main() {
    try {
        secure_gateway::run_case_study();
        secure_gateway::run_invariant_checks();

        std::cout << "\nProduction boundary\n";
        std::cout << "--------------------------------------------\n";
        std::cout
            << "This program models authenticated symmetric-encryption "
            << "architecture but does not implement production cryptography. "
            << "Use a vetted AEAD implementation such as AES-GCM or "
            << "ChaCha20-Poly1305 from a maintained cryptographic library "
            << "for real confidential data.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what()
                  << '\n';
        return 1;
    }
}
