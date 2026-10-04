#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/*
 * Stream Cipher Repository Governance Case Study
 *
 * Scenario:
 * A security-sensitive repository transports encrypted audit records between
 * services. The system must decide whether a proposed encrypted record can be
 * accepted by the receiving service.
 *
 * The case study models:
 * - stream-cipher state
 * - nonce uniqueness
 * - block counters
 * - ciphertext transformation
 * - authentication state
 * - replay detection
 * - protocol policy
 *
 * The cryptographic primitive below is an educational ChaCha20-style core.
 * It is intentionally kept self-contained and uses only the C++ standard
 * library. Production cryptography should use a vetted implementation.
 */

namespace stream_cipher {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Key = std::array<Byte, 32>;
using Nonce = std::array<Byte, 12>;


// ---------------------------------------------------------------------------
// Byte utilities
// ---------------------------------------------------------------------------

Bytes xor_bytes(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("XOR operands have different lengths");
    }

    Bytes result(left.size());

    for (std::size_t i = 0; i < left.size(); ++i) {
        result[i] = static_cast<Byte>(left[i] ^ right[i]);
    }

    return result;
}

std::string hex(const Bytes& bytes) {
    std::ostringstream output;

    for (Byte value : bytes) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(value);
    }

    return output.str();
}

std::uint32_t rotate_left(std::uint32_t value, unsigned amount) {
    return (value << amount) | (value >> (32U - amount));
}


// ---------------------------------------------------------------------------
// ChaCha20 block
// ---------------------------------------------------------------------------

void quarter_round(
    std::array<std::uint32_t, 16>& state,
    std::size_t a,
    std::size_t b,
    std::size_t c,
    std::size_t d
) {
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = rotate_left(state[d], 16);

    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = rotate_left(state[b], 12);

    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = rotate_left(state[d], 8);

    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = rotate_left(state[b], 7);
}

std::uint32_t load_u32_le(const Byte* input) {
    return
        static_cast<std::uint32_t>(input[0]) |
        (static_cast<std::uint32_t>(input[1]) << 8U) |
        (static_cast<std::uint32_t>(input[2]) << 16U) |
        (static_cast<std::uint32_t>(input[3]) << 24U);
}

void store_u32_le(Byte* output, std::uint32_t value) {
    output[0] = static_cast<Byte>(value);
    output[1] = static_cast<Byte>(value >> 8U);
    output[2] = static_cast<Byte>(value >> 16U);
    output[3] = static_cast<Byte>(value >> 24U);
}

std::array<Byte, 64> chacha20_block(
    const Key& key,
    std::uint32_t counter,
    const Nonce& nonce
) {
    const std::array<std::uint32_t, 4> constants = {
        0x61707865U,
        0x3320646eU,
        0x79622d32U,
        0x6b206574U
    };

    std::array<std::uint32_t, 16> state{};

    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];

    for (std::size_t i = 0; i < 8; ++i) {
        state[4 + i] = load_u32_le(key.data() + i * 4);
    }

    state[12] = counter;

    for (std::size_t i = 0; i < 3; ++i) {
        state[13 + i] = load_u32_le(nonce.data() + i * 4);
    }

    auto working = state;

    for (int round = 0; round < 10; ++round) {
        // Column rounds provide local mixing.
        quarter_round(working, 0, 4, 8, 12);
        quarter_round(working, 1, 5, 9, 13);
        quarter_round(working, 2, 6, 10, 14);
        quarter_round(working, 3, 7, 11, 15);

        // Diagonal rounds connect words that were not mixed together
        // during the preceding column phase.
        quarter_round(working, 0, 5, 10, 15);
        quarter_round(working, 1, 6, 11, 12);
        quarter_round(working, 2, 7, 8, 13);
        quarter_round(working, 3, 4, 9, 14);
    }

    std::array<Byte, 64> output{};

    for (std::size_t i = 0; i < 16; ++i) {
        store_u32_le(
            output.data() + i * 4,
            state[i] + working[i]
        );
    }

    return output;
}


// ---------------------------------------------------------------------------
// Stateful stream-cipher engine
// ---------------------------------------------------------------------------

class StreamCipher {
public:
    StreamCipher(const Key& key, const Nonce& nonce)
        : key_(key), nonce_(nonce), counter_(1), pending_{} {}

    Bytes crypt(const Bytes& input) {
        Bytes output(input.size());
        std::size_t input_offset = 0;

        while (input_offset < input.size()) {
            if (pending_offset_ < pending_.size()) {
                const std::size_t available =
                    pending_.size() - pending_offset_;

                const std::size_t required =
                    input.size() - input_offset;

                const std::size_t take =
                    std::min(available, required);

                for (std::size_t i = 0; i < take; ++i) {
                    output[input_offset + i] =
                        static_cast<Byte>(
                            input[input_offset + i] ^
                            pending_[pending_offset_ + i]
                        );
                }

                input_offset += take;
                pending_offset_ += take;
                continue;
            }

            if (counter_ == 0) {
                throw std::overflow_error(
                    "ChaCha20 counter exhausted"
                );
            }

            const auto block =
                chacha20_block(key_, counter_, nonce_);

            ++counter_;

            const std::size_t required =
                input.size() - input_offset;

            const std::size_t take =
                std::min<std::size_t>(64, required);

            for (std::size_t i = 0; i < take; ++i) {
                output[input_offset + i] =
                    static_cast<Byte>(
                        input[input_offset + i] ^ block[i]
                    );
            }

            input_offset += take;

            if (take < block.size()) {
                pending_.assign(
                    block.begin() + static_cast<std::ptrdiff_t>(take),
                    block.end()
                );
                pending_offset_ = 0;
            } else {
                pending_.clear();
                pending_offset_ = 0;
            }
        }

        return output;
    }

private:
    Key key_;
    Nonce nonce_;
    std::uint32_t counter_;
    std::array<Byte, 64> pending_{};
    std::size_t pending_offset_ = 0;
};


// ---------------------------------------------------------------------------
// Protocol records
// ---------------------------------------------------------------------------

enum class AuthenticationState {
    Missing,
    Valid,
    Invalid
};

enum class Decision {
    Accept,
    RejectNonceReuse,
    RejectReplay,
    RejectAuthentication,
    RejectVersion,
    RejectEmptyPayload
};

struct EncryptedRecord {
    std::uint32_t protocol_version = 1;
    std::string record_id;
    Nonce nonce{};
    Bytes ciphertext;
    Bytes authentication_tag;
    AuthenticationState authentication = AuthenticationState::Missing;
};

std::string decision_text(Decision decision) {
    switch (decision) {
        case Decision::Accept:
            return "accepted";
        case Decision::RejectNonceReuse:
            return "rejected: nonce reuse";
        case Decision::RejectReplay:
            return "rejected: replay";
        case Decision::RejectAuthentication:
            return "rejected: authentication failure";
        case Decision::RejectVersion:
            return "rejected: unsupported protocol version";
        case Decision::RejectEmptyPayload:
            return "rejected: empty ciphertext";
    }

    return "rejected: unknown";
}


// ---------------------------------------------------------------------------
// Repository-style security policy engine
// ---------------------------------------------------------------------------

class GovernanceEngine {
public:
    GovernanceEngine(
        std::uint32_t required_protocol_version,
        std::size_t replay_capacity
    )
        : required_protocol_version_(required_protocol_version),
          replay_capacity_(replay_capacity) {}

    Decision evaluate(const EncryptedRecord& record) const {
        if (record.protocol_version != required_protocol_version_) {
            return Decision::RejectVersion;
        }

        if (record.ciphertext.empty()) {
            return Decision::RejectEmptyPayload;
        }

        if (record.authentication != AuthenticationState::Valid) {
            return Decision::RejectAuthentication;
        }

        if (seen_records_.contains(record.record_id)) {
            return Decision::RejectReplay;
        }

        const std::string nonce_key =
            record_id_for_nonce(record.nonce);

        if (used_nonces_.contains(nonce_key)) {
            return Decision::RejectNonceReuse;
        }

        return Decision::Accept;
    }

    void commit(const EncryptedRecord& record) {
        const Decision decision = evaluate(record);

        if (decision != Decision::Accept) {
            throw std::logic_error(
                "Cannot commit record: " + decision_text(decision)
            );
        }

        if (seen_records_.size() >= replay_capacity_) {
            throw std::overflow_error(
                "Replay tracking capacity exhausted"
            );
        }

        seen_records_.insert(record.record_id);
        used_nonces_.insert(record_id_for_nonce(record.nonce));
    }

private:
    static std::string record_id_for_nonce(const Nonce& nonce) {
        return std::string(
            reinterpret_cast<const char*>(nonce.data()),
            nonce.size()
        );
    }

    std::uint32_t required_protocol_version_;
    std::size_t replay_capacity_;
    std::set<std::string> seen_records_;
    std::set<std::string> used_nonces_;
};


// ---------------------------------------------------------------------------
// Deterministic record factory for the case study
// ---------------------------------------------------------------------------

EncryptedRecord create_record(
    const Key& key,
    const Nonce& nonce,
    std::string record_id,
    std::string_view plaintext,
    AuthenticationState authentication
) {
    StreamCipher cipher(key, nonce);

    Bytes data(
        plaintext.begin(),
        plaintext.end()
    );

    return EncryptedRecord{
        1,
        std::move(record_id),
        nonce,
        cipher.crypt(data),
        Bytes(32, 0xAB),
        authentication
    };
}


// ---------------------------------------------------------------------------
// Technical demonstrations
// ---------------------------------------------------------------------------

void demonstrate_basic_stream_operation() {
    std::cout << "\n=== Stream-cipher transformation ===\n";

    Key key{};
    Nonce nonce{};

    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<Byte>(i);
    }

    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<Byte>(i + 32);
    }

    const Bytes plaintext = {
        's', 't', 'r', 'e', 'a', 'm',
        '-', 'c', 'i', 'p', 'h', 'e', 'r'
    };

    StreamCipher encryptor(key, nonce);
    const Bytes ciphertext = encryptor.crypt(plaintext);

    StreamCipher decryptor(key, nonce);
    const Bytes recovered = decryptor.crypt(ciphertext);

    std::cout << "Ciphertext: " << hex(ciphertext) << '\n';
    std::cout
        << "Recovered : "
        << std::string(recovered.begin(), recovered.end())
        << '\n';

    if (recovered != plaintext) {
        throw std::runtime_error("Round-trip encryption failed");
    }
}

void demonstrate_chunk_boundaries() {
    std::cout << "\n=== Chunk boundary preservation ===\n";

    Key key{};
    Nonce nonce{};

    key.fill(0x42);
    nonce.fill(0x19);

    const Bytes plaintext = {
        'p', 'a', 'c', 'k', 'e', 't', '-',
        'b', 'o', 'u', 'n', 'd', 'a', 'r', 'y'
    };

    StreamCipher encryptor(key, nonce);

    Bytes encrypted;

    const std::array<std::size_t, 4> chunk_sizes = {
        2, 3, 1, 9
    };

    std::size_t offset = 0;

    for (std::size_t chunk_size : chunk_sizes) {
        const std::size_t remaining = plaintext.size() - offset;
        const std::size_t take = std::min(chunk_size, remaining);

        Bytes chunk(
            plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
            plaintext.begin() + static_cast<std::ptrdiff_t>(offset + take)
        );

        Bytes encrypted_chunk = encryptor.crypt(chunk);
        encrypted.insert(
            encrypted.end(),
            encrypted_chunk.begin(),
            encrypted_chunk.end()
        );

        offset += take;

        if (offset == plaintext.size()) {
            break;
        }
    }

    StreamCipher decryptor(key, nonce);
    const Bytes recovered = decryptor.crypt(encrypted);

    std::cout
        << "Recovered: "
        << std::string(recovered.begin(), recovered.end())
        << '\n';

    if (recovered != plaintext) {
        throw std::runtime_error(
            "Chunked processing changed the plaintext"
        );
    }
}

void demonstrate_nonce_reuse() {
    std::cout << "\n=== Nonce reuse failure ===\n";

    Key key{};
    Nonce nonce{};

    key.fill(0x55);
    nonce.fill(0x77);

    const Bytes first = {
        'a', 'm', 'o', 'u', 'n', 't', '=', '1', '0', '0'
    };

    const Bytes second = {
        'a', 'm', 'o', 'u', 'n', 't', '=', '9', '0', '0'
    };

    const Bytes first_ciphertext =
        StreamCipher(key, nonce).crypt(first);

    const Bytes second_ciphertext =
        StreamCipher(key, nonce).crypt(second);

    const Bytes ciphertext_relation =
        xor_bytes(first_ciphertext, second_ciphertext);

    const Bytes plaintext_relation =
        xor_bytes(first, second);

    std::cout
        << "Ciphertext XOR equality: "
        << (ciphertext_relation == plaintext_relation ? "true" : "false")
        << '\n';

    if (ciphertext_relation != plaintext_relation) {
        throw std::runtime_error(
            "Expected nonce-reuse relationship was not observed"
        );
    }
}

void demonstrate_governance_engine() {
    std::cout << "\n=== Secure record governance engine ===\n";

    Key key{};
    key.fill(0x31);

    Nonce nonce_a{};
    Nonce nonce_b{};

    nonce_a.fill(0x11);
    nonce_b.fill(0x22);

    GovernanceEngine engine(1, 100);

    EncryptedRecord valid = create_record(
        key,
        nonce_a,
        "record-001",
        "audit: payment accepted",
        AuthenticationState::Valid
    );

    std::cout
        << "Valid record: "
        << decision_text(engine.evaluate(valid))
        << '\n';

    engine.commit(valid);

    std::cout
        << "Replay attempt: "
        << decision_text(engine.evaluate(valid))
        << '\n';

    EncryptedRecord invalid_authentication = create_record(
        key,
        nonce_b,
        "record-002",
        "audit: payment rejected",
        AuthenticationState::Invalid
    );

    std::cout
        << "Invalid authentication: "
        << decision_text(
            engine.evaluate(invalid_authentication)
        )
        << '\n';

    EncryptedRecord nonce_reuse = create_record(
        key,
        nonce_a,
        "record-003",
        "audit: another event",
        AuthenticationState::Valid
    );

    std::cout
        << "Nonce reuse: "
        << decision_text(engine.evaluate(nonce_reuse))
        << '\n';

    EncryptedRecord wrong_version = create_record(
        key,
        nonce_b,
        "record-004",
        "audit: protocol mismatch",
        AuthenticationState::Valid
    );

    wrong_version.protocol_version = 2;

    std::cout
        << "Version mismatch: "
        << decision_text(engine.evaluate(wrong_version))
        << '\n';
}

void demonstrate_failure_conditions() {
    std::cout << "\n=== Failure conditions ===\n";

    try {
        Key key{};
        Nonce nonce{};

        StreamCipher cipher(key, nonce);
        cipher.crypt(Bytes{});

        std::cout << "Empty payload: handled safely\n";
    } catch (const std::exception& error) {
        std::cout
            << "Unexpected empty-payload failure: "
            << error.what()
            << '\n';
    }

    try {
        Key key{};
        Nonce nonce{};

        GovernanceEngine engine(1, 1);

        EncryptedRecord record = create_record(
            key,
            nonce,
            "single",
            "data",
            AuthenticationState::Valid
        );

        engine.commit(record);

        std::cout
            << "Capacity test: "
            << decision_text(engine.evaluate(record))
            << '\n';
    } catch (const std::exception& error) {
        std::cout
            << "Capacity handling: "
            << error.what()
            << '\n';
    }
}


// ---------------------------------------------------------------------------
// Complexity discussion encoded as executable metadata
// ---------------------------------------------------------------------------

struct ComplexityModel {
    std::string transformation;
    std::string memory;
    std::string replay_lookup;
};

ComplexityModel describe_complexity() {
    return {
        "O(n) for n plaintext bytes; each byte is XORed with one keystream byte",
        "O(b) temporary state for b-byte processing; a streaming cursor avoids O(n) buffering",
        "O(1) expected lookup with a hash set; this case study uses std::set, so lookup is O(log r)"
    };
}


// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

} // namespace stream_cipher

int main() {
    using namespace stream_cipher;

    try {
        std::cout << "STREAM CIPHERS: C++ TECHNICAL CASE STUDY\n";

        demonstrate_basic_stream_operation();
        demonstrate_chunk_boundaries();
        demonstrate_nonce_reuse();
        demonstrate_governance_engine();
        demonstrate_failure_conditions();

        const ComplexityModel complexity = describe_complexity();

        std::cout << "\n=== Complexity model ===\n";
        std::cout << "Transformation: "
                  << complexity.transformation << '\n';
        std::cout << "Memory       : "
                  << complexity.memory << '\n';
        std::cout << "Replay lookup: "
                  << complexity.replay_lookup << '\n';

        std::cout << "\n=== Security boundary ===\n";
        std::cout
            << "The XOR stream operation provides confidentiality only when "
               "the keystream is generated securely and its nonce/counter "
               "state is managed correctly. Authentication and replay "
               "protection are separate protocol responsibilities. "
               "Production systems should use standardized AEAD primitives."
            << '\n';

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
