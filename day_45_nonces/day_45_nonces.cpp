#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

/*
 * Repository Message Nonce Governance Engine
 *
 * Technical case study:
 *
 * A repository service encrypts sensitive event payloads using an AEAD
 * primitive. The cryptographic primitive is deliberately outside this
 * program. The engine is responsible for the surrounding nonce lifecycle:
 *
 *   session -> key scope -> nonce allocation -> replay validation
 *            -> sequence window -> message acceptance
 *
 * The central security invariant is:
 *
 *   The same nonce must not be reused with the same key when the selected
 *   cryptographic construction requires nonce uniqueness.
 *
 * The program is C++17-compatible and uses only the standard library.
 */

using Byte = std::uint8_t;
using Nonce = std::array<Byte, 12>;

/* -------------------------------------------------------------------------
 * Utility functions
 * ---------------------------------------------------------------------- */

std::string toHex(const Nonce& nonce) {
    std::ostringstream output;

    for (Byte byte : nonce) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return output.str();
}

Nonce counterNonce(std::uint64_t counter) {
    Nonce nonce{};

    /*
     * Twelve bytes are used here. The first four bytes remain zero and the
     * final eight bytes encode the counter in network byte order.
     */
    for (int index = 0; index < 8; ++index) {
        const int position = 11 - index;
        nonce[position] =
            static_cast<Byte>((counter >> (index * 8)) & 0xffU);
    }

    return nonce;
}

/* -------------------------------------------------------------------------
 * Cryptographically strong random nonce source
 * ---------------------------------------------------------------------- */

class RandomNonceSource {
public:
    RandomNonceSource()
        : generator_(std::random_device{}()) {}

    Nonce next() {
        Nonce nonce{};

        for (Byte& byte : nonce) {
            byte = static_cast<Byte>(distribution_(generator_));
        }

        return nonce;
    }

private:
    std::mt19937_64 generator_;
    std::uniform_int_distribution<unsigned int> distribution_{0, 255};
};

/*
 * Note:
 * std::random_device is implementation-dependent. For actual cryptographic
 * production systems, a platform CSPRNG or audited cryptographic library
 * should be used instead of treating a generic standard-library PRNG as a
 * universal cryptographic source.
 */

/* -------------------------------------------------------------------------
 * Session-scoped deterministic allocator
 * ---------------------------------------------------------------------- */

class SessionNonceAllocator {
public:
    SessionNonceAllocator(
        std::uint32_t sessionId,
        std::uint64_t initialCounter = 0)
        : sessionId_(sessionId),
          counter_(initialCounter) {}

    Nonce next() {
        std::lock_guard<std::mutex> lock(mutex_);

        if (counter_ == std::numeric_limits<std::uint64_t>::max()) {
            throw std::overflow_error(
                "Nonce counter exhausted; key/session rotation is required."
            );
        }

        ++counter_;

        Nonce nonce = counterNonce(counter_);

        /*
         * The session identifier occupies the first four bytes. Combining
         * the session namespace with a monotonic counter prevents two
         * independent sessions from accidentally producing the same
         * structured nonce under a properly scoped key.
         */
        nonce[0] = static_cast<Byte>((sessionId_ >> 24) & 0xffU);
        nonce[1] = static_cast<Byte>((sessionId_ >> 16) & 0xffU);
        nonce[2] = static_cast<Byte>((sessionId_ >> 8) & 0xffU);
        nonce[3] = static_cast<Byte>(sessionId_ & 0xffU);

        return nonce;
    }

private:
    std::uint32_t sessionId_;
    std::uint64_t counter_;
    std::mutex mutex_;
};

/* -------------------------------------------------------------------------
 * Key-scoped nonce registry
 * ---------------------------------------------------------------------- */

class KeyNonceRegistry {
public:
    bool reserve(const std::string& keyId, const Nonce& nonce) {
        if (keyId.empty()) {
            throw std::invalid_argument("keyId cannot be empty.");
        }

        std::lock_guard<std::mutex> lock(mutex_);

        auto& namespaceSet = used_[keyId];

        const auto [iterator, inserted] = namespaceSet.insert(nonce);

        (void)iterator;
        return inserted;
    }

    std::size_t count(const std::string& keyId) const {
        std::lock_guard<std::mutex> lock(mutex_);

        const auto found = used_.find(keyId);

        if (found == used_.end()) {
            return 0;
        }

        return found->second.size();
    }

private:
    struct NonceHash {
        std::size_t operator()(const Nonce& nonce) const noexcept {
            std::size_t hash = 0;

            for (Byte byte : nonce) {
                hash ^= static_cast<std::size_t>(byte)
                    + 0x9e3779b9
                    + (hash << 6)
                    + (hash >> 2);
            }

            return hash;
        }
    };

    using NonceSet = std::unordered_set<Nonce, NonceHash>;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, NonceSet> used_;
};

/* -------------------------------------------------------------------------
 * Replay window
 * ---------------------------------------------------------------------- */

class ReplayWindow {
public:
    explicit ReplayWindow(std::uint64_t width = 64)
        : width_(width) {
        if (width_ == 0 || width_ > 64) {
            throw std::invalid_argument(
                "Replay window must be between 1 and 64."
            );
        }
    }

    bool accept(std::uint64_t sequence) {
        if (!highest_.has_value()) {
            highest_ = sequence;
            bitmap_ = 1;
            return true;
        }

        const std::uint64_t highest = *highest_;

        if (sequence > highest) {
            const std::uint64_t shift = sequence - highest;

            if (shift >= width_) {
                bitmap_ = 1;
            } else {
                bitmap_ = (bitmap_ << shift) | 1ULL;

                if (width_ < 64) {
                    const std::uint64_t mask =
                        (1ULL << width_) - 1ULL;

                    bitmap_ &= mask;
                }
            }

            highest_ = sequence;
            return true;
        }

        const std::uint64_t distance = highest - sequence;

        if (distance >= width_) {
            return false;
        }

        const std::uint64_t bit = 1ULL << distance;

        if ((bitmap_ & bit) != 0) {
            return false;
        }

        bitmap_ |= bit;
        return true;
    }

private:
    std::uint64_t width_;
    std::optional<std::uint64_t> highest_;
    std::uint64_t bitmap_ = 0;
};

/* -------------------------------------------------------------------------
 * Repository event model
 * ---------------------------------------------------------------------- */

enum class MessageState {
    Created,
    Accepted,
    RejectedReplay,
    RejectedNonce,
    RejectedSession
};

struct RepositoryMessage {
    std::string messageId;
    std::string keyId;
    std::uint64_t sequence;
    Nonce nonce;
    std::string payload;
    MessageState state = MessageState::Created;
};

/* -------------------------------------------------------------------------
 * Governance engine
 * ---------------------------------------------------------------------- */

class NonceGovernanceEngine {
public:
    explicit NonceGovernanceEngine(std::uint64_t replayWindow = 64)
        : replayWindow_(replayWindow) {}

    bool process(RepositoryMessage& message) {
        if (message.messageId.empty()) {
            message.state = MessageState::RejectedNonce;
            return false;
        }

        if (message.keyId.empty()) {
            message.state = MessageState::RejectedNonce;
            return false;
        }

        if (message.payload.empty()) {
            message.state = MessageState::RejectedNonce;
            return false;
        }

        /*
         * Sequence validation and nonce reservation are separate checks.
         * A sequence number protects protocol ordering/replay state, while
         * the nonce registry protects cryptographic nonce uniqueness.
         */
        if (!replayWindow_.accept(message.sequence)) {
            message.state = MessageState::RejectedReplay;
            return false;
        }

        if (!registry_.reserve(message.keyId, message.nonce)) {
            message.state = MessageState::RejectedNonce;
            return false;
        }

        message.state = MessageState::Accepted;
        return true;
    }

    std::size_t registeredNonceCount(
        const std::string& keyId) const {
        return registry_.count(keyId);
    }

private:
    KeyNonceRegistry registry_;
    ReplayWindow replayWindow_;
};

/* -------------------------------------------------------------------------
 * Collision probability approximation
 * ---------------------------------------------------------------------- */

long double collisionProbability(
    long double samples,
    unsigned int bits) {

    if (samples <= 1.0L) {
        return 0.0L;
    }

    const long double space =
        std::pow(2.0L, static_cast<long double>(bits));

    const long double exponent =
        -(samples * (samples - 1.0L)) / (2.0L * space);

    return 1.0L - std::exp(exponent);
}

/* -------------------------------------------------------------------------
 * Demonstrations
 * ---------------------------------------------------------------------- */

void demonstrateCounterNonces() {
    std::cout << "\n=== Session counter nonces ===\n";

    SessionNonceAllocator allocator(0xA17C2026);

    for (int index = 0; index < 4; ++index) {
        std::cout << toHex(allocator.next()) << '\n';
    }
}

void demonstrateKeyScoping() {
    std::cout << "\n=== Key-scoped uniqueness ===\n";

    KeyNonceRegistry registry;
    RandomNonceSource source;

    const Nonce nonce = source.next();

    std::cout
        << "key-A first reservation: "
        << std::boolalpha
        << registry.reserve("key-A", nonce)
        << '\n';

    std::cout
        << "key-A replay reservation: "
        << registry.reserve("key-A", nonce)
        << '\n';

    /*
     * The same byte sequence is permitted in a separate namespace only if
     * the cryptographic design defines uniqueness per key. It must not be
     * interpreted as a license to reuse nonce/key pairs.
     */
    std::cout
        << "key-B reservation: "
        << registry.reserve("key-B", nonce)
        << '\n';
}

void demonstrateReplayWindow() {
    std::cout << "\n=== Replay window ===\n";

    ReplayWindow window(4);

    for (std::uint64_t sequence : {10, 11, 9, 12, 11, 8, 13}) {
        std::cout
            << "sequence=" << sequence
            << " accepted=" << std::boolalpha
            << window.accept(sequence)
            << '\n';
    }
}

void demonstrateGovernanceEngine() {
    std::cout << "\n=== Repository message governance ===\n";

    NonceGovernanceEngine engine;
    SessionNonceAllocator allocator(0x12345678);

    RepositoryMessage first{
        "msg-001",
        "repo-key-2026",
        100,
        allocator.next(),
        "encrypted repository event"
    };

    RepositoryMessage second{
        "msg-002",
        "repo-key-2026",
        101,
        allocator.next(),
        "another encrypted repository event"
    };

    RepositoryMessage replay{
        "msg-003",
        "repo-key-2026",
        101,
        allocator.next(),
        "sequence replay"
    };

    RepositoryMessage nonceReuse{
        "msg-004",
        "repo-key-2026",
        102,
        first.nonce,
        "nonce reuse attempt"
    };

    std::cout << "first accepted: "
              << engine.process(first) << '\n';

    std::cout << "second accepted: "
              << engine.process(second) << '\n';

    std::cout << "sequence replay accepted: "
              << engine.process(replay) << '\n';

    /*
     * This illustrates why sequence replay protection and nonce uniqueness
     * are different controls. The message uses a new sequence but repeats
     * a nonce already registered under the same key.
     */
    std::cout << "nonce reuse accepted: "
              << engine.process(nonceReuse) << '\n';

    std::cout
        << "registered nonces: "
        << engine.registeredNonceCount("repo-key-2026")
        << '\n';
}

void demonstrateCollisionMath() {
    std::cout << "\n=== 96-bit random nonce collision estimate ===\n";

    for (long double samples :
         {1000.0L, 1000000.0L, 1000000000.0L}) {

        const long double probability =
            collisionProbability(samples, 96);

        std::cout
            << std::fixed
            << std::setprecision(12)
            << "samples=" << static_cast<unsigned long long>(samples)
            << " probability=" << probability
            << '\n';
    }
}

int main() {
    try {
        std::cout << "NONCE GOVERNANCE ENGINE\n";
        std::cout << "======================\n";

        demonstrateCounterNonces();
        demonstrateKeyScoping();
        demonstrateReplayWindow();
        demonstrateGovernanceEngine();
        demonstrateCollisionMath();

        std::cout << "\nCase study completed successfully.\n";
        return 0;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
