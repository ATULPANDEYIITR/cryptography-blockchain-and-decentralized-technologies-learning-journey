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
 * MESSAGE AUTHENTICATION
 *
 * C++17 implementation of:
 * - SHA-256
 * - HMAC-SHA256
 * - Message integrity verification
 * - Key ownership and revocation
 * - Replay protection
 * - Timestamp validation
 * - Merge-free authentication policy evaluation
 *
 * No external libraries required.
 */

// ============================================================
// 1. SHA-256 IMPLEMENTATION
// ============================================================

class SHA256 {
private:
    static constexpr std::array<uint32_t, 64> K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    static uint32_t rotateRight(uint32_t x, int n) {
        return (x >> n) | (x << (32 - n));
    }

    static uint32_t choose(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }

    static uint32_t majority(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

public:
    static std::array<uint8_t, 32> hash(
        const std::string& input
    ) {

        std::vector<uint8_t> data(input.begin(), input.end());

        uint64_t bitLength =
            static_cast<uint64_t>(data.size()) * 8;

        data.push_back(0x80);

        while (data.size() % 64 != 56) {
            data.push_back(0);
        }

        for (int i = 7; i >= 0; --i) {
            data.push_back(
                static_cast<uint8_t>(bitLength >> (i * 8))
            );
        }

        std::array<uint32_t, 8> H = {
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
            0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
        };

        for (size_t offset = 0; offset < data.size(); offset += 64) {

            std::array<uint32_t, 64> W{};

            for (int i = 0; i < 16; ++i) {
                size_t p = offset + i * 4;

                W[i] =
                    (uint32_t(data[p]) << 24) |
                    (uint32_t(data[p + 1]) << 16) |
                    (uint32_t(data[p + 2]) << 8) |
                    uint32_t(data[p + 3]);
            }

            for (int i = 16; i < 64; ++i) {

                uint32_t s0 =
                    rotateRight(W[i - 15], 7) ^
                    rotateRight(W[i - 15], 18) ^
                    (W[i - 15] >> 3);

                uint32_t s1 =
                    rotateRight(W[i - 2], 17) ^
                    rotateRight(W[i - 2], 19) ^
                    (W[i - 2] >> 10);

                W[i] = W[i - 16] + s0 +
                       W[i - 7] + s1;
            }

            uint32_t a = H[0];
            uint32_t b = H[1];
            uint32_t c = H[2];
            uint32_t d = H[3];
            uint32_t e = H[4];
            uint32_t f = H[5];
            uint32_t g = H[6];
            uint32_t h = H[7];

            for (int i = 0; i < 64; ++i) {

                uint32_t S1 =
                    rotateRight(e, 6) ^
                    rotateRight(e, 11) ^
                    rotateRight(e, 25);

                uint32_t temp1 =
                    h + S1 + choose(e, f, g) + K[i] + W[i];

                uint32_t S0 =
                    rotateRight(a, 2) ^
                    rotateRight(a, 13) ^
                    rotateRight(a, 22);

                uint32_t temp2 =
                    S0 + majority(a, b, c);

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
            H[5] += f;
            H[6] += g;
            H[7] += h;
        }

        std::array<uint8_t, 32> result{};

        for (int i = 0; i < 8; ++i) {
            for (int j = 0; j < 4; ++j) {
                result[i * 4 + j] =
                    static_cast<uint8_t>(
                        H[i] >> (24 - j * 8)
                    );
            }
        }

        return result;
    }

    static std::string toHex(
        const std::array<uint8_t, 32>& digest
    ) {

        std::ostringstream output;

        output << std::hex << std::setfill('0');

        for (uint8_t byte : digest) {
            output << std::setw(2) << unsigned(byte);
        }

        return output.str();
    }
};

// ============================================================
// 2. HMAC-SHA256
// ============================================================

class HMAC {

public:
    static std::string calculate(
        const std::string& key,
        const std::string& message
    ) {

        if (key.size() < 32) {
            throw std::invalid_argument(
                "HMAC key must contain at least 32 bytes"
            );
        }

        constexpr size_t BLOCK_SIZE = 64;

        std::string normalized = key;

        if (normalized.size() > BLOCK_SIZE) {
            auto digest = SHA256::hash(normalized);

            normalized.assign(
                digest.begin(),
                digest.end()
            );
        }

        normalized.resize(BLOCK_SIZE, '\0');

        std::string innerPad(BLOCK_SIZE, '\0');
        std::string outerPad(BLOCK_SIZE, '\0');

        for (size_t i = 0; i < BLOCK_SIZE; ++i) {

            innerPad[i] = normalized[i] ^ 0x36;
            outerPad[i] = normalized[i] ^ 0x5c;
        }

        auto innerHash = SHA256::hash(
            innerPad + message
        );

        std::string innerDigest(
            innerHash.begin(),
            innerHash.end()
        );

        auto finalHash = SHA256::hash(
            outerPad + innerDigest
        );

        return SHA256::toHex(finalHash);
    }

    static bool verify(
        const std::string& key,
        const std::string& message,
        const std::string& supplied
    ) {

        if (supplied.size() != 64) {
            return false;
        }

        std::string expected = calculate(key, message);

        unsigned char difference = 0;

        for (size_t i = 0; i < expected.size(); ++i) {
            difference |= static_cast<unsigned char>(
                expected[i] ^ supplied[i]
            );
        }

        return difference == 0;
    }
};

// ============================================================
// 3. DOMAIN MODEL
// ============================================================

enum class AuthStatus {
    AUTHENTICATED,
    INVALID_SIGNATURE,
    UNKNOWN_KEY,
    REVOKED_KEY,
    EXPIRED_MESSAGE,
    REPLAY_DETECTED,
    INVALID_MESSAGE
};

std::string statusName(AuthStatus status) {

    switch (status) {
        case AuthStatus::AUTHENTICATED:
            return "authenticated";

        case AuthStatus::INVALID_SIGNATURE:
            return "invalid_signature";

        case AuthStatus::UNKNOWN_KEY:
            return "unknown_key";

        case AuthStatus::REVOKED_KEY:
            return "revoked_key";

        case AuthStatus::EXPIRED_MESSAGE:
            return "expired_message";

        case AuthStatus::REPLAY_DETECTED:
            return "replay_detected";

        case AuthStatus::INVALID_MESSAGE:
            return "invalid_message";
    }

    return "unknown";
}

struct Message {
    std::string sender;
    std::string receiver;
    std::string messageId;
    int64_t timestamp;
    std::string payload;
    std::string keyId;
    std::string signature;
};

struct Key {
    std::string id;
    std::string owner;
    std::string secret;
    bool active = true;
};

// ============================================================
// 4. CANONICAL ENCODING
// ============================================================

class Serializer {

public:
    static std::string encode(const Message& message) {

        // Length-prefix encoding prevents delimiter ambiguity.
        std::ostringstream output;

        auto append = [&output](const std::string& value) {

            output << value.size() << ':' << value;
        };

        append(message.sender);
        append(message.receiver);
        append(message.messageId);

        output << message.timestamp << ':';

        append(message.payload);
        append(message.keyId);

        return output.str();
    }
};

// ============================================================
// 5. KEY REGISTRY
// ============================================================

class KeyRegistry {

private:
    std::map<std::string, Key> keys;
    uint64_t nextId = 1;

public:
    Key create(const std::string& owner) {

        if (owner.empty()) {
            throw std::invalid_argument("Owner required");
        }

        std::string id = "KEY-" + std::to_string(nextId++);

        Key key{
            id,
            owner,
            std::string(32, '\0'),
            true
        };

        // Demonstration secret. Production systems must use
        // a cryptographically secure random generator or KMS.
        for (size_t i = 0; i < key.secret.size(); ++i) {
            key.secret[i] = static_cast<char>(
                (nextId * 31 + i * 17) & 0xff
            );
        }

        keys[id] = key;

        return key;
    }

    std::optional<Key> find(const std::string& id) const {

        auto iterator = keys.find(id);

        if (iterator == keys.end()) {
            return std::nullopt;
        }

        return iterator->second;
    }

    Key rotate(const std::string& id) {

        auto iterator = keys.find(id);

        if (iterator == keys.end() || !iterator->second.active) {
            throw std::runtime_error("Key cannot be rotated");
        }

        std::string owner = iterator->second.owner;

        iterator->second.active = false;

        return create(owner);
    }

    bool revoke(const std::string& id) {

        auto iterator = keys.find(id);

        if (iterator == keys.end()) {
            return false;
        }

        iterator->second.active = false;
        return true;
    }
};

// ============================================================
// 6. REPLAY PROTECTION
// ============================================================

class ReplayRegistry {

private:
    std::set<std::pair<std::string, std::string>> processed;

public:
    bool registerMessage(
        const std::string& sender,
        const std::string& messageId
    ) {

        return processed.insert({
            sender,
            messageId
        }).second;
    }
};

// ============================================================
// 7. AUTHENTICATION ENGINE
// ============================================================

class AuthenticationEngine {

private:
    KeyRegistry& registry;
    ReplayRegistry& replay;

    int64_t allowedClockSkew;
    size_t maximumPayloadSize;

public:
    AuthenticationEngine(
        KeyRegistry& registry,
        ReplayRegistry& replay,
        int64_t skew = 60,
        size_t maximumPayload = 65536
    )
        : registry(registry),
          replay(replay),
          allowedClockSkew(skew),
          maximumPayloadSize(maximumPayload) {

        if (skew < 0 || maximumPayload == 0) {
            throw std::invalid_argument(
                "Invalid authentication configuration"
            );
        }
    }

    Message sign(
        const std::string& sender,
        const std::string& receiver,
        const std::string& payload,
        const Key& key,
        int64_t timestamp
    ) {

        if (!key.active || key.owner != sender) {
            throw std::runtime_error("Unauthorized signing key");
        }

        if (
            sender.empty() ||
            receiver.empty() ||
            payload.size() > maximumPayloadSize ||
            timestamp <= 0
        ) {
            throw std::invalid_argument("Invalid message");
        }

        static uint64_t sequence = 1;

        Message message{
            sender,
            receiver,
            "MSG-" + std::to_string(sequence++),
            timestamp,
            payload,
            key.id,
            ""
        };

        message.signature = HMAC::calculate(
            key.secret,
            Serializer::encode(message)
        );

        return message;
    }

    AuthStatus verify(
        const Message& message,
        int64_t currentTime
    ) {

        if (
            message.sender.empty() ||
            message.receiver.empty() ||
            message.messageId.empty() ||
            message.keyId.empty() ||
            message.timestamp <= 0 ||
            message.payload.size() > maximumPayloadSize
        ) {
            return AuthStatus::INVALID_MESSAGE;
        }

        if (
            currentTime < message.timestamp - allowedClockSkew ||
            currentTime > message.timestamp + allowedClockSkew
        ) {
            return AuthStatus::EXPIRED_MESSAGE;
        }

        auto key = registry.find(message.keyId);

        if (!key.has_value()) {
            return AuthStatus::UNKNOWN_KEY;
        }

        if (!key->active) {
            return AuthStatus::REVOKED_KEY;
        }

        if (key->owner != message.sender) {
            return AuthStatus::INVALID_SIGNATURE;
        }

        if (!HMAC::verify(
            key->secret,
            Serializer::encode(message),
            message.signature
        )) {
            return AuthStatus::INVALID_SIGNATURE;
        }

        if (!replay.registerMessage(
            message.sender,
            message.messageId
        )) {
            return AuthStatus::REPLAY_DETECTED;
        }

        return AuthStatus::AUTHENTICATED;
    }
};

// ============================================================
// 8. GOVERNANCE AND TEST SCENARIOS
// ============================================================

int main() {

    try {

        KeyRegistry keys;
        ReplayRegistry replay;

        AuthenticationEngine engine(
            keys,
            replay,
            60,
            65536
        );

        int64_t now = 1800000000;

        Key aliceKey = keys.create("alice");

        std::cout << "MESSAGE AUTHENTICATION ENGINE\n";
        std::cout << "=============================\n\n";

        Message valid = engine.sign(
            "alice",
            "bob",
            "Transfer INR 5000",
            aliceKey,
            now
        );

        AuthStatus validResult = engine.verify(valid, now);

        std::cout << "1. Valid message: "
                  << statusName(validResult) << '\n';

        if (validResult != AuthStatus::AUTHENTICATED) {
            throw std::runtime_error("Valid message rejected");
        }

        AuthStatus replayResult = engine.verify(valid, now);

        std::cout << "2. Replay attempt: "
                  << statusName(replayResult) << '\n';

        Message tampered = valid;
        tampered.payload = "Transfer INR 500000";

        AuthStatus tamperedResult = engine.verify(
            tampered,
            now
        );

        std::cout << "3. Modified payload: "
                  << statusName(tamperedResult) << '\n';

        Message expired = engine.sign(
            "alice",
            "bob",
            "Old message",
            aliceKey,
            now - 300
        );

        AuthStatus expiredResult = engine.verify(
            expired,
            now
        );

        std::cout << "4. Expired message: "
                  << statusName(expiredResult) << '\n';

        Message unknown = valid;
        unknown.messageId = "UNKNOWN-001";
        unknown.keyId = "UNKNOWN-KEY";

        AuthStatus unknownResult = engine.verify(
            unknown,
            now
        );

        std::cout << "5. Unknown key: "
                  << statusName(unknownResult) << '\n';

        Key rotated = keys.rotate(aliceKey.id);

        Message newMessage = engine.sign(
            "alice",
            "bob",
            "Message signed after rotation",
            rotated,
            now
        );

        AuthStatus rotationResult = engine.verify(
            newMessage,
            now
        );

        std::cout << "6. Rotated key: "
                  << statusName(rotationResult) << '\n';

        Message revokedMessage = engine.sign(
            "alice",
            "bob",
            "Revocation test",
            rotated,
            now
        );

        keys.revoke(rotated.id);

        AuthStatus revokedResult = engine.verify(
            revokedMessage,
            now
        );

        std::cout << "7. Revoked key: "
                  << statusName(revokedResult) << '\n';

        // Standard SHA-256 known-answer test.
        auto digest = SHA256::hash("abc");

        const std::string expected =
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad";

        if (SHA256::toHex(digest) != expected) {
            throw std::runtime_error("SHA-256 test failed");
        }

        std::cout << "\nSHA-256 known-answer test: passed\n";

        if (
            replayResult != AuthStatus::REPLAY_DETECTED ||
            tamperedResult != AuthStatus::INVALID_SIGNATURE ||
            expiredResult != AuthStatus::EXPIRED_MESSAGE ||
            unknownResult != AuthStatus::UNKNOWN_KEY ||
            rotationResult != AuthStatus::AUTHENTICATED ||
            revokedResult != AuthStatus::REVOKED_KEY
        ) {
            throw std::runtime_error("Authentication test failed");
        }

        std::cout << "All C++17 tests passed.\n";

    } catch (const std::exception& error) {

        std::cerr << "ERROR: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
