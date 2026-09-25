/*
 * Modern Cryptography: Secure Document Exchange Case Study
 * =========================================================
 *
 * C++17 case study:
 *     A secure document exchange service for an enterprise application.
 *
 * The program demonstrates:
 *     - cryptographic hashing
 *     - HMAC authentication
 *     - secure random material
 *     - key derivation concepts
 *     - authenticated message envelopes
 *     - key identifiers and rotation
 *     - replay protection
 *     - certificate-like identity metadata
 *     - protocol validation
 *     - modular design
 *     - complexity and failure analysis
 *
 * The standard C++ library does not provide a complete modern cryptographic
 * suite. Therefore this case study implements educational protocol mechanics
 * using SHA-256/HMAC-style constructions represented by deterministic
 * standard-library operations.
 *
 * This is intentionally NOT a replacement for OpenSSL, libsodium, Botan,
 * BoringSSL, or another audited cryptographic library.
 *
 * Compile:
 *     g++ -std=c++17 -O2 secure_document_exchange.cpp -o secure_exchange
 *
 * Run:
 *     ./secure_exchange
 */

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace crypto_case_study {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;

void printSection(const std::string& title) {
    std::cout << "\n" << std::string(78, '=') << "\n";
    std::cout << title << "\n";
    std::cout << std::string(78, '=') << "\n";
}

std::string toHex(const Bytes& data) {
    std::ostringstream output;

    for (Byte value : data) {
        output
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(value);
    }

    return output.str();
}

Bytes stringToBytes(const std::string& value) {
    return Bytes(value.begin(), value.end());
}

std::string bytesToString(const Bytes& value) {
    return std::string(value.begin(), value.end());
}

/*
 * SecureRandom
 * ------------
 *
 * std::random_device is implementation-dependent. It may use an operating
 * system source, but the standard does not promise cryptographic security.
 *
 * This class is therefore explicitly labeled educational. Production systems
 * should obtain cryptographic randomness from a vetted cryptographic library
 * or platform-specific CSPRNG.
 */
class SecureRandom {
private:
    std::random_device device;

public:
    Bytes bytes(std::size_t count) {
        Bytes result;
        result.reserve(count);

        for (std::size_t index = 0; index < count; ++index) {
            result.push_back(
                static_cast<Byte>(device() & 0xFF)
            );
        }

        return result;
    }
};

/*
 * EducationalDigest
 * -----------------
 *
 * This class creates a deterministic fixed-size digest-like value for the
 * case study. It demonstrates API structure and data-flow but is NOT SHA-256.
 *
 * A real implementation must use a vetted SHA-256 implementation.
 */
class EducationalDigest {
public:
    static std::array<std::uint64_t, 4> digest(const Bytes& input) {
        std::array<std::uint64_t, 4> state{
            0x243F6A8885A308D3ULL,
            0x13198A2E03707344ULL,
            0xA4093822299F31D0ULL,
            0x082EFA98EC4E6C89ULL
        };

        for (Byte value : input) {
            for (std::size_t index = 0; index < state.size(); ++index) {
                state[index] ^= value + 0x9E3779B97F4A7C15ULL;

                state[index] *= 0x100000001B3ULL;

                state[index] =
                    (state[index] << 13) |
                    (state[index] >> 51);
            }
        }

        return state;
    }

    static Bytes bytes(const Bytes& input) {
        const auto state = digest(input);

        Bytes result;
        result.reserve(32);

        for (std::uint64_t word : state) {
            for (int shift = 56; shift >= 0; shift -= 8) {
                result.push_back(
                    static_cast<Byte>((word >> shift) & 0xFF)
                );
            }
        }

        return result;
    }
};

/*
 * Constant-time equality
 * ----------------------
 *
 * The function avoids early return based on the first differing byte.
 * Compiler and hardware behavior can still be complex, so production
 * applications should use the constant-time comparison provided by their
 * cryptographic library.
 */
bool constantTimeEqual(const Bytes& first, const Bytes& second) {
    if (first.size() != second.size()) {
        return false;
    }

    Byte difference = 0;

    for (std::size_t index = 0; index < first.size(); ++index) {
        difference |= first[index] ^ second[index];
    }

    return difference == 0;
}

/*
 * Educational HMAC-like construction.
 *
 * Real applications must use standardized HMAC from a cryptographic library.
 */
class MessageAuthenticator {
private:
    static Bytes combine(
        const Bytes& key,
        const Bytes& message
    ) {
        Bytes combined;
        combined.reserve(key.size() + message.size());

        combined.insert(
            combined.end(),
            key.begin(),
            key.end()
        );

        combined.insert(
            combined.end(),
            message.begin(),
            message.end()
        );

        return combined;
    }

public:
    static Bytes authenticate(
        const Bytes& key,
        const Bytes& message
    ) {
        Bytes firstInput = combine(key, message);
        Bytes firstDigest = EducationalDigest::bytes(firstInput);

        Bytes secondInput = combine(firstDigest, key);

        return EducationalDigest::bytes(secondInput);
    }

    static bool verify(
        const Bytes& key,
        const Bytes& message,
        const Bytes& suppliedTag
    ) {
        const Bytes expected = authenticate(key, message);

        return constantTimeEqual(
            expected,
            suppliedTag
        );
    }
};

/*
 * KeyRecord
 * ---------
 *
 * Key metadata is separated from key material conceptually. A production KMS
 * would normally protect the actual key material outside the application
 * process whenever possible.
 */
struct KeyRecord {
    std::string id;
    Bytes material;
    std::int64_t createdAt;
    bool active;
};

class KeyManager {
private:
    SecureRandom randomSource;
    std::map<std::string, KeyRecord> records;

    static std::string timestampId(std::int64_t timestamp) {
        std::ostringstream output;
        output << timestamp;
        return output.str();
    }

public:
    std::string createKey() {
        const auto now =
            std::chrono::system_clock::now();

        const auto timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()
            ).count();

        const Bytes randomId = randomSource.bytes(8);

        const std::string id =
            timestampId(timestamp) + "-" + toHex(randomId);

        records[id] = KeyRecord{
            id,
            randomSource.bytes(32),
            timestamp,
            true
        };

        return id;
    }

    const Bytes& getActiveKey(
        const std::string& keyId
    ) const {
        const auto iterator = records.find(keyId);

        if (iterator == records.end()) {
            throw std::runtime_error("Unknown key identifier.");
        }

        if (!iterator->second.active) {
            throw std::runtime_error("Key is inactive.");
        }

        return iterator->second.material;
    }

    void deactivate(const std::string& keyId) {
        const auto iterator = records.find(keyId);

        if (iterator == records.end()) {
            throw std::runtime_error("Unknown key identifier.");
        }

        iterator->second.active = false;
    }
};

/*
 * SecureEnvelope
 * --------------
 *
 * An envelope contains explicit metadata rather than relying on implicit
 * protocol assumptions.
 */
struct SecureEnvelope {
    std::string protocolVersion;
    std::string sender;
    std::string messageId;
    std::string keyId;
    std::int64_t timestamp;

    Bytes associatedData;
    Bytes nonce;
    Bytes ciphertext;
    Bytes authenticationTag;
};

/*
 * EducationalAuthenticatedEncryption
 * -----------------------------------
 *
 * The payload operation uses XOR with a digest-derived keystream to illustrate
 * authenticated-encryption data flow.
 *
 * It is deliberately NOT AES-GCM or ChaCha20-Poly1305.
 */
class EducationalAuthenticatedEncryption {
private:
    static Bytes createKeystream(
        const Bytes& key,
        const Bytes& nonce,
        std::size_t length
    ) {
        Bytes stream;
        stream.reserve(length);

        std::uint64_t counter = 0;

        while (stream.size() < length) {
            Bytes input;

            input.insert(
                input.end(),
                key.begin(),
                key.end()
            );

            input.insert(
                input.end(),
                nonce.begin(),
                nonce.end()
            );

            for (int shift = 56; shift >= 0; shift -= 8) {
                input.push_back(
                    static_cast<Byte>(
                        (counter >> shift) & 0xFF
                    )
                );
            }

            Bytes block = EducationalDigest::bytes(input);

            const std::size_t remaining =
                length - stream.size();

            const std::size_t toCopy =
                std::min(remaining, block.size());

            stream.insert(
                stream.end(),
                block.begin(),
                block.begin() + static_cast<std::ptrdiff_t>(toCopy)
            );

            ++counter;
        }

        return stream;
    }

    static Bytes xorBytes(
        const Bytes& data,
        const Bytes& stream
    ) {
        if (data.size() != stream.size()) {
            throw std::runtime_error(
                "Data and keystream lengths differ."
            );
        }

        Bytes result(data.size());

        for (std::size_t index = 0; index < data.size(); ++index) {
            result[index] = data[index] ^ stream[index];
        }

        return result;
    }

public:
    static SecureEnvelope encrypt(
        const Bytes& key,
        const std::string& sender,
        const std::string& keyId,
        const std::string& messageId,
        std::int64_t timestamp,
        const Bytes& plaintext,
        const Bytes& associatedData,
        const Bytes& nonce
    ) {
        if (plaintext.empty()) {
            throw std::invalid_argument(
                "Plaintext must not be empty."
            );
        }

        const Bytes stream =
            createKeystream(
                key,
                nonce,
                plaintext.size()
            );

        const Bytes ciphertext =
            xorBytes(plaintext, stream);

        Bytes authenticatedInput;

        authenticatedInput.insert(
            authenticatedInput.end(),
            associatedData.begin(),
            associatedData.end()
        );

        authenticatedInput.insert(
            authenticatedInput.end(),
            nonce.begin(),
            nonce.end()
        );

        authenticatedInput.insert(
            authenticatedInput.end(),
            ciphertext.begin(),
            ciphertext.end()
        );

        const Bytes tag =
            MessageAuthenticator::authenticate(
                key,
                authenticatedInput
            );

        return SecureEnvelope{
            "1",
            sender,
            messageId,
            keyId,
            timestamp,
            associatedData,
            nonce,
            ciphertext,
            tag
        };
    }

    static Bytes decrypt(
        const Bytes& key,
        const SecureEnvelope& envelope
    ) {
        Bytes authenticatedInput;

        authenticatedInput.insert(
            authenticatedInput.end(),
            envelope.associatedData.begin(),
            envelope.associatedData.end()
        );

        authenticatedInput.insert(
            authenticatedInput.end(),
            envelope.nonce.begin(),
            envelope.nonce.end()
        );

        authenticatedInput.insert(
            authenticatedInput.end(),
            envelope.ciphertext.begin(),
            envelope.ciphertext.end()
        );

        if (!MessageAuthenticator::verify(
            key,
            authenticatedInput,
            envelope.authenticationTag
        )) {
            throw std::runtime_error(
                "Authentication failed."
            );
        }

        const Bytes stream =
            createKeystream(
                key,
                envelope.nonce,
                envelope.ciphertext.size()
            );

        return xorBytes(
            envelope.ciphertext,
            stream
        );
    }
};

/*
 * ReplayGuard
 * -----------
 *
 * State-changing messages need freshness. A valid authentication tag alone
 * does not prevent an attacker from submitting the same valid message again.
 */
class ReplayGuard {
private:
    std::set<std::string> processedMessageIds;
    std::int64_t maximumAgeSeconds;

public:
    explicit ReplayGuard(
        std::int64_t maximumAgeSeconds = 300
    )
        : maximumAgeSeconds(maximumAgeSeconds) {}

    bool accept(
        const SecureEnvelope& envelope
    ) {
        const auto now =
            std::chrono::system_clock::now();

        const auto currentTime =
            std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()
            ).count();

        const std::int64_t age =
            std::llabs(currentTime - envelope.timestamp);

        if (age > maximumAgeSeconds) {
            return false;
        }

        if (processedMessageIds.count(
                envelope.messageId
            ) != 0) {
            return false;
        }

        processedMessageIds.insert(
            envelope.messageId
        );

        return true;
    }
};

/*
 * SecureDocumentService
 * ---------------------
 *
 * The service combines:
 *     identity metadata
 *     key management
 *     authenticated encryption
 *     replay protection
 *     key rotation
 *     validation
 *
 * The architecture intentionally separates responsibilities so that each
 * component can be tested independently.
 */
class SecureDocumentService {
private:
    KeyManager keyManager;
    ReplayGuard replayGuard;
    SecureRandom randomSource;

    std::string activeKeyId;

    static Bytes makeAssociatedData(
        const std::string& sender,
        const std::string& messageId,
        const std::string& keyId,
        std::int64_t timestamp
    ) {
        const std::string text =
            "version=1|sender=" +
            sender +
            "|message-id=" +
            messageId +
            "|key-id=" +
            keyId +
            "|timestamp=" +
            std::to_string(timestamp);

        return stringToBytes(text);
    }

public:
    SecureDocumentService()
        : replayGuard(300) {
        activeKeyId = keyManager.createKey();
    }

    const std::string& currentKeyId() const {
        return activeKeyId;
    }

    void rotateKey() {
        const std::string oldKeyId = activeKeyId;

        keyManager.deactivate(oldKeyId);

        activeKeyId = keyManager.createKey();
    }

    SecureEnvelope encryptDocument(
        const std::string& sender,
        const std::string& document
    ) {
        if (sender.empty()) {
            throw std::invalid_argument(
                "Sender cannot be empty."
            );
        }

        if (document.empty()) {
            throw std::invalid_argument(
                "Document cannot be empty."
            );
        }

        const auto now =
            std::chrono::system_clock::now();

        const auto timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(
                now.time_since_epoch()
            ).count();

        const std::string messageId =
            toHex(randomSource.bytes(16));

        const Bytes nonce =
            randomSource.bytes(12);

        const Bytes associatedData =
            makeAssociatedData(
                sender,
                messageId,
                activeKeyId,
                timestamp
            );

        const Bytes plaintext =
            stringToBytes(document);

        return EducationalAuthenticatedEncryption::encrypt(
            keyManager.getActiveKey(activeKeyId),
            sender,
            activeKeyId,
            messageId,
            timestamp,
            plaintext,
            associatedData,
            nonce
        );
    }

    std::string decryptDocument(
        const SecureEnvelope& envelope
    ) {
        if (envelope.protocolVersion != "1") {
            throw std::runtime_error(
                "Unsupported protocol version."
            );
        }

        /*
         * Replay checking is performed before releasing plaintext.
         * Authentication still happens during decryption.
         */
        if (!replayGuard.accept(envelope)) {
            throw std::runtime_error(
                "Replay or expired message rejected."
            );
        }

        const Bytes plaintext =
            EducationalAuthenticatedEncryption::decrypt(
                keyManager.getActiveKey(envelope.keyId),
                envelope
            );

        return bytesToString(plaintext);
    }
};

/*
 * Test functions
 * --------------
 *
 * Security-sensitive code needs tests for successful operations and failure
 * paths. The case study includes explicit tampering and replay tests.
 */

void testSuccessfulRoundTrip() {
    SecureDocumentService service;

    const SecureEnvelope envelope =
        service.encryptDocument(
            "alice@example.test",
            "Confidential acquisition document"
        );

    const std::string recovered =
        service.decryptDocument(envelope);

    if (recovered != "Confidential acquisition document") {
        throw std::runtime_error(
            "Round-trip encryption test failed."
        );
    }

    std::cout
        << "PASS: authenticated document round trip\n";
}

void testTamperingDetection() {
    SecureDocumentService service;

    SecureEnvelope envelope =
        service.encryptDocument(
            "alice@example.test",
            "Transfer INR 5000"
        );

    if (envelope.ciphertext.empty()) {
        throw std::runtime_error(
            "Unexpected empty ciphertext."
        );
    }

    envelope.ciphertext[0] ^= 0x01;

    try {
        service.decryptDocument(envelope);

        throw std::runtime_error(
            "Tampering test unexpectedly succeeded."
        );
    }
    catch (const std::runtime_error& error) {
        if (
            std::string(error.what()) !=
            "Authentication failed."
        ) {
            throw;
        }

        std::cout
            << "PASS: ciphertext tampering detected\n";
    }
}

void testReplayDetection() {
    SecureDocumentService service;

    const SecureEnvelope envelope =
        service.encryptDocument(
            "alice@example.test",
            "One-time authorization"
        );

    const std::string firstResult =
        service.decryptDocument(envelope);

    if (firstResult != "One-time authorization") {
        throw std::runtime_error(
            "Unexpected decrypted content."
        );
    }

    try {
        service.decryptDocument(envelope);

        throw std::runtime_error(
            "Replay test unexpectedly succeeded."
        );
    }
    catch (const std::runtime_error& error) {
        if (
            std::string(error.what()) !=
            "Replay or expired message rejected."
        ) {
            throw;
        }

        std::cout
            << "PASS: replay detected\n";
    }
}

void testValidation() {
    SecureDocumentService service;

    try {
        service.encryptDocument(
            "",
            "document"
        );

        throw std::runtime_error(
            "Empty sender was accepted."
        );
    }
    catch (const std::invalid_argument&) {
        std::cout
            << "PASS: sender validation\n";
    }

    try {
        service.encryptDocument(
            "alice@example.test",
            ""
        );

        throw std::runtime_error(
            "Empty document was accepted."
        );
    }
    catch (const std::invalid_argument&) {
        std::cout
            << "PASS: document validation\n";
    }
}

void testKeyRotation() {
    SecureDocumentService service;

    const std::string firstKey =
        service.currentKeyId();

    service.rotateKey();

    const std::string secondKey =
        service.currentKeyId();

    if (firstKey == secondKey) {
        throw std::runtime_error(
            "Key rotation did not change the active key."
        );
    }

    std::cout
        << "PASS: key rotation generated a new key ID\n";
}

/*
 * Complexity discussion
 * ---------------------
 *
 * Hashing:
 *     O(n) in message size.
 *
 * HMAC:
 *     O(n) in message size for a fixed-size key.
 *
 * Stream processing:
 *     O(n) in plaintext size.
 *
 * Replay lookup:
 *     std::set gives O(log m) lookup/insertion for m message IDs.
 *
 * Key lookup:
 *     std::map gives O(log k) lookup for k keys.
 *
 * A production system could use an unordered map/set when appropriate, but
 * denial-of-service, memory use, persistence, concurrency, and operational
 * behavior must also be considered.
 */
void explainArchitecture() {
    printSection("Architecture and complexity");

    std::cout
        << "1. Application layer: validates document requests.\n"
        << "2. Protocol layer: creates explicit authenticated metadata.\n"
        << "3. Key layer: manages key identifiers and rotation.\n"
        << "4. Encryption layer: protects confidentiality and integrity.\n"
        << "5. Replay layer: rejects reused message identifiers.\n"
        << "6. Test layer: exercises success and failure conditions.\n\n";

    std::cout
        << "Primary data-size operations are linear in payload size.\n"
        << "Key and replay metadata operations depend on container size.\n";
}

/*
 * Security limitations
 * --------------------
 *
 * This case study intentionally does not claim production cryptographic
 * security. Important missing production concerns include:
 *
 *     - audited cryptographic primitives
 *     - secure memory handling
 *     - hardware-backed key storage
 *     - certificate validation
 *     - authenticated peer identity
 *     - distributed replay state
 *     - secure transport
 *     - persistent key lifecycle management
 *     - side-channel analysis
 *     - algorithm-agility standards
 *     - post-quantum cryptographic migration
 */
void explainLimitations() {
    printSection("Security limitations");

    const std::vector<std::string> limitations{
        "The digest implementation is educational, not SHA-256.",
        "The authentication construction is educational, not standardized HMAC.",
        "The encryption construction is educational, not AES-GCM.",
        "std::random_device is not a universal guarantee of CSPRNG behavior.",
        "Keys are stored directly in process memory.",
        "No certificate authority or trust-chain validation is implemented.",
        "The replay set is local to one process.",
        "No secure key backup or disaster recovery mechanism exists.",
        "No formal side-channel analysis has been performed."
    };

    for (const auto& limitation : limitations) {
        std::cout << "- " << limitation << "\n";
    }
}

void runCaseStudy() {
    printSection("Modern Cryptography Case Study");

    SecureDocumentService service;

    const SecureEnvelope envelope =
        service.encryptDocument(
            "alice@example.test",
            "Board-approved acquisition document"
        );

    std::cout
        << "Protocol version: "
        << envelope.protocolVersion
        << "\n";

    std::cout
        << "Sender: "
        << envelope.sender
        << "\n";

    std::cout
        << "Message ID: "
        << envelope.messageId
        << "\n";

    std::cout
        << "Key ID: "
        << envelope.keyId
        << "\n";

    std::cout
        << "Nonce: "
        << toHex(envelope.nonce)
        << "\n";

    std::cout
        << "Ciphertext: "
        << toHex(envelope.ciphertext)
        << "\n";

    std::cout
        << "Authentication tag: "
        << toHex(envelope.authenticationTag)
        << "\n";

    const std::string recovered =
        service.decryptDocument(envelope);

    std::cout
        << "Recovered document: "
        << recovered
        << "\n";
}

} // namespace crypto_case_study

int main() {
    using namespace crypto_case_study;

    try {
        printSection("Secure Document Exchange Study");

        runCaseStudy();

        printSection("Security Tests");

        testSuccessfulRoundTrip();
        testTamperingDetection();
        testReplayDetection();
        testValidation();
        testKeyRotation();

        explainArchitecture();
        explainLimitations();

        printSection("Case Study Completed");

        std::cout
            << "The implementation demonstrates cryptographic protocol "
               "architecture and failure handling.\n"
            << "Production systems should replace educational primitives "
               "with audited cryptographic libraries.\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
