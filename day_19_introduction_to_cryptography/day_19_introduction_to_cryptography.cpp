#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * Introduction to Cryptography
 * =============================
 *
 * Industry-style C++ case study:
 *
 * A secure document-transfer service is modeled using:
 *   - users and identities
 *   - cryptographic hashes
 *   - keyed authentication
 *   - authenticated message envelopes
 *   - sequence numbers for replay protection
 *   - key versions and rotation
 *   - audit records
 *   - validation and failure handling
 *
 * The program deliberately uses a small educational cryptographic model
 * rather than pretending that handwritten cryptography is production safe.
 *
 * In production, use established cryptographic libraries and standardized
 * protocols such as TLS and standardized AEAD constructions.
 */

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;


// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

std::string toHex(const Bytes& data) {
    std::ostringstream output;

    for (Byte value : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(value);
    }

    return output.str();
}

Bytes stringToBytes(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

std::string bytesToString(const Bytes& bytes) {
    return std::string(bytes.begin(), bytes.end());
}

Bytes xorBytes(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) {
        throw std::invalid_argument("XOR operands must have equal length.");
    }

    Bytes result(left.size());

    for (std::size_t i = 0; i < left.size(); ++i) {
        result[i] = left[i] ^ right[i];
    }

    return result;
}

bool constantTimeEqual(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) {
        return false;
    }

    Byte difference = 0;

    for (std::size_t i = 0; i < left.size(); ++i) {
        difference |= left[i] ^ right[i];
    }

    return difference == 0;
}


// ---------------------------------------------------------------------------
// Educational hash function
// ---------------------------------------------------------------------------

/*
 * This is NOT a cryptographic hash algorithm.
 *
 * It exists to demonstrate the interface and architectural role of a digest
 * without implementing a real cryptographic primitive from scratch.
 *
 * A production system must use a vetted implementation of SHA-256, SHA-3,
 * BLAKE2, or another algorithm appropriate to its security requirements.
 */
class EducationalHash {
public:
    static Bytes digest(const Bytes& input) {
        std::uint64_t state1 = 0x243F6A8885A308D3ULL;
        std::uint64_t state2 = 0x13198A2E03707344ULL;

        for (Byte value : input) {
            state1 ^= value;
            state1 *= 0x100000001B3ULL;
            state1 ^= state1 >> 29;

            state2 += value + 0x9E3779B97F4A7C15ULL;
            state2 ^= state2 << 17;
            state2 ^= state2 >> 31;
        }

        Bytes result(16);

        for (int i = 0; i < 8; ++i) {
            result[i] = static_cast<Byte>(
                (state1 >> (i * 8)) & 0xFF
            );

            result[i + 8] = static_cast<Byte>(
                (state2 >> (i * 8)) & 0xFF
            );
        }

        return result;
    }
};


// ---------------------------------------------------------------------------
// Secure random bytes for the demonstration environment
// ---------------------------------------------------------------------------

class RandomGenerator {
private:
    std::random_device device;

public:
    Bytes bytes(std::size_t count) {
        Bytes result(count);

        for (Byte& value : result) {
            value = static_cast<Byte>(device() & 0xFF);
        }

        return result;
    }
};


// ---------------------------------------------------------------------------
// Key management
// ---------------------------------------------------------------------------

struct KeyRecord {
    int version;
    Bytes key;
    bool active;
};

class KeyRing {
private:
    std::map<int, KeyRecord> keys;

public:
    void addKey(int version, const Bytes& key) {
        if (version <= 0) {
            throw std::invalid_argument("Key version must be positive.");
        }

        if (key.size() < 16) {
            throw std::invalid_argument(
                "Educational key must contain at least 16 bytes."
            );
        }

        keys[version] = KeyRecord{
            version,
            key,
            true
        };
    }

    void deactivate(int version) {
        auto iterator = keys.find(version);

        if (iterator == keys.end()) {
            throw std::out_of_range("Unknown key version.");
        }

        iterator->second.active = false;
    }

    const KeyRecord& get(int version) const {
        auto iterator = keys.find(version);

        if (iterator == keys.end()) {
            throw std::out_of_range("Unknown key version.");
        }

        return iterator->second;
    }

    int latestActiveVersion() const {
        for (auto iterator = keys.rbegin(); iterator != keys.rend(); ++iterator) {
            if (iterator->second.active) {
                return iterator->first;
            }
        }

        throw std::runtime_error("No active key exists.");
    }
};


// ---------------------------------------------------------------------------
// Educational keyed authentication
// ---------------------------------------------------------------------------

class MessageAuthenticator {
public:
    static Bytes authenticate(
        const Bytes& key,
        const Bytes& message
    ) {
        Bytes combined = key;

        combined.insert(
            combined.end(),
            message.begin(),
            message.end()
        );

        return EducationalHash::digest(combined);
    }

    static bool verify(
        const Bytes& key,
        const Bytes& message,
        const Bytes& tag
    ) {
        const Bytes expected = authenticate(key, message);

        return constantTimeEqual(expected, tag);
    }
};


// ---------------------------------------------------------------------------
// Application data structures
// ---------------------------------------------------------------------------

struct User {
    std::string id;
    std::string displayName;
};

struct Document {
    std::string documentId;
    std::string ownerId;
    Bytes content;
};

struct SecureEnvelope {
    int keyVersion;
    std::string senderId;
    std::string receiverId;
    std::uint64_t sequenceNumber;
    Bytes nonce;
    Bytes ciphertext;
    Bytes authenticationTag;
};


// ---------------------------------------------------------------------------
// Educational encryption service
// ---------------------------------------------------------------------------

class EducationalEncryption {
public:
    /*
     * The encryption mechanism here is deliberately simple:
     *
     * ciphertext = plaintext XOR generated keystream
     *
     * It is useful for illustrating that encryption transforms plaintext into
     * ciphertext, but it is NOT secure cryptography.
     *
     * Real systems should use a standardized AEAD construction such as
     * AES-GCM or ChaCha20-Poly1305.
     */
    static Bytes encrypt(
        const Bytes& plaintext,
        const Bytes& key,
        const Bytes& nonce
    ) {
        Bytes seed = key;
        seed.insert(seed.end(), nonce.begin(), nonce.end());

        Bytes stream;
        stream.reserve(plaintext.size());

        std::uint32_t counter = 0;

        while (stream.size() < plaintext.size()) {
            Bytes block = seed;

            block.push_back(
                static_cast<Byte>((counter >> 24) & 0xFF)
            );
            block.push_back(
                static_cast<Byte>((counter >> 16) & 0xFF)
            );
            block.push_back(
                static_cast<Byte>((counter >> 8) & 0xFF)
            );
            block.push_back(
                static_cast<Byte>(counter & 0xFF)
            );

            Bytes digest = EducationalHash::digest(block);

            stream.insert(
                stream.end(),
                digest.begin(),
                digest.end()
            );

            ++counter;
        }

        stream.resize(plaintext.size());

        return xorBytes(plaintext, stream);
    }

    static Bytes decrypt(
        const Bytes& ciphertext,
        const Bytes& key,
        const Bytes& nonce
    ) {
        return encrypt(ciphertext, key, nonce);
    }
};


// ---------------------------------------------------------------------------
// Audit system
// ---------------------------------------------------------------------------

struct AuditEvent {
    std::uint64_t eventNumber;
    std::string eventType;
    std::string actor;
    std::string description;
};

class AuditLog {
private:
    std::vector<AuditEvent> events;

public:
    void record(
        const std::string& type,
        const std::string& actor,
        const std::string& description
    ) {
        events.push_back(AuditEvent{
            static_cast<std::uint64_t>(events.size() + 1),
            type,
            actor,
            description
        });
    }

    void print() const {
        std::cout << "\nAudit log\n";
        std::cout << "----------------------------------------\n";

        for (const auto& event : events) {
            std::cout
                << "#" << event.eventNumber
                << " [" << event.eventType << "] "
                << event.actor << " -> "
                << event.description << '\n';
        }
    }
};


// ---------------------------------------------------------------------------
// Secure document service
// ---------------------------------------------------------------------------

class SecureDocumentService {
private:
    RandomGenerator randomGenerator;
    KeyRing keyRing;
    AuditLog auditLog;

    std::unordered_map<std::string, User> users;
    std::unordered_map<std::string, Document> documents;

    /*
     * Replay protection tracks the highest sequence number accepted for
     * each sender/receiver relationship.
     */
    std::map<std::pair<std::string, std::string>, std::uint64_t>
        highestSequence;

    Bytes envelopeAuthenticationData(
        const SecureEnvelope& envelope
    ) const {
        Bytes data;

        const auto appendString = [&data](const std::string& value) {
            data.insert(
                data.end(),
                value.begin(),
                value.end()
            );
            data.push_back(0);
        };

        appendString(envelope.senderId);
        appendString(envelope.receiverId);

        for (int shift = 56; shift >= 0; shift -= 8) {
            data.push_back(
                static_cast<Byte>(
                    (envelope.sequenceNumber >> shift) & 0xFF
                )
            );
        }

        data.insert(
            data.end(),
            envelope.nonce.begin(),
            envelope.nonce.end()
        );

        data.insert(
            data.end(),
            envelope.ciphertext.begin(),
            envelope.ciphertext.end()
        );

        return data;
    }

public:
    SecureDocumentService() {
        // Initial key. Real systems would obtain keys from a secure KMS/HSM
        // or another carefully controlled key-management architecture.
        keyRing.addKey(
            1,
            randomGenerator.bytes(32)
        );

        auditLog.record(
            "SYSTEM",
            "system",
            "Initial encryption key created."
        );
    }

    void registerUser(
        const std::string& id,
        const std::string& displayName
    ) {
        if (id.empty()) {
            throw std::invalid_argument("User ID cannot be empty.");
        }

        if (users.find(id) != users.end()) {
            throw std::invalid_argument("User already exists.");
        }

        users.emplace(
            id,
            User{id, displayName}
        );

        auditLog.record(
            "USER_CREATED",
            id,
            "User registered."
        );
    }

    void createDocument(
        const std::string& documentId,
        const std::string& ownerId,
        const std::string& content
    ) {
        if (users.find(ownerId) == users.end()) {
            throw std::invalid_argument("Document owner does not exist.");
        }

        if (documents.find(documentId) != documents.end()) {
            throw std::invalid_argument("Document already exists.");
        }

        documents.emplace(
            documentId,
            Document{
                documentId,
                ownerId,
                stringToBytes(content)
            }
        );

        auditLog.record(
            "DOCUMENT_CREATED",
            ownerId,
            "Document " + documentId + " created."
        );
    }

    SecureEnvelope encryptDocument(
        const std::string& documentId,
        const std::string& senderId,
        const std::string& receiverId,
        std::uint64_t sequenceNumber
    ) {
        if (users.find(senderId) == users.end()) {
            throw std::invalid_argument("Unknown sender.");
        }

        if (users.find(receiverId) == users.end()) {
            throw std::invalid_argument("Unknown receiver.");
        }

        auto documentIterator = documents.find(documentId);

        if (documentIterator == documents.end()) {
            throw std::out_of_range("Unknown document.");
        }

        const int version = keyRing.latestActiveVersion();
        const KeyRecord& key = keyRing.get(version);

        Bytes nonce = randomGenerator.bytes(12);

        Bytes ciphertext = EducationalEncryption::encrypt(
            documentIterator->second.content,
            key.key,
            nonce
        );

        SecureEnvelope envelope{
            version,
            senderId,
            receiverId,
            sequenceNumber,
            nonce,
            ciphertext,
            {}
        };

        Bytes authenticatedData = envelopeAuthenticationData(envelope);

        envelope.authenticationTag =
            MessageAuthenticator::authenticate(
                key.key,
                authenticatedData
            );

        auditLog.record(
            "DOCUMENT_ENCRYPTED",
            senderId,
            "Document " + documentId
            + " encrypted with key version "
            + std::to_string(version)
            + "."
        );

        return envelope;
    }

    std::optional<std::string> decryptDocument(
        const SecureEnvelope& envelope
    ) {
        if (users.find(envelope.senderId) == users.end()) {
            auditLog.record(
                "REJECTED",
                envelope.senderId,
                "Unknown sender."
            );

            return std::nullopt;
        }

        if (users.find(envelope.receiverId) == users.end()) {
            auditLog.record(
                "REJECTED",
                envelope.receiverId,
                "Unknown receiver."
            );

            return std::nullopt;
        }

        const auto pairKey = std::make_pair(
            envelope.senderId,
            envelope.receiverId
        );

        /*
         * Reject a sequence number that is not strictly newer.
         * This simple policy demonstrates replay protection.
         */
        auto sequenceIterator = highestSequence.find(pairKey);

        if (
            sequenceIterator != highestSequence.end()
            && envelope.sequenceNumber <= sequenceIterator->second
        ) {
            auditLog.record(
                "REPLAY_REJECTED",
                envelope.receiverId,
                "Sequence number was already used or is too old."
            );

            return std::nullopt;
        }

        const KeyRecord* key = nullptr;

        try {
            key = &keyRing.get(envelope.keyVersion);
        } catch (const std::exception&) {
            auditLog.record(
                "REJECTED",
                envelope.receiverId,
                "Unknown cryptographic key version."
            );

            return std::nullopt;
        }

        if (!key->active) {
            auditLog.record(
                "REJECTED",
                envelope.receiverId,
                "Cryptographic key version is inactive."
            );

            return std::nullopt;
        }

        Bytes authenticatedData = envelopeAuthenticationData(envelope);

        if (
            !MessageAuthenticator::verify(
                key->key,
                authenticatedData,
                envelope.authenticationTag
            )
        ) {
            auditLog.record(
                "AUTH_FAILURE",
                envelope.receiverId,
                "Authentication tag verification failed."
            );

            return std::nullopt;
        }

        Bytes plaintext = EducationalEncryption::decrypt(
            envelope.ciphertext,
            key->key,
            envelope.nonce
        );

        highestSequence[pairKey] = envelope.sequenceNumber;

        auditLog.record(
            "DOCUMENT_DECRYPTED",
            envelope.receiverId,
            "Authenticated encrypted message accepted."
        );

        return bytesToString(plaintext);
    }

    void rotateKey() {
        const int nextVersion =
            keyRing.latestActiveVersion() + 1;

        keyRing.addKey(
            nextVersion,
            randomGenerator.bytes(32)
        );

        auditLog.record(
            "KEY_ROTATED",
            "system",
            "New active key version "
            + std::to_string(nextVersion)
            + " created."
        );
    }

    void printAuditLog() const {
        auditLog.print();
    }

    int activeKeyVersion() const {
        return keyRing.latestActiveVersion();
    }
};


// ---------------------------------------------------------------------------
// Demonstration helpers
// ---------------------------------------------------------------------------

void printEnvelope(const SecureEnvelope& envelope) {
    std::cout << "\nSecure envelope\n";
    std::cout << "----------------------------------------\n";
    std::cout << "Key version : " << envelope.keyVersion << '\n';
    std::cout << "Sender      : " << envelope.senderId << '\n';
    std::cout << "Receiver    : " << envelope.receiverId << '\n';
    std::cout << "Sequence    : " << envelope.sequenceNumber << '\n';
    std::cout << "Nonce       : " << toHex(envelope.nonce) << '\n';
    std::cout << "Ciphertext  : " << toHex(envelope.ciphertext) << '\n';
    std::cout << "Auth tag    : " << toHex(envelope.authenticationTag) << '\n';
}

void demonstrateBasicHashing() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "Basic cryptographic hash demonstration\n";
    std::cout << "========================================\n";

    const Bytes first = stringToBytes("Hello");
    const Bytes second = stringToBytes("hello");

    std::cout
        << "Hash(Hello): "
        << toHex(EducationalHash::digest(first))
        << '\n';

    std::cout
        << "Hash(hello): "
        << toHex(EducationalHash::digest(second))
        << '\n';

    std::cout
        << "A small input modification produces a different digest.\n";
}

void demonstrateConstantTimeComparison() {
    std::cout << "\n";
    std::cout << "========================================\n";
    std::cout << "Constant-time comparison\n";
    std::cout << "========================================\n";

    const Bytes left = {
        0x01, 0x02, 0x03, 0x04
    };

    const Bytes right = {
        0x01, 0x02, 0x03, 0x04
    };

    const Bytes altered = {
        0x01, 0x02, 0x03, 0x05
    };

    std::cout
        << "Equal values: "
        << std::boolalpha
        << constantTimeEqual(left, right)
        << '\n';

    std::cout
        << "Altered value: "
        << constantTimeEqual(left, altered)
        << '\n';

    std::cout
        << "Authentication tags should be compared with timing-aware "
        << "operations where appropriate.\n";
}


// ---------------------------------------------------------------------------
// Main case study
// ---------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "Introduction to Cryptography - C++ Case Study\n";

        demonstrateBasicHashing();
        demonstrateConstantTimeComparison();

        SecureDocumentService service;

        std::cout << "\n";
        std::cout << "========================================\n";
        std::cout << "Secure document service\n";
        std::cout << "========================================\n";

        service.registerUser(
            "alice",
            "Alice"
        );

        service.registerUser(
            "bob",
            "Bob"
        );

        service.createDocument(
            "DOC-001",
            "alice",
            "Confidential quarterly financial document."
        );

        std::cout
            << "Initial active key version: "
            << service.activeKeyVersion()
            << '\n';

        SecureEnvelope firstMessage =
            service.encryptDocument(
                "DOC-001",
                "alice",
                "bob",
                1
            );

        printEnvelope(firstMessage);

        std::optional<std::string> firstResult =
            service.decryptDocument(firstMessage);

        if (firstResult) {
            std::cout
                << "\nDecrypted content: "
                << *firstResult
                << '\n';
        } else {
            std::cout
                << "\nDocument was rejected.\n";
        }

        std::cout << "\n";
        std::cout << "Replay attack demonstration\n";
        std::cout << "----------------------------------------\n";

        std::optional<std::string> replayResult =
            service.decryptDocument(firstMessage);

        std::cout
            << "Replay accepted: "
            << std::boolalpha
            << replayResult.has_value()
            << '\n';

        std::cout << "\n";
        std::cout << "Tampering demonstration\n";
        std::cout << "----------------------------------------\n";

        SecureEnvelope tamperedMessage =
            service.encryptDocument(
                "DOC-001",
                "alice",
                "bob",
                2
            );

        if (!tamperedMessage.ciphertext.empty()) {
            tamperedMessage.ciphertext[0] ^= 0x01;
        }

        std::optional<std::string> tamperedResult =
            service.decryptDocument(tamperedMessage);

        std::cout
            << "Tampered message accepted: "
            << tamperedResult.has_value()
            << '\n';

        std::cout << "\n";
        std::cout << "Key rotation demonstration\n";
        std::cout << "----------------------------------------\n";

        service.rotateKey();

        std::cout
            << "Current active key version: "
            << service.activeKeyVersion()
            << '\n';

        SecureEnvelope secondMessage =
            service.encryptDocument(
                "DOC-001",
                "alice",
                "bob",
                3
            );

        printEnvelope(secondMessage);

        std::optional<std::string> secondResult =
            service.decryptDocument(secondMessage);

        if (secondResult) {
            std::cout
                << "Decrypted after key rotation: "
                << *secondResult
                << '\n';
        }

        std::cout << "\n";
        std::cout << "Failure-condition demonstration\n";
        std::cout << "----------------------------------------\n";

        SecureEnvelope invalidReceiver =
            service.encryptDocument(
                "DOC-001",
                "alice",
                "bob",
                4
            );

        invalidReceiver.receiverId = "unknown-user";

        std::optional<std::string> invalidResult =
            service.decryptDocument(invalidReceiver);

        std::cout
            << "Invalid receiver accepted: "
            << invalidResult.has_value()
            << '\n';

        service.printAuditLog();

        std::cout << "\n";
        std::cout << "Case study complete.\n";
        std::cout
            << "The architecture demonstrates confidentiality as an application "
            << "goal, authentication, integrity verification, replay protection, "
            << "key versioning, validation, failure handling, and auditing.\n";

        std::cout
            << "\nProduction warning: the educational hash and XOR encryption "
            << "used here are not secure cryptographic primitives.\n";
        std::cout
            << "A production implementation should use a vetted cryptographic "
            << "library and standardized authenticated-encryption protocols.\n";

    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }

    return 0;
}
