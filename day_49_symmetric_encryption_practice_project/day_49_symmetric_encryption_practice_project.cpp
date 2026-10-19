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
#include <unordered_set>
#include <vector>

/*
 * Symmetric Encryption Governance Case Study
 *
 * Scenario:
 * A document platform stores confidential records that must be protected
 * with a shared symmetric key. The system models:
 *
 * - encryption key ownership
 * - key versions
 * - authenticated message envelopes
 * - nonce uniqueness
 * - integrity verification
 * - key rotation
 * - authorization around encryption operations
 *
 * The program uses a compact educational authenticated-encryption model
 * rather than implementing a production cipher from scratch. The purpose is
 * to make the system-level responsibilities around symmetric encryption
 * visible: key lifecycle, nonce management, authentication, and policy.
 */

namespace crypto_practice {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;

constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;

Bytes random_bytes(std::size_t count) {
    std::random_device device;
    std::mt19937_64 generator(
        (static_cast<std::uint64_t>(device()) << 32) ^ device()
    );

    Bytes result(count);
    for (auto& value : result) {
        value = static_cast<Byte>(generator() & 0xFF);
    }
    return result;
}

std::string hex(const Bytes& data) {
    std::ostringstream output;

    for (Byte value : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(value);
    }

    return output.str();
}

Bytes from_string(const std::string& value) {
    return Bytes(value.begin(), value.end());
}

std::string to_string(const Bytes& value) {
    return std::string(value.begin(), value.end());
}

/*
 * This operation is deliberately a model, not AES. Production C++ software
 * should use a reviewed cryptographic library rather than handwritten
 * cryptographic primitives.
 */
Bytes stream_transform(
    const Bytes& plaintext,
    const Bytes& key,
    const Bytes& nonce
) {
    if (key.size() != KEY_SIZE) {
        throw std::invalid_argument("Invalid symmetric key size");
    }

    if (nonce.size() != NONCE_SIZE) {
        throw std::invalid_argument("Invalid nonce size");
    }

    Bytes output(plaintext.size());

    std::uint64_t state = 0x9E3779B97F4A7C15ULL;

    for (Byte value : key) {
        state ^= value;
        state *= 0x100000001B3ULL;
    }

    for (Byte value : nonce) {
        state ^= value;
        state *= 0x100000001B3ULL;
    }

    for (std::size_t index = 0; index < plaintext.size(); ++index) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;

        const Byte mask =
            static_cast<Byte>((state * 0x2545F4914F6CDD1DULL) >> 56);

        output[index] = plaintext[index] ^ mask;
    }

    return output;
}

Bytes authentication_tag(
    const Bytes& ciphertext,
    const Bytes& key,
    const Bytes& nonce,
    const Bytes& associated_data
) {
    /*
     * The tag represents the architectural role of authenticated encryption:
     * ciphertext and protected metadata are both covered by authentication.
     * This compact demonstration is not intended as a cryptographic primitive.
     */
    std::uint64_t state = 1469598103934665603ULL;

    auto absorb = [&state](const Bytes& data) {
        for (Byte value : data) {
            state ^= value;
            state *= 1099511628211ULL;
            state ^= state >> 29;
        }
    };

    absorb(key);
    absorb(nonce);
    absorb(associated_data);
    absorb(ciphertext);

    Bytes tag(TAG_SIZE);

    for (std::size_t index = 0; index < TAG_SIZE; ++index) {
        state ^= state >> 13;
        state *= 0x9E3779B185EBCA87ULL;
        state ^= state >> 17;
        tag[index] = static_cast<Byte>(state >> 56);
    }

    return tag;
}

bool constant_time_equal(const Bytes& left, const Bytes& right) {
    if (left.size() != right.size()) {
        return false;
    }

    Byte difference = 0;

    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= left[index] ^ right[index];
    }

    return difference == 0;
}

struct KeyVersion {
    std::string id;
    Bytes material;
    bool active;
};

class KeyManager {
private:
    std::map<std::string, KeyVersion> keys;

public:
    void create(const std::string& id) {
        if (id.empty()) {
            throw std::invalid_argument("Key ID cannot be empty");
        }

        if (keys.contains(id)) {
            throw std::logic_error("Key ID already exists");
        }

        keys.emplace(
            id,
            KeyVersion{id, random_bytes(KEY_SIZE), true}
        );
    }

    const KeyVersion& get(const std::string& id) const {
        auto iterator = keys.find(id);

        if (iterator == keys.end()) {
            throw std::out_of_range("Unknown key version: " + id);
        }

        if (!iterator->second.active) {
            throw std::runtime_error("Key version is disabled: " + id);
        }

        return iterator->second;
    }

    void deactivate(const std::string& id) {
        auto iterator = keys.find(id);

        if (iterator == keys.end()) {
            throw std::out_of_range("Unknown key version: " + id);
        }

        iterator->second.active = false;
    }

    std::size_t active_key_count() const {
        return std::count_if(
            keys.begin(),
            keys.end(),
            [](const auto& entry) {
                return entry.second.active;
            }
        );
    }
};

class NonceRegistry {
private:
    std::unordered_set<std::string> used;

    static std::string identity(
        const std::string& key_id,
        const Bytes& nonce
    ) {
        return key_id + ":" + hex(nonce);
    }

public:
    bool reserve(
        const std::string& key_id,
        const Bytes& nonce
    ) {
        if (nonce.size() != NONCE_SIZE) {
            throw std::invalid_argument("Nonce has invalid length");
        }

        return used.insert(identity(key_id, nonce)).second;
    }

    bool seen(
        const std::string& key_id,
        const Bytes& nonce
    ) const {
        return used.contains(identity(key_id, nonce));
    }
};

struct EncryptedRecord {
    std::string key_id;
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
    Bytes associated_data;
};

class EncryptionService {
private:
    KeyManager& key_manager;
    NonceRegistry& nonce_registry;

public:
    EncryptionService(
        KeyManager& keys,
        NonceRegistry& nonces
    )
        : key_manager(keys),
          nonce_registry(nonces) {}

    EncryptedRecord encrypt(
        const std::string& key_id,
        const Bytes& plaintext,
        const Bytes& associated_data
    ) {
        const KeyVersion& key = key_manager.get(key_id);

        Bytes nonce;

        /*
         * The service owns nonce generation and registration. A caller cannot
         * silently provide a reused GCM-style nonce to the encryption layer.
         */
        do {
            nonce = random_bytes(NONCE_SIZE);
        } while (!nonce_registry.reserve(key_id, nonce));

        Bytes ciphertext =
            stream_transform(plaintext, key.material, nonce);

        Bytes tag = authentication_tag(
            ciphertext,
            key.material,
            nonce,
            associated_data
        );

        return {
            key_id,
            std::move(nonce),
            std::move(ciphertext),
            std::move(tag),
            associated_data
        };
    }

    Bytes decrypt(const EncryptedRecord& record) const {
        const KeyVersion& key =
            key_manager.get(record.key_id);

        if (record.nonce.size() != NONCE_SIZE) {
            throw std::invalid_argument("Malformed nonce");
        }

        if (record.tag.size() != TAG_SIZE) {
            throw std::invalid_argument("Malformed authentication tag");
        }

        const Bytes expected_tag = authentication_tag(
            record.ciphertext,
            key.material,
            record.nonce,
            record.associated_data
        );

        /*
         * No plaintext is returned if authentication fails. This is an
         * important boundary between untrusted ciphertext and trusted data.
         */
        if (!constant_time_equal(record.tag, expected_tag)) {
            throw std::runtime_error(
                "Authentication failure: record was modified or wrong key used"
            );
        }

        return stream_transform(
            record.ciphertext,
            key.material,
            record.nonce
        );
    }
};

class DocumentRepository {
private:
    std::map<std::string, EncryptedRecord> records;

public:
    void store(
        const std::string& document_id,
        EncryptedRecord record
    ) {
        if (document_id.empty()) {
            throw std::invalid_argument("Document ID cannot be empty");
        }

        if (records.contains(document_id)) {
            throw std::logic_error("Document already exists");
        }

        records.emplace(document_id, std::move(record));
    }

    EncryptedRecord& get(const std::string& document_id) {
        auto iterator = records.find(document_id);

        if (iterator == records.end()) {
            throw std::out_of_range("Document not found");
        }

        return iterator->second;
    }
};

void demonstrate_document_workflow() {
    KeyManager keys;
    NonceRegistry nonces;
    EncryptionService service(keys, nonces);
    DocumentRepository repository;

    keys.create("documents-v1");

    const Bytes metadata =
        from_string("document=FIN-2026-001;classification=confidential");

    const Bytes plaintext =
        from_string(
            "Quarterly financial controls require protected storage."
        );

    EncryptedRecord record =
        service.encrypt(
            "documents-v1",
            plaintext,
            metadata
        );

    repository.store("FIN-2026-001", std::move(record));

    const Bytes recovered =
        service.decrypt(repository.get("FIN-2026-001"));

    std::cout << "\n=== Protected Document ===\n";
    std::cout << "Key version: "
              << repository.get("FIN-2026-001").key_id
              << '\n';
    std::cout << "Ciphertext: "
              << hex(repository.get("FIN-2026-001").ciphertext)
              << '\n';
    std::cout << "Recovered: "
              << to_string(recovered)
              << '\n';
}

void demonstrate_metadata_authentication() {
    KeyManager keys;
    NonceRegistry nonces;
    EncryptionService service(keys, nonces);

    keys.create("metadata-v1");

    EncryptedRecord record = service.encrypt(
        "metadata-v1",
        from_string("salary=protected"),
        from_string("employee=E-2048")
    );

    record.associated_data =
        from_string("employee=E-9999");

    try {
        service.decrypt(record);
        throw std::runtime_error(
            "Metadata modification was incorrectly accepted"
        );
    } catch (const std::runtime_error& error) {
        std::cout << "\n=== Associated Data Protection ===\n";
        std::cout << "Modified metadata rejected: "
                  << error.what()
                  << '\n';
    }
}

void demonstrate_ciphertext_tampering() {
    KeyManager keys;
    NonceRegistry nonces;
    EncryptionService service(keys, nonces);

    keys.create("tamper-v1");

    EncryptedRecord record = service.encrypt(
        "tamper-v1",
        from_string("do not modify"),
        from_string("record=7")
    );

    record.ciphertext[0] ^= 0x40;

    try {
        service.decrypt(record);
        throw std::runtime_error(
            "Ciphertext modification was incorrectly accepted"
        );
    } catch (const std::runtime_error& error) {
        std::cout << "\n=== Ciphertext Integrity ===\n";
        std::cout << "Tampering rejected: "
                  << error.what()
                  << '\n';
    }
}

void demonstrate_key_rotation() {
    KeyManager keys;
    NonceRegistry nonces;
    EncryptionService service(keys, nonces);
    DocumentRepository repository;

    keys.create("archive-v1");
    keys.create("archive-v2");

    const Bytes metadata =
        from_string("document=ARCHIVE-42");

    EncryptedRecord first =
        service.encrypt(
            "archive-v1",
            from_string("legacy protected archive"),
            metadata
        );

    repository.store("ARCHIVE-42", first);

    Bytes plaintext =
        service.decrypt(repository.get("ARCHIVE-42"));

    EncryptedRecord rotated =
        service.encrypt(
            "archive-v2",
            plaintext,
            metadata
        );

    repository.get("ARCHIVE-42") = rotated;

    std::cout << "\n=== Key Rotation ===\n";
    std::cout << "New key version: "
              << repository.get("ARCHIVE-42").key_id
              << '\n';
    std::cout << "Recovered after rotation: "
              << to_string(
                     service.decrypt(repository.get("ARCHIVE-42"))
                 )
              << '\n';

    keys.deactivate("archive-v1");

    std::cout << "Active key versions after retiring old key: "
              << keys.active_key_count()
              << '\n';
}

void demonstrate_nonce_reuse_guard() {
    NonceRegistry registry;
    Bytes nonce(NONCE_SIZE, 0x42);

    const bool first =
        registry.reserve("key-a", nonce);

    const bool second =
        registry.reserve("key-a", nonce);

    std::cout << "\n=== Nonce Reuse Guard ===\n";
    std::cout << "First reservation accepted: "
              << std::boolalpha << first << '\n';
    std::cout << "Second reservation accepted: "
              << std::boolalpha << second << '\n';

    if (second) {
        throw std::runtime_error(
            "Nonce registry failed to prevent reuse"
        );
    }
}

void demonstrate_invalid_key_usage() {
    KeyManager keys;
    NonceRegistry nonces;
    EncryptionService service(keys, nonces);

    try {
        service.encrypt(
            "missing-key",
            from_string("secret"),
            from_string("record=x")
        );

        throw std::runtime_error(
            "Unknown key was incorrectly accepted"
        );
    } catch (const std::out_of_range& error) {
        std::cout << "\n=== Key Validation ===\n";
        std::cout << "Unknown key rejected: "
                  << error.what()
                  << '\n';
    }
}

} // namespace crypto_practice

int main() {
    try {
        std::cout
            << "SYMMETRIC ENCRYPTION PRACTICE PROJECT\n"
            << "C++17 repository document-protection case study\n";

        crypto_practice::demonstrate_document_workflow();
        crypto_practice::demonstrate_metadata_authentication();
        crypto_practice::demonstrate_ciphertext_tampering();
        crypto_practice::demonstrate_key_rotation();
        crypto_practice::demonstrate_nonce_reuse_guard();
        crypto_practice::demonstrate_invalid_key_usage();

        std::cout << "\n=== Engineering Boundaries ===\n";
        std::cout
            << "Encryption protects confidentiality, while authentication "
               "protects integrity and authenticity.\n";
        std::cout
            << "Nonce uniqueness is a key-management responsibility for "
               "nonce-based authenticated encryption.\n";
        std::cout
            << "Key rotation requires decrypting under the old key and "
               "re-encrypting under the replacement key.\n";
        std::cout
            << "Production systems should use a reviewed cryptographic "
               "library rather than custom cipher primitives.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what()
                  << '\n';
        return 1;
    }
}
