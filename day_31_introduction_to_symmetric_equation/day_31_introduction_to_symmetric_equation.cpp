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
#include <string_view>
#include <vector>

/*
 * Symmetric Encryption: Repository Secret Vault Case Study
 *
 * Scenario
 * --------
 * A deployment platform stores encrypted application configuration. Each
 * record contains:
 *
 *   - a key identifier
 *   - a nonce
 *   - ciphertext
 *   - an authentication tag
 *   - visible metadata that must still be protected against modification
 *
 * This C++17 program models the governance and cryptographic data flow
 * without depending on an external cryptography library.
 *
 * The cryptographic construction below is intentionally educational. It uses
 * a deterministic SHA-256-like interface implemented for demonstration of
 * data flow, key separation, authentication, and nonce handling. It is NOT a
 * substitute for AES-GCM or ChaCha20-Poly1305.
 *
 * Production systems should use a professionally reviewed cryptographic
 * library and should not implement cryptographic primitives themselves.
 */


// ---------------------------------------------------------------------------
// Educational digest primitive
// ---------------------------------------------------------------------------

class EducationalHash {
public:
    static std::array<std::uint8_t, 32> digest(
        std::string_view input
    ) {
        /*
         * This is a deliberately simple mixing construction used only to
         * make the case study self-contained. It is not SHA-256.
         */
        std::array<std::uint32_t, 8> state{
            0x243F6A88u,
            0x85A308D3u,
            0x13198A2Eu,
            0x03707344u,
            0xA4093822u,
            0x299F31D0u,
            0x082EFA98u,
            0xEC4E6C89u
        };

        for (std::size_t index = 0; index < input.size(); ++index) {
            const auto byte =
                static_cast<std::uint8_t>(input[index]);

            const std::size_t slot = index % state.size();

            state[slot] ^= static_cast<std::uint32_t>(byte)
                + static_cast<std::uint32_t>(index * 0x9E3779B9u);

            state[slot] =
                (state[slot] << 7)
                | (state[slot] >> 25);

            state[(slot + 1) % state.size()] +=
                state[slot] ^ 0xA5A5A5A5u;
        }

        for (std::size_t round = 0; round < 32; ++round) {
            for (std::size_t slot = 0; slot < state.size(); ++slot) {
                const auto next =
                    state[(slot + 1) % state.size()];

                state[slot] ^= next + 0x9E3779B9u;
                state[slot] =
                    (state[slot] << 11)
                    | (state[slot] >> 21);
            }
        }

        std::array<std::uint8_t, 32> output{};

        for (std::size_t index = 0; index < state.size(); ++index) {
            const std::uint32_t value = state[index];

            output[index * 4] =
                static_cast<std::uint8_t>(value >> 24);
            output[index * 4 + 1] =
                static_cast<std::uint8_t>(value >> 16);
            output[index * 4 + 2] =
                static_cast<std::uint8_t>(value >> 8);
            output[index * 4 + 3] =
                static_cast<std::uint8_t>(value);
        }

        return output;
    }
};


// ---------------------------------------------------------------------------
// Byte utilities
// ---------------------------------------------------------------------------

using Bytes = std::vector<std::uint8_t>;
using Key = std::array<std::uint8_t, 32>;
using Nonce = std::array<std::uint8_t, 12>;
using Tag = std::array<std::uint8_t, 32>;

Bytes toBytes(std::string_view text) {
    return Bytes(text.begin(), text.end());
}

std::string fromBytes(const Bytes& data) {
    return std::string(data.begin(), data.end());
}

std::string hexEncode(const Bytes& data) {
    std::ostringstream output;

    for (std::uint8_t byte : data) {
        output
            << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(byte);
    }

    return output.str();
}

template <std::size_t N>
std::string hexEncode(const std::array<std::uint8_t, N>& data) {
    return hexEncode(Bytes(data.begin(), data.end()));
}

template <std::size_t N>
bool constantTimeEqual(
    const std::array<std::uint8_t, N>& left,
    const std::array<std::uint8_t, N>& right
) {
    std::uint8_t difference = 0;

    for (std::size_t index = 0; index < N; ++index) {
        difference |= left[index] ^ right[index];
    }

    return difference == 0;
}

std::uint64_t load64(const std::uint8_t* bytes) {
    std::uint64_t result = 0;

    for (int index = 0; index < 8; ++index) {
        result =
            (result << 8)
            | static_cast<std::uint64_t>(bytes[index]);
    }

    return result;
}


// ---------------------------------------------------------------------------
// Random key and nonce generation
// ---------------------------------------------------------------------------

class SecureRandomModel {
public:
    SecureRandomModel()
        : engine_(std::random_device{}()) {}

    template <std::size_t N>
    std::array<std::uint8_t, N> bytes() {
        std::array<std::uint8_t, N> output{};

        std::uniform_int_distribution<int> distribution(0, 255);

        for (auto& byte : output) {
            byte =
                static_cast<std::uint8_t>(distribution(engine_));
        }

        return output;
    }

private:
    std::mt19937_64 engine_;
};


// ---------------------------------------------------------------------------
// Educational authenticated stream construction
// ---------------------------------------------------------------------------

class EducationalCipher {
public:
    explicit EducationalCipher(const Key& masterKey)
        : encryptionKey_(derive(masterKey, "encryption")),
          authenticationKey_(derive(masterKey, "authentication")) {}

    Bytes encrypt(
        const Bytes& plaintext,
        const Nonce& nonce,
        const Bytes& associatedData
    ) const {
        Bytes ciphertext = applyKeystream(
            plaintext,
            encryptionKey_,
            nonce
        );

        return ciphertext;
    }

    Tag authenticate(
        const Nonce& nonce,
        const Bytes& ciphertext,
        const Bytes& associatedData
    ) const {
        Bytes input;

        append(input, associatedData);
        append(input, Bytes(nonce.begin(), nonce.end()));
        append(input, ciphertext);
        append(input, Bytes(authenticationKey_.begin(),
                            authenticationKey_.end()));

        return EducationalHash::digest(
            std::string_view(
                reinterpret_cast<const char*>(input.data()),
                input.size()
            )
        );
    }

    Bytes decrypt(
        const Bytes& ciphertext,
        const Nonce& nonce,
        const Bytes& associatedData,
        const Tag& suppliedTag
    ) const {
        const Tag expectedTag =
            authenticate(
                nonce,
                ciphertext,
                associatedData
            );

        if (!constantTimeEqual(suppliedTag, expectedTag)) {
            throw std::runtime_error(
                "authentication failed"
            );
        }

        return applyKeystream(
            ciphertext,
            encryptionKey_,
            nonce
        );
    }

private:
    Key encryptionKey_{};
    Key authenticationKey_{};

    static Key derive(
        const Key& masterKey,
        std::string_view purpose
    ) {
        Bytes material(
            masterKey.begin(),
            masterKey.end()
        );

        append(
            material,
            toBytes(purpose)
        );

        return EducationalHash::digest(
            std::string_view(
                reinterpret_cast<const char*>(material.data()),
                material.size()
            )
        );
    }

    static void append(Bytes& destination, const Bytes& source) {
        destination.insert(
            destination.end(),
            source.begin(),
            source.end()
        );
    }

    static Bytes applyKeystream(
        const Bytes& input,
        const Key& encryptionKey,
        const Nonce& nonce
    ) {
        Bytes output(input.size());

        for (
            std::size_t offset = 0;
            offset < input.size();
            offset += 32
        ) {
            Bytes material(
                encryptionKey.begin(),
                encryptionKey.end()
            );

            material.insert(
                material.end(),
                nonce.begin(),
                nonce.end()
            );

            const std::uint64_t counter =
                static_cast<std::uint64_t>(offset / 32);

            for (int byteIndex = 7; byteIndex >= 0; --byteIndex) {
                material.push_back(
                    static_cast<std::uint8_t>(
                        counter >> (byteIndex * 8)
                    )
                );
            }

            const auto digest =
                EducationalHash::digest(
                    std::string_view(
                        reinterpret_cast<const char*>(
                            material.data()
                        ),
                        material.size()
                    )
                );

            const std::size_t blockLength =
                std::min<std::size_t>(
                    32,
                    input.size() - offset
                );

            for (std::size_t index = 0; index < blockLength; ++index) {
                output[offset + index] =
                    input[offset + index]
                    ^ digest[index];
            }
        }

        return output;
    }
};


// ---------------------------------------------------------------------------
// Encrypted repository record
// ---------------------------------------------------------------------------

struct EncryptedSecret {
    std::string keyId;
    Nonce nonce{};
    Bytes ciphertext;
    Bytes associatedData;
    Tag authenticationTag{};
};


// ---------------------------------------------------------------------------
// Repository key ring
// ---------------------------------------------------------------------------

struct KeyRecord {
    Key key{};
    bool active{false};
    bool decryptable{true};
};

class RepositoryKeyRing {
public:
    void addKey(
        const std::string& keyId,
        const Key& key,
        bool active
    ) {
        if (keyId.empty()) {
            throw std::invalid_argument(
                "key ID cannot be empty"
            );
        }

        if (keys_.contains(keyId)) {
            throw std::invalid_argument(
                "duplicate key ID: " + keyId
            );
        }

        keys_.emplace(
            keyId,
            KeyRecord{key, active, true}
        );

        if (active) {
            activate(keyId);
        }
    }

    void activate(const std::string& keyId) {
        auto iterator = keys_.find(keyId);

        if (iterator == keys_.end()) {
            throw std::out_of_range(
                "unknown key ID: " + keyId
            );
        }

        for (auto& [id, record] : keys_) {
            record.active = false;
        }

        iterator->second.active = true;
        activeKeyId_ = keyId;
    }

    void stopNewWrites(const std::string& keyId) {
        auto iterator = keys_.find(keyId);

        if (iterator == keys_.end()) {
            throw std::out_of_range(
                "unknown key ID: " + keyId
            );
        }

        iterator->second.active = false;

        if (activeKeyId_ == keyId) {
            activeKeyId_.reset();
        }
    }

    void revokeDecryption(const std::string& keyId) {
        auto iterator = keys_.find(keyId);

        if (iterator == keys_.end()) {
            throw std::out_of_range(
                "unknown key ID: " + keyId
            );
        }

        iterator->second.active = false;
        iterator->second.decryptable = false;

        if (activeKeyId_ == keyId) {
            activeKeyId_.reset();
        }
    }

    const Key& activeKey() const {
        if (!activeKeyId_) {
            throw std::runtime_error(
                "no active key configured"
            );
        }

        return key(*activeKeyId_);
    }

    const Key& key(const std::string& keyId) const {
        auto iterator = keys_.find(keyId);

        if (iterator == keys_.end()) {
            throw std::out_of_range(
                "unknown key ID: " + keyId
            );
        }

        if (!iterator->second.decryptable) {
            throw std::runtime_error(
                "key has been revoked: " + keyId
            );
        }

        return iterator->second.key;
    }

    std::string activeKeyId() const {
        if (!activeKeyId_) {
            throw std::runtime_error(
                "no active key ID"
            );
        }

        return *activeKeyId_;
    }

private:
    std::map<std::string, KeyRecord> keys_;
    std::optional<std::string> activeKeyId_;
};


// ---------------------------------------------------------------------------
// Repository secret vault
// ---------------------------------------------------------------------------

class RepositorySecretVault {
public:
    explicit RepositorySecretVault(
        RepositoryKeyRing& keyRing
    )
        : keyRing_(keyRing) {}

    EncryptedSecret store(
        const std::string& repository,
        const std::string& secretName,
        const std::string& secretValue,
        const std::string& environment
    ) {
        if (repository.empty()) {
            throw std::invalid_argument(
                "repository cannot be empty"
            );
        }

        if (secretName.empty()) {
            throw std::invalid_argument(
                "secret name cannot be empty"
            );
        }

        if (secretValue.empty()) {
            throw std::invalid_argument(
                "secret value cannot be empty"
            );
        }

        if (environment.empty()) {
            throw std::invalid_argument(
                "environment cannot be empty"
            );
        }

        const std::string keyId =
            keyRing_.activeKeyId();

        const Key& key =
            keyRing_.activeKey();

        const Bytes associatedData =
            buildAssociatedData(
                repository,
                secretName,
                environment
            );

        const Nonce nonce =
            random_.bytes<12>();

        EducationalCipher cipher(key);

        const Bytes plaintext =
            toBytes(secretValue);

        const Bytes ciphertext =
            cipher.encrypt(
                plaintext,
                nonce,
                associatedData
            );

        const Tag tag =
            cipher.authenticate(
                nonce,
                ciphertext,
                associatedData
            );

        EncryptedSecret record{
            keyId,
            nonce,
            ciphertext,
            associatedData,
            tag
        };

        return record;
    }

    std::string retrieve(
        const EncryptedSecret& record
    ) const {
        const Key& key =
            keyRing_.key(record.keyId);

        EducationalCipher cipher(key);

        const Bytes plaintext =
            cipher.decrypt(
                record.ciphertext,
                record.nonce,
                record.associatedData,
                record.authenticationTag
            );

        return fromBytes(plaintext);
    }

private:
    RepositoryKeyRing& keyRing_;
    mutable SecureRandomModel random_;

    static Bytes buildAssociatedData(
        const std::string& repository,
        const std::string& secretName,
        const std::string& environment
    ) {
        /*
         * These fields are not secret. They remain outside the ciphertext but
         * become part of authentication. A modified repository or environment
         * therefore invalidates the encrypted record.
         */
        const std::string metadata =
            "repository=" + repository
            + "|secret=" + secretName
            + "|environment=" + environment;

        return toBytes(metadata);
    }
};


// ---------------------------------------------------------------------------
// Repository operations
// ---------------------------------------------------------------------------

void printRecord(const EncryptedSecret& record) {
    std::cout
        << "Key ID: "
        << record.keyId
        << '\n';

    std::cout
        << "Nonce: "
        << hexEncode(record.nonce)
        << '\n';

    std::cout
        << "Ciphertext: "
        << hexEncode(record.ciphertext)
        << '\n';

    std::cout
        << "Authentication tag: "
        << hexEncode(record.authenticationTag)
        << '\n';

    std::cout
        << "Associated data: "
        << fromBytes(record.associatedData)
        << '\n';
}

void demonstrateBasicRoundTrip() {
    std::cout
        << "\n=== Basic Symmetric Encryption Flow ===\n";

    SecureRandomModel random;
    const Key key = random.bytes<32>();

    EducationalCipher cipher(key);

    const Nonce nonce = random.bytes<12>();

    const Bytes plaintext =
        toBytes("deployment-token-for-staging");

    const Bytes metadata =
        toBytes("repository=payments-api|environment=staging");

    const Bytes ciphertext =
        cipher.encrypt(
            plaintext,
            nonce,
            metadata
        );

    const Tag tag =
        cipher.authenticate(
            nonce,
            ciphertext,
            metadata
        );

    const Bytes recovered =
        cipher.decrypt(
            ciphertext,
            nonce,
            metadata,
            tag
        );

    std::cout
        << "Plaintext: "
        << fromBytes(plaintext)
        << '\n';

    std::cout
        << "Ciphertext: "
        << hexEncode(ciphertext)
        << '\n';

    std::cout
        << "Recovered: "
        << fromBytes(recovered)
        << '\n';

    if (recovered != plaintext) {
        throw std::runtime_error(
            "round-trip encryption failed"
        );
    }
}


// ---------------------------------------------------------------------------
// Tamper and failure scenarios
// ---------------------------------------------------------------------------

void demonstrateTampering() {
    std::cout
        << "\n=== Tamper Detection ===\n";

    SecureRandomModel random;
    const Key key = random.bytes<32>();
    const Nonce nonce = random.bytes<12>();

    const Bytes metadata =
        toBytes("repository=analytics|environment=production");

    EducationalCipher cipher(key);

    const Bytes ciphertext =
        cipher.encrypt(
            toBytes("database-password"),
            nonce,
            metadata
        );

    const Tag tag =
        cipher.authenticate(
            nonce,
            ciphertext,
            metadata
        );

    Bytes modifiedCiphertext = ciphertext;

    if (!modifiedCiphertext.empty()) {
        modifiedCiphertext[0] ^= 0x01;
    }

    try {
        cipher.decrypt(
            modifiedCiphertext,
            nonce,
            metadata,
            tag
        );

        throw std::runtime_error(
            "tampered ciphertext was accepted"
        );
    } catch (const std::runtime_error& error) {
        std::cout
            << "Ciphertext modification rejected: "
            << error.what()
            << '\n';
    }

    try {
        cipher.decrypt(
            ciphertext,
            nonce,
            toBytes("repository=attacker|environment=production"),
            tag
        );

        throw std::runtime_error(
            "modified metadata was accepted"
        );
    } catch (const std::runtime_error& error) {
        std::cout
            << "Metadata modification rejected: "
            << error.what()
            << '\n';
    }
}


// ---------------------------------------------------------------------------
// Key rotation case study
// ---------------------------------------------------------------------------

void demonstrateKeyRotation() {
    std::cout
        << "\n=== Key Rotation Case Study ===\n";

    SecureRandomModel random;

    RepositoryKeyRing keyRing;

    keyRing.addKey(
        "vault-key-2026-09",
        random.bytes<32>(),
        true
    );

    RepositorySecretVault vault(keyRing);

    EncryptedSecret oldRecord =
        vault.store(
            "payments-api",
            "DATABASE_PASSWORD",
            "old-secret-value",
            "production"
        );

    std::cout
        << "Stored record under "
        << oldRecord.keyId
        << '\n';

    /*
     * Rotation changes the key used for future writes. Existing records carry
     * their key ID, allowing controlled decryption during migration.
     */
    keyRing.addKey(
        "vault-key-2026-10",
        random.bytes<32>(),
        false
    );

    keyRing.activate("vault-key-2026-10");

    EncryptedSecret newRecord =
        vault.store(
            "payments-api",
            "DATABASE_PASSWORD",
            "new-secret-value",
            "production"
        );

    std::cout
        << "New writes use "
        << newRecord.keyId
        << '\n';

    const std::string oldValue =
        vault.retrieve(oldRecord);

    const std::string newValue =
        vault.retrieve(newRecord);

    std::cout
        << "Old record recovered: "
        << oldValue
        << '\n';

    std::cout
        << "New record recovered: "
        << newValue
        << '\n';

    if (
        oldValue != "old-secret-value"
        || newValue != "new-secret-value"
    ) {
        throw std::runtime_error(
            "key rotation retrieval failed"
        );
    }

    keyRing.stopNewWrites("vault-key-2026-09");

    /*
     * Stopping new writes is not the same as immediately destroying a key.
     * Old ciphertext can remain readable during a planned migration window.
     */
    std::cout
        << "Old key is no longer eligible for new writes.\n";
}


// ---------------------------------------------------------------------------
// Nonce reuse demonstration
// ---------------------------------------------------------------------------

void demonstrateNonceReuseRisk() {
    std::cout
        << "\n=== Nonce Reuse Risk ===\n";

    SecureRandomModel random;

    const Key key = random.bytes<32>();

    EducationalCipher cipher(key);

    /*
     * Deliberately reuse a nonce to demonstrate a stream-cipher failure mode.
     * The same key and nonce produce the same keystream.
     */
    const Nonce reusedNonce = random.bytes<12>();

    const Bytes firstPlaintext =
        toBytes("first secret message");

    const Bytes secondPlaintext =
        toBytes("second secret message");

    const Bytes firstCiphertext =
        cipher.encrypt(
            firstPlaintext,
            reusedNonce,
            {}
        );

    const Bytes secondCiphertext =
        cipher.encrypt(
            secondPlaintext,
            reusedNonce,
            {}
        );

    const std::size_t commonLength =
        std::min(
            firstPlaintext.size(),
            secondPlaintext.size()
        );

    Bytes ciphertextRelationship(commonLength);
    Bytes plaintextRelationship(commonLength);

    for (std::size_t index = 0; index < commonLength; ++index) {
        ciphertextRelationship[index] =
            firstCiphertext[index]
            ^ secondCiphertext[index];

        plaintextRelationship[index] =
            firstPlaintext[index]
            ^ secondPlaintext[index];
    }

    if (ciphertextRelationship != plaintextRelationship) {
        throw std::runtime_error(
            "nonce-reuse demonstration failed"
        );
    }

    std::cout
        << "Reusing a nonce exposes a plaintext relationship.\n";

    std::cout
        << "Nonce uniqueness is therefore a key security requirement.\n";
}


// ---------------------------------------------------------------------------
// Performance and edge-case behavior
// ---------------------------------------------------------------------------

void demonstrateEdgeCases() {
    std::cout
        << "\n=== Edge Cases ===\n";

    SecureRandomModel random;
    const Key key = random.bytes<32>();
    const Nonce nonce = random.bytes<12>();

    EducationalCipher cipher(key);

    const Bytes empty;

    const Bytes emptyCiphertext =
        cipher.encrypt(
            empty,
            nonce,
            {}
        );

    const Tag emptyTag =
        cipher.authenticate(
            nonce,
            emptyCiphertext,
            {}
        );

    const Bytes recovered =
        cipher.decrypt(
            emptyCiphertext,
            nonce,
            {},
            emptyTag
        );

    if (!recovered.empty()) {
        throw std::runtime_error(
            "empty plaintext test failed"
        );
    }

    std::cout
        << "Empty plaintext remains authenticated.\n";

    try {
        const Nonce invalidNonce{};
        cipher.encrypt(
            toBytes("data"),
            invalidNonce,
            {}
        );
    } catch (...) {
        /*
         * The educational API would normally validate nonce length at its
         * boundary. This branch documents the required production behavior.
         */
        std::cout
            << "Invalid nonce input should be rejected at the API boundary.\n";
    }

    const Bytes largeInput(
        1024 * 1024,
        static_cast<std::uint8_t>('A')
    );

    const Nonce largeNonce = random.bytes<12>();

    const Bytes largeCiphertext =
        cipher.encrypt(
            largeInput,
            largeNonce,
            {}
        );

    if (largeCiphertext.size() != largeInput.size()) {
        throw std::runtime_error(
            "ciphertext size changed unexpectedly"
        );
    }

    std::cout
        << "1 MiB payload preserved ciphertext length: "
        << largeCiphertext.size()
        << " bytes\n";

    /*
     * Stream-style XOR processing uses O(n) time and O(n) output storage.
     * A real streaming API can reduce working memory by processing bounded
     * chunks while preserving authentication requirements.
     */
}


// ---------------------------------------------------------------------------
// Complete repository scenario
// ---------------------------------------------------------------------------

void runRepositoryCaseStudy() {
    std::cout
        << "\n=== Repository Secret Vault ===\n";

    SecureRandomModel random;

    RepositoryKeyRing keyRing;

    keyRing.addKey(
        "repository-key-2026-10",
        random.bytes<32>(),
        true
    );

    RepositorySecretVault vault(keyRing);

    EncryptedSecret record =
        vault.store(
            "market-data-service",
            "API_TOKEN",
            "token-value-never-stored-as-plaintext",
            "production"
        );

    printRecord(record);

    const std::string secret =
        vault.retrieve(record);

    std::cout
        << "Retrieved secret: "
        << secret
        << '\n';

    if (
        secret
        != "token-value-never-stored-as-plaintext"
    ) {
        throw std::runtime_error(
            "repository secret retrieval failed"
        );
    }

    /*
     * A database can store keyId, nonce, ciphertext, associated metadata,
     * and authentication tag. It does not need the plaintext secret.
     *
     * The key itself belongs in a protected key-management boundary rather
     * than inside the repository record.
     */
}


// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {
    try {
        demonstrateBasicRoundTrip();
        demonstrateTampering();
        demonstrateKeyRotation();
        demonstrateNonceReuseRisk();
        demonstrateEdgeCases();
        runRepositoryCaseStudy();

        std::cout
            << "\n=== Production Boundary ===\n";

        std::cout
            << "The custom cryptographic construction in this case study "
               "is educational only.\n";

        std::cout
            << "Production software should use AES-GCM or ChaCha20-Poly1305 "
               "from a reviewed cryptographic library.\n";

        std::cout
            << "Keys require lifecycle controls covering generation, "
               "storage, rotation, access, auditing, and destruction.\n";

        std::cout
            << "Authentication must be verified before application code "
               "trusts decrypted data.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
