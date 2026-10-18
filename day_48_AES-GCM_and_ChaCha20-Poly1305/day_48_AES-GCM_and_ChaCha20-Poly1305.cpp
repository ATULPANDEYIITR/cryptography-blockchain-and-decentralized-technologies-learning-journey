/*
 * AES-GCM and ChaCha20-Poly1305
 *
 * C++17 technical case study:
 * A repository artifact service encrypts build manifests and deployment
 * metadata before persistence. The service supports both AEAD algorithms,
 * authenticates metadata as AAD, tracks key versions, rejects tampering,
 * and evaluates algorithm/key compatibility before decryption.
 *
 * OpenSSL 3.x is used because production cryptographic primitives should
 * come from a maintained, audited cryptographic library rather than from
 * handwritten block-cipher code.
 *
 * Build:
 *   g++ -std=c++17 -O2 secure_artifact_store.cpp -lcrypto -o secure_artifact_store
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

enum class Algorithm {
    AES_256_GCM,
    CHACHA20_POLY1305
};

std::string algorithmName(Algorithm algorithm) {
    switch (algorithm) {
        case Algorithm::AES_256_GCM:
            return "AES-256-GCM";
        case Algorithm::CHACHA20_POLY1305:
            return "ChaCha20-Poly1305";
    }

    throw std::logic_error("Unknown algorithm");
}

const EVP_CIPHER* opensslCipher(Algorithm algorithm) {
    switch (algorithm) {
        case Algorithm::AES_256_GCM:
            return EVP_aes_256_gcm();
        case Algorithm::CHACHA20_POLY1305:
            return EVP_chacha20_poly1305();
    }

    return nullptr;
}

using Bytes = std::vector<unsigned char>;

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message)
        : std::runtime_error(message) {}
};

void check(bool condition, const std::string& message) {
    if (!condition) {
        throw CryptoError(message);
    }
}

Bytes randomBytes(std::size_t length) {
    Bytes result(length);

    check(
        RAND_bytes(result.data(), static_cast<int>(result.size())) == 1,
        "OpenSSL secure random generation failed"
    );

    return result;
}

std::string hex(const Bytes& data) {
    std::ostringstream output;

    for (unsigned char byte : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<unsigned int>(byte);
    }

    return output.str();
}

struct KeyMaterial {
    std::uint32_t version;
    Algorithm algorithm;
    Bytes key;
};

class KeyRing {
private:
    std::map<std::uint32_t, KeyMaterial> keys_;
    std::uint32_t activeVersion_ = 0;

public:
    void addKey(
        std::uint32_t version,
        Algorithm algorithm,
        Bytes key,
        bool active
    ) {
        check(version != 0, "Key version must be non-zero");
        check(key.size() == 32, "This case study requires 256-bit keys");

        keys_[version] = KeyMaterial{
            version,
            algorithm,
            std::move(key)
        };

        if (active) {
            activeVersion_ = version;
        }
    }

    const KeyMaterial& activeKey() const {
        check(activeVersion_ != 0, "No active key configured");
        return keys_.at(activeVersion_);
    }

    const KeyMaterial& key(std::uint32_t version) const {
        auto it = keys_.find(version);

        if (it == keys_.end()) {
            throw CryptoError("Unknown key version");
        }

        return it->second;
    }
};

struct EncryptedArtifact {
    Algorithm algorithm;
    std::uint32_t keyVersion;
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
    Bytes aad;
};

class AeadEngine {
private:
    static constexpr std::size_t NonceSize = 12;
    static constexpr std::size_t TagSize = 16;

    static void processAad(
        EVP_CIPHER_CTX* context,
        const Bytes& aad
    ) {
        int produced = 0;

        check(
            EVP_EncryptUpdate(
                context,
                nullptr,
                &produced,
                aad.data(),
                static_cast<int>(aad.size())
            ) == 1,
            "AAD authentication failed"
        );
    }

public:
    static EncryptedArtifact encrypt(
        const KeyMaterial& keyMaterial,
        const Bytes& plaintext,
        const Bytes& aad
    ) {
        const EVP_CIPHER* cipher = opensslCipher(keyMaterial.algorithm);

        check(cipher != nullptr, "Unsupported AEAD algorithm");
        check(keyMaterial.key.size() == 32, "AEAD key must be 32 bytes");

        auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(),
            EVP_CIPHER_CTX_free
        );

        check(context != nullptr, "Unable to allocate EVP context");

        Bytes nonce = randomBytes(NonceSize);

        check(
            EVP_EncryptInit_ex(
                context.get(),
                cipher,
                nullptr,
                nullptr,
                nullptr
            ) == 1,
            "EVP encryption initialization failed"
        );

        check(
            EVP_CIPHER_CTX_ctrl(
                context.get(),
                EVP_CTRL_AEAD_SET_IVLEN,
                static_cast<int>(nonce.size()),
                nullptr
            ) == 1,
            "Unable to configure nonce length"
        );

        check(
            EVP_EncryptInit_ex(
                context.get(),
                nullptr,
                nullptr,
                keyMaterial.key.data(),
                nonce.data()
            ) == 1,
            "Unable to configure AEAD key and nonce"
        );

        processAad(context.get(), aad);

        Bytes ciphertext(plaintext.size() + 16);
        int produced = 0;
        int total = 0;

        if (!plaintext.empty()) {
            check(
                EVP_EncryptUpdate(
                    context.get(),
                    ciphertext.data(),
                    &produced,
                    plaintext.data(),
                    static_cast<int>(plaintext.size())
                ) == 1,
                "AEAD encryption failed"
            );

            total += produced;
        }

        check(
            EVP_EncryptFinal_ex(
                context.get(),
                ciphertext.data() + total,
                &produced
            ) == 1,
            "AEAD finalization failed"
        );

        total += produced;
        ciphertext.resize(static_cast<std::size_t>(total));

        Bytes tag(TagSize);

        check(
            EVP_CIPHER_CTX_ctrl(
                context.get(),
                EVP_CTRL_AEAD_GET_TAG,
                static_cast<int>(tag.size()),
                tag.data()
            ) == 1,
            "Unable to retrieve authentication tag"
        );

        return EncryptedArtifact{
            keyMaterial.algorithm,
            keyMaterial.version,
            std::move(nonce),
            std::move(ciphertext),
            std::move(tag),
            aad
        };
    }

    static Bytes decrypt(
        const KeyMaterial& keyMaterial,
        const EncryptedArtifact& artifact
    ) {
        check(
            keyMaterial.algorithm == artifact.algorithm,
            "Algorithm/key mismatch"
        );
        check(
            artifact.nonce.size() == NonceSize,
            "Invalid AEAD nonce length"
        );
        check(
            artifact.tag.size() == TagSize,
            "Invalid AEAD tag length"
        );

        const EVP_CIPHER* cipher = opensslCipher(artifact.algorithm);
        check(cipher != nullptr, "Unsupported AEAD algorithm");

        auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(),
            EVP_CIPHER_CTX_free
        );

        check(context != nullptr, "Unable to allocate EVP context");

        check(
            EVP_DecryptInit_ex(
                context.get(),
                cipher,
                nullptr,
                nullptr,
                nullptr
            ) == 1,
            "EVP decryption initialization failed"
        );

        check(
            EVP_CIPHER_CTX_ctrl(
                context.get(),
                EVP_CTRL_AEAD_SET_IVLEN,
                static_cast<int>(artifact.nonce.size()),
                nullptr
            ) == 1,
            "Unable to configure nonce length"
        );

        check(
            EVP_DecryptInit_ex(
                context.get(),
                nullptr,
                nullptr,
                keyMaterial.key.data(),
                artifact.nonce.data()
            ) == 1,
            "Unable to configure decryption key and nonce"
        );

        int produced = 0;

        check(
            EVP_DecryptUpdate(
                context.get(),
                nullptr,
                &produced,
                artifact.aad.data(),
                static_cast<int>(artifact.aad.size())
            ) == 1,
            "AAD processing failed"
        );

        Bytes plaintext(artifact.ciphertext.size() + 16);
        int total = 0;

        if (!artifact.ciphertext.empty()) {
            check(
                EVP_DecryptUpdate(
                    context.get(),
                    plaintext.data(),
                    &produced,
                    artifact.ciphertext.data(),
                    static_cast<int>(artifact.ciphertext.size())
                ) == 1,
                "Ciphertext processing failed"
            );

            total += produced;
        }

        /*
         * The tag must be installed before EVP_DecryptFinal_ex.
         * A modified ciphertext, tag, AAD, nonce, or wrong key causes the
         * final operation to fail rather than returning unauthenticated data.
         */
        check(
            EVP_CIPHER_CTX_ctrl(
                context.get(),
                EVP_CTRL_AEAD_SET_TAG,
                static_cast<int>(artifact.tag.size()),
                const_cast<unsigned char*>(artifact.tag.data())
            ) == 1,
            "Unable to configure authentication tag"
        );

        const int finalResult = EVP_DecryptFinal_ex(
            context.get(),
            plaintext.data() + total,
            &produced
        );

        if (finalResult != 1) {
            throw CryptoError("AEAD authentication failed");
        }

        total += produced;
        plaintext.resize(static_cast<std::size_t>(total));

        return plaintext;
    }
};

class ArtifactRepository {
private:
    KeyRing keyRing_;

public:
    void configureKeys() {
        keyRing_.addKey(
            41,
            Algorithm::AES_256_GCM,
            randomBytes(32),
            false
        );

        keyRing_.addKey(
            42,
            Algorithm::CHACHA20_POLY1305,
            randomBytes(32),
            true
        );
    }

    EncryptedArtifact store(
        const std::string& manifest,
        const std::string& tenant,
        const std::string& environment
    ) const {
        const auto& activeKey = keyRing_.activeKey();

        /*
         * The metadata is authenticated as AAD. It remains visible to the
         * storage layer but cannot be modified without invalidating the tag.
         */
        const std::string aadText =
            "tenant=" + tenant +
            ";environment=" + environment +
            ";artifact=deployment-manifest";

        Bytes plaintext(manifest.begin(), manifest.end());
        Bytes aad(aadText.begin(), aadText.end());

        return AeadEngine::encrypt(activeKey, plaintext, aad);
    }

    std::string load(const EncryptedArtifact& artifact) const {
        const auto& key = keyRing_.key(artifact.keyVersion);

        Bytes plaintext = AeadEngine::decrypt(key, artifact);

        return std::string(
            plaintext.begin(),
            plaintext.end()
        );
    }
};

void demonstrateRepositoryFlow() {
    ArtifactRepository repository;
    repository.configureKeys();

    auto artifact = repository.store(
        "release=2026.10;image=payments-api:v17;rollback=false",
        "finance",
        "production"
    );

    std::cout << "Algorithm: "
              << algorithmName(artifact.algorithm)
              << "\n";

    std::cout << "Key version: "
              << artifact.keyVersion
              << "\n";

    std::cout << "Nonce: "
              << hex(artifact.nonce)
              << "\n";

    std::cout << "Tag: "
              << hex(artifact.tag)
              << "\n";

    std::cout << "Recovered manifest: "
              << repository.load(artifact)
              << "\n";

    auto tampered = artifact;

    if (!tampered.ciphertext.empty()) {
        tampered.ciphertext[0] ^= 0x80;
    }

    try {
        repository.load(tampered);
        throw CryptoError(
            "Tampered ciphertext was incorrectly accepted"
        );
    } catch (const CryptoError& error) {
        std::cout << "Tampering rejected: "
                  << error.what()
                  << "\n";
    }

    auto alteredMetadata = artifact;
    alteredMetadata.aad.push_back(';');
    alteredMetadata.aad.push_back('x');

    try {
        repository.load(alteredMetadata);
        throw CryptoError(
            "Altered AAD was incorrectly accepted"
        );
    } catch (const CryptoError& error) {
        std::cout << "AAD modification rejected: "
                  << error.what()
                  << "\n";
    }
}

void demonstrateAlgorithmDifference() {
    KeyRing keys;

    keys.addKey(
        100,
        Algorithm::AES_256_GCM,
        randomBytes(32),
        false
    );

    keys.addKey(
        101,
        Algorithm::CHACHA20_POLY1305,
        randomBytes(32),
        true
    );

    const std::string message = "same plaintext, different AEAD primitive";
    const Bytes plaintext(message.begin(), message.end());

    Bytes aad{'m', 'o', 'd', 'e', '=', 'c', 'o', 'm', 'p', 'a', 'r', 'e'};

    auto aesArtifact = AeadEngine::encrypt(
        keys.key(100),
        plaintext,
        aad
    );

    auto chachaArtifact = AeadEngine::encrypt(
        keys.key(101),
        plaintext,
        aad
    );

    std::cout << "\nAlgorithm comparison\n";
    std::cout << algorithmName(aesArtifact.algorithm)
              << " ciphertext: "
              << hex(aesArtifact.ciphertext)
              << "\n";

    std::cout << algorithmName(chachaArtifact.algorithm)
              << " ciphertext: "
              << hex(chachaArtifact.ciphertext)
              << "\n";

    try {
        AeadEngine::decrypt(keys.key(100), chachaArtifact);
        throw CryptoError("Algorithm mismatch was accepted");
    } catch (const CryptoError& error) {
        std::cout << "Algorithm mismatch rejected: "
                  << error.what()
                  << "\n";
    }
}

int main() {
    try {
        std::cout << "AES-GCM and ChaCha20-Poly1305 case study\n";
        std::cout << "=========================================\n\n";

        demonstrateRepositoryFlow();
        demonstrateAlgorithmDifference();

        std::cout << "\nSecurity model demonstrated:\n";
        std::cout << "  Confidentiality comes from AEAD encryption.\n";
        std::cout << "  Integrity comes from authenticated tags.\n";
        std::cout << "  AAD protects visible metadata from modification.\n";
        std::cout << "  Key versions support controlled key rotation.\n";
        std::cout << "  Decryption never returns unauthenticated plaintext.\n";
        std::cout << "  OpenSSL supplies the cryptographic primitives.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what()
                  << "\n";
        return 1;
    }
}
