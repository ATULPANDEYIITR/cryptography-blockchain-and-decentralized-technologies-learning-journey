/*
 * Authenticated Encryption Case Study
 *
 * Scenario:
 * A repository governance service stores sensitive policy snapshots.
 * Every snapshot has encrypted content plus authenticated metadata.
 * The merge-eligibility engine refuses a policy record if its encrypted
 * representation has been modified.
 *
 * Build:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic aead_governance.cpp \
 *       -lcrypto -o aead_governance
 *
 * Requires OpenSSL 1.1.1 or later.
 *
 * OpenSSL is used for AES-256-GCM rather than implementing AES/GCM manually.
 */

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

constexpr std::size_t KEY_SIZE = 32;
constexpr std::size_t NONCE_SIZE = 12;
constexpr std::size_t TAG_SIZE = 16;

struct EncryptedArtifact {
    std::string repository;
    std::string artifact_name;
    std::string key_id;
    Bytes nonce;
    Bytes ciphertext;
    Bytes tag;
};

struct PullRequest {
    int id;
    std::string source_branch;
    std::string target_branch;
    bool draft;
    bool conflicts;
    std::map<std::string, bool> status_checks;
    int approvals;
    int required_approvals;
};

class AeadException : public std::runtime_error {
public:
    explicit AeadException(const std::string& message)
        : std::runtime_error(message) {}
};

Bytes random_bytes(std::size_t count) {
    Bytes result(count);

    if (RAND_bytes(result.data(), static_cast<int>(result.size())) != 1) {
        throw AeadException("Cryptographically secure random generation failed");
    }

    return result;
}

std::string hex(const Bytes& data) {
    std::ostringstream output;

    for (unsigned char byte : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return output.str();
}

class AesGcm {
public:
    explicit AesGcm(std::string key_id)
        : key_id_(std::move(key_id)),
          key_(random_bytes(KEY_SIZE)) {}

    const std::string& key_id() const {
        return key_id_;
    }

    EncryptedArtifact encrypt(
        const std::string& repository,
        const std::string& artifact_name,
        const std::string& plaintext) const {

        const Bytes nonce = random_bytes(NONCE_SIZE);

        /*
         * Repository and artifact identity are AAD. They remain visible,
         * but the GCM tag makes unauthorized modification detectable.
         */
        const std::string aad =
            "repository=" + repository +
            ";artifact=" + artifact_name;

        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();

        if (context == nullptr) {
            throw AeadException("Unable to allocate OpenSSL cipher context");
        }

        Bytes ciphertext(plaintext.size());
        int produced = 0;
        int final_bytes = 0;

        bool successful =
            EVP_EncryptInit_ex(
                context,
                EVP_aes_256_gcm(),
                nullptr,
                nullptr,
                nullptr) == 1;

        successful = successful &&
            EVP_CIPHER_CTX_ctrl(
                context,
                EVP_CTRL_GCM_SET_IVLEN,
                NONCE_SIZE,
                nullptr) == 1;

        successful = successful &&
            EVP_EncryptInit_ex(
                context,
                nullptr,
                nullptr,
                key_.data(),
                nonce.data()) == 1;

        if (successful && !aad.empty()) {
            successful =
                EVP_EncryptUpdate(
                    context,
                    nullptr,
                    &produced,
                    reinterpret_cast<const unsigned char*>(aad.data()),
                    static_cast<int>(aad.size())) == 1;
        }

        successful = successful &&
            EVP_EncryptUpdate(
                context,
                ciphertext.data(),
                &produced,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) == 1;

        successful = successful &&
            EVP_EncryptFinal_ex(
                context,
                ciphertext.data() + produced,
                &final_bytes) == 1;

        Bytes tag(TAG_SIZE);

        successful = successful &&
            EVP_CIPHER_CTX_ctrl(
                context,
                EVP_CTRL_GCM_GET_TAG,
                TAG_SIZE,
                tag.data()) == 1;

        EVP_CIPHER_CTX_free(context);

        if (!successful) {
            throw AeadException("AES-GCM encryption failed");
        }

        ciphertext.resize(
            static_cast<std::size_t>(produced + final_bytes));

        return EncryptedArtifact{
            repository,
            artifact_name,
            key_id_,
            nonce,
            ciphertext,
            tag
        };
    }

    std::string decrypt(const EncryptedArtifact& artifact) const {
        if (artifact.key_id != key_id_) {
            throw AeadException("Encryption key ID is not trusted");
        }

        const std::string aad =
            "repository=" + artifact.repository +
            ";artifact=" + artifact.artifact_name;

        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();

        if (context == nullptr) {
            throw AeadException("Unable to allocate OpenSSL cipher context");
        }

        Bytes plaintext(artifact.ciphertext.size());
        int produced = 0;
        int final_bytes = 0;

        bool successful =
            EVP_DecryptInit_ex(
                context,
                EVP_aes_256_gcm(),
                nullptr,
                nullptr,
                nullptr) == 1;

        successful = successful &&
            EVP_CIPHER_CTX_ctrl(
                context,
                EVP_CTRL_GCM_SET_IVLEN,
                NONCE_SIZE,
                nullptr) == 1;

        successful = successful &&
            EVP_DecryptInit_ex(
                context,
                nullptr,
                nullptr,
                key_.data(),
                artifact.nonce.data()) == 1;

        if (successful && !aad.empty()) {
            successful =
                EVP_DecryptUpdate(
                    context,
                    nullptr,
                    &produced,
                    reinterpret_cast<const unsigned char*>(aad.data()),
                    static_cast<int>(aad.size())) == 1;
        }

        successful = successful &&
            EVP_DecryptUpdate(
                context,
                plaintext.data(),
                &produced,
                artifact.ciphertext.data(),
                static_cast<int>(artifact.ciphertext.size())) == 1;

        /*
         * The tag must be supplied before EVP_DecryptFinal_ex().
         * Finalization is where GCM authentication determines whether the
         * ciphertext, nonce, and AAD form a valid authenticated message.
         */
        successful = successful &&
            EVP_CIPHER_CTX_ctrl(
                context,
                EVP_CTRL_GCM_SET_TAG,
                TAG_SIZE,
                const_cast<unsigned char*>(artifact.tag.data())) == 1;

        if (successful) {
            successful =
                EVP_DecryptFinal_ex(
                    context,
                    plaintext.data() + produced,
                    &final_bytes) == 1;
        }

        EVP_CIPHER_CTX_free(context);

        if (!successful) {
            throw AeadException("Authenticated decryption failed");
        }

        plaintext.resize(
            static_cast<std::size_t>(produced + final_bytes));

        return std::string(
            reinterpret_cast<const char*>(plaintext.data()),
            plaintext.size());
    }

private:
    std::string key_id_;
    Bytes key_;
};

class GovernanceEngine {
public:
    explicit GovernanceEngine(const AesGcm& cipher)
        : cipher_(cipher) {}

    bool eligible_for_merge(const PullRequest& request) const {
        if (request.draft) {
            return false;
        }

        if (request.conflicts) {
            return false;
        }

        if (request.source_branch == request.target_branch) {
            return false;
        }

        if (request.approvals < request.required_approvals) {
            return false;
        }

        for (const auto& [name, passed] : request.status_checks) {
            if (!passed) {
                return false;
            }
        }

        return true;
    }

    void explain(const PullRequest& request) const {
        std::cout
            << "PR #" << request.id
            << " source=" << request.source_branch
            << " target=" << request.target_branch << '\n';

        if (request.draft) {
            std::cout << "  rejected: draft Pull Request\n";
        }

        if (request.conflicts) {
            std::cout << "  rejected: merge conflicts exist\n";
        }

        if (request.approvals < request.required_approvals) {
            std::cout << "  rejected: insufficient approvals\n";
        }

        for (const auto& [name, passed] : request.status_checks) {
            if (!passed) {
                std::cout
                    << "  rejected: failed status check "
                    << name << '\n';
            }
        }

        if (eligible_for_merge(request)) {
            std::cout << "  eligible: governance conditions satisfied\n";
        }
    }

private:
    const AesGcm& cipher_;
};

void demonstrate_authenticated_artifact(AesGcm& cipher) {
    std::cout << "\n=== Authenticated repository artifact ===\n";

    EncryptedArtifact artifact =
        cipher.encrypt(
            "platform-security",
            "branch-protection-policy",
            R"({"required_reviews":2,"force_push":false})");

    std::cout << "Key ID: " << artifact.key_id << '\n';
    std::cout << "Nonce: " << hex(artifact.nonce) << '\n';
    std::cout << "Ciphertext bytes: "
              << artifact.ciphertext.size() << '\n';
    std::cout << "Authentication tag: "
              << hex(artifact.tag) << '\n';

    std::cout << "Recovered policy: "
              << cipher.decrypt(artifact) << '\n';

    /*
     * An attacker changes the ciphertext but cannot produce a new valid tag.
     */
    EncryptedArtifact tampered = artifact;

    if (!tampered.ciphertext.empty()) {
        tampered.ciphertext[0] ^= 0x01;
    }

    try {
        cipher.decrypt(tampered);
        std::cout << "Unexpected success\n";
    } catch (const AeadException& error) {
        std::cout
            << "Tampered artifact rejected: "
            << error.what() << '\n';
    }

    /*
     * Changing the repository identity modifies AAD rather than ciphertext.
     * GCM authentication still detects the modification.
     */
    EncryptedArtifact wrong_identity = artifact;
    wrong_identity.repository = "untrusted-repository";

    try {
        cipher.decrypt(wrong_identity);
        std::cout << "Unexpected success\n";
    } catch (const AeadException& error) {
        std::cout
            << "Modified authenticated metadata rejected: "
            << error.what() << '\n';
    }
}

void demonstrate_governance_engine(AesGcm& cipher) {
    std::cout << "\n=== Merge governance case study ===\n";

    GovernanceEngine engine(cipher);

    PullRequest approved{
        482,
        "feature/security-policy",
        "main",
        false,
        false,
        {
            {"unit-tests", true},
            {"security-scan", true},
            {"policy-validation", true}
        },
        2,
        2
    };

    PullRequest insufficient_reviews = approved;
    insufficient_reviews.id = 483;
    insufficient_reviews.approvals = 1;

    PullRequest failed_check = approved;
    failed_check.id = 484;
    failed_check.status_checks["security-scan"] = false;

    PullRequest conflicting = approved;
    conflicting.id = 485;
    conflicting.conflicts = true;

    engine.explain(approved);
    engine.explain(insufficient_reviews);
    engine.explain(failed_check);
    engine.explain(conflicting);

    EncryptedArtifact decision =
        cipher.encrypt(
            "platform-security",
            "merge-decision-482",
            engine.eligible_for_merge(approved)
                ? "ELIGIBLE"
                : "BLOCKED");

    std::cout
        << "Authenticated decision: "
        << cipher.decrypt(decision) << '\n';
}

int main() {
    try {
        std::cout
            << "AES-256-GCM authenticated-encryption case study\n";

        AesGcm cipher("repository-key-2026");

        demonstrate_authenticated_artifact(cipher);
        demonstrate_governance_engine(cipher);

        std::cout << "\nSecurity properties demonstrated:\n";
        std::cout
            << "Confidentiality is provided by AES encryption.\n";
        std::cout
            << "Integrity and authenticity are provided by the GCM tag.\n";
        std::cout
            << "Repository metadata is authenticated as AAD.\n";
        std::cout
            << "Authentication failure blocks consumption of modified data.\n";
        std::cout
            << "A fresh random nonce is generated for every encryption.\n";

    } catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what() << '\n';
        return 1;
    }

    return 0;
}
