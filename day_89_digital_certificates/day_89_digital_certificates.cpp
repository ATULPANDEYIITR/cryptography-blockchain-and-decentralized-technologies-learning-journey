#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

/*
 * Digital Certificate Governance Engine
 *
 * Models:
 * - Root and intermediate certificate authorities
 * - End-entity certificates
 * - Trust anchors
 * - Certificate validity
 * - Issuer relationships
 * - Key usage constraints
 * - Revocation
 * - Certificate chain construction
 * - Certificate validation decisions
 * - Renewal and inventory reporting
 *
 * This program models PKI governance and validation policy.
 * It does not implement RSA, X.509 encoding or cryptographic signatures.
 */

using Clock = std::chrono::system_clock;
using TimePoint = Clock::time_point;

enum class CertificateType {
    RootCA,
    IntermediateCA,
    Server,
    Client,
    CodeSigning
};

enum class CertificateStatus {
    Active,
    Revoked,
    Suspended
};

enum class KeyUsage {
    DigitalSignature,
    KeyCertSign,
    CRLSign,
    KeyEncipherment
};

enum class ValidationCode {
    Valid,
    NotFound,
    Expired,
    NotYetValid,
    Revoked,
    Suspended,
    UnknownIssuer,
    UntrustedRoot,
    InvalidCA,
    MissingUsage,
    HostnameMismatch,
    ChainCycle
};

std::string toString(CertificateType type) {
    switch (type) {
        case CertificateType::RootCA: return "Root CA";
        case CertificateType::IntermediateCA: return "Intermediate CA";
        case CertificateType::Server: return "Server";
        case CertificateType::Client: return "Client";
        case CertificateType::CodeSigning: return "Code Signing";
    }

    throw std::logic_error("Unknown certificate type.");
}

std::string toString(CertificateStatus status) {
    switch (status) {
        case CertificateStatus::Active: return "Active";
        case CertificateStatus::Revoked: return "Revoked";
        case CertificateStatus::Suspended: return "Suspended";
    }

    throw std::logic_error("Unknown status.");
}

struct Certificate {
    std::string serial;
    std::string subject;
    std::string issuer;
    std::string publicKeyFingerprint;

    CertificateType type;
    CertificateStatus status = CertificateStatus::Active;

    TimePoint notBefore;
    TimePoint notAfter;

    std::set<KeyUsage> usages;
    std::set<std::string> subjectAltNames;

    bool isCA = false;
    int pathLength = -1;

    void validateStructure() const {
        if (serial.empty() || subject.empty() || issuer.empty()) {
            throw std::invalid_argument(
                "Serial, subject and issuer are mandatory."
            );
        }

        if (publicKeyFingerprint.empty()) {
            throw std::invalid_argument("Public key fingerprint required.");
        }

        if (notAfter <= notBefore) {
            throw std::invalid_argument("Invalid validity interval.");
        }

        if (usages.empty()) {
            throw std::invalid_argument("At least one key usage required.");
        }

        if (isCA && usages.count(KeyUsage::KeyCertSign) == 0) {
            throw std::invalid_argument("CA requires keyCertSign.");
        }

        if (pathLength < -1 || (pathLength >= 0 && !isCA)) {
            throw std::invalid_argument("Invalid path length.");
        }

        if (!isCA && usages.count(KeyUsage::KeyCertSign) != 0) {
            throw std::invalid_argument(
                "End-entity certificate cannot sign certificates."
            );
        }
    }
};

struct CertificateAuthority {
    std::string name;
    std::string certificateSerial;
    bool trusted = false;
};

struct ValidationResult {
    bool valid = false;
    std::vector<ValidationCode> errors;
    std::vector<std::string> chain;
};

class PKIException : public std::runtime_error {
public:
    explicit PKIException(const std::string& message)
        : std::runtime_error(message) {}
};

class CertificateStore {
private:
    std::map<std::string, Certificate> certificates;
    std::map<std::string, CertificateAuthority> authorities;

public:
    void addAuthority(
        const CertificateAuthority& authority,
        const Certificate& certificate
    ) {
        certificate.validateStructure();

        if (!certificate.isCA) {
            throw PKIException("Authority certificate is not a CA.");
        }

        if (authority.name != certificate.subject) {
            throw PKIException("Authority subject mismatch.");
        }

        if (authority.certificateSerial != certificate.serial) {
            throw PKIException("Authority serial mismatch.");
        }

        if (authorities.count(authority.name)) {
            throw PKIException("Duplicate authority.");
        }

        addCertificate(certificate);
        authorities.emplace(authority.name, authority);
    }

    void addCertificate(const Certificate& certificate) {
        certificate.validateStructure();

        if (certificates.count(certificate.serial)) {
            throw PKIException("Duplicate certificate serial.");
        }

        certificates.emplace(certificate.serial, certificate);
    }

    const Certificate* find(const std::string& serial) const {
        auto it = certificates.find(serial);

        if (it == certificates.end()) {
            return nullptr;
        }

        return &it->second;
    }

    const CertificateAuthority* findAuthority(
        const std::string& name
    ) const {
        auto it = authorities.find(name);

        if (it == authorities.end()) {
            return nullptr;
        }

        return &it->second;
    }

    void revoke(
        const std::string& serial,
        const std::string& reason
    ) {
        auto it = certificates.find(serial);

        if (it == certificates.end()) {
            throw PKIException("Certificate not found.");
        }

        if (reason.empty()) {
            throw PKIException("Revocation reason is required.");
        }

        if (it->second.status == CertificateStatus::Revoked) {
            throw PKIException("Certificate already revoked.");
        }

        it->second.status = CertificateStatus::Revoked;
    }

    std::vector<Certificate> inventory() const {
        std::vector<Certificate> result;
        result.reserve(certificates.size());

        for (const auto& entry : certificates) {
            result.push_back(entry.second);
        }

        return result;
    }
};

class CertificateValidator {
private:
    const CertificateStore& store;

    bool checkValidity(
        const Certificate& certificate,
        TimePoint moment,
        ValidationResult& result
    ) const {
        if (certificate.status == CertificateStatus::Revoked) {
            result.errors.push_back(ValidationCode::Revoked);
            return false;
        }

        if (certificate.status == CertificateStatus::Suspended) {
            result.errors.push_back(ValidationCode::Suspended);
            return false;
        }

        if (moment < certificate.notBefore) {
            result.errors.push_back(ValidationCode::NotYetValid);
            return false;
        }

        if (moment > certificate.notAfter) {
            result.errors.push_back(ValidationCode::Expired);
            return false;
        }

        return true;
    }

public:
    explicit CertificateValidator(const CertificateStore& value)
        : store(value) {}

    ValidationResult validate(
        const std::string& serial,
        std::optional<std::string> hostname = std::nullopt,
        std::optional<KeyUsage> requiredUsage = std::nullopt,
        TimePoint moment = Clock::now()
    ) const {
        ValidationResult result;

        const Certificate* leaf = store.find(serial);

        if (!leaf) {
            result.errors.push_back(ValidationCode::NotFound);
            return result;
        }

        bool valid = true;
        const Certificate* current = leaf;
        std::set<std::string> visited;

        while (current != nullptr) {
            if (!visited.insert(current->serial).second) {
                result.errors.push_back(ValidationCode::ChainCycle);
                valid = false;
                break;
            }

            result.chain.push_back(current->subject);

            if (!checkValidity(*current, moment, result)) {
                valid = false;
            }

            if (current->isCA &&
                current->usages.count(KeyUsage::KeyCertSign) == 0) {
                result.errors.push_back(ValidationCode::InvalidCA);
                valid = false;
            }

            if (current->issuer == current->subject) {
                const auto* root = store.findAuthority(current->subject);

                if (!root || !root->trusted) {
                    result.errors.push_back(
                        ValidationCode::UntrustedRoot
                    );
                    valid = false;
                }

                break;
            }

            const auto* issuerAuthority =
                store.findAuthority(current->issuer);

            if (!issuerAuthority) {
                result.errors.push_back(
                    ValidationCode::UnknownIssuer
                );
                valid = false;
                break;
            }

            current = store.find(
                issuerAuthority->certificateSerial
            );

            if (!current) {
                result.errors.push_back(
                    ValidationCode::UnknownIssuer
                );
                valid = false;
                break;
            }
        }

        if (requiredUsage &&
            leaf->usages.count(*requiredUsage) == 0) {
            result.errors.push_back(ValidationCode::MissingUsage);
            valid = false;
        }

        if (hostname) {
            if (leaf->type != CertificateType::Server ||
                leaf->subjectAltNames.count(*hostname) == 0) {
                result.errors.push_back(
                    ValidationCode::HostnameMismatch
                );
                valid = false;
            }
        }

        result.valid = valid && result.errors.empty();

        return result;
    }
};

class CertificateLifecycle {
private:
    CertificateStore& store;

public:
    explicit CertificateLifecycle(CertificateStore& value)
        : store(value) {}

    void renew(
        const std::string& oldSerial,
        Certificate replacement
    ) {
        const Certificate* oldCertificate = store.find(oldSerial);

        if (!oldCertificate) {
            throw PKIException("Original certificate not found.");
        }

        if (oldCertificate->status == CertificateStatus::Revoked) {
            throw PKIException("Revoked certificates cannot be renewed.");
        }

        if (oldCertificate->subject != replacement.subject) {
            throw PKIException("Renewal subject must match.");
        }

        if (oldCertificate->issuer != replacement.issuer) {
            throw PKIException("Renewal issuer must match.");
        }

        if (oldCertificate->publicKeyFingerprint ==
            replacement.publicKeyFingerprint) {
            std::cout
                << "Notice: renewal reuses the previous public key.\n";
        }

        store.addCertificate(replacement);
    }
};

Certificate makeCertificate(
    std::string serial,
    std::string subject,
    std::string issuer,
    CertificateType type,
    bool isCA,
    int days,
    std::set<KeyUsage> usages,
    std::string fingerprint,
    int pathLength = -1
) {
    const auto now = Clock::now();

    Certificate certificate{
        std::move(serial),
        std::move(subject),
        std::move(issuer),
        std::move(fingerprint),
        type,
        CertificateStatus::Active,
        now - std::chrono::hours(24),
        now + std::chrono::hours(24 * days),
        std::move(usages),
        {},
        isCA,
        pathLength
    };

    certificate.validateStructure();
    return certificate;
}

void printResult(const ValidationResult& result) {
    std::cout << "\nValidation: "
              << (result.valid ? "ACCEPTED" : "REJECTED")
              << "\n";

    std::cout << "Certificate chain:\n";

    for (const auto& name : result.chain) {
        std::cout << "  -> " << name << '\n';
    }

    if (!result.errors.empty()) {
        std::cout << "Validation errors: "
                  << result.errors.size() << '\n';

        for (const auto& error : result.errors) {
            std::cout << "  Error code: "
                      << static_cast<int>(error) << '\n';
        }
    }
}

int main() {
    try {
        CertificateStore store;

        const auto root = makeCertificate(
            "1000",
            "Example Root CA",
            "Example Root CA",
            CertificateType::RootCA,
            true,
            3650,
            {KeyUsage::KeyCertSign, KeyUsage::CRLSign},
            "root-public-key-sha256",
            1
        );

        store.addAuthority(
            {"Example Root CA", "1000", true},
            root
        );

        const auto intermediate = makeCertificate(
            "2000",
            "Example Intermediate CA",
            "Example Root CA",
            CertificateType::IntermediateCA,
            true,
            730,
            {KeyUsage::KeyCertSign, KeyUsage::CRLSign},
            "intermediate-public-key-sha256",
            0
        );

        store.addAuthority(
            {"Example Intermediate CA", "2000", false},
            intermediate
        );

        auto server = makeCertificate(
            "3000",
            "www.example.com",
            "Example Intermediate CA",
            CertificateType::Server,
            false,
            90,
            {
                KeyUsage::DigitalSignature,
                KeyUsage::KeyEncipherment
            },
            "server-public-key-sha256"
        );

        server.subjectAltNames.insert("www.example.com");
        server.subjectAltNames.insert("api.example.com");

        store.addCertificate(server);

        CertificateValidator validator(store);

        std::cout << "DIGITAL CERTIFICATE GOVERNANCE ENGINE\n";

        const auto valid = validator.validate(
            "3000",
            "www.example.com",
            KeyUsage::DigitalSignature
        );

        printResult(valid);

        if (!valid.valid) {
            throw PKIException("Expected certificate validation failed.");
        }

        const auto invalid = validator.validate(
            "3000",
            "attacker.example.net"
        );

        printResult(invalid);

        if (invalid.valid) {
            throw PKIException("Hostname validation failed.");
        }

        store.revoke("3000", "Private key compromise");

        const auto revoked = validator.validate("3000");

        printResult(revoked);

        if (revoked.valid) {
            throw PKIException("Revocation enforcement failed.");
        }

        std::cout << "\nCertificate Inventory\n";

        for (const auto& certificate : store.inventory()) {
            std::cout
                << certificate.serial
                << " | "
                << certificate.subject
                << " | "
                << toString(certificate.type)
                << " | "
                << toString(certificate.status)
                << '\n';
        }

        std::cout << "\nAll governance scenarios completed.\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "PKI error: " << error.what() << '\n';
        return 1;
    }
}
