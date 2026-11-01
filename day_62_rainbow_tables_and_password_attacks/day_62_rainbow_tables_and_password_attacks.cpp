#include <algorithm>
#include <chrono>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * Rainbow Tables and Password Attacks
 *
 * Repository-independent password security governance engine.
 *
 * Implements:
 * - Synthetic password attack classification
 * - Rainbow-table risk analysis
 * - Credential storage policy evaluation
 * - Authentication state transitions
 * - Rate limiting and account lockout
 * - Security event reporting
 *
 * Cryptographic password hashing is delegated to a reviewed
 * cryptographic library in production. This C++17 case study
 * deliberately does not implement cryptographic primitives.
 */

// ---------------------------------------------------------
// 1. Domain types
// ---------------------------------------------------------

enum class AttackType {
    Dictionary,
    BruteForce,
    RainbowTable,
    CredentialStuffing,
    PasswordSpraying,
    Phishing
};

enum class AuthenticationStatus {
    Success,
    Invalid,
    Locked
};

enum class HashAlgorithm {
    SHA256,
    PBKDF2,
    Argon2id,
    Bcrypt
};

enum class RiskLevel {
    Low,
    Medium,
    High,
    Critical
};

std::string toString(AttackType type) {
    switch (type) {
        case AttackType::Dictionary:
            return "Dictionary";
        case AttackType::BruteForce:
            return "Brute Force";
        case AttackType::RainbowTable:
            return "Rainbow Table";
        case AttackType::CredentialStuffing:
            return "Credential Stuffing";
        case AttackType::PasswordSpraying:
            return "Password Spraying";
        case AttackType::Phishing:
            return "Phishing";
    }

    throw std::invalid_argument("Unknown attack type");
}

std::string toString(RiskLevel risk) {
    switch (risk) {
        case RiskLevel::Low: return "LOW";
        case RiskLevel::Medium: return "MEDIUM";
        case RiskLevel::High: return "HIGH";
        case RiskLevel::Critical: return "CRITICAL";
    }

    throw std::invalid_argument("Unknown risk level");
}

// ---------------------------------------------------------
// 2. Attack classification
// ---------------------------------------------------------

struct AttackProfile {
    AttackType type;
    std::string description;
    std::vector<std::string> defenses;
};

class AttackCatalog {
private:
    std::map<AttackType, AttackProfile> profiles;

public:
    AttackCatalog() {
        profiles.emplace(
            AttackType::Dictionary,
            AttackProfile{
                AttackType::Dictionary,
                "Testing likely passwords against password hashes.",
                {
                    "Common-password screening",
                    "Adaptive password hashing"
                }
            }
        );

        profiles.emplace(
            AttackType::BruteForce,
            AttackProfile{
                AttackType::BruteForce,
                "Exhaustive candidate-space enumeration.",
                {
                    "Rate limiting",
                    "Authentication delays"
                }
            }
        );

        profiles.emplace(
            AttackType::RainbowTable,
            AttackProfile{
                AttackType::RainbowTable,
                "Precomputed hash-chain lookup.",
                {
                    "Unique random salts",
                    "Memory-hard password hashing"
                }
            }
        );

        profiles.emplace(
            AttackType::CredentialStuffing,
            AttackProfile{
                AttackType::CredentialStuffing,
                "Reuse of previously exposed credentials.",
                {
                    "Multi-factor authentication",
                    "Credential reuse detection"
                }
            }
        );

        profiles.emplace(
            AttackType::PasswordSpraying,
            AttackProfile{
                AttackType::PasswordSpraying,
                "Attempts involving a small number of passwords across accounts.",
                {
                    "Distributed failure monitoring",
                    "Account-aware rate limiting"
                }
            }
        );

        profiles.emplace(
            AttackType::Phishing,
            AttackProfile{
                AttackType::Phishing,
                "Deceptive collection of authentication credentials.",
                {
                    "Passkeys",
                    "Phishing-resistant authentication"
                }
            }
        );
    }

    const AttackProfile& get(AttackType type) const {
        auto iterator = profiles.find(type);

        if (iterator == profiles.end()) {
            throw std::invalid_argument("Attack profile not found");
        }

        return iterator->second;
    }

    void display() const {
        for (const auto& entry : profiles) {
            const auto& profile = entry.second;

            std::cout << "\n" << profile.description << "\n";

            for (const auto& defense : profile.defenses) {
                std::cout << "  - " << defense << "\n";
            }
        }
    }
};

// ---------------------------------------------------------
// 3. Password storage policy
// ---------------------------------------------------------

struct PasswordStoragePolicy {
    HashAlgorithm algorithm;
    unsigned int minimumIterations;
    bool uniqueSaltRequired;
    bool memoryHardRequired;
};

class StoragePolicyEvaluator {
public:
    static RiskLevel evaluate(
        const PasswordStoragePolicy& policy
    ) {
        if (!policy.uniqueSaltRequired) {
            return RiskLevel::Critical;
        }

        if (policy.algorithm == HashAlgorithm::SHA256) {
            return RiskLevel::Critical;
        }

        if (
            policy.algorithm == HashAlgorithm::Argon2id &&
            policy.memoryHardRequired
        ) {
            return RiskLevel::Low;
        }

        if (
            policy.algorithm == HashAlgorithm::PBKDF2 &&
            policy.minimumIterations >= 600000
        ) {
            return RiskLevel::Low;
        }

        if (
            policy.algorithm == HashAlgorithm::Bcrypt &&
            policy.minimumIterations >= 12
        ) {
            return RiskLevel::Medium;
        }

        return RiskLevel::High;
    }
};

// ---------------------------------------------------------
// 4. Password policy
// ---------------------------------------------------------

class PasswordValidator {
private:
    static bool containsLetter(const std::string& value) {
        return std::any_of(
            value.begin(),
            value.end(),
            [](unsigned char c) {
                return std::isalpha(c);
            }
        );
    }

    static bool containsDigit(const std::string& value) {
        return std::any_of(
            value.begin(),
            value.end(),
            [](unsigned char c) {
                return std::isdigit(c);
            }
        );
    }

public:
    static std::vector<std::string> validate(
        const std::string& password
    ) {
        std::vector<std::string> errors;

        if (password.size() < 12) {
            errors.push_back("Minimum length is 12 bytes");
        }

        if (password.size() > 1024) {
            errors.push_back("Password exceeds maximum size");
        }

        if (!containsLetter(password)) {
            errors.push_back("A letter is required");
        }

        if (!containsDigit(password)) {
            errors.push_back("A digit is required");
        }

        const std::set<std::string> commonPasswords = {
            "password123!",
            "admin123456!",
            "welcome12345"
        };

        if (commonPasswords.count(password)) {
            errors.push_back("Common password detected");
        }

        return errors;
    }
};

// ---------------------------------------------------------
// 5. Account domain model
// ---------------------------------------------------------

struct Account {
    std::string username;
    std::string passwordVerifier;
    bool enabled = true;
    unsigned int failedAttempts = 0;
    std::chrono::steady_clock::time_point lockedUntil{};
};

// ---------------------------------------------------------
// 6. Authentication policy
// ---------------------------------------------------------

struct AuthenticationPolicy {
    unsigned int maximumFailures = 5;
    std::chrono::seconds lockoutDuration{30};
};

class AuthenticationService {
private:
    std::unordered_map<std::string, Account> accounts;
    AuthenticationPolicy policy;

    std::vector<std::string> securityEvents;

public:
    explicit AuthenticationService(AuthenticationPolicy p)
        : policy(p) {
        if (policy.maximumFailures == 0) {
            throw std::invalid_argument(
                "Maximum failures must be positive"
            );
        }

        if (policy.lockoutDuration.count() <= 0) {
            throw std::invalid_argument(
                "Lockout duration must be positive"
            );
        }
    }

    void registerAccount(
        const std::string& username,
        const std::string& passwordVerifier
    ) {
        if (username.size() < 3 || username.size() > 64) {
            throw std::invalid_argument("Invalid username");
        }

        if (passwordVerifier.empty()) {
            throw std::invalid_argument(
                "Password verifier cannot be empty"
            );
        }

        if (accounts.count(username)) {
            throw std::invalid_argument("Account already exists");
        }

        // The verifier is supplied by a trusted password-hashing
        // component. Plaintext passwords are never stored here.
        accounts.emplace(
            username,
            Account{
                username,
                passwordVerifier
            }
        );

        securityEvents.push_back(
            "Account registered: " + username
        );
    }

    AuthenticationStatus authenticate(
        const std::string& username,
        const std::string& suppliedVerifier
    ) {
        auto iterator = accounts.find(username);

        if (iterator == accounts.end()) {
            securityEvents.push_back(
                "Authentication failure for unknown account"
            );

            return AuthenticationStatus::Invalid;
        }

        Account& account = iterator->second;

        if (!account.enabled) {
            return AuthenticationStatus::Locked;
        }

        const auto now = std::chrono::steady_clock::now();

        if (now < account.lockedUntil) {
            return AuthenticationStatus::Locked;
        }

        // This comparison is illustrative. Production systems
        // must verify a password using a constant-time,
        // algorithm-aware cryptographic verifier.
        if (suppliedVerifier != account.passwordVerifier) {
            account.failedAttempts++;

            securityEvents.push_back(
                "Failed authentication: " + username
            );

            if (
                account.failedAttempts >=
                policy.maximumFailures
            ) {
                account.lockedUntil =
                    now + policy.lockoutDuration;

                securityEvents.push_back(
                    "Account temporarily locked: " + username
                );

                return AuthenticationStatus::Locked;
            }

            return AuthenticationStatus::Invalid;
        }

        account.failedAttempts = 0;
        account.lockedUntil = {};

        securityEvents.push_back(
            "Successful authentication: " + username
        );

        return AuthenticationStatus::Success;
    }

    void displayEvents() const {
        std::cout << "\nSECURITY EVENT LOG\n";

        for (const auto& event : securityEvents) {
            std::cout << event << "\n";
        }
    }

    std::size_t accountCount() const {
        return accounts.size();
    }
};

// ---------------------------------------------------------
// 7. Synthetic rainbow-table risk assessment
// ---------------------------------------------------------

class RainbowTableRiskAnalyzer {
public:
    static RiskLevel evaluate(
        bool unsalted,
        bool fastHash,
        bool uniqueRandomSalt,
        bool memoryHard
    ) {
        if (unsalted && fastHash) {
            return RiskLevel::Critical;
        }

        if (unsalted) {
            return RiskLevel::High;
        }

        if (uniqueRandomSalt && memoryHard) {
            return RiskLevel::Low;
        }

        if (uniqueRandomSalt) {
            return RiskLevel::Medium;
        }

        return RiskLevel::High;
    }

    static void report(
        const std::string& system,
        RiskLevel risk
    ) {
        std::cout
            << system
            << " | Rainbow-table risk: "
            << toString(risk)
            << "\n";
    }
};

// ---------------------------------------------------------
// 8. Repository security evaluation
// ---------------------------------------------------------

struct SecurityConfiguration {
    PasswordStoragePolicy storagePolicy;

    bool multiFactorAuthentication;
    bool breachedPasswordScreening;
    bool rateLimiting;
    bool auditLogging;
};

class SecurityGovernance {
public:
    static RiskLevel assess(
        const SecurityConfiguration& configuration
    ) {
        RiskLevel storageRisk =
            StoragePolicyEvaluator::evaluate(
                configuration.storagePolicy
            );

        if (storageRisk == RiskLevel::Critical) {
            return RiskLevel::Critical;
        }

        if (
            !configuration.rateLimiting ||
            !configuration.auditLogging
        ) {
            return RiskLevel::High;
        }

        if (
            !configuration.multiFactorAuthentication ||
            !configuration.breachedPasswordScreening
        ) {
            return RiskLevel::Medium;
        }

        return storageRisk;
    }
};

// ---------------------------------------------------------
// 9. Main workflow
// ---------------------------------------------------------

int main() {
    try {
        std::cout
            << "RAINBOW TABLES AND PASSWORD ATTACKS\n"
            << "Defensive Security Governance Engine\n"
            << "====================================\n";

        AttackCatalog catalog;

        std::cout << "\nATTACK CLASSIFICATION\n";
        catalog.display();

        std::cout << "\nSTORAGE POLICY EVALUATION\n";

        PasswordStoragePolicy insecurePolicy{
            HashAlgorithm::SHA256,
            1,
            false,
            false
        };

        PasswordStoragePolicy securePolicy{
            HashAlgorithm::Argon2id,
            0,
            true,
            true
        };

        std::cout
            << "Unsalted SHA-256: "
            << toString(
                StoragePolicyEvaluator::evaluate(
                    insecurePolicy
                )
            )
            << "\n";

        std::cout
            << "Salted Argon2id: "
            << toString(
                StoragePolicyEvaluator::evaluate(
                    securePolicy
                )
            )
            << "\n";

        std::cout << "\nPASSWORD VALIDATION\n";

        auto errors = PasswordValidator::validate(
            "weak"
        );

        for (const auto& error : errors) {
            std::cout << "Rejected: " << error << "\n";
        }

        auto validErrors = PasswordValidator::validate(
            "SecurePass123!"
        );

        std::cout
            << "Strong password accepted: "
            << std::boolalpha
            << validErrors.empty()
            << "\n";

        std::cout << "\nRAINBOW TABLE RISK\n";

        RainbowTableRiskAnalyzer::report(
            "Legacy application",
            RainbowTableRiskAnalyzer::evaluate(
                true,
                true,
                false,
                false
            )
        );

        RainbowTableRiskAnalyzer::report(
            "Modern password storage",
            RainbowTableRiskAnalyzer::evaluate(
                false,
                false,
                true,
                true
            )
        );

        std::cout << "\nAUTHENTICATION WORKFLOW\n";

        AuthenticationService authentication({
            3,
            std::chrono::seconds(30)
        });

        // Synthetic verifier for state-machine testing only.
        // A production deployment must use a password-hashing
        // library and verify the actual password securely.
        authentication.registerAccount(
            "researcher",
            "synthetic-verifier-001"
        );

        auto status = authentication.authenticate(
            "researcher",
            "synthetic-verifier-001"
        );

        std::cout
            << "Successful login: "
            << static_cast<int>(status)
            << "\n";

        for (int i = 0; i < 3; ++i) {
            authentication.authenticate(
                "researcher",
                "incorrect-verifier"
            );
        }

        status = authentication.authenticate(
            "researcher",
            "synthetic-verifier-001"
        );

        std::cout
            << "Login after lockout: "
            << static_cast<int>(status)
            << "\n";

        authentication.displayEvents();

        std::cout << "\nGOVERNANCE EVALUATION\n";

        SecurityConfiguration configuration{
            securePolicy,
            true,
            true,
            true,
            true
        };

        std::cout
            << "Application security rating: "
            << toString(
                SecurityGovernance::assess(configuration)
            )
            << "\n";

        std::cout << "\nAll workflow operations completed.\n";

    } catch (const std::exception& exception) {
        std::cerr
            << "Execution error: "
            << exception.what()
            << "\n";

        return 1;
    }

    return 0;
}
