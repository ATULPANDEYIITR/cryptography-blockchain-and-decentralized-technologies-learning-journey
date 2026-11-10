#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

enum class KeyStatus {
    ACTIVE,
    ROTATED,
    REVOKED,
    COMPROMISED
};

enum class Operation {
    ENCRYPTION,
    DECRYPTION,
    SIGNATURE,
    VERIFICATION
};

enum class Padding {
    RAW_RSA,
    PKCS1_V15,
    OAEP_SHA256,
    PSS_SHA256
};

enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct RSAKey {
    string id;
    unsigned int modulusBits;
    uint32_t publicExponent;
    KeyStatus status;
    bool privateKeyExportable;
    string owner;
};

struct Finding {
    Severity severity;
    string code;
    string description;
};

struct PolicyResult {
    string keyId;
    bool approved;
    vector<Finding> findings;
};

struct BranchProtection {
    bool requireApproval = true;
    bool requireChecks = true;
    bool prohibitLegacyPadding = true;
    unsigned int minimumBits = 2048;
    unsigned int minimumApprovals = 2;
    bool requireIndependentReviewers = true;
};

struct OperationRequest {
    string requestId;
    string keyId;
    Operation operation;
    Padding padding;
    set<string> approvers;
    set<string> reviewers;
    map<string, bool> statusChecks;
};

string toString(KeyStatus status) {
    switch (status) {
        case KeyStatus::ACTIVE: return "ACTIVE";
        case KeyStatus::ROTATED: return "ROTATED";
        case KeyStatus::REVOKED: return "REVOKED";
        case KeyStatus::COMPROMISED: return "COMPROMISED";
    }
    throw logic_error("Invalid key status");
}

string toString(Operation operation) {
    switch (operation) {
        case Operation::ENCRYPTION: return "ENCRYPTION";
        case Operation::DECRYPTION: return "DECRYPTION";
        case Operation::SIGNATURE: return "SIGNATURE";
        case Operation::VERIFICATION: return "VERIFICATION";
    }
    throw logic_error("Invalid operation");
}

string toString(Severity severity) {
    switch (severity) {
        case Severity::LOW: return "LOW";
        case Severity::MEDIUM: return "MEDIUM";
        case Severity::HIGH: return "HIGH";
        case Severity::CRITICAL: return "CRITICAL";
    }
    throw logic_error("Invalid severity");
}

class RSAPolicyEngine {
private:
    BranchProtection policy;

public:
    explicit RSAPolicyEngine(BranchProtection configuration)
        : policy(configuration) {
        if (policy.minimumBits < 2048) {
            throw invalid_argument(
                "Production RSA minimum cannot be below 2048 bits"
            );
        }

        if (policy.minimumApprovals == 0) {
            throw invalid_argument("At least one approval is required");
        }
    }

    PolicyResult evaluate(
        const RSAKey& key,
        Operation operation,
        Padding padding
    ) const {
        PolicyResult result{key.id, true, {}};

        auto add = [&](Severity severity,
                       const string& code,
                       const string& description) {
            result.findings.push_back({
                severity, code, description
            });
        };

        if (key.id.empty()) {
            add(Severity::CRITICAL, "MISSING_ID",
                "Key identifier is empty");
        }

        if (key.status != KeyStatus::ACTIVE) {
            add(Severity::CRITICAL, "INACTIVE_KEY",
                "Key is not active");
        }

        if (key.modulusBits < policy.minimumBits) {
            add(Severity::CRITICAL, "WEAK_MODULUS",
                "RSA modulus does not meet minimum size");
        }

        if (key.publicExponent != 65537) {
            add(Severity::HIGH, "INVALID_EXPONENT",
                "Expected public exponent 65537");
        }

        if (key.privateKeyExportable) {
            add(Severity::HIGH, "EXPORTABLE_PRIVATE_KEY",
                "Private key export increases compromise risk");
        }

        if (padding == Padding::RAW_RSA) {
            add(Severity::CRITICAL, "RAW_RSA",
                "Textbook RSA is vulnerable to structural attacks");
        }

        bool encryption =
            operation == Operation::ENCRYPTION ||
            operation == Operation::DECRYPTION;

        bool signing =
            operation == Operation::SIGNATURE ||
            operation == Operation::VERIFICATION;

        if (encryption && padding != Padding::OAEP_SHA256) {
            add(Severity::HIGH, "ENCRYPTION_PADDING",
                "Encryption requires OAEP-SHA256");
        }

        if (signing && padding != Padding::PSS_SHA256) {
            add(Severity::HIGH, "SIGNATURE_PADDING",
                "Signatures require PSS-SHA256");
        }

        if (policy.prohibitLegacyPadding &&
            padding == Padding::PKCS1_V15) {
            add(Severity::HIGH, "LEGACY_PADDING",
                "PKCS#1 v1.5 is prohibited");
        }

        result.approved = result.findings.empty();

        return result;
    }
};

class GovernanceEngine {
private:
    BranchProtection protection;
    RSAPolicyEngine rsaPolicy;
    map<string, RSAKey> keys;
    vector<string> audit;

public:
    explicit GovernanceEngine(BranchProtection configuration)
        : protection(configuration), rsaPolicy(configuration) {}

    void registerKey(const RSAKey& key) {
        if (key.id.empty()) {
            throw invalid_argument("Empty key identifier");
        }

        if (keys.count(key.id)) {
            throw invalid_argument("Duplicate key identifier");
        }

        keys.emplace(key.id, key);
        audit.push_back("REGISTERED:" + key.id);
    }

    void updateStatus(const string& id, KeyStatus status) {
        auto iterator = keys.find(id);

        if (iterator == keys.end()) {
            throw out_of_range("Unknown key");
        }

        iterator->second.status = status;
        audit.push_back("STATUS_CHANGED:" + id + ":" + toString(status));
    }

    PolicyResult evaluateKey(
        const string& id,
        Operation operation,
        Padding padding
    ) const {
        auto iterator = keys.find(id);

        if (iterator == keys.end()) {
            throw out_of_range("Unknown key identifier");
        }

        return rsaPolicy.evaluate(iterator->second, operation, padding);
    }

    bool evaluateRequest(const OperationRequest& request) {
        if (request.requestId.empty()) {
            throw invalid_argument("Missing request identifier");
        }

        auto iterator = keys.find(request.keyId);

        if (iterator == keys.end()) {
            throw out_of_range("Unknown RSA key");
        }

        PolicyResult keyResult = evaluateKey(
            request.keyId,
            request.operation,
            request.padding
        );

        if (!keyResult.approved) {
            audit.push_back("DENIED:" + request.requestId);
            return false;
        }

        if (protection.requireApproval &&
            request.approvers.size() < protection.minimumApprovals) {
            audit.push_back("DENIED_INSUFFICIENT_APPROVALS");
            return false;
        }

        if (protection.requireIndependentReviewers) {
            for (const auto& approver : request.approvers) {
                if (request.reviewers.count(approver)) {
                    audit.push_back("DENIED_SELF_APPROVAL");
                    return false;
                }
            }
        }

        if (protection.requireChecks) {
            if (request.statusChecks.empty()) {
                audit.push_back("DENIED_MISSING_CHECKS");
                return false;
            }

            for (const auto& check : request.statusChecks) {
                if (!check.second) {
                    audit.push_back("DENIED_FAILED_CHECK:" + check.first);
                    return false;
                }
            }
        }

        audit.push_back("APPROVED:" + request.requestId);
        return true;
    }

    void printAudit() const {
        cout << "\nGovernance audit:\n";

        for (const auto& entry : audit) {
            cout << "  " << entry << '\n';
        }
    }
};

void printResult(const PolicyResult& result) {
    cout << "\nKey: " << result.keyId
         << "\nApproved: " << boolalpha << result.approved << '\n';

    for (const auto& finding : result.findings) {
        cout << "  [" << toString(finding.severity) << "] "
             << finding.code << ": "
             << finding.description << '\n';
    }
}

// Educational modular exponentiation.
// This is not a production cryptographic implementation.
uint64_t modularPower(uint64_t base, uint64_t exponent, uint64_t modulus) {
    if (modulus == 0) {
        throw invalid_argument("Modulus cannot be zero");
    }

    uint64_t result = 1;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1) {
            result = static_cast<uint64_t>(
                static_cast<__uint128_t>(result) * base % modulus
            );
        }

        base = static_cast<uint64_t>(
            static_cast<__uint128_t>(base) * base % modulus
        );

        exponent >>= 1;
    }

    return result;
}

void demonstrateRSAArithmetic() {
    // Small textbook RSA example: p=61, q=53, n=3233.
    constexpr uint64_t n = 3233;
    constexpr uint64_t e = 17;
    constexpr uint64_t d = 2753;
    constexpr uint64_t message = 65;

    const uint64_t ciphertext = modularPower(message, e, n);
    const uint64_t plaintext = modularPower(ciphertext, d, n);

    cout << "\nEducational textbook RSA demonstration\n";
    cout << "Modulus: " << n << '\n';
    cout << "Ciphertext: " << ciphertext << '\n';
    cout << "Recovered plaintext: " << plaintext << '\n';
    cout << "Correct recovery: " << boolalpha
         << (plaintext == message) << '\n';

    uint64_t c1 = modularPower(7, e, n);
    uint64_t c2 = modularPower(9, e, n);

    uint64_t combined = c1 * c2 % n;
    uint64_t expected = modularPower(63, e, n);

    cout << "Multiplicative malleability: "
         << (combined == expected) << '\n';
}

void runTests() {
    BranchProtection configuration;

    RSAPolicyEngine engine(configuration);

    RSAKey secure{
        "RSA-SECURE",
        3072,
        65537,
        KeyStatus::ACTIVE,
        false,
        "security-team"
    };

    RSAKey weak{
        "RSA-WEAK",
        1024,
        3,
        KeyStatus::ACTIVE,
        true,
        "legacy-service"
    };

    assert(engine.evaluate(
        secure,
        Operation::ENCRYPTION,
        Padding::OAEP_SHA256
    ).approved);

    assert(!engine.evaluate(
        weak,
        Operation::ENCRYPTION,
        Padding::RAW_RSA
    ).approved);

    assert(!engine.evaluate(
        secure,
        Operation::SIGNATURE,
        Padding::OAEP_SHA256
    ).approved);

    assert(modularPower(65, 17, 3233) == 2790);
    assert(modularPower(2790, 2753, 3233) == 65);
}

int main() {
    try {
        runTests();

        BranchProtection configuration;
        configuration.minimumBits = 2048;
        configuration.minimumApprovals = 2;

        GovernanceEngine governance(configuration);

        governance.registerKey({
            "RSA-PROD-001",
            3072,
            65537,
            KeyStatus::ACTIVE,
            false,
            "payments-service"
        });

        governance.registerKey({
            "RSA-LEGACY-001",
            1024,
            3,
            KeyStatus::ACTIVE,
            true,
            "legacy-service"
        });

        printResult(governance.evaluateKey(
            "RSA-PROD-001",
            Operation::ENCRYPTION,
            Padding::OAEP_SHA256
        ));

        printResult(governance.evaluateKey(
            "RSA-LEGACY-001",
            Operation::ENCRYPTION,
            Padding::RAW_RSA
        ));

        OperationRequest request{
            "REQUEST-001",
            "RSA-PROD-001",
            Operation::SIGNATURE,
            Padding::PSS_SHA256,
            {"security-lead", "crypto-owner"},
            {"developer-a"},
            {
                {"key-audit", true},
                {"configuration-review", true},
                {"private-key-protection", true}
            }
        };

        cout << "\nEnterprise request eligible: "
             << boolalpha << governance.evaluateRequest(request) << '\n';

        OperationRequest failedRequest = request;
        failedRequest.requestId = "REQUEST-002";
        failedRequest.statusChecks["private-key-protection"] = false;

        cout << "Failed-check request eligible: "
             << governance.evaluateRequest(failedRequest) << '\n';

        governance.updateStatus("RSA-LEGACY-001", KeyStatus::REVOKED);

        printResult(governance.evaluateKey(
            "RSA-LEGACY-001",
            Operation::SIGNATURE,
            Padding::PSS_SHA256
        ));

        demonstrateRSAArithmetic();

        governance.printAudit();

        cout << "\nAll C++17 tests passed.\n";
    }
    catch (const exception& error) {
        cerr << "Execution failed: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
