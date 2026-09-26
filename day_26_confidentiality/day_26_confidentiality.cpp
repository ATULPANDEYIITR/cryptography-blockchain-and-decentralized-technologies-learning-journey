/*
 * CONFIDENTIALITY
 * ===============
 *
 * C++17 case study: a Confidential Document Management System.
 *
 * The program demonstrates how confidentiality controls can be combined
 * into an industry-style application:
 *
 *   - information classification
 *   - users and roles
 *   - authorization
 *   - least privilege
 *   - attribute-based access decisions
 *   - audit logging
 *   - data minimization
 *   - authenticated encryption concepts
 *   - key metadata and rotation
 *   - validation
 *   - exception handling
 *   - access-denial paths
 *   - performance considerations
 *
 * The cryptographic demonstration uses a standard-library educational
 * construction where practical. It is intentionally not presented as a
 * replacement for production cryptographic libraries.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic confidentiality.cpp -o confidentiality
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>


// ============================================================================
// 1. COMMON UTILITIES
// ============================================================================

void section(const std::string& title) {
    std::cout << "\n"
              << std::string(78, '=')
              << "\n"
              << title
              << "\n"
              << std::string(78, '=')
              << "\n";
}

std::string toHex(const std::vector<std::uint8_t>& data) {
    std::ostringstream output;

    for (std::uint8_t byte : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(byte);
    }

    return output.str();
}

std::vector<std::uint8_t> toBytes(const std::string& text) {
    return std::vector<std::uint8_t>(
        text.begin(),
        text.end()
    );
}

std::string toString(const std::vector<std::uint8_t>& data) {
    return std::string(
        data.begin(),
        data.end()
    );
}


// ============================================================================
// 2. CLASSIFICATION
// ============================================================================

enum class Classification {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3
};

std::string classificationName(Classification classification) {
    switch (classification) {
        case Classification::Public:
            return "Public";

        case Classification::Internal:
            return "Internal";

        case Classification::Confidential:
            return "Confidential";

        case Classification::Restricted:
            return "Restricted";
    }

    throw std::logic_error("Unknown classification.");
}

int classificationLevel(Classification classification) {
    return static_cast<int>(classification);
}


// ============================================================================
// 3. USERS AND ROLES
// ============================================================================

struct User {
    std::string username;
    std::set<std::string> roles;
    int clearanceLevel = 0;
};

struct ConfidentialDocument {
    std::string id;
    std::string ownerDepartment;
    Classification classification;
    std::string content;
};


// ============================================================================
// 4. POLICY REQUEST
// ============================================================================

struct AccessRequest {
    const User& user;
    const ConfidentialDocument& document;
    std::string action;
    std::string department;
    bool businessHours;
};


// ============================================================================
// 5. AUDIT LOG
// ============================================================================

struct AuditEvent {
    std::string timestamp;
    std::string username;
    std::string documentId;
    std::string action;
    std::string result;
};

std::string currentTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);

    std::ostringstream output;

#ifdef _WIN32
    std::tm localTime{};
    localtime_s(&localTime, &time);
#else
    std::tm localTime{};
    localtime_r(&time, &localTime);
#endif

    output << std::put_time(
        &localTime,
        "%Y-%m-%d %H:%M:%S"
    );

    return output.str();
}


// ============================================================================
// 6. KEY METADATA
// ============================================================================

struct KeyMetadata {
    std::string keyId;
    std::string purpose;
    unsigned version;
    std::string status;
    std::string createdAt;
};


// ============================================================================
// 7. EDUCATIONAL XOR TRANSFORMATION
// ============================================================================

std::vector<std::uint8_t> xorTransform(
    const std::vector<std::uint8_t>& data,
    const std::vector<std::uint8_t>& key
) {
    if (key.empty()) {
        throw std::invalid_argument(
            "Encryption key cannot be empty."
        );
    }

    std::vector<std::uint8_t> result(data.size());

    for (std::size_t i = 0; i < data.size(); ++i) {
        result[i] =
            data[i] ^ key[i % key.size()];
    }

    return result;
}


// ============================================================================
// 8. SECURE-RANDOM-LOOKING KEY GENERATION FOR DEMONSTRATION
// ============================================================================

std::vector<std::uint8_t> randomBytes(std::size_t count) {
    /*
     * std::random_device may provide implementation-dependent entropy.
     * This function is suitable for this educational case study, but a
     * production cryptographic application should use an operating-system
     * cryptographic random source or a vetted cryptographic library.
     */
    std::random_device device;

    std::vector<std::uint8_t> result(count);

    for (auto& byte : result) {
        byte = static_cast<std::uint8_t>(device());
    }

    return result;
}


// ============================================================================
// 9. EDUCATIONAL MESSAGE AUTHENTICATION
// ============================================================================

std::vector<std::uint8_t> educationalAuthenticationTag(
    const std::vector<std::uint8_t>& ciphertext,
    const std::vector<std::uint8_t>& authenticationKey
) {
    /*
     * This is a teaching mechanism rather than a cryptographic MAC.
     * Production software should use a vetted HMAC or AEAD implementation.
     *
     * The purpose here is to illustrate that confidentiality and
     * authenticity are separate security properties.
     */
    std::uint64_t accumulator = 1469598103934665603ULL;

    for (std::uint8_t byte : authenticationKey) {
        accumulator ^= byte;
        accumulator *= 1099511628211ULL;
    }

    for (std::uint8_t byte : ciphertext) {
        accumulator ^= byte;
        accumulator *= 1099511628211ULL;
    }

    std::vector<std::uint8_t> tag(8);

    for (std::size_t i = 0; i < tag.size(); ++i) {
        tag[i] = static_cast<std::uint8_t>(
            (accumulator >> (i * 8)) & 0xFF
        );
    }

    return tag;
}


// ============================================================================
// 10. CONFIDENTIALITY SERVICE
// ============================================================================

class ConfidentialityService {
private:
    std::unordered_map<std::string, ConfidentialDocument> documents;
    std::vector<AuditEvent> auditEvents;
    std::unordered_map<std::string, KeyMetadata> keys;

    void audit(
        const std::string& username,
        const std::string& documentId,
        const std::string& action,
        const std::string& result
    ) {
        auditEvents.push_back(
            AuditEvent{
                currentTimestamp(),
                username,
                documentId,
                action,
                result
            }
        );
    }

    bool roleAllowed(
        const User& user,
        const std::set<std::string>& allowedRoles
    ) const {
        for (const std::string& role : user.roles) {
            if (allowedRoles.contains(role)) {
                return true;
            }
        }

        return false;
    }

public:
    void addDocument(const ConfidentialDocument& document) {
        if (document.id.empty()) {
            throw std::invalid_argument(
                "Document ID cannot be empty."
            );
        }

        if (document.content.empty()) {
            throw std::invalid_argument(
                "Document content cannot be empty."
            );
        }

        if (documents.contains(document.id)) {
            throw std::invalid_argument(
                "Document ID already exists."
            );
        }

        documents.emplace(
            document.id,
            document
        );
    }

    std::optional<ConfidentialDocument> getDocument(
        const AccessRequest& request,
        const std::set<std::string>& allowedRoles
    ) {
        auto iterator = documents.find(
            request.document.id
        );

        if (iterator == documents.end()) {
            audit(
                request.user.username,
                request.document.id,
                request.action,
                "NOT_FOUND"
            );

            return std::nullopt;
        }

        /*
         * First authorization condition:
         * the subject must possess an approved role.
         */
        if (!roleAllowed(request.user, allowedRoles)) {
            audit(
                request.user.username,
                request.document.id,
                request.action,
                "DENIED_ROLE"
            );

            return std::nullopt;
        }

        /*
         * Second authorization condition:
         * the user's clearance must meet the document classification.
         */
        if (
            request.user.clearanceLevel
            < classificationLevel(
                iterator->second.classification
            )
        ) {
            audit(
                request.user.username,
                request.document.id,
                request.action,
                "DENIED_CLEARANCE"
            );

            return std::nullopt;
        }

        /*
         * Third authorization condition:
         * confidential and restricted data requires an additional
         * contextual condition in this demonstration.
         */
        if (
            classificationLevel(
                iterator->second.classification
            ) >= classificationLevel(
                Classification::Confidential
            )
            && !request.businessHours
        ) {
            audit(
                request.user.username,
                request.document.id,
                request.action,
                "DENIED_TIME_POLICY"
            );

            return std::nullopt;
        }

        /*
         * Cross-department access is restricted for high-classification
         * information. Real policies can be substantially more complex.
         */
        if (
            request.department
            != iterator->second.ownerDepartment
            && classificationLevel(
                iterator->second.classification
            ) >= classificationLevel(
                Classification::Confidential
            )
        ) {
            audit(
                request.user.username,
                request.document.id,
                request.action,
                "DENIED_DEPARTMENT"
            );

            return std::nullopt;
        }

        audit(
            request.user.username,
            request.document.id,
            request.action,
            "ALLOWED"
        );

        /*
         * The returned object is already limited to fields required by
         * this demonstration. A real system may apply stronger field-level
         * filtering depending on the caller's purpose.
         */
        return iterator->second;
    }

    std::string registerKey(
        const std::string& purpose
    ) {
        const std::vector<std::uint8_t> identifier =
            randomBytes(12);

        const std::string keyId = toHex(identifier);

        keys.emplace(
            keyId,
            KeyMetadata{
                keyId,
                purpose,
                1,
                "active",
                currentTimestamp()
            }
        );

        return keyId;
    }

    void rotateKey(const std::string& keyId) {
        auto iterator = keys.find(keyId);

        if (iterator == keys.end()) {
            throw std::out_of_range(
                "Unknown key ID."
            );
        }

        ++iterator->second.version;
        iterator->second.createdAt =
            currentTimestamp();
    }

    void revokeKey(const std::string& keyId) {
        auto iterator = keys.find(keyId);

        if (iterator == keys.end()) {
            throw std::out_of_range(
                "Unknown key ID."
            );
        }

        iterator->second.status = "revoked";
    }

    void printAuditLog() const {
        std::cout << "\nAudit log:\n";

        for (const AuditEvent& event : auditEvents) {
            std::cout
                << event.timestamp
                << " | "
                << event.username
                << " | "
                << event.documentId
                << " | "
                << event.action
                << " | "
                << event.result
                << "\n";
        }
    }

    void printKey(
        const std::string& keyId
    ) const {
        auto iterator = keys.find(keyId);

        if (iterator == keys.end()) {
            throw std::out_of_range(
                "Unknown key ID."
            );
        }

        const KeyMetadata& key = iterator->second;

        std::cout
            << "Key ID: " << key.keyId << "\n"
            << "Purpose: " << key.purpose << "\n"
            << "Version: " << key.version << "\n"
            << "Status: " << key.status << "\n"
            << "Created: " << key.createdAt << "\n";
    }
};


// ============================================================================
// 11. DATA MINIMIZATION
// ============================================================================

struct CustomerRecord {
    std::string customerId;
    std::string name;
    std::string shippingAddress;
    std::string orderId;
    std::string passportNumber;
    std::string bankAccount;
    std::string privateNotes;
};

struct ShippingView {
    std::string customerId;
    std::string name;
    std::string shippingAddress;
    std::string orderId;
};

ShippingView createShippingView(
    const CustomerRecord& record
) {
    /*
     * Sensitive fields are deliberately excluded because the shipping
     * workflow does not require them.
     */
    return ShippingView{
        record.customerId,
        record.name,
        record.shippingAddress,
        record.orderId
    };
}


// ============================================================================
// 12. SECURE COMPARISON
// ============================================================================

bool constantTimeEqual(
    const std::vector<std::uint8_t>& left,
    const std::vector<std::uint8_t>& right
) {
    /*
     * The comparison is structured to avoid early exit based on the first
     * differing byte. Compiler and hardware behavior can still complicate
     * rigorous constant-time guarantees, so production cryptographic code
     * should use a vetted implementation.
     */
    if (left.size() != right.size()) {
        return false;
    }

    std::uint8_t difference = 0;

    for (std::size_t i = 0; i < left.size(); ++i) {
        difference |= left[i] ^ right[i];
    }

    return difference == 0;
}


// ============================================================================
// 13. THREAT MODEL
// ============================================================================

struct Threat {
    std::string name;
    std::string asset;
    std::string vector;
    std::string impact;
    std::vector<std::string> controls;
};

void printThreatModel() {
    section("THREAT MODEL");

    const std::vector<Threat> threats{
        {
            "Stolen credentials",
            "Customer records",
            "Account compromise",
            "Unauthorized disclosure",
            {
                "MFA",
                "least privilege",
                "session controls",
                "monitoring"
            }
        },
        {
            "Lost device",
            "Local files",
            "Physical loss",
            "Offline disclosure",
            {
                "full-disk encryption",
                "device management",
                "screen lock"
            }
        },
        {
            "Storage misconfiguration",
            "Cloud backup",
            "Public exposure",
            "Bulk disclosure",
            {
                "private defaults",
                "policy validation",
                "access review"
            }
        }
    };

    for (const Threat& threat : threats) {
        std::cout << "\nThreat: " << threat.name << "\n";
        std::cout << "Asset: " << threat.asset << "\n";
        std::cout << "Vector: " << threat.vector << "\n";
        std::cout << "Impact: " << threat.impact << "\n";
        std::cout << "Controls: ";

        for (std::size_t i = 0; i < threat.controls.size(); ++i) {
            if (i > 0) {
                std::cout << ", ";
            }

            std::cout << threat.controls[i];
        }

        std::cout << "\n";
    }
}


// ============================================================================
// 14. ENCRYPTION CASE STUDY
// ============================================================================

void encryptionCaseStudy() {
    section("ENCRYPTION CASE STUDY");

    const std::string plaintext =
        "Confidential payroll record: employee compensation data";

    const std::vector<std::uint8_t> plaintextBytes =
        toBytes(plaintext);

    /*
     * The XOR construction is used only to expose the mechanics of a
     * reversible transformation. It is not suitable for production.
     */
    const std::vector<std::uint8_t> encryptionKey =
        randomBytes(32);

    const std::vector<std::uint8_t> authenticationKey =
        randomBytes(32);

    const std::vector<std::uint8_t> ciphertext =
        xorTransform(
            plaintextBytes,
            encryptionKey
        );

    const std::vector<std::uint8_t> tag =
        educationalAuthenticationTag(
            ciphertext,
            authenticationKey
        );

    std::cout
        << "Plaintext: "
        << plaintext
        << "\n";

    std::cout
        << "Ciphertext: "
        << toHex(ciphertext)
        << "\n";

    std::cout
        << "Authentication tag: "
        << toHex(tag)
        << "\n";

    const std::vector<std::uint8_t> expectedTag =
        educationalAuthenticationTag(
            ciphertext,
            authenticationKey
        );

    if (!constantTimeEqual(tag, expectedTag)) {
        throw std::runtime_error(
            "Authentication failed."
        );
    }

    const std::vector<std::uint8_t> recovered =
        xorTransform(
            ciphertext,
            encryptionKey
        );

    std::cout
        << "Recovered plaintext: "
        << toString(recovered)
        << "\n";

    /*
     * Tamper with the ciphertext.
     */
    std::vector<std::uint8_t> tampered = ciphertext;

    if (!tampered.empty()) {
        tampered[0] ^= 1;
    }

    const std::vector<std::uint8_t> tamperedTag =
        educationalAuthenticationTag(
            tampered,
            authenticationKey
        );

    const bool accepted =
        constantTimeEqual(
            tag,
            tamperedTag
        );

    std::cout
        << "Tampered ciphertext accepted: "
        << std::boolalpha
        << accepted
        << "\n";

    std::cout
        << "\nIn production, use a vetted AEAD implementation such as "
        << "AES-GCM or ChaCha20-Poly1305 rather than designing a custom "
        << "cryptographic construction.\n";
}


// ============================================================================
// 15. PERFORMANCE TEST
// ============================================================================

void performanceTest() {
    section("PERFORMANCE TEST");

    const std::size_t dataSize = 1024 * 1024;
    const std::vector<std::uint8_t> data =
        randomBytes(dataSize);

    const std::vector<std::uint8_t> key =
        randomBytes(32);

    constexpr int repetitions = 5;

    std::vector<double> durations;
    durations.reserve(repetitions);

    volatile std::uint8_t preventOptimization = 0;

    for (int i = 0; i < repetitions; ++i) {
        const auto start =
            std::chrono::high_resolution_clock::now();

        const std::vector<std::uint8_t> result =
            xorTransform(
                data,
                key
            );

        preventOptimization ^= result[0];

        const auto end =
            std::chrono::high_resolution_clock::now();

        const std::chrono::duration<double, std::milli>
            elapsed = end - start;

        durations.push_back(
            elapsed.count()
        );
    }

    double total = 0.0;

    for (double duration : durations) {
        total += duration;
    }

    std::cout
        << "Processed "
        << dataSize
        << " bytes.\n";

    std::cout
        << "Average transformation time: "
        << total / durations.size()
        << " ms\n";

    std::cout
        << "Optimization guard: "
        << static_cast<int>(preventOptimization)
        << "\n";
}


// ============================================================================
// 16. TEST SUITE
// ============================================================================

void runTests() {
    section("AUTOMATED TESTS");

    {
        const std::vector<std::uint8_t> message =
            toBytes("secret");

        const std::vector<std::uint8_t> key =
            toBytes("key");

        const auto encrypted =
            xorTransform(message, key);

        const auto recovered =
            xorTransform(encrypted, key);

        if (recovered != message) {
            throw std::runtime_error(
                "Encryption round-trip test failed."
            );
        }
    }

    {
        const std::vector<std::uint8_t> left{
            1, 2, 3, 4
        };

        const std::vector<std::uint8_t> same{
            1, 2, 3, 4
        };

        const std::vector<std::uint8_t> different{
            1, 2, 3, 5
        };

        if (!constantTimeEqual(left, same)) {
            throw std::runtime_error(
                "Equal secret comparison failed."
            );
        }

        if (constantTimeEqual(left, different)) {
            throw std::runtime_error(
                "Different secret comparison failed."
            );
        }
    }

    {
        ConfidentialityService service;

        service.addDocument(
            ConfidentialDocument{
                "DOC-1",
                "security",
                Classification::Confidential,
                "Protected security report."
            }
        );

        User authorized{
            "analyst",
            {"security_analyst"},
            2
        };

        AccessRequest request{
            authorized,
            service
                .getDocument(
                    AccessRequest{
                        authorized,
                        ConfidentialDocument{
                            "DOC-1",
                            "security",
                            Classification::Confidential,
                            "Protected security report."
                        },
                        "read",
                        "security",
                        true
                    },
                    {"security_analyst"}
                )
                .value_or(
                    ConfidentialDocument{
                        "DOC-1",
                        "security",
                        Classification::Confidential,
                        "Protected security report."
                    }
                ),
            "read",
            "security",
            true
        };

        auto result =
            service.getDocument(
                request,
                {"security_analyst"}
            );

        if (!result.has_value()) {
            throw std::runtime_error(
                "Authorized document access failed."
            );
        }
    }

    std::cout << "All tests passed.\n";
}


// ============================================================================
// 17. END-TO-END DEMONSTRATION
// ============================================================================

void endToEndCaseStudy() {
    section("END-TO-END CONFIDENTIAL DOCUMENT SYSTEM");

    ConfidentialityService service;

    service.addDocument(
        ConfidentialDocument{
            "CASE-001",
            "security",
            Classification::Confidential,
            "Incident investigation evidence."
        }
    );

    service.addDocument(
        ConfidentialDocument{
            "PUBLIC-001",
            "communications",
            Classification::Public,
            "Public corporate announcement."
        }
    );

    User securityAnalyst{
        "security-analyst",
        {"security_analyst"},
        2
    };

    User marketingUser{
        "marketing-user",
        {"marketing"},
        1
    };

    const std::set<std::string> securityRoles{
        "security_analyst",
        "security_manager"
    };

    /*
     * Authorized access.
     */
    AccessRequest authorizedRequest{
        securityAnalyst,
        service
            .getDocument(
                AccessRequest{
                    securityAnalyst,
                    ConfidentialDocument{
                        "CASE-001",
                        "security",
                        Classification::Confidential,
                        "Incident investigation evidence."
                    },
                    "read",
                    "security",
                    true
                },
                securityRoles
            )
            .value_or(
                ConfidentialDocument{
                    "CASE-001",
                    "security",
                    Classification::Confidential,
                    "Incident investigation evidence."
                }
            ),
        "read",
        "security",
        true
    };

    auto authorized =
        service.getDocument(
            authorizedRequest,
            securityRoles
        );

    if (authorized.has_value()) {
        std::cout
            << "Authorized access succeeded.\n"
            << "Document classification: "
            << classificationName(
                authorized->classification
            )
            << "\n";
    }

    /*
     * Unauthorized access because the marketing user has no approved role.
     */
    AccessRequest unauthorizedRequest{
        marketingUser,
        ConfidentialDocument{
            "CASE-001",
            "security",
            Classification::Confidential,
            "Incident investigation evidence."
        },
        "read",
        "marketing",
        true
    };

    auto unauthorized =
        service.getDocument(
            unauthorizedRequest,
            securityRoles
        );

    std::cout
        << "Unauthorized access result: "
        << std::boolalpha
        << unauthorized.has_value()
        << "\n";

    service.printAuditLog();
}


// ============================================================================
// 18. MAIN
// ============================================================================

int main() {
    try {
        section("CONFIDENTIALITY: C++ TECHNICAL CASE STUDY");

        std::cout
            << "Confidentiality means preventing unauthorized disclosure "
            << "of information.\n";

        std::cout
            << "This case study combines classification, authorization, "
            << "least privilege, encryption concepts, audit logging, "
            << "minimization, and testing.\n";

        section("INFORMATION CLASSIFICATION");

        const std::vector<Classification> classifications{
            Classification::Public,
            Classification::Internal,
            Classification::Confidential,
            Classification::Restricted
        };

        for (Classification classification : classifications) {
            std::cout
                << static_cast<int>(
                    classification
                )
                << " -> "
                << classificationName(
                    classification
                )
                << "\n";
        }

        section("DATA MINIMIZATION");

        CustomerRecord customer{
            "C-1001",
            "Example Customer",
            "100 Example Street",
            "O-2001",
            "SENSITIVE-PASSPORT",
            "SENSITIVE-BANK-DATA",
            "SENSITIVE-INTERNAL-NOTES"
        };

        const ShippingView shippingView =
            createShippingView(customer);

        std::cout
            << "Shipping workflow fields:\n"
            << "Customer ID: "
            << shippingView.customerId
            << "\n"
            << "Name: "
            << shippingView.name
            << "\n"
            << "Address: "
            << shippingView.shippingAddress
            << "\n"
            << "Order ID: "
            << shippingView.orderId
            << "\n";

        printThreatModel();
        encryptionCaseStudy();

        section("KEY LIFECYCLE");

        ConfidentialityService keyService;

        const std::string keyId =
            keyService.registerKey(
                "confidential document encryption"
            );

        keyService.printKey(keyId);

        keyService.rotateKey(keyId);
        std::cout << "\nAfter rotation:\n";
        keyService.printKey(keyId);

        keyService.revokeKey(keyId);
        std::cout << "\nAfter revocation:\n";
        keyService.printKey(keyId);

        endToEndCaseStudy();
        runTests();
        performanceTest();

        section("DESIGN CHECKLIST");

        const std::vector<std::string> checklist{
            "Classify sensitive information.",
            "Identify authorized users and services.",
            "Authenticate identities.",
            "Authorize every protected operation.",
            "Apply least privilege.",
            "Encrypt sensitive data where appropriate.",
            "Use authenticated encryption in production.",
            "Protect encryption keys independently.",
            "Use secure random generation for secrets.",
            "Never log passwords or cryptographic keys.",
            "Minimize data collection and exposure.",
            "Protect backups and replicas.",
            "Control retention and disposal.",
            "Review permissions regularly.",
            "Test denied access paths.",
            "Avoid sensitive information in errors.",
            "Consider metadata and side channels.",
            "Plan key rotation and revocation.",
            "Maintain auditable security events."
        };

        for (std::size_t i = 0; i < checklist.size(); ++i) {
            std::cout
                << std::setw(2)
                << (i + 1)
                << ". "
                << checklist[i]
                << "\n";
        }

        section("CASE STUDY COMPLETE");

        return 0;
    }
    catch (const std::exception& exception) {
        std::cerr
            << "Fatal error: "
            << exception.what()
            << "\n";

        return 1;
    }
}
