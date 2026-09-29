/*
 * Non-Repudiation: C++17 Industry-Style Case Study
 *
 * Scenario:
 * A financial organization operates a contract-approval service. Authorized
 * employees approve high-value contracts. The organization must preserve
 * evidence showing what was approved, by whom, when, and whether the record
 * was altered after signing.
 *
 * This program models:
 *   - canonical record construction
 *   - hashing
 *   - a simulated digital-signature interface
 *   - signed evidence records
 *   - an append-only hash chain
 *   - key lifecycle state
 *   - replay protection
 *   - audit events
 *   - timestamp evidence
 *   - verification reports
 *   - tamper detection
 *
 * Important:
 * The standard C++ library does not provide a production cryptographic
 * signature implementation. The educational signature mechanism below uses
 * deterministic hashing to model the API and verification flow. Production
 * systems must use a reviewed cryptographic library and standardized
 * algorithms such as Ed25519, ECDSA, or RSA-PSS.
 *
 * Compile:
 *   g++ -std=c++17 -O2 -Wall -Wextra -pedantic non_repudiation.cpp -o non_repudiation
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
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

namespace nr {

// -----------------------------------------------------------------------------
// 1. Utility functions
// -----------------------------------------------------------------------------

std::string toHex(std::uint64_t value) {
    std::ostringstream output;
    output << std::hex << std::setw(16) << std::setfill('0') << value;
    return output.str();
}

/*
 * This is an educational deterministic digest, not a cryptographic hash.
 *
 * The purpose is to make the case study completely standard-library-only.
 * Production software must replace it with a real SHA-256 or equivalent
 * implementation from a security-reviewed cryptographic library.
 */
std::string educationalHash(const std::string& input) {
    std::uint64_t h1 = 1469598103934665603ULL;
    std::uint64_t h2 = 1099511628211ULL;

    for (unsigned char character : input) {
        h1 ^= character;
        h1 *= 1099511628211ULL;

        h2 ^= static_cast<std::uint64_t>(character + 17);
        h2 *= 14029467366897019727ULL;
        h2 ^= (h2 >> 29);
    }

    return toHex(h1) + toHex(h2);
}

std::string currentTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const auto seconds =
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()
        ).count();

    return std::to_string(seconds);
}

std::string generateId(const std::string& prefix) {
    static std::uint64_t counter = 1000;
    return prefix + "-" + std::to_string(counter++);
}

// -----------------------------------------------------------------------------
// 2. Business document
// -----------------------------------------------------------------------------

struct Contract {
    std::string contractId;
    int version{};
    std::string vendor;
    long long amount{};
    std::string currency;
    std::string decision;

    /*
     * Deterministic serialization is critical. The exact representation
     * becomes part of the signed evidence.
     */
    std::string canonical() const {
        return
            "contractId=" + contractId +
            "|version=" + std::to_string(version) +
            "|vendor=" + vendor +
            "|amount=" + std::to_string(amount) +
            "|currency=" + currency +
            "|decision=" + decision;
    }
};

// -----------------------------------------------------------------------------
// 3. Key lifecycle
// -----------------------------------------------------------------------------

enum class KeyState {
    ACTIVE,
    EXPIRED,
    REVOKED
};

std::string keyStateToString(KeyState state) {
    switch (state) {
        case KeyState::ACTIVE:
            return "ACTIVE";
        case KeyState::EXPIRED:
            return "EXPIRED";
        case KeyState::REVOKED:
            return "REVOKED";
    }

    return "UNKNOWN";
}

struct SigningKey {
    std::string keyId;
    std::string owner;
    KeyState state{KeyState::ACTIVE};
    std::string createdAt;
};

class KeyRegistry {
private:
    std::unordered_map<std::string, SigningKey> keys;

public:
    SigningKey createKey(const std::string& owner) {
        SigningKey key;
        key.keyId = generateId("KEY");
        key.owner = owner;
        key.state = KeyState::ACTIVE;
        key.createdAt = currentTimestamp();

        keys.emplace(key.keyId, key);
        return key;
    }

    void revoke(const std::string& keyId) {
        auto iterator = keys.find(keyId);

        if (iterator == keys.end()) {
            throw std::runtime_error("Unknown key.");
        }

        iterator->second.state = KeyState::REVOKED;
    }

    bool canSign(const std::string& keyId) const {
        auto iterator = keys.find(keyId);

        if (iterator == keys.end()) {
            return false;
        }

        return iterator->second.state == KeyState::ACTIVE;
    }

    const SigningKey& get(const std::string& keyId) const {
        auto iterator = keys.find(keyId);

        if (iterator == keys.end()) {
            throw std::runtime_error("Unknown key.");
        }

        return iterator->second;
    }
};

// -----------------------------------------------------------------------------
// 4. Educational signature service
// -----------------------------------------------------------------------------

class SignatureService {
private:
    /*
     * In a real implementation, this would be a private asymmetric signing
     * key stored inside a protected key-management system or HSM.
     */
    std::string privateSigningMaterial;

public:
    explicit SignatureService(std::string privateMaterial)
        : privateSigningMaterial(std::move(privateMaterial)) {}

    std::string sign(const std::string& message) const {
        return educationalHash(privateSigningMaterial + "|" + message);
    }

    bool verify(
        const std::string& message,
        const std::string& signature
    ) const {
        /*
         * The case study models a public verification operation. The
         * implementation is deliberately educational rather than secure.
         */
        return sign(message) == signature;
    }
};

// -----------------------------------------------------------------------------
// 5. Signed evidence record
// -----------------------------------------------------------------------------

struct EvidenceRecord {
    std::string recordId;
    std::string signerId;
    std::string keyId;
    std::string eventType;
    std::string payload;
    std::string payloadHash;
    std::string createdAt;
    std::size_t sequenceNumber{};
    std::optional<std::string> previousRecordHash;
    std::string signature;

    std::string unsignedCanonical() const {
        std::string previous =
            previousRecordHash.has_value()
                ? *previousRecordHash
                : "<GENESIS>";

        return
            "recordId=" + recordId +
            "|signerId=" + signerId +
            "|keyId=" + keyId +
            "|eventType=" + eventType +
            "|payload=" + payload +
            "|payloadHash=" + payloadHash +
            "|createdAt=" + createdAt +
            "|sequence=" + std::to_string(sequenceNumber) +
            "|previous=" + previous;
    }
};

// -----------------------------------------------------------------------------
// 6. Evidence ledger
// -----------------------------------------------------------------------------

struct VerificationResult {
    bool valid{};
    std::string reason;
};

class EvidenceLedger {
private:
    std::vector<EvidenceRecord> records;
    const SignatureService& signatureService;

public:
    explicit EvidenceLedger(const SignatureService& service)
        : signatureService(service) {}

    EvidenceRecord append(
        const std::string& signerId,
        const std::string& keyId,
        const std::string& eventType,
        const std::string& payload
    ) {
        EvidenceRecord record;

        record.recordId = generateId("REC");
        record.signerId = signerId;
        record.keyId = keyId;
        record.eventType = eventType;
        record.payload = payload;
        record.payloadHash = educationalHash(payload);
        record.createdAt = currentTimestamp();
        record.sequenceNumber = records.size() + 1;

        if (!records.empty()) {
            record.previousRecordHash =
                educationalHash(records.back().unsignedCanonical());
        }

        record.signature =
            signatureService.sign(record.unsignedCanonical());

        records.push_back(record);
        return record;
    }

    VerificationResult verifyRecord(
        const EvidenceRecord& record
    ) const {
        const std::string calculatedPayloadHash =
            educationalHash(record.payload);

        if (calculatedPayloadHash != record.payloadHash) {
            return {
                false,
                "Payload hash mismatch."
            };
        }

        if (!signatureService.verify(
                record.unsignedCanonical(),
                record.signature)) {
            return {
                false,
                "Signature verification failed."
            };
        }

        return {
            true,
            "Record signature and payload integrity are valid."
        };
    }

    std::vector<VerificationResult> verifyChain() const {
        std::vector<VerificationResult> results;

        for (std::size_t index = 0; index < records.size(); ++index) {
            VerificationResult result =
                verifyRecord(records[index]);

            if (!result.valid) {
                results.push_back(result);
                continue;
            }

            if (index == 0) {
                if (records[index].previousRecordHash.has_value()) {
                    results.push_back({
                        false,
                        "Genesis record has a predecessor."
                    });
                } else {
                    results.push_back({
                        true,
                        "Genesis record is valid."
                    });
                }

                continue;
            }

            const std::string expectedPrevious =
                educationalHash(
                    records[index - 1].unsignedCanonical()
                );

            if (
                !records[index].previousRecordHash.has_value() ||
                records[index].previousRecordHash.value() != expectedPrevious
            ) {
                results.push_back({
                    false,
                    "Previous-record hash mismatch."
                });
            } else {
                results.push_back({
                    true,
                    "Chain link is valid."
                });
            }
        }

        return results;
    }

    EvidenceRecord& at(std::size_t index) {
        if (index >= records.size()) {
            throw std::out_of_range("Evidence record index out of range.");
        }

        return records[index];
    }

    const EvidenceRecord& at(std::size_t index) const {
        if (index >= records.size()) {
            throw std::out_of_range("Evidence record index out of range.");
        }

        return records[index];
    }

    std::size_t size() const {
        return records.size();
    }
};

// -----------------------------------------------------------------------------
// 7. Replay protection
// -----------------------------------------------------------------------------

struct SignedRequest {
    std::string requestId;
    std::string nonce;
    long long issuedAt{};
    long long expiresAt{};
    std::string operation;
};

class ReplayGuard {
private:
    std::set<std::string> usedNonces;

public:
    VerificationResult validate(
        const SignedRequest& request,
        long long currentTime
    ) {
        if (usedNonces.find(request.nonce) != usedNonces.end()) {
            return {
                false,
                "Replay detected: nonce was already consumed."
            };
        }

        if (request.expiresAt <= request.issuedAt) {
            return {
                false,
                "Invalid request lifetime."
            };
        }

        if (request.expiresAt < currentTime) {
            return {
                false,
                "Request has expired."
            };
        }

        if (request.issuedAt > currentTime + 60) {
            return {
                false,
                "Request timestamp is too far in the future."
            };
        }

        usedNonces.insert(request.nonce);

        return {
            true,
            "Request freshness checks passed."
        };
    }
};

// -----------------------------------------------------------------------------
// 8. Audit events
// -----------------------------------------------------------------------------

struct AuditEvent {
    std::string eventId;
    std::string actor;
    std::string action;
    std::string resource;
    std::string timestamp;
    std::string result;
    std::string evidenceHash;
};

class AuditLog {
private:
    std::vector<AuditEvent> events;

public:
    void append(
        const std::string& actor,
        const std::string& action,
        const std::string& resource,
        const std::string& result,
        const std::string& evidence
    ) {
        AuditEvent event;

        event.eventId = generateId("AUDIT");
        event.actor = actor;
        event.action = action;
        event.resource = resource;
        event.timestamp = currentTimestamp();
        event.result = result;
        event.evidenceHash = educationalHash(evidence);

        events.push_back(event);
    }

    const std::vector<AuditEvent>& all() const {
        return events;
    }
};

// -----------------------------------------------------------------------------
// 9. Timestamp evidence
// -----------------------------------------------------------------------------

struct TimestampEvidence {
    std::string recordHash;
    std::string timestamp;
    std::string authority;
    std::string authorityToken;
};

TimestampEvidence createTimestampEvidence(
    const EvidenceRecord& record
) {
    TimestampEvidence evidence;

    evidence.recordHash =
        educationalHash(record.unsignedCanonical());

    evidence.timestamp = currentTimestamp();
    evidence.authority = "Example Trusted Timestamp Authority";

    /*
     * This token is only a simulation. A production timestamp authority
     * would sign a standardized timestamp token with an independently
     * protected authority key.
     */
    evidence.authorityToken =
        educationalHash(
            evidence.recordHash +
            "|" +
            evidence.timestamp +
            "|" +
            evidence.authority
        );

    return evidence;
}

// -----------------------------------------------------------------------------
// 10. Reporting
// -----------------------------------------------------------------------------

void printRecord(const EvidenceRecord& record) {
    std::cout << "Record ID:       " << record.recordId << "\n";
    std::cout << "Signer ID:       " << record.signerId << "\n";
    std::cout << "Key ID:          " << record.keyId << "\n";
    std::cout << "Event:           " << record.eventType << "\n";
    std::cout << "Payload:         " << record.payload << "\n";
    std::cout << "Payload hash:    " << record.payloadHash << "\n";
    std::cout << "Created at:      " << record.createdAt << "\n";
    std::cout << "Sequence:        " << record.sequenceNumber << "\n";
    std::cout << "Signature:       " << record.signature << "\n";

    if (record.previousRecordHash.has_value()) {
        std::cout
            << "Previous hash:   "
            << record.previousRecordHash.value()
            << "\n";
    } else {
        std::cout << "Previous hash:   <GENESIS>\n";
    }
}

void printVerificationReport(
    const EvidenceLedger& ledger
) {
    std::cout << "\nVerification report\n";
    std::cout << "-------------------\n";

    const auto results = ledger.verifyChain();

    std::size_t validCount = 0;

    for (std::size_t index = 0; index < results.size(); ++index) {
        std::cout
            << "Record "
            << index + 1
            << ": "
            << (results[index].valid ? "VALID" : "INVALID")
            << " - "
            << results[index].reason
            << "\n";

        if (results[index].valid) {
            ++validCount;
        }
    }

    std::cout
        << "Valid records: "
        << validCount
        << "/"
        << results.size()
        << "\n";
}

// -----------------------------------------------------------------------------
// 11. Tampering demonstration
// -----------------------------------------------------------------------------

void demonstrateTampering(
    EvidenceLedger& ledger
) {
    std::cout << "\nTampering demonstration\n";
    std::cout << "-----------------------\n";

    EvidenceRecord& record = ledger.at(0);

    const std::string originalPayload = record.payload;

    record.payload =
        "contractId=CONTRACT-2026-0042|version=7|vendor=ACME|amount=999999999|currency=INR|decision=APPROVED";

    const VerificationResult result =
        ledger.verifyRecord(record);

    std::cout
        << "After payload modification: "
        << (result.valid ? "VALID" : "INVALID")
        << "\nReason: "
        << result.reason
        << "\n";

    /*
     * Restore the evidence so the remaining demonstrations operate on a
     * legitimate record set.
     */
    record.payload = originalPayload;
}

// -----------------------------------------------------------------------------
// 12. Unit-style assertions
// -----------------------------------------------------------------------------

void runTests(
    const SignatureService& signatureService,
    const EvidenceLedger& ledger
) {
    std::cout << "\nSelf-tests\n";
    std::cout << "----------\n";

    const std::string message = "test-message";
    const std::string signature =
        signatureService.sign(message);

    if (!signatureService.verify(message, signature)) {
        throw std::runtime_error(
            "Valid signature verification test failed."
        );
    }

    if (signatureService.verify(
            "modified-message",
            signature)) {
        throw std::runtime_error(
            "Modified message incorrectly verified."
        );
    }

    for (const auto& result : ledger.verifyChain()) {
        if (!result.valid) {
            throw std::runtime_error(
                "Initial evidence chain should be valid."
            );
        }
    }

    std::cout << "All signature and chain tests passed.\n";
}

// -----------------------------------------------------------------------------
// 13. Main industry scenario
// -----------------------------------------------------------------------------

int runCaseStudy() {
    std::cout
        << "NON-REPUDIATION: C++ INDUSTRY CASE STUDY\n"
        << "Contract approval evidence system\n";

    // Step 1: establish a signer and a key registry.
    KeyRegistry keyRegistry;

    SigningKey signingKey =
        keyRegistry.createKey("alice@example.test");

    std::cout
        << "\nSigning key created: "
        << signingKey.keyId
        << " ("
        << keyStateToString(signingKey.state)
        << ")\n";

    if (!keyRegistry.canSign(signingKey.keyId)) {
        throw std::runtime_error(
            "New signing key unexpectedly unavailable."
        );
    }

    // Step 2: create the signature service.
    SignatureService signatureService(
        "EDUCATIONAL-PRIVATE-SIGNING-MATERIAL"
    );

    // Step 3: initialize the evidence ledger.
    EvidenceLedger ledger(signatureService);

    // Step 4: construct a business document.
    Contract contract{
        "CONTRACT-2026-0042",
        7,
        "ACME-SUPPLIER",
        1250000,
        "INR",
        "APPROVED"
    };

    /*
     * The payload contains the business facts that matter to the approval.
     * A real system would use a formal schema and deterministic canonical
     * serialization format.
     */
    const std::string payload = contract.canonical();

    // Step 5: sign and append the approval event.
    EvidenceRecord approval = ledger.append(
        "alice@example.test",
        signingKey.keyId,
        "CONTRACT_APPROVAL",
        payload
    );

    std::cout << "\nCreated approval evidence:\n";
    printRecord(approval);

    // Step 6: add a timestamp evidence record.
    TimestampEvidence timestamp =
        createTimestampEvidence(approval);

    std::cout << "\nTimestamp evidence:\n";
    std::cout << "Record hash:     "
              << timestamp.recordHash << "\n";
    std::cout << "Timestamp:       "
              << timestamp.timestamp << "\n";
    std::cout << "Authority:       "
              << timestamp.authority << "\n";
    std::cout << "Authority token: "
              << timestamp.authorityToken << "\n";

    // Step 7: write audit evidence.
    AuditLog audit;

    audit.append(
        "alice@example.test",
        "SIGN",
        contract.contractId,
        "SUCCESS",
        approval.unsignedCanonical()
    );

    audit.append(
        "verification-service",
        "VERIFY",
        contract.contractId,
        "SUCCESS",
        approval.signature
    );

    std::cout << "\nAudit events: "
              << audit.all().size()
              << "\n";

    // Step 8: verify the complete evidence chain.
    printVerificationReport(ledger);

    // Step 9: demonstrate that modification is detected.
    demonstrateTampering(ledger);

    // Step 10: replay protection.
    std::cout << "\nReplay protection\n";
    std::cout << "------------------\n";

    ReplayGuard replayGuard;

    const long long currentTime =
        std::stoll(currentTimestamp());

    SignedRequest request{
        generateId("REQ"),
        "NONCE-001",
        currentTime,
        currentTime + 300,
        "RELEASE_PAYMENT"
    };

    VerificationResult firstRequest =
        replayGuard.validate(request, currentTime);

    VerificationResult replay =
        replayGuard.validate(request, currentTime);

    std::cout
        << "First submission: "
        << (firstRequest.valid ? "ACCEPTED" : "REJECTED")
        << " - "
        << firstRequest.reason
        << "\n";

    std::cout
        << "Replay submission: "
        << (replay.valid ? "ACCEPTED" : "REJECTED")
        << " - "
        << replay.reason
        << "\n";

    // Step 11: demonstrate key revocation.
    std::cout << "\nKey lifecycle\n";
    std::cout << "-------------\n";

    keyRegistry.revoke(signingKey.keyId);

    std::cout
        << "Key "
        << signingKey.keyId
        << " state after revocation: "
        << keyStateToString(
            keyRegistry.get(signingKey.keyId).state
        )
        << "\n";

    /*
     * Existing signatures should not simply disappear when a key is revoked.
     * Historical verification requires a policy describing whether the key
     * was valid at the signing time and what evidence establishes that fact.
     */
    std::cout
        << "Historical evidence remains stored separately from current "
        << "key activation state.\n";

    // Step 12: self-tests.
    runTests(signatureService, ledger);

    return 0;
}

} // namespace nr

int main() {
    try {
        return nr::runCaseStudy();
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
