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
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

/*
 * Security Governance and Transaction Authorization Case Study
 *
 * Scenario:
 * A financial operations repository contains an internal service that
 * receives requests to create controlled reports and transaction records.
 * The service must protect sensitive data and operations against:
 *
 * - unauthorized access
 * - privilege escalation
 * - malformed input
 * - replayed requests
 * - message tampering
 * - excessive requests
 * - inadequate auditability
 *
 * This C++17 program models a defense-in-depth security engine.
 *
 * The cryptographic routines here are deliberately educational. A real
 * production system should use a vetted cryptographic library rather than
 * treating this compact implementation as a replacement for established
 * cryptographic primitives.
 */

namespace security_case_study {

/* -------------------------------------------------------------------------
 * Basic data structures
 * ------------------------------------------------------------------------- */

enum class RiskLevel {
    Low,
    Medium,
    High,
    Critical
};

std::string to_string(RiskLevel level) {
    switch (level) {
        case RiskLevel::Low:
            return "low";
        case RiskLevel::Medium:
            return "medium";
        case RiskLevel::High:
            return "high";
        case RiskLevel::Critical:
            return "critical";
    }

    return "unknown";
}

struct SecurityThreat {
    std::string name;
    std::string asset;
    std::string attack_surface;
    RiskLevel impact;
    RiskLevel likelihood;
    std::vector<std::string> controls;
};

struct User {
    std::string username;
    std::set<std::string> roles;
    bool active{true};
};

struct SecurityEvent {
    std::uint64_t timestamp;
    std::string type;
    std::string actor;
    std::string outcome;
    std::string resource;
    std::string detail;
};


/* -------------------------------------------------------------------------
 * Random identifier generation
 * ------------------------------------------------------------------------- */

class SecureIdentifierGenerator {
public:
    std::string generate(std::size_t length = 32) {
        /*
         * std::random_device is used here to obtain entropy from the host
         * implementation. Production applications should use an OS-specific
         * CSPRNG or a mature cryptographic library when identifier security
         * is critical.
         */
        std::random_device random_source;
        std::uniform_int_distribution<int> distribution(0, 15);

        std::ostringstream output;

        for (std::size_t index = 0; index < length; ++index) {
            output << std::hex << distribution(random_source);
        }

        return output.str();
    }
};


/* -------------------------------------------------------------------------
 * Input validation
 * ------------------------------------------------------------------------- */

class SecurityValidationError : public std::runtime_error {
public:
    explicit SecurityValidationError(const std::string& message)
        : std::runtime_error(message) {}
};

class InputValidator {
public:
    static std::string username(std::string_view value) {
        if (value.size() < 3 || value.size() > 32) {
            throw SecurityValidationError(
                "username length outside security policy"
            );
        }

        for (char character : value) {
            const bool allowed =
                (character >= 'a' && character <= 'z') ||
                (character >= 'A' && character <= 'Z') ||
                (character >= '0' && character <= '9') ||
                character == '.' ||
                character == '_' ||
                character == '-';

            if (!allowed) {
                throw SecurityValidationError(
                    "username contains unsupported character"
                );
            }
        }

        return std::string(value);
    }

    static std::int64_t amount(std::int64_t value) {
        if (value < 1 || value > 1'000'000) {
            throw SecurityValidationError(
                "amount outside transaction boundary"
            );
        }

        return value;
    }
};


/* -------------------------------------------------------------------------
 * Authorization and least privilege
 * ------------------------------------------------------------------------- */

class AuthorizationPolicy {
private:
    std::unordered_map<std::string, std::set<std::string>> role_permissions{
        {
            "viewer",
            {"read:reports"}
        },
        {
            "analyst",
            {"read:reports", "create:reports"}
        },
        {
            "administrator",
            {
                "read:reports",
                "create:reports",
                "delete:reports",
                "manage:users"
            }
        }
    };

public:
    bool allowed(
        const User& user,
        const std::string& permission
    ) const {
        if (!user.active) {
            return false;
        }

        /*
         * Authorization is evaluated at the operation boundary. Possessing
         * a valid identity is not equivalent to possessing permission for
         * every action.
         */
        for (const auto& role : user.roles) {
            const auto role_iterator = role_permissions.find(role);

            if (role_iterator == role_permissions.end()) {
                continue;
            }

            if (
                role_iterator->second.find(permission) !=
                role_iterator->second.end()
            ) {
                return true;
            }
        }

        return false;
    }
};


/* -------------------------------------------------------------------------
 * Sliding-window rate limiter
 * ------------------------------------------------------------------------- */

class RateLimiter {
private:
    std::size_t maximum_requests;
    std::uint64_t window_seconds;

    std::unordered_map<
        std::string,
        std::vector<std::uint64_t>
    > request_times;

public:
    RateLimiter(
        std::size_t maximum_requests,
        std::uint64_t window_seconds
    )
        : maximum_requests(maximum_requests),
          window_seconds(window_seconds) {
        if (maximum_requests == 0 || window_seconds == 0) {
            throw std::invalid_argument(
                "rate limiter values must be positive"
            );
        }
    }

    bool allow(
        const std::string& identity,
        std::uint64_t now
    ) {
        auto& timestamps = request_times[identity];

        const std::uint64_t cutoff =
            now > window_seconds
                ? now - window_seconds
                : 0;

        timestamps.erase(
            std::remove_if(
                timestamps.begin(),
                timestamps.end(),
                [cutoff](std::uint64_t timestamp) {
                    return timestamp <= cutoff;
                }
            ),
            timestamps.end()
        );

        if (timestamps.size() >= maximum_requests) {
            return false;
        }

        timestamps.push_back(now);
        return true;
    }
};


/* -------------------------------------------------------------------------
 * Replay protection
 * ------------------------------------------------------------------------- */

class ReplayGuard {
private:
    std::uint64_t maximum_age_seconds;
    std::unordered_set<std::string> consumed_nonces;

public:
    explicit ReplayGuard(std::uint64_t maximum_age_seconds)
        : maximum_age_seconds(maximum_age_seconds) {}

    bool accept(
        const std::string& nonce,
        std::uint64_t timestamp,
        std::uint64_t now
    ) {
        /*
         * A nonce must be unique and the timestamp must be close enough to
         * the receiver's clock. Both controls are needed because a timestamp
         * alone does not prevent two valid requests from being submitted
         * repeatedly within the accepted time window.
         */
        const std::uint64_t age =
            now >= timestamp ? now - timestamp : timestamp - now;

        if (age > maximum_age_seconds) {
            return false;
        }

        if (consumed_nonces.find(nonce) != consumed_nonces.end()) {
            return false;
        }

        consumed_nonces.insert(nonce);
        return true;
    }
};


/* -------------------------------------------------------------------------
 * Educational integrity authenticator
 * ------------------------------------------------------------------------- */

class IntegrityAuthenticator {
private:
    std::string secret;

    static std::uint64_t fnv1a(
        std::string_view input,
        std::uint64_t seed
    ) {
        std::uint64_t hash = seed;

        for (unsigned char character : input) {
            hash ^= character;
            hash *= 1099511628211ULL;
        }

        return hash;
    }

public:
    explicit IntegrityAuthenticator(std::string secret)
        : secret(std::move(secret)) {
        if (this->secret.size() < 32) {
            throw std::invalid_argument(
                "integrity key must contain at least 32 characters"
            );
        }
    }

    std::string sign(std::string_view payload) const {
        /*
         * This is only a deterministic integrity demonstration. FNV-1a is
         * NOT a cryptographic MAC. Production systems should use HMAC,
         * authenticated encryption, or another vetted construction.
         */
        const std::uint64_t first =
            fnv1a(secret + std::string(payload), 1469598103934665603ULL);

        const std::uint64_t second =
            fnv1a(std::string(payload) + secret, 1099511628211ULL);

        std::ostringstream result;
        result << std::hex
               << std::setw(16) << std::setfill('0') << first
               << std::setw(16) << std::setfill('0') << second;

        return result.str();
    }

    bool verify(
        std::string_view payload,
        std::string_view supplied_signature
    ) const {
        const std::string expected = sign(payload);

        /*
         * Production cryptographic comparison should use a constant-time
         * primitive supplied by the cryptographic library.
         */
        if (expected.size() != supplied_signature.size()) {
            return false;
        }

        unsigned char difference = 0;

        for (std::size_t index = 0; index < expected.size(); ++index) {
            difference |= static_cast<unsigned char>(
                expected[index] ^ supplied_signature[index]
            );
        }

        return difference == 0;
    }
};


/* -------------------------------------------------------------------------
 * Audit logging
 * ------------------------------------------------------------------------- */

class AuditLogger {
private:
    std::vector<SecurityEvent> events;

public:
    void record(SecurityEvent event) {
        if (
            event.type.empty() ||
            event.actor.empty() ||
            event.outcome.empty()
        ) {
            throw SecurityValidationError(
                "audit event lacks mandatory fields"
            );
        }

        events.push_back(std::move(event));
    }

    void print() const {
        for (const auto& event : events) {
            std::cout
                << "  ["
                << event.timestamp
                << "] "
                << event.type
                << " actor="
                << event.actor
                << " outcome="
                << event.outcome
                << " resource="
                << event.resource
                << " detail="
                << event.detail
                << '\n';
        }
    }

    std::size_t size() const {
        return events.size();
    }
};


/* -------------------------------------------------------------------------
 * Secure transaction request
 * ------------------------------------------------------------------------- */

struct TransactionRequest {
    User actor;
    std::string destination;
    std::int64_t amount;
    std::string nonce;
    std::uint64_t timestamp;
    std::string payload;
    std::string signature;
};


/* -------------------------------------------------------------------------
 * Security engine
 * ------------------------------------------------------------------------- */

class SecurityEngine {
private:
    AuthorizationPolicy authorization;
    RateLimiter rate_limiter;
    ReplayGuard replay_guard;
    IntegrityAuthenticator integrity;
    AuditLogger audit;

public:
    explicit SecurityEngine(std::string integrity_key)
        : rate_limiter(3, 60),
          replay_guard(300),
          integrity(std::move(integrity_key)) {}

    std::string process(
        const TransactionRequest& request,
        std::uint64_t now
    ) {
        /*
         * The order of controls is deliberate. Cheap structural checks
         * reject malformed data before more expensive policy decisions.
         * Authorization happens before the protected operation can proceed.
         */
        try {
            InputValidator::username(request.actor.username);
            InputValidator::username(request.destination);
            InputValidator::amount(request.amount);
        } catch (const SecurityValidationError& error) {
            audit.record({
                now,
                "input-validation",
                request.actor.username,
                "denied",
                "transaction",
                error.what()
            });

            return "rejected: invalid input";
        }

        if (!request.actor.active) {
            audit.record({
                now,
                "authorization",
                request.actor.username,
                "denied",
                "transaction",
                "inactive account"
            });

            return "rejected: inactive account";
        }

        if (
            !authorization.allowed(
                request.actor,
                "create:reports"
            )
        ) {
            audit.record({
                now,
                "authorization",
                request.actor.username,
                "denied",
                "transaction",
                "missing create permission"
            });

            return "rejected: insufficient privilege";
        }

        if (
            !rate_limiter.allow(
                request.actor.username,
                now
            )
        ) {
            audit.record({
                now,
                "rate-limit",
                request.actor.username,
                "denied",
                "transaction",
                "request threshold exceeded"
            });

            return "rejected: rate limit";
        }

        if (
            !replay_guard.accept(
                request.nonce,
                request.timestamp,
                now
            )
        ) {
            audit.record({
                now,
                "replay-protection",
                request.actor.username,
                "denied",
                "transaction",
                "stale or reused nonce"
            });

            return "rejected: replay";
        }

        if (
            !integrity.verify(
                request.payload,
                request.signature
            )
        ) {
            audit.record({
                now,
                "integrity",
                request.actor.username,
                "denied",
                "transaction",
                "signature verification failed"
            });

            return "rejected: tampered request";
        }

        audit.record({
            now,
            "transaction",
            request.actor.username,
            "accepted",
            "transaction",
            "all security policy checks passed"
        });

        return "accepted";
    }

    void printAuditLog() const {
        audit.print();
    }

    std::size_t auditEventCount() const {
        return audit.size();
    }

    std::string signPayload(std::string_view payload) const {
        return integrity.sign(payload);
    }
};


/* -------------------------------------------------------------------------
 * Threat model
 * ------------------------------------------------------------------------- */

void printThreatModel() {
    std::cout << "\n=== Threat Model ===\n";

    const std::vector<SecurityThreat> threats{
        {
            "Credential stuffing",
            "User accounts",
            "Authentication endpoint",
            RiskLevel::High,
            RiskLevel::High,
            {
                "Password KDF",
                "Rate limiting",
                "MFA",
                "Monitoring"
            }
        },
        {
            "Path traversal",
            "Private documents",
            "File retrieval endpoint",
            RiskLevel::High,
            RiskLevel::Medium,
            {
                "Canonicalization",
                "Storage boundary",
                "Filename allowlisting"
            }
        },
        {
            "Request tampering",
            "Transaction records",
            "API message boundary",
            RiskLevel::High,
            RiskLevel::Medium,
            {
                "Authenticated messages",
                "Nonce validation",
                "Timestamp validation"
            }
        },
        {
            "Resource exhaustion",
            "Service availability",
            "Public API",
            RiskLevel::High,
            RiskLevel::Medium,
            {
                "Rate limiting",
                "Request limits",
                "Resource quotas"
            }
        }
    };

    for (const auto& threat : threats) {
        std::cout
            << threat.name
            << ": asset="
            << threat.asset
            << ", surface="
            << threat.attack_surface
            << ", impact="
            << to_string(threat.impact)
            << ", likelihood="
            << to_string(threat.likelihood)
            << '\n';

        std::cout << "  Controls: ";

        for (std::size_t index = 0; index < threat.controls.size(); ++index) {
            if (index > 0) {
                std::cout << ", ";
            }

            std::cout << threat.controls[index];
        }

        std::cout << '\n';
    }
}


/* -------------------------------------------------------------------------
 * Demonstrations
 * ------------------------------------------------------------------------- */

void demonstrateAuthorization() {
    std::cout << "\n=== Least-Privilege Authorization ===\n";

    AuthorizationPolicy policy;

    const User viewer{
        "viewer_user",
        {"viewer"},
        true
    };

    const User analyst{
        "analyst_user",
        {"analyst"},
        true
    };

    const User administrator{
        "administrator",
        {"administrator"},
        true
    };

    for (const auto& user : {
        viewer,
        analyst,
        administrator
    }) {
        std::cout
            << user.username
            << ": read="
            << policy.allowed(user, "read:reports")
            << ", delete="
            << policy.allowed(user, "delete:reports")
            << '\n';
    }
}

void demonstrateRateLimiter() {
    std::cout << "\n=== Availability Protection Through Rate Limiting ===\n";

    RateLimiter limiter(3, 60);

    for (std::uint64_t request = 1; request <= 5; ++request) {
        std::cout
            << "Request "
            << request
            << ": "
            << (limiter.allow("client-A", 100) ? "allowed" : "blocked")
            << '\n';
    }
}

void demonstrateReplayProtection() {
    std::cout << "\n=== Replay Protection ===\n";

    ReplayGuard guard(300);

    std::cout
        << "Fresh request: "
        << guard.accept("nonce-A", 1000, 1001)
        << '\n';

    std::cout
        << "Replayed request: "
        << guard.accept("nonce-A", 1000, 1002)
        << '\n';

    std::cout
        << "Stale request: "
        << guard.accept("nonce-B", 1000, 1401)
        << '\n';
}

void demonstrateValidation() {
    std::cout << "\n=== Input Validation ===\n";

    for (const std::string value : {
        "secure_user",
        "../admin",
        "user name",
        "x"
    }) {
        try {
            std::cout
                << "Accepted username: "
                << InputValidator::username(value)
                << '\n';
        } catch (const SecurityValidationError& error) {
            std::cout
                << "Rejected "
                << value
                << ": "
                << error.what()
                << '\n';
        }
    }
}

void demonstrateSecureTransactionEngine() {
    std::cout << "\n=== Secure Transaction Engine ===\n";

    SecureIdentifierGenerator identifiers;

    const std::string key =
        "example-educational-integrity-key-32";

    SecurityEngine engine(key);

    const User analyst{
        "analyst_user",
        {"analyst"},
        true
    };

    const std::string payload =
        R"({"destination":"secure_account","amount":500})";

    TransactionRequest request{
        analyst,
        "secure_account",
        500,
        identifiers.generate(32),
        1000,
        payload,
        engine.signPayload(payload)
    };

    std::cout
        << "Valid transaction: "
        << engine.process(request, 1001)
        << '\n';

    /*
     * Reusing the same nonce is a replay attempt. The request has not been
     * changed, but it must still be rejected because the operation has
     * already consumed its nonce.
     */
    std::cout
        << "Replay attempt: "
        << engine.process(request, 1002)
        << '\n';

    TransactionRequest tampered_request{
        analyst,
        "secure_account",
        500'000,
        identifiers.generate(32),
        1003,
        R"({"destination":"secure_account","amount":500000})",
        engine.signPayload(payload)
    };

    std::cout
        << "Tampered payload: "
        << engine.process(tampered_request, 1004)
        << '\n';

    User unauthorized{
        "viewer_user",
        {"viewer"},
        true
    };

    TransactionRequest unauthorized_request{
        unauthorized,
        "secure_account",
        100,
        identifiers.generate(32),
        1005,
        R"({"destination":"secure_account","amount":100})",
        engine.signPayload(
            R"({"destination":"secure_account","amount":100})"
        )
    };

    std::cout
        << "Unauthorized operation: "
        << engine.process(
            unauthorized_request,
            1006
        )
        << '\n';

    std::cout << "\nAudit trail:\n";
    engine.printAuditLog();

    std::cout
        << "Recorded security events: "
        << engine.auditEventCount()
        << '\n';
}


/* -------------------------------------------------------------------------
 * Security design checks
 * ------------------------------------------------------------------------- */

void runAssertions() {
    std::cout << "\n=== Security Assertions ===\n";

    if (
        InputValidator::username("security_user") !=
        "security_user"
    ) {
        throw std::runtime_error(
            "valid username failed validation"
        );
    }

    bool invalid_username_rejected = false;

    try {
        InputValidator::username("../admin");
    } catch (const SecurityValidationError&) {
        invalid_username_rejected = true;
    }

    if (!invalid_username_rejected) {
        throw std::runtime_error(
            "unsafe username was accepted"
        );
    }

    bool invalid_amount_rejected = false;

    try {
        InputValidator::amount(-1);
    } catch (const SecurityValidationError&) {
        invalid_amount_rejected = true;
    }

    if (!invalid_amount_rejected) {
        throw std::runtime_error(
            "invalid amount was accepted"
        );
    }

    AuthorizationPolicy authorization;

    User viewer{
        "viewer",
        {"viewer"},
        true
    };

    if (
        authorization.allowed(viewer, "delete:reports")
    ) {
        throw std::runtime_error(
            "least-privilege policy failed"
        );
    }

    RateLimiter limiter(2, 10);

    if (!limiter.allow("client", 100)) {
        throw std::runtime_error("first request was blocked");
    }

    if (!limiter.allow("client", 101)) {
        throw std::runtime_error("second request was blocked");
    }

    if (limiter.allow("client", 102)) {
        throw std::runtime_error(
            "rate limit failed to block third request"
        );
    }

    ReplayGuard replay_guard(300);

    if (!replay_guard.accept("nonce", 1000, 1001)) {
        throw std::runtime_error(
            "fresh nonce was rejected"
        );
    }

    if (replay_guard.accept("nonce", 1000, 1002)) {
        throw std::runtime_error(
            "replayed nonce was accepted"
        );
    }

    std::cout << "All assertions passed.\n";
}


/* -------------------------------------------------------------------------
 * Main
 * ------------------------------------------------------------------------- */

} // namespace security_case_study

int main() {
    using namespace security_case_study;

    try {
        std::cout
            << "SECURITY THREATS AND BASIC SECURITY PRINCIPLES\n"
            << "===============================================\n";

        printThreatModel();
        demonstrateValidation();
        demonstrateAuthorization();
        demonstrateRateLimiter();
        demonstrateReplayProtection();
        demonstrateSecureTransactionEngine();
        runAssertions();

        std::cout
            << "\nSecurity case study completed successfully.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Security case study failed: "
            << error.what()
            << '\n';

        return 1;
    }
}
