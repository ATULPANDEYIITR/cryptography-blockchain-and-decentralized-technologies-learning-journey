#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Repository secrets service: a C++17 case study for IV allocation.
 *
 * The service models encrypted deployment artifacts, nonce allocation,
 * key generations, and audit records. It deliberately does not implement
 * AES. A production cipher must come from a maintained cryptographic
 * library such as OpenSSL, with authenticated encryption APIs.
 *
 * Compile:
 *   g++ -std=c++17 -Wall -Wextra -Wpedantic initialization_vectors.cpp -o iv_demo
 */

class PolicyError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

using Nonce = std::array<std::uint8_t, 12>;

std::string toHex(const Nonce& nonce) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    for (const auto byte : nonce) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }

    return output.str();
}

class NonceAllocator {
private:
    // A four-byte namespace distinguishes independently provisioned workers.
    std::array<std::uint8_t, 4> prefix_;
    std::uint64_t nextCounter_;
    bool exhausted_ = false;

public:
    NonceAllocator(std::array<std::uint8_t, 4> prefix,
                   std::uint64_t initialCounter = 0)
        : prefix_(prefix), nextCounter_(initialCounter) {}

    Nonce next() {
        if (exhausted_) {
            throw PolicyError("Nonce counter exhausted; rotate the key.");
        }

        Nonce result{};

        for (std::size_t index = 0; index < prefix_.size(); ++index) {
            result[index] = prefix_[index];
        }

        // Encode the counter in network byte order for a stable representation.
        for (int index = 11; index >= 4; --index) {
            result[static_cast<std::size_t>(index)] =
                static_cast<std::uint8_t>(nextCounter_ & 0xffU);
            nextCounter_ >>= 8U;
        }

        // The original value is reconstructed from the encoded suffix.
        // Keeping allocation state separate avoids arithmetic overflow.
        std::uint64_t allocated = 0;
        for (std::size_t index = 4; index < result.size(); ++index) {
            allocated = (allocated << 8U) | result[index];
        }

        if (allocated == std::numeric_limits<std::uint64_t>::max()) {
            exhausted_ = true;
        } else {
            nextCounter_ = allocated + 1;
        }

        return result;
    }
};

struct KeyGeneration {
    std::string keyId;
    unsigned int generation;
    bool active;
};

struct Artifact {
    std::string id;
    std::string branch;
    std::string keyId;
    Nonce nonce;
    std::string status;
};

class GovernanceService {
private:
    std::set<std::string> nonceLedger_;
    std::vector<Artifact> artifacts_;
    std::vector<std::string> audit_;

    std::string ledgerKey(const std::string& keyId, const Nonce& nonce) const {
        return keyId + ":" + toHex(nonce);
    }

public:
    void registerArtifact(const Artifact& artifact) {
        if (artifact.id.empty() || artifact.branch.empty() ||
            artifact.keyId.empty()) {
            throw PolicyError("Artifact identity, branch, and key are required.");
        }

        if (artifact.status != "READY" && artifact.status != "QUARANTINED") {
            throw PolicyError("Unsupported artifact state.");
        }

        const auto identity = ledgerKey(artifact.keyId, artifact.nonce);

        // A nonce may be used with another key, but never reused with the
        // same key. A production ledger must enforce this atomically in storage.
        if (!nonceLedger_.insert(identity).second) {
            throw PolicyError("Repeated nonce for the same encryption key.");
        }

        artifacts_.push_back(artifact);
        audit_.push_back("registered:" + artifact.id);
    }

    void rotateKey(const KeyGeneration& previous,
                   const KeyGeneration& replacement) {
        if (!previous.active || replacement.active ||
            previous.keyId == replacement.keyId) {
            throw PolicyError("Invalid key-generation transition.");
        }

        audit_.push_back("retired:" + previous.keyId);
        audit_.push_back("activated:" + replacement.keyId);
    }

    void printReport() const {
        std::cout << "\nArtifact inventory\n";

        for (const auto& artifact : artifacts_) {
            std::cout << "  " << artifact.id
                      << " branch=" << artifact.branch
                      << " key=" << artifact.keyId
                      << " nonce=" << toHex(artifact.nonce)
                      << " status=" << artifact.status << '\n';
        }

        std::cout << "\nAudit events\n";
        for (const auto& event : audit_) {
            std::cout << "  " << event << '\n';
        }
    }
};

int main() {
    try {
        GovernanceService service;
        NonceAllocator allocator({0x52, 0x45, 0x4c, 0x31});

        service.registerArtifact({
            "build-2026-104",
            "release/4.2",
            "artifact-key-v3",
            allocator.next(),
            "READY"
        });

        service.registerArtifact({
            "build-2026-105",
            "release/4.2",
            "artifact-key-v3",
            allocator.next(),
            "QUARANTINED"
        });

        service.rotateKey(
            {"artifact-key-v3", 3, true},
            {"artifact-key-v4", 4, false}
        );

        service.printReport();

        std::cout << "\nReuse rejection test\n";
        const Nonce repeated = allocator.next();

        service.registerArtifact({
            "build-2026-106",
            "release/4.3",
            "artifact-key-v4",
            repeated,
            "READY"
        });

        try {
            service.registerArtifact({
                "build-2026-107",
                "release/4.3",
                "artifact-key-v4",
                repeated,
                "READY"
            });
        } catch (const PolicyError& error) {
            std::cout << "Rejected: " << error.what() << '\n';
        }

        std::cout << "\nSecurity boundary\n"
                  << "This program validates allocation policy; it does not "
                  << "encrypt data.\n"
                  << "Persist counter state atomically, coordinate workers, "
                  << "and use authenticated encryption in production.\n";

    } catch (const std::exception& error) {
        std::cerr << "Fatal policy error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
