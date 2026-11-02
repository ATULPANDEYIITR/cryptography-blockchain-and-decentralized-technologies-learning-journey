#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

class CryptoError : public std::runtime_error {
public:
    explicit CryptoError(const std::string& message)
        : std::runtime_error(message) {}
};

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;
using Hash = std::array<Byte, 32>;

namespace sha256 {

constexpr std::array<std::uint32_t, 64> K = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline std::uint32_t rotr(std::uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

inline std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline std::uint32_t bigSigma0(std::uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline std::uint32_t bigSigma1(std::uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline std::uint32_t smallSigma0(std::uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline std::uint32_t smallSigma1(std::uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

Hash digest(const Bytes& input) {
    std::array<std::uint32_t, 8> h = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    Bytes data = input;
    const std::uint64_t bitLength =
        static_cast<std::uint64_t>(data.size()) * 8ULL;

    data.push_back(0x80);

    while (data.size() % 64 != 56) {
        data.push_back(0);
    }

    for (int shift = 56; shift >= 0; shift -= 8) {
        data.push_back(
            static_cast<Byte>((bitLength >> shift) & 0xff)
        );
    }

    for (std::size_t offset = 0; offset < data.size(); offset += 64) {
        std::array<std::uint32_t, 64> w{};

        for (std::size_t i = 0; i < 16; ++i) {
            const std::size_t p = offset + i * 4;
            w[i] =
                (static_cast<std::uint32_t>(data[p]) << 24) |
                (static_cast<std::uint32_t>(data[p + 1]) << 16) |
                (static_cast<std::uint32_t>(data[p + 2]) << 8) |
                static_cast<std::uint32_t>(data[p + 3]);
        }

        for (std::size_t i = 16; i < 64; ++i) {
            w[i] =
                smallSigma1(w[i - 2]) +
                w[i - 7] +
                smallSigma0(w[i - 15]) +
                w[i - 16];
        }

        auto a = h[0];
        auto b = h[1];
        auto c = h[2];
        auto d = h[3];
        auto e = h[4];
        auto f = h[5];
        auto g = h[6];
        auto hh = h[7];

        for (std::size_t i = 0; i < 64; ++i) {
            const std::uint32_t t1 =
                hh + bigSigma1(e) + ch(e, f, g) + K[i] + w[i];

            const std::uint32_t t2 =
                bigSigma0(a) + maj(a, b, c);

            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    }

    Hash result{};

    for (std::size_t i = 0; i < h.size(); ++i) {
        result[i * 4] =
            static_cast<Byte>((h[i] >> 24) & 0xff);
        result[i * 4 + 1] =
            static_cast<Byte>((h[i] >> 16) & 0xff);
        result[i * 4 + 2] =
            static_cast<Byte>((h[i] >> 8) & 0xff);
        result[i * 4 + 3] =
            static_cast<Byte>(h[i] & 0xff);
    }

    return result;
}

Bytes toBytes(const Hash& hash) {
    return Bytes(hash.begin(), hash.end());
}

} // namespace sha256

Bytes concat(const Bytes& a, const Bytes& b) {
    Bytes result;
    result.reserve(a.size() + b.size());
    result.insert(result.end(), a.begin(), a.end());
    result.insert(result.end(), b.begin(), b.end());
    return result;
}

Bytes concat(const std::initializer_list<Bytes>& parts) {
    Bytes result;

    std::size_t total = 0;
    for (const auto& part : parts) {
        total += part.size();
    }

    result.reserve(total);

    for (const auto& part : parts) {
        result.insert(result.end(), part.begin(), part.end());
    }

    return result;
}

Bytes stringBytes(std::string_view value) {
    return Bytes(value.begin(), value.end());
}

Hash hmacSha256(const Bytes& key, const Bytes& message) {
    constexpr std::size_t BLOCK_SIZE = 64;

    Bytes normalized = key;

    if (normalized.size() > BLOCK_SIZE) {
        const Hash hashed = sha256::digest(normalized);
        normalized = sha256::toBytes(hashed);
    }

    normalized.resize(BLOCK_SIZE, 0);

    Bytes ipad(BLOCK_SIZE);
    Bytes opad(BLOCK_SIZE);

    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        ipad[i] = normalized[i] ^ 0x36;
        opad[i] = normalized[i] ^ 0x5c;
    }

    const Hash inner = sha256::digest(concat(ipad, message));
    const Hash outer = sha256::digest(
        concat(opad, sha256::toBytes(inner))
    );

    return outer;
}

Bytes toBytes(std::uint32_t value) {
    return {
        static_cast<Byte>((value >> 24) & 0xff),
        static_cast<Byte>((value >> 16) & 0xff),
        static_cast<Byte>((value >> 8) & 0xff),
        static_cast<Byte>(value & 0xff)
    };
}

Hash hkdfExtract(const Bytes& salt, const Bytes& ikm) {
    if (ikm.empty()) {
        throw CryptoError("HKDF input key material is empty");
    }

    Bytes actualSalt = salt;

    if (actualSalt.empty()) {
        actualSalt.resize(32, 0);
    }

    return hmacSha256(actualSalt, ikm);
}

Bytes hkdfExpand(
    const Hash& prk,
    const Bytes& info,
    std::size_t length
) {
    if (length == 0 || length > 255 * 32) {
        throw CryptoError("invalid HKDF output length");
    }

    Bytes result;
    Bytes previous;

    for (Byte counter = 1; result.size() < length; ++counter) {
        previous = sha256::toBytes(
            hmacSha256(
                sha256::toBytes(prk),
                concat({
                    previous,
                    info,
                    Bytes{counter}
                })
            )
        );

        result.insert(
            result.end(),
            previous.begin(),
            previous.end()
        );
    }

    result.resize(length);
    return result;
}

Bytes hkdfSha256(
    const Bytes& ikm,
    const Bytes& salt,
    const Bytes& info,
    std::size_t length = 32
) {
    const Hash prk = hkdfExtract(salt, ikm);
    return hkdfExpand(prk, info, length);
}

Bytes pbkdf2Sha256(
    const Bytes& password,
    const Bytes& salt,
    std::uint32_t iterations,
    std::size_t outputLength
) {
    if (password.empty()) {
        throw CryptoError("PBKDF2 password is empty");
    }

    if (salt.size() < 16) {
        throw CryptoError("PBKDF2 salt must contain at least 16 bytes");
    }

    if (iterations < 100000) {
        throw CryptoError("PBKDF2 iteration count is too low");
    }

    if (outputLength == 0 || outputLength > 64) {
        throw CryptoError("invalid PBKDF2 output length");
    }

    Bytes result;
    const std::size_t blocks =
        (outputLength + 31) / 32;

    for (std::uint32_t block = 1;
         block <= blocks;
         ++block) {
        Bytes message = salt;
        const Bytes blockNumber = toBytes(block);

        message.insert(
            message.end(),
            blockNumber.begin(),
            blockNumber.end()
        );

        Hash u = hmacSha256(password, message);
        Hash t = u;

        for (std::uint32_t i = 1; i < iterations; ++i) {
            u = hmacSha256(
                password,
                sha256::toBytes(u)
            );

            for (std::size_t j = 0; j < t.size(); ++j) {
                t[j] ^= u[j];
            }
        }

        const Bytes blockResult = sha256::toBytes(t);

        result.insert(
            result.end(),
            blockResult.begin(),
            blockResult.end()
        );
    }

    result.resize(outputLength);
    return result;
}

enum class BranchType {
    Protected,
    Development,
    Feature
};

enum class MergeStrategy {
    MergeCommit,
    Squash,
    Rebase
};

struct Commit {
    std::string id;
    std::string message;
    std::string author;
};

struct Branch {
    std::string name;
    BranchType type;
    std::string headCommit;
    bool protectedBranch;
};

struct DerivedKey {
    std::string path;
    Bytes key;
    Bytes chainCode;
};

class HDGovernanceKeyTree {
public:
    explicit HDGovernanceKeyTree(const Bytes& seed) {
        if (seed.size() < 16) {
            throw CryptoError("seed must contain at least 16 bytes");
        }

        root_.key = sha256::toBytes(
            hmacSha256(
                stringBytes("Blockchain HD Root"),
                seed
            )
        );

        root_.chainCode = sha256::toBytes(
            hmacSha256(
                stringBytes("Blockchain Chain Code"),
                seed
            )
        );

        root_.path = "m";
    }

    DerivedKey derive(
        const DerivedKey& parent,
        std::uint32_t index,
        bool hardened
    ) const {
        if (index >= 0x80000000U) {
            throw CryptoError("index must be below 2^31");
        }

        Bytes encoded = toBytes(
            index | (hardened ? 0x80000000U : 0U)
        );

        Bytes context = concat({
            stringBytes("HD-NODE"),
            Bytes{static_cast<Byte>(
                parent.path.count('/') + 1
            )},
            encoded,
            parent.key
        });

        DerivedKey child;

        child.key = sha256::toBytes(
            hmacSha256(parent.chainCode, context)
        );

        child.chainCode = sha256::toBytes(
            hmacSha256(
                parent.key,
                concat({
                    stringBytes("CHAIN"),
                    context
                })
            )
        );

        child.path =
            parent.path + "/" +
            std::to_string(index) +
            (hardened ? "'" : "");

        return child;
    }

    DerivedKey derivePath(const std::string& path) const {
        if (path == "m") {
            return root_;
        }

        if (path.rfind("m/", 0) != 0) {
            throw CryptoError("derivation path must start with m/");
        }

        DerivedKey current = root_;
        std::stringstream stream(path.substr(2));
        std::string component;

        while (std::getline(stream, component, '/')) {
            if (component.empty()) {
                throw CryptoError("empty derivation component");
            }

            bool hardened = component.back() == '\'';

            if (hardened) {
                component.pop_back();
            }

            if (component.empty() ||
                !std::all_of(
                    component.begin(),
                    component.end(),
                    [](char c) {
                        return c >= '0' && c <= '9';
                    }
                )) {
                throw CryptoError("invalid derivation component");
            }

            const auto index =
                static_cast<std::uint32_t>(
                    std::stoull(component)
                );

            current = derive(current, index, hardened);
        }

        return current;
    }

private:
    DerivedKey root_;
};

struct ReviewRecord {
    std::string reviewer;
    bool approved;
    bool stale;
};

struct PullRequest {
    std::string id;
    std::string sourceBranch;
    std::string targetBranch;
    std::vector<Commit> commits;
    std::vector<ReviewRecord> reviews;
    std::map<std::string, bool> statusChecks;
    bool draft;
    bool mergeConflict;
};

struct ProtectionPolicy {
    std::size_t requiredApprovals;
    std::vector<std::string> requiredChecks;
    bool requireConversationResolution;
    bool forbidDirectPush;
    bool forbidForcePush;
    bool forbidBranchDeletion;
    bool requireLinearHistory;
    bool administratorBypass;
};

struct Eligibility {
    bool eligible;
    std::vector<std::string> failures;
};

class GovernanceEngine {
public:
    Eligibility evaluate(
        const PullRequest& pullRequest,
        const Branch& target,
        const ProtectionPolicy& policy
    ) const {
        Eligibility result{true, {}};

        if (pullRequest.draft) {
            reject(result, "Pull Request is still a draft");
        }

        if (pullRequest.sourceBranch.empty() ||
            pullRequest.targetBranch.empty()) {
            reject(result, "source and target branches are required");
        }

        if (pullRequest.commits.empty()) {
            reject(result, "Pull Request contains no commits");
        }

        if (pullRequest.mergeConflict) {
            reject(result, "Pull Request has unresolved merge conflicts");
        }

        if (target.protectedBranch &&
            pullRequest.sourceBranch == target.name &&
            policy.forbidDirectPush) {
            reject(result, "direct changes to protected branch are prohibited");
        }

        std::size_t validApprovals = 0;

        for (const auto& review : pullRequest.reviews) {
            if (review.approved && !review.stale) {
                ++validApprovals;
            }
        }

        if (validApprovals < policy.requiredApprovals) {
            reject(
                result,
                "required non-stale approvals are missing"
            );
        }

        for (const auto& requiredCheck : policy.requiredChecks) {
            const auto it =
                pullRequest.statusChecks.find(requiredCheck);

            if (it == pullRequest.statusChecks.end()) {
                reject(
                    result,
                    "required status check is missing: " +
                    requiredCheck
                );
            } else if (!it->second) {
                reject(
                    result,
                    "required status check failed: " +
                    requiredCheck
                );
            }
        }

        return result;
    }

private:
    static void reject(
        Eligibility& result,
        const std::string& reason
    ) {
        result.eligible = false;
        result.failures.push_back(reason);
    }
};

std::string hex(const Bytes& data) {
    std::ostringstream out;

    for (Byte value : data) {
        out << std::hex
            << std::setw(2)
            << std::setfill('0')
            << static_cast<int>(value);
    }

    return out.str();
}

void runTests() {
    const Bytes password = stringBytes("password");
    const Bytes salt = {
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff
    };

    const Bytes key =
        pbkdf2Sha256(password, salt, 100000, 32);

    if (key.size() != 32) {
        throw CryptoError("PBKDF2 test failed");
    }

    const Bytes expanded =
        hkdfSha256(
            key,
            salt,
            stringBytes("blockchain/account")
        );

    if (expanded.size() != 32) {
        throw CryptoError("HKDF test failed");
    }

    const HDGovernanceKeyTree tree(key);
    const DerivedKey account =
        tree.derivePath("m/44'/0'/0'");

    const DerivedKey address =
        tree.derive(
            tree.derive(account, 0, false),
            0,
            false
        );

    if (address.key.size() != 32) {
        throw CryptoError("HD derivation test failed");
    }
}

int main() {
    try {
        runTests();

        const Bytes seed = stringBytes(
            "example blockchain wallet seed with sufficient entropy"
        );

        const HDGovernanceKeyTree keyTree(seed);

        const DerivedKey account =
            keyTree.derivePath("m/44'/0'/0'");

        const DerivedKey external =
            keyTree.derive(account, 0, false);

        const DerivedKey address =
            keyTree.derive(external, 0, false);

        const Bytes signingKey =
            hkdfSha256(
                address.key,
                address.chainCode,
                stringBytes("blockchain/signing-key/v1")
            );

        std::cout << "Blockchain key derivation\n";
        std::cout << "=========================\n";
        std::cout << "Account path: " << account.path << '\n';
        std::cout << "Address path: " << address.path << '\n';
        std::cout << "Address key fingerprint: "
                  << hex(
                         sha256::toBytes(
                             sha256::digest(address.key)
                         )
                     ).substr(0, 16)
                  << '\n';
        std::cout << "Signing key fingerprint: "
                  << hex(
                         sha256::toBytes(
                             sha256::digest(signingKey)
                         )
                     ).substr(0, 16)
                  << '\n';

        Branch main{
            "main",
            BranchType::Protected,
            "c200",
            true
        };

        PullRequest pullRequest{
            "PR-1042",
            "feature/key-rotation",
            "main",
            {
                {"c198", "add key rotation policy", "developer"},
                {"c199", "validate KDF parameters", "developer"},
                {"c200", "add audit event", "developer"}
            },
            {
                {"security-reviewer", true, false},
                {"cryptography-reviewer", true, false}
            },
            {
                {"unit-tests", true},
                {"security-scan", true},
                {"policy-check", true}
            },
            false,
            false
        };

        ProtectionPolicy policy{
            2,
            {"unit-tests", "security-scan", "policy-check"},
            true,
            true,
            true,
            true,
            true,
            false
        };

        GovernanceEngine engine;
        const Eligibility eligibility =
            engine.evaluate(
                pullRequest,
                main,
                policy
            );

        std::cout << "\nRepository governance\n";
        std::cout << "=====================\n";
        std::cout << "Merge eligible: "
                  << (eligibility.eligible ? "yes" : "no")
                  << '\n';

        for (const auto& failure : eligibility.failures) {
            std::cout << "Failure: " << failure << '\n';
        }

        PullRequest staleApprovalCase = pullRequest;
        staleApprovalCase.reviews[0].stale = true;

        const Eligibility blocked =
            engine.evaluate(
                staleApprovalCase,
                main,
                policy
            );

        std::cout << "\nStale approval scenario\n";
        std::cout << "=======================\n";
        std::cout << "Merge eligible: "
                  << (blocked.eligible ? "yes" : "no")
                  << '\n';

        for (const auto& failure : blocked.failures) {
            std::cout << "Failure: " << failure << '\n';
        }

        std::cout << "\nSecurity controls\n";
        std::cout << "=================\n";
        std::cout << "Password-derived material uses PBKDF2 with a unique salt in real deployments.\n";
        std::cout << "HKDF separates cryptographic purposes through explicit info strings.\n";
        std::cout << "Private key material must never be logged or committed to repositories.\n";
        std::cout << "The HD tree here is intentionally not wire-compatible with BIP-32.\n";
        std::cout << "Production blockchain systems should use audited standard cryptographic implementations.\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr << "Fatal error: "
                  << error.what()
                  << '\n';
        return 1;
    }
}
