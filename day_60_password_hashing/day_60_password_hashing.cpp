/*
 * Secure Password Hashing and Repository Authentication
 *
 * Language: C++17
 * Cryptographic dependency: OpenSSL
 *
 * Compile:
 * g++ -std=c++17 password_hashing.cpp -O2 -Wall -Wextra -lcrypto -o password_hashing
 *
 * Design:
 * - PBKDF2-HMAC-SHA256
 * - OpenSSL cryptographically secure random salt generation
 * - Constant-time password comparison
 * - Versioned credential encoding
 * - UTF-8 validation
 * - Per-account synchronization
 * - Legacy credential migration
 * - Account throttling
 */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace security {

constexpr int CURRENT_ITERATIONS = 600000;
constexpr int MIN_ITERATIONS = 100000;
constexpr int MAX_ITERATIONS = 2000000;

constexpr std::size_t SALT_LENGTH = 16;
constexpr std::size_t KEY_LENGTH = 32;

constexpr int MAXIMUM_FAILURES = 5;
constexpr int LOCK_SECONDS = 60;

const std::string ALGORITHM = "pbkdf2-sha256";


struct ParsedCredential {
    int iterations;
    std::vector<unsigned char> salt;
    std::vector<unsigned char> expected;
};


std::string bytesToHex(const unsigned char* data, std::size_t length) {
    static const char HEX[] = "0123456789abcdef";

    std::string output;
    output.reserve(length * 2);

    for (std::size_t i = 0; i < length; ++i) {
        output.push_back(HEX[data[i] >> 4]);
        output.push_back(HEX[data[i] & 0x0F]);
    }

    return output;
}


std::vector<unsigned char> hexToBytes(const std::string& input) {
    if (input.empty() || input.size() % 2 != 0) {
        throw std::invalid_argument("Invalid hexadecimal encoding.");
    }

    auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::vector<unsigned char> output;
    output.reserve(input.size() / 2);

    for (std::size_t i = 0; i < input.size(); i += 2) {
        int high = digit(input[i]);
        int low = digit(input[i + 1]);

        if (high < 0 || low < 0) {
            throw std::invalid_argument("Invalid hexadecimal character.");
        }

        output.push_back(
            static_cast<unsigned char>((high << 4) | low)
        );
    }

    return output;
}


/*
 * Validates UTF-8 and counts Unicode code points.
 *
 * C++17 has no standard Unicode normalization API.
 * The calling application must NFC-normalize password input before
 * invoking this program when Unicode-equivalent passwords are supported.
 */
std::optional<std::size_t> countUtf8CodePoints(const std::string& input) {
    std::size_t count = 0;

    for (std::size_t i = 0; i < input.size();) {
        unsigned char first =
            static_cast<unsigned char>(input[i]);

        std::size_t length = 0;

        if (first <= 0x7F) {
            length = 1;
        } else if (first >= 0xC2 && first <= 0xDF) {
            length = 2;
        } else if (first >= 0xE0 && first <= 0xEF) {
            length = 3;
        } else if (first >= 0xF0 && first <= 0xF4) {
            length = 4;
        } else {
            return std::nullopt;
        }

        if (i + length > input.size()) {
            return std::nullopt;
        }

        for (std::size_t j = 1; j < length; ++j) {
            unsigned char continuation =
                static_cast<unsigned char>(input[i + j]);

            if ((continuation & 0xC0) != 0x80) {
                return std::nullopt;
            }
        }

        if (length >= 3) {
            unsigned char second =
                static_cast<unsigned char>(input[i + 1]);

            if (first == 0xE0 && second < 0xA0) return std::nullopt;
            if (first == 0xED && second >= 0xA0) return std::nullopt;
            if (first == 0xF0 && second < 0x90) return std::nullopt;
            if (first == 0xF4 && second >= 0x90) return std::nullopt;
        }

        ++count;
        i += length;
    }

    return count;
}


class PasswordPolicy {
private:
    const std::unordered_set<std::string> blockedPasswords = {
        "password",
        "password123",
        "123456789012345",
        "qwerty123456789",
        "letmein123456"
    };

public:
    void validate(
        const std::string& password,
        const std::string& username
    ) const {

        if (password.find('\0') != std::string::npos) {
            throw std::invalid_argument(
                "Null characters are not permitted."
            );
        }

        auto characters = countUtf8CodePoints(password);

        if (!characters.has_value()) {
            throw std::invalid_argument("Invalid UTF-8 password.");
        }

        if (*characters < 15 || *characters > 256) {
            throw std::invalid_argument(
                "Password length is outside permitted limits."
            );
        }

        if (password.size() > 1024) {
            throw std::invalid_argument("Password exceeds byte limit.");
        }

        std::string folded = password;

        std::transform(
            folded.begin(),
            folded.end(),
            folded.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            }
        );

        if (blockedPasswords.count(folded)) {
            throw std::invalid_argument(
                "Password appears on the blocked-password list."
            );
        }

        if (!username.empty() && folded == username) {
            throw std::invalid_argument(
                "Password cannot equal account identifier."
            );
        }
    }
};


class PasswordHasher {
private:
    std::vector<unsigned char> derive(
        const std::string& password,
        const std::vector<unsigned char>& salt,
        int iterations
    ) const {

        if (
            iterations < MIN_ITERATIONS ||
            iterations > MAX_ITERATIONS
        ) {
            throw std::invalid_argument(
                "Unsupported PBKDF2 iteration count."
            );
        }

        if (password.size() > 1024) {
            throw std::invalid_argument("Password exceeds byte limit.");
        }

        if (password.size() >
            static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            throw std::invalid_argument("Password is too large.");
        }

        std::vector<unsigned char> result(KEY_LENGTH);

        const int success = PKCS5_PBKDF2_HMAC(
            password.data(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            iterations,
            EVP_sha256(),
            static_cast<int>(result.size()),
            result.data()
        );

        if (success != 1) {
            OPENSSL_cleanse(result.data(), result.size());

            throw std::runtime_error(
                "OpenSSL PBKDF2 derivation failed."
            );
        }

        return result;
    }

public:
    std::string hash(
        const std::string& password,
        int iterations = CURRENT_ITERATIONS
    ) const {

        std::array<unsigned char, SALT_LENGTH> salt{};

        if (RAND_bytes(
                salt.data(),
                static_cast<int>(salt.size())
            ) != 1) {

            throw std::runtime_error(
                "Cryptographically secure salt generation failed."
            );
        }

        std::vector<unsigned char> saltVector(
            salt.begin(),
            salt.end()
        );

        auto derived = derive(
            password,
            saltVector,
            iterations
        );

        std::string encoded =
            ALGORITHM + "$" +
            std::to_string(iterations) + "$" +
            bytesToHex(salt.data(), salt.size()) + "$" +
            bytesToHex(derived.data(), derived.size());

        // Clear temporary derived-key material after serialization.
        OPENSSL_cleanse(derived.data(), derived.size());

        return encoded;
    }

    ParsedCredential parse(const std::string& encoded) const {
        std::vector<std::string> fields;

        std::size_t start = 0;

        while (true) {
            std::size_t position = encoded.find('$', start);

            if (position == std::string::npos) {
                fields.push_back(encoded.substr(start));
                break;
            }

            fields.push_back(
                encoded.substr(start, position - start)
            );

            start = position + 1;
        }

        if (fields.size() != 4 || fields[0] != ALGORITHM) {
            throw std::invalid_argument(
                "Unsupported password hash format."
            );
        }

        std::size_t consumed = 0;

        int iterations = std::stoi(fields[1], &consumed);

        if (consumed != fields[1].size()) {
            throw std::invalid_argument("Invalid iteration count.");
        }

        if (
            iterations < MIN_ITERATIONS ||
            iterations > MAX_ITERATIONS
        ) {
            throw std::invalid_argument(
                "Iteration count outside permitted limits."
            );
        }

        auto salt = hexToBytes(fields[2]);
        auto expected = hexToBytes(fields[3]);

        if (
            salt.size() < SALT_LENGTH ||
            salt.size() > 64 ||
            expected.size() != KEY_LENGTH
        ) {
            throw std::invalid_argument(
                "Invalid credential component lengths."
            );
        }

        return ParsedCredential{
            iterations,
            std::move(salt),
            std::move(expected)
        };
    }

    bool verify(
        const std::string& password,
        const std::string& encoded
    ) const {

        try {
            auto parsed = parse(encoded);

            auto actual = derive(
                password,
                parsed.salt,
                parsed.iterations
            );

            bool equal = CRYPTO_memcmp(
                actual.data(),
                parsed.expected.data(),
                KEY_LENGTH
            ) == 0;

            OPENSSL_cleanse(actual.data(), actual.size());

            return equal;

        } catch (const std::exception&) {
            return false;
        }
    }

    bool needsRehash(const std::string& encoded) const {
        try {
            return parse(encoded).iterations < CURRENT_ITERATIONS;
        } catch (const std::exception&) {
            return true;
        }
    }
};


struct Account {
    std::string username;
    std::string passwordHash;

    bool enabled = true;
    int failedAttempts = 0;

    std::chrono::steady_clock::time_point lockedUntil{};

    std::mutex mutex;
};


class AuthenticationService {
private:
    PasswordHasher hasher;
    PasswordPolicy policy;

    std::unordered_map<std::string, std::shared_ptr<Account>> accounts;
    std::mutex registryMutex;

    std::string dummyHash;

public:
    AuthenticationService() {
        dummyHash = hasher.hash(
            "internal dummy credential not for authentication"
        );
    }

    static std::string normalizeUsername(const std::string& username) {
        std::string key = username;

        std::transform(
            key.begin(),
            key.end(),
            key.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            }
        );

        if (
            key.size() < 3 ||
            key.size() > 64 ||
            !std::all_of(
                key.begin(),
                key.end(),
                [](unsigned char c) {
                    return std::isalnum(c) ||
                           c == '.' ||
                           c == '_' ||
                           c == '-';
                }
            )
        ) {
            throw std::invalid_argument(
                "Invalid account identifier."
            );
        }

        return key;
    }

    void registerAccount(
        const std::string& username,
        const std::string& password
    ) {

        const std::string key = normalizeUsername(username);

        policy.validate(password, key);

        auto account = std::make_shared<Account>();

        account->username = key;
        account->passwordHash = hasher.hash(password);

        std::lock_guard<std::mutex> guard(registryMutex);

        if (accounts.count(key)) {
            throw std::invalid_argument("Account already exists.");
        }

        accounts.emplace(key, std::move(account));
    }

    bool authenticate(
        const std::string& username,
        const std::string& password
    ) {

        std::string key;

        try {
            key = normalizeUsername(username);
        } catch (const std::exception&) {
            hasher.verify(password, dummyHash);
            return false;
        }

        std::shared_ptr<Account> account;

        {
            std::lock_guard<std::mutex> guard(registryMutex);

            auto iterator = accounts.find(key);

            if (iterator == accounts.end()) {
                hasher.verify(password, dummyHash);
                return false;
            }

            account = iterator->second;
        }

        std::lock_guard<std::mutex> guard(account->mutex);

        if (!account->enabled) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();

        if (now < account->lockedUntil) {
            return false;
        }

        if (!hasher.verify(password, account->passwordHash)) {
            ++account->failedAttempts;

            if (account->failedAttempts >= MAXIMUM_FAILURES) {
                account->lockedUntil =
                    now + std::chrono::seconds(LOCK_SECONDS);
            }

            return false;
        }

        account->failedAttempts = 0;
        account->lockedUntil =
            std::chrono::steady_clock::time_point{};

        // Never upgrade a legacy credential using an unverified password.
        if (hasher.needsRehash(account->passwordHash)) {
            account->passwordHash = hasher.hash(password);
        }

        return true;
    }

    void seedLegacyCredential(
        const std::string& username,
        const std::string& password
    ) {

        const std::string key = normalizeUsername(username);

        std::shared_ptr<Account> account;

        {
            std::lock_guard<std::mutex> guard(registryMutex);

            auto iterator = accounts.find(key);

            if (iterator == accounts.end()) {
                throw std::invalid_argument("Account does not exist.");
            }

            account = iterator->second;
        }

        // Test fixture representing an older credential.
        std::lock_guard<std::mutex> guard(account->mutex);

        account->passwordHash = hasher.hash(
            password,
            120000
        );
    }
};


} // namespace security


int main() {
    try {
        using namespace security;

        AuthenticationService service;

        const std::string username = "alex.developer";
        const std::string password =
            "Correct-Horse-Battery-Staple-2026!";

        service.registerAccount(username, password);

        // Construct an older credential to test migration behavior.
        service.seedLegacyCredential(username, password);

        bool incorrect = service.authenticate(
            username,
            "incorrect-authentication-secret"
        );

        std::cout
            << "Incorrect password accepted: "
            << std::boolalpha
            << incorrect
            << '\n';

        bool correct = service.authenticate(
            username,
            password
        );

        std::cout
            << "Correct password accepted: "
            << correct
            << '\n';

        if (!correct || incorrect) {
            throw std::runtime_error(
                "Authentication assertion failed."
            );
        }

        // Unique salt validation.
        PasswordHasher hasher;

        std::string first = hasher.hash(password);
        std::string second = hasher.hash(password);

        if (first == second) {
            throw std::runtime_error("Salt uniqueness assertion failed.");
        }

        if (!hasher.verify(password, first)) {
            throw std::runtime_error("Password verification failed.");
        }

        if (hasher.verify("incorrect-secret", first)) {
            throw std::runtime_error(
                "Incorrect password was accepted."
            );
        }

        std::cout << "Random salt assertion passed.\n";
        std::cout << "Constant-time verification path exercised.\n";

        // Validate malformed credential rejection.
        if (hasher.verify(password, "invalid$credential")) {
            throw std::runtime_error(
                "Malformed credential was incorrectly accepted."
            );
        }

        std::cout << "Malformed credential rejection passed.\n";

        // Validate account throttling.
        service.registerAccount(
            "throttle.user",
            "A-Long-Unique-Authentication-Secret-2026!"
        );

        for (int i = 0; i < MAXIMUM_FAILURES; ++i) {
            service.authenticate(
                "throttle.user",
                "incorrect-authentication-secret"
            );
        }

        bool lockedLogin = service.authenticate(
            "throttle.user",
            "A-Long-Unique-Authentication-Secret-2026!"
        );

        if (lockedLogin) {
            throw std::runtime_error(
                "Locked account incorrectly authenticated."
            );
        }

        std::cout << "Account throttling assertion passed.\n";
        std::cout << "All C++ security checks passed.\n";

    } catch (const std::exception& error) {
        std::cerr
            << "Security demonstration failed: "
            << error.what()
            << '\n';

        return 1;
    }

    return 0;
}
