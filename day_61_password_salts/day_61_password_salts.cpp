#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

/*
 * Password-salt governance case study.
 *
 * This program deliberately separates:
 *   1. password policy
 *   2. salt generation
 *   3. password derivation
 *   4. credential state
 *   5. authentication decisions
 *
 * The standard C++17 library does not provide a production password KDF such
 * as Argon2, scrypt, or PBKDF2. Therefore this standalone case study uses a
 * deliberately explicit educational key-derivation construction based on a
 * SHA-256 implementation and repeated domain-separated hashing.
 *
 * Production systems should replace derivePassword() with a vetted Argon2id,
 * scrypt, or PBKDF2 implementation from a maintained cryptographic library.
 */

class Sha256 {
public:
    static std::array<std::uint8_t, 32> hash(
        const std::vector<std::uint8_t>& input
    ) {
        std::uint32_t h0 = 0x6a09e667;
        std::uint32_t h1 = 0xbb67ae85;
        std::uint32_t h2 = 0x3c6ef372;
        std::uint32_t h3 = 0xa54ff53a;
        std::uint32_t h4 = 0x510e527f;
        std::uint32_t h5 = 0x9b05688c;
        std::uint32_t h6 = 0x1f83d9ab;
        std::uint32_t h7 = 0x5be0cd19;

        std::vector<std::uint8_t> message = input;
        std::uint64_t bitLength =
            static_cast<std::uint64_t>(message.size()) * 8ULL;

        message.push_back(0x80);

        while ((message.size() % 64) != 56) {
            message.push_back(0);
        }

        for (int i = 7; i >= 0; --i) {
            message.push_back(
                static_cast<std::uint8_t>((bitLength >> (i * 8)) & 0xff)
            );
        }

        const std::array<std::uint32_t, 64> k = {
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

        auto rotr = [](std::uint32_t x, unsigned n) {
            return (x >> n) | (x << (32 - n));
        };

        for (std::size_t offset = 0; offset < message.size(); offset += 64) {
            std::array<std::uint32_t, 64> w{};

            for (int i = 0; i < 16; ++i) {
                const std::size_t p = offset + i * 4;
                w[i] =
                    (static_cast<std::uint32_t>(message[p]) << 24) |
                    (static_cast<std::uint32_t>(message[p + 1]) << 16) |
                    (static_cast<std::uint32_t>(message[p + 2]) << 8) |
                    static_cast<std::uint32_t>(message[p + 3]);
            }

            for (int i = 16; i < 64; ++i) {
                std::uint32_t s0 =
                    rotr(w[i - 15], 7) ^
                    rotr(w[i - 15], 18) ^
                    (w[i - 15] >> 3);

                std::uint32_t s1 =
                    rotr(w[i - 2], 17) ^
                    rotr(w[i - 2], 19) ^
                    (w[i - 2] >> 10);

                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            std::uint32_t a = h0;
            std::uint32_t b = h1;
            std::uint32_t c = h2;
            std::uint32_t d = h3;
            std::uint32_t e = h4;
            std::uint32_t f = h5;
            std::uint32_t g = h6;
            std::uint32_t h = h7;

            for (int i = 0; i < 64; ++i) {
                std::uint32_t S1 =
                    rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);

                std::uint32_t ch = (e & f) ^ ((~e) & g);

                std::uint32_t temp1 =
                    h + S1 + ch + k[i] + w[i];

                std::uint32_t S0 =
                    rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);

                std::uint32_t maj =
                    (a & b) ^ (a & c) ^ (b & c);

                std::uint32_t temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;
        }

        std::array<std::uint32_t, 8> words = {
            h0, h1, h2, h3, h4, h5, h6, h7
        };

        std::array<std::uint8_t, 32> result{};

        for (std::size_t i = 0; i < words.size(); ++i) {
            result[i * 4] =
                static_cast<std::uint8_t>(words[i] >> 24);
            result[i * 4 + 1] =
                static_cast<std::uint8_t>(words[i] >> 16);
            result[i * 4 + 2] =
                static_cast<std::uint8_t>(words[i] >> 8);
            result[i * 4 + 3] =
                static_cast<std::uint8_t>(words[i]);
        }

        return result;
    }
};

enum class AccountState {
    ACTIVE,
    LOCKED
};

struct PasswordPolicy {
    std::size_t saltBytes = 16;
    std::size_t rounds = 10000;
    std::size_t minimumLength = 12;
    std::size_t maximumFailedAttempts = 5;

    void validate() const {
        if (saltBytes < 16) {
            throw std::invalid_argument("salt size is too small");
        }
        if (rounds < 1000) {
            throw std::invalid_argument("derivation rounds are too small");
        }
        if (minimumLength < 12) {
            throw std::invalid_argument("minimum password length is too small");
        }
    }
};

struct Credential {
    std::string username;
    std::vector<std::uint8_t> salt;
    std::array<std::uint8_t, 32> passwordHash{};
    std::size_t rounds;
    std::size_t failedAttempts = 0;
    AccountState state = AccountState::ACTIVE;
    std::uint64_t passwordVersion = 1;
};

class CredentialEngine {
private:
    PasswordPolicy policy;
    std::map<std::string, Credential> accounts;
    std::mt19937_64 rng;

    std::vector<std::uint8_t> bytesFromString(
        const std::string& value
    ) const {
        return std::vector<std::uint8_t>(value.begin(), value.end());
    }

    std::vector<std::uint8_t> concatenate(
        const std::vector<std::uint8_t>& a,
        const std::vector<std::uint8_t>& b
    ) const {
        std::vector<std::uint8_t> result;
        result.reserve(a.size() + b.size());
        result.insert(result.end(), a.begin(), a.end());
        result.insert(result.end(), b.begin(), b.end());
        return result;
    }

    std::array<std::uint8_t, 32> derivePassword(
        const std::string& password,
        const std::vector<std::uint8_t>& salt,
        std::size_t rounds
    ) const {
        /*
         * Domain separation prevents the derivation stages from being
         * confused with ordinary application hashing.
         *
         * This is a standalone demonstration, not a replacement for a
         * standard password KDF.
         */
        std::vector<std::uint8_t> material =
            bytesFromString("PASSWORD-KDF-V1:");

        auto passwordBytes = bytesFromString(password);
        material = concatenate(material, salt);
        material = concatenate(material, passwordBytes);

        auto digest = Sha256::hash(material);

        for (std::size_t i = 1; i < rounds; ++i) {
            std::vector<std::uint8_t> roundInput(
                digest.begin(),
                digest.end()
            );

            std::uint8_t counter[8]{};

            std::uint64_t value = i;
            for (int j = 7; j >= 0; --j) {
                counter[j] =
                    static_cast<std::uint8_t>(value & 0xff);
                value >>= 8;
            }

            roundInput.insert(
                roundInput.end(),
                std::begin(counter),
                std::end(counter)
            );

            digest = Sha256::hash(roundInput);
        }

        return digest;
    }

    bool constantTimeEqual(
        const std::array<std::uint8_t, 32>& a,
        const std::array<std::uint8_t, 32>& b
    ) const {
        std::uint8_t difference = 0;

        for (std::size_t i = 0; i < a.size(); ++i) {
            difference |= static_cast<std::uint8_t>(a[i] ^ b[i]);
        }

        return difference == 0;
    }

    std::vector<std::uint8_t> generateSalt() {
        std::vector<std::uint8_t> salt(policy.saltBytes);

        std::uniform_int_distribution<unsigned int> distribution(
            0,
            255
        );

        for (auto& value : salt) {
            value = static_cast<std::uint8_t>(distribution(rng));
        }

        return salt;
    }

    void validateUsername(const std::string& username) const {
        if (username.empty() || username.size() > 128) {
            throw std::invalid_argument("invalid username");
        }

        for (char c : username) {
            const bool allowed =
                std::isalnum(static_cast<unsigned char>(c)) ||
                c == '.' || c == '_' || c == '-' || c == '@';

            if (!allowed) {
                throw std::invalid_argument("invalid username");
            }
        }
    }

    void validatePassword(const std::string& password) const {
        if (password.size() < policy.minimumLength) {
            throw std::invalid_argument("password is too short");
        }

        bool nonWhitespace = false;

        for (unsigned char c : password) {
            if (!std::isspace(c)) {
                nonWhitespace = true;
                break;
            }
        }

        if (!nonWhitespace) {
            throw std::invalid_argument(
                "password cannot contain only whitespace"
            );
        }
    }

public:
    explicit CredentialEngine(PasswordPolicy p)
        : policy(std::move(p)),
          rng(std::random_device{}()) {
        policy.validate();
    }

    void createAccount(
        const std::string& username,
        const std::string& password
    ) {
        validateUsername(username);
        validatePassword(password);

        if (accounts.contains(username)) {
            throw std::runtime_error("account already exists");
        }

        Credential credential;
        credential.username = username;
        credential.salt = generateSalt();
        credential.rounds = policy.rounds;
        credential.passwordHash =
            derivePassword(
                password,
                credential.salt,
                credential.rounds
            );

        accounts.emplace(username, std::move(credential));
    }

    bool authenticate(
        const std::string& username,
        const std::string& password
    ) {
        auto it = accounts.find(username);

        if (it == accounts.end()) {
            return false;
        }

        Credential& credential = it->second;

        if (credential.state == AccountState::LOCKED) {
            return false;
        }

        auto candidate =
            derivePassword(
                password,
                credential.salt,
                credential.rounds
            );

        if (constantTimeEqual(candidate, credential.passwordHash)) {
            credential.failedAttempts = 0;
            return true;
        }

        ++credential.failedAttempts;

        if (
            credential.failedAttempts >=
            policy.maximumFailedAttempts
        ) {
            credential.state = AccountState::LOCKED;
        }

        return false;
    }

    void changePassword(
        const std::string& username,
        const std::string& currentPassword,
        const std::string& newPassword
    ) {
        if (!authenticate(username, currentPassword)) {
            throw std::runtime_error(
                "current password is invalid"
            );
        }

        validatePassword(newPassword);

        Credential& credential = accounts.at(username);

        // Never reuse the previous salt during password rotation.
        credential.salt = generateSalt();
        credential.passwordHash =
            derivePassword(
                newPassword,
                credential.salt,
                credential.rounds
            );

        credential.passwordVersion++;
        credential.failedAttempts = 0;
        credential.state = AccountState::ACTIVE;
    }

    void unlock(const std::string& username) {
        Credential& credential = accounts.at(username);
        credential.failedAttempts = 0;
        credential.state = AccountState::ACTIVE;
    }

    const Credential& getCredential(
        const std::string& username
    ) const {
        return accounts.at(username);
    }
};

std::string hex(
    const std::vector<std::uint8_t>& data
) {
    std::ostringstream output;

    for (std::uint8_t value : data) {
        output << std::hex
               << std::setw(2)
               << std::setfill('0')
               << static_cast<int>(value);
    }

    return output.str();
}

int main() {
    try {
        PasswordPolicy policy;
        CredentialEngine engine(policy);

        engine.createAccount(
            "alice@example.com",
            "Correct-Horse-Battery-42!"
        );

        engine.createAccount(
            "bob@example.com",
            "Correct-Horse-Battery-42!"
        );

        const Credential& alice =
            engine.getCredential("alice@example.com");

        const Credential& bob =
            engine.getCredential("bob@example.com");

        if (alice.salt == bob.salt) {
            throw std::runtime_error(
                "unique-salt invariant failed"
            );
        }

        if (
            alice.passwordHash ==
            bob.passwordHash
        ) {
            throw std::runtime_error(
                "different-salt hash invariant failed"
            );
        }

        std::cout
            << "Alice salt: "
            << hex(alice.salt)
            << '\n';

        std::cout
            << "Bob salt:   "
            << hex(bob.salt)
            << '\n';

        std::cout
            << "Correct password: "
            << std::boolalpha
            << engine.authenticate(
                "alice@example.com",
                "Correct-Horse-Battery-42!"
            )
            << '\n';

        std::cout
            << "Wrong password: "
            << engine.authenticate(
                "alice@example.com",
                "wrong-password"
            )
            << '\n';

        for (int i = 0; i < 4; ++i) {
            engine.authenticate(
                "alice@example.com",
                "wrong-password"
            );
        }

        std::cout
            << "Correct password after lock: "
            << engine.authenticate(
                "alice@example.com",
                "Correct-Horse-Battery-42!"
            )
            << '\n';

        engine.unlock("alice@example.com");

        engine.changePassword(
            "alice@example.com",
            "Correct-Horse-Battery-42!",
            "New-Longer-Password-99!"
        );

        std::cout
            << "New password after rotation: "
            << engine.authenticate(
                "alice@example.com",
                "New-Longer-Password-99!"
            )
            << '\n';

        const Credential& rotated =
            engine.getCredential("alice@example.com");

        std::cout
            << "Password version: "
            << rotated.passwordVersion
            << '\n';

        /*
         * Complexity:
         * - account lookup: O(log n) because std::map is used
         * - salt generation: O(salt size)
         * - derivation: O(rounds)
         *
         * Security:
         * - salts are unique per password
         * - hashes are compared without early exit
         * - plaintext passwords are never stored
         */
        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
