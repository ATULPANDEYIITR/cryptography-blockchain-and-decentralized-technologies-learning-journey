#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

/*
 * SHA-3 and Keccak repository artifact verification engine.
 *
 * This program implements the Keccak-f[1600] permutation and the
 * SHA3-256 sponge construction directly, without external dependencies.
 *
 * Compile: g++ -std=c++17 -O2 sha3_keccak.cpp -o sha3_keccak
 */

namespace crypto {

constexpr std::size_t STATE_BYTES = 200;
constexpr std::size_t SHA3_256_RATE = 136;

constexpr std::array<std::uint64_t, 24> ROUND_CONSTANTS = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

constexpr std::array<int, 25> ROTATION = {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};

constexpr std::uint64_t rotate_left(std::uint64_t value, int amount) {
    if (amount == 0) return value;
    return (value << amount) | (value >> (64 - amount));
}

using State = std::array<std::uint64_t, 25>;

void keccak_f1600(State& state) {
    for (std::uint64_t rc : ROUND_CONSTANTS) {
        std::array<std::uint64_t, 5> column{};
        std::array<std::uint64_t, 5> delta{};
        State rotated{};

        // Theta: mix the parity of each five-lane column.
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                column[x] ^= state[x + 5 * y];
            }
        }

        for (int x = 0; x < 5; ++x) {
            delta[x] = column[(x + 4) % 5] ^
                       rotate_left(column[(x + 1) % 5], 1);
        }

        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x + 5 * y] ^= delta[x];
            }
        }

        // Rho and Pi rotate lanes and permute their positions.
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                rotated[y + 5 * ((2 * x + 3 * y) % 5)] =
                    rotate_left(state[x + 5 * y], ROTATION[x + 5 * y]);
            }
        }

        // Chi is nonlinear and acts independently on each row.
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                state[x + 5 * y] = rotated[x + 5 * y] ^
                    ((~rotated[(x + 1) % 5 + 5 * y]) &
                     rotated[(x + 2) % 5 + 5 * y]);
            }
        }

        // Iota injects the round constant.
        state[0] ^= rc;
    }
}

class Sha3_256 {
public:
    static std::array<std::uint8_t, 32> digest(std::string_view input) {
        State state{};
        std::vector<std::uint8_t> padded(input.begin(), input.end());

        // SHA-3 domain separation differs from legacy Keccak padding.
        padded.push_back(0x06);
        while (padded.size() % SHA3_256_RATE != SHA3_256_RATE - 1) {
            padded.push_back(0x00);
        }
        padded.push_back(0x80);

        for (std::size_t offset = 0; offset < padded.size();
             offset += SHA3_256_RATE) {
            for (std::size_t i = 0; i < SHA3_256_RATE; ++i) {
                state[i / 8] ^=
                    static_cast<std::uint64_t>(padded[offset + i])
                    << (8 * (i % 8));
            }
            keccak_f1600(state);
        }

        std::array<std::uint8_t, 32> output{};
        for (std::size_t i = 0; i < output.size(); ++i) {
            output[i] = static_cast<std::uint8_t>(
                (state[i / 8] >> (8 * (i % 8))) & 0xff
            );
        }
        return output;
    }

    static std::string hex(std::string_view input) {
        const auto bytes = digest(input);
        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (std::uint8_t byte : bytes) {
            output << std::setw(2) << static_cast<unsigned>(byte);
        }
        return output.str();
    }
};

} // namespace crypto

enum class ArtifactState {
    PENDING,
    VERIFIED,
    REJECTED
};

struct Artifact {
    std::string name;
    std::string content;
    std::string expected_digest;
    ArtifactState state = ArtifactState::PENDING;
};

class RepositoryVerifier {
private:
    std::map<std::string, Artifact> artifacts_;

public:
    void add_artifact(Artifact artifact) {
        if (artifact.name.empty() || artifact.name.size() > 200) {
            throw std::invalid_argument("Artifact name is invalid.");
        }
        if (artifact.content.size() > 16 * 1024 * 1024) {
            throw std::invalid_argument("Artifact exceeds the 16 MiB limit.");
        }
        if (artifact.expected_digest.size() != 64 ||
            !std::all_of(
                artifact.expected_digest.begin(),
                artifact.expected_digest.end(),
                [](unsigned char c) {
                    return (c >= '0' && c <= '9') ||
                           (c >= 'a' && c <= 'f') ||
                           (c >= 'A' && c <= 'F');
                })) {
            throw std::invalid_argument("Expected digest must be 64 hex characters.");
        }
        if (artifacts_.count(artifact.name)) {
            throw std::invalid_argument("Duplicate artifact name.");
        }
        artifacts_.emplace(artifact.name, std::move(artifact));
    }

    void verify_all() {
        for (auto& entry : artifacts_) {
            Artifact& artifact = entry.second;
            const std::string actual = crypto::Sha3_256::hex(artifact.content);

            // Digest encodings are public; comparison is normalized to lowercase.
            std::string expected = artifact.expected_digest;
            std::transform(expected.begin(), expected.end(), expected.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            artifact.state = (actual == expected)
                ? ArtifactState::VERIFIED
                : ArtifactState::REJECTED;
        }
    }

    void print_report() const {
        for (const auto& entry : artifacts_) {
            const auto& artifact = entry.second;
            const char* status =
                artifact.state == ArtifactState::VERIFIED ? "VERIFIED" :
                artifact.state == ArtifactState::REJECTED ? "REJECTED" :
                "PENDING";

            std::cout << artifact.name << " | " << status
                      << " | " << crypto::Sha3_256::hex(artifact.content)
                      << '\n';
        }
    }
};

int main() {
    try {
        const std::string abc_expected =
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";

        if (crypto::Sha3_256::hex("abc") != abc_expected) {
            throw std::runtime_error("SHA3-256 known-answer test failed.");
        }

        RepositoryVerifier repository;

        const std::string source = "int main() { return 0; }\n";
        const std::string manifest = "{\"version\":\"1.0\"}\n";

        repository.add_artifact({
            "src/main.cpp",
            source,
            crypto::Sha3_256::hex(source)
        });

        repository.add_artifact({
            "release.json",
            manifest,
            std::string(64, '0')
        });

        repository.verify_all();
        repository.print_report();

        std::cout << "Known-answer test: PASSED\n";
        std::cout << "SHA3-256 empty message: "
                  << crypto::Sha3_256::hex("") << '\n';

        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Verification error: " << error.what() << '\n';
        return 1;
    }
}
