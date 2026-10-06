#include <algorithm>
#include <array>
#include <bitset>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

/*
 * Technical case study: cryptographic algorithm migration from DES.
 *
 * The program models a legacy enterprise data-protection service that must
 * evaluate whether DES, 3DES, or AES is appropriate for a new deployment.
 *
 * The DES implementation is complete enough to verify the standard test
 * vector. The migration engine then evaluates key size, block size, legacy
 * status, and operational constraints.
 */

class DES {
private:
    static constexpr array<int, 64> IP = {
        58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
        62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
        57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
        61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
    };

    static constexpr array<int, 64> FP = {
        40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,
        38,6,46,14,54,22,62,30,37,5,45,13,21,61,29,
        36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,
        34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25
    };

    static constexpr array<int, 48> E = {
        32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,
        12,13,12,13,14,15,16,17,16,17,18,19,
        20,21,20,21,22,23,24,25,24,25,26,27,
        28,29,28,29,30,31,32,1
    };

    static constexpr array<int, 32> P = {
        16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25
    };

    static constexpr array<int, 56> PC1 = {
        57,49,41,33,25,17,9,1,58,50,42,34,26,18,
        10,2,59,51,43,35,27,19,11,3,60,52,44,36,
        63,55,47,39,31,23,15,7,62,54,46,38,30,22,
        14,6,61,53,45,37,29,21,13,5,28,20,12,4
    };

    static constexpr array<int, 48> PC2 = {
        14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
        26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,
        51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32
    };

    static constexpr array<int, 16> SHIFTS =
        {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

    static constexpr int S[8][4][16] = {
        {
            {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
            {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
            {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
            {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}
        },
        {
            {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
            {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
            {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
            {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}
        },
        {
            {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
            {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
            {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
            {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}
        },
        {
            {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
            {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
            {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
            {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}
        },
        {
            {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
            {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
            {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
            {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}
        },
        {
            {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
            {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
            {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
            {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}
        },
        {
            {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
            {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
            {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
            {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}
        },
        {
            {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
            {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
            {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
            {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}
        }
    };

    static uint64_t permute(uint64_t value, const int* table,
                            size_t tableSize, int inputBits) {
        uint64_t result = 0;
        for (size_t i = 0; i < tableSize; ++i) {
            result <<= 1;
            result |= (value >> (inputBits - table[i])) & 1ULL;
        }
        return result;
    }

    static uint32_t rotate28(uint32_t value, int amount) {
        constexpr uint32_t mask = 0x0FFFFFFF;
        return ((value << amount) | (value >> (28 - amount))) & mask;
    }

    static array<uint64_t, 16> makeKeys(uint64_t key) {
        uint64_t selected = permute(key, PC1.data(), PC1.size(), 64);
        uint32_t c = static_cast<uint32_t>(selected >> 28);
        uint32_t d = static_cast<uint32_t>(selected & 0x0FFFFFFF);

        array<uint64_t, 16> keys{};

        for (size_t i = 0; i < 16; ++i) {
            c = rotate28(c, SHIFTS[i]);
            d = rotate28(d, SHIFTS[i]);
            uint64_t combined = (static_cast<uint64_t>(c) << 28) | d;
            keys[i] = permute(combined, PC2.data(), PC2.size(), 56);
        }

        return keys;
    }

    static uint32_t feistel(uint32_t right, uint64_t key) {
        uint64_t expanded = permute(right, E.data(), E.size(), 32);
        uint64_t mixed = expanded ^ key;

        uint32_t substituted = 0;

        for (int box = 0; box < 8; ++box) {
            uint8_t six = static_cast<uint8_t>(
                (mixed >> (42 - 6 * box)) & 0x3F
            );

            int row = ((six & 0x20) >> 4) | (six & 1);
            int column = (six >> 1) & 0x0F;

            substituted = (substituted << 4) |
                          static_cast<uint32_t>(S[box][row][column]);
        }

        return static_cast<uint32_t>(
            permute(substituted, P.data(), P.size(), 32)
        );
    }

public:
    static uint64_t crypt(uint64_t block, uint64_t key, bool decrypt = false) {
        auto keys = makeKeys(key);

        if (decrypt) {
            reverse(keys.begin(), keys.end());
        }

        uint64_t state = permute(block, IP.data(), IP.size(), 64);
        uint32_t left = static_cast<uint32_t>(state >> 32);
        uint32_t right = static_cast<uint32_t>(state);

        for (uint64_t roundKey : keys) {
            uint32_t oldRight = right;
            right = left ^ feistel(right, roundKey);
            left = oldRight;
        }

        uint64_t preOutput =
            (static_cast<uint64_t>(right) << 32) | left;

        return permute(preOutput, FP.data(), FP.size(), 64);
    }
};

enum class Algorithm {
    DES,
    TripleDES,
    AES128,
    AES256
};

struct AlgorithmProfile {
    Algorithm algorithm;
    string name;
    int effectiveKeyBits;
    int blockBits;
    string status;
    string reason;
};

class MigrationEngine {
private:
    vector<AlgorithmProfile> profiles;

public:
    MigrationEngine() {
        profiles = {
            {Algorithm::DES, "DES", 56, 64, "REJECT",
             "56-bit effective key space is vulnerable to exhaustive search."},

            {Algorithm::TripleDES, "3DES", 112, 64, "LEGACY",
             "Higher effective strength than DES, but the 64-bit block remains."},

            {Algorithm::AES128, "AES-128", 128, 128, "ACCEPT",
             "Modern block size and key space."},

            {Algorithm::AES256, "AES-256", 256, 128, "ACCEPT",
             "Large key space and modern block size."}
        };
    }

    const vector<AlgorithmProfile>& assess() const {
        return profiles;
    }
};

static string hex64(uint64_t value) {
    ostringstream output;
    output << uppercase << hex << setw(16) << setfill('0') << value;
    return output.str();
}

static void printProfile(const AlgorithmProfile& profile) {
    cout << left << setw(12) << profile.name
         << setw(18) << profile.effectiveKeyBits
         << setw(14) << profile.blockBits
         << setw(10) << profile.status
         << profile.reason << '\n';
}

static void knownVectorTest() {
    const uint64_t key = 0x133457799BBCDFF1ULL;
    const uint64_t plaintext = 0x0123456789ABCDEFULL;
    const uint64_t expected = 0x85E813540F0AB405ULL;

    const uint64_t ciphertext = DES::crypt(plaintext, key);
    const uint64_t recovered = DES::crypt(ciphertext, key, true);

    cout << "DES known-vector verification\n";
    cout << "  Ciphertext: " << hex64(ciphertext) << '\n';
    cout << "  Expected  : " << hex64(expected) << '\n';
    cout << "  Valid     : " << boolalpha << (ciphertext == expected) << '\n';
    cout << "  Recovered : " << hex64(recovered) << "\n\n";
}

static void avalancheTest() {
    const uint64_t key = 0x133457799BBCDFF1ULL;
    const uint64_t a = DES::crypt(0x0123456789ABCDEFULL, key);
    const uint64_t b = DES::crypt(0x0123456789ABCDEEULL, key);

    uint64_t difference = a ^ b;
    int changedBits = 0;

    while (difference != 0) {
        difference &= difference - 1;
        ++changedBits;
    }

    cout << "Avalanche behavior\n";
    cout << "  Cipher A: " << hex64(a) << '\n';
    cout << "  Cipher B: " << hex64(b) << '\n';
    cout << "  Changed bits: " << changedBits << "/64\n\n";
}

static void blockSizeAnalysis() {
    const long double birthdayBlocks = pow(2.0L, 32.0L);
    const long double bytes = birthdayBlocks * 8.0L;
    const long double gib = bytes / pow(1024.0L, 3.0L);

    cout << "64-bit block-size analysis\n";
    cout << "  Approximate birthday-bound scale: 2^32 blocks\n";
    cout << "  Approximate data volume: "
         << fixed << setprecision(1) << gib << " GiB\n";
    cout << "  AES uses a 128-bit block, greatly increasing this scale.\n\n";
}

static void reducedBruteForceExplanation() {
    const uint64_t demonstrationSpace = 1ULL << 16;
    const uint64_t averageTrials = demonstrationSpace / 2;

    cout << "Brute-force economics\n";
    cout << "  Demonstration key space: 2^16 = "
         << demonstrationSpace << " candidates\n";
    cout << "  Average demonstration trials: "
         << averageTrials << '\n';
    cout << "  Real DES key space: 2^56 = "
         << (1ULL << 56) << " candidates\n";
    cout << "  The important security change is computational feasibility,\n";
    cout << "  not a failure of DES's encryption/decryption inverse relationship.\n\n";
}

int main() {
    try {
        cout << "============================================================\n";
        cout << "WHY DES BECAME OUTDATED: ENTERPRISE MIGRATION CASE STUDY\n";
        cout << "============================================================\n\n";

        knownVectorTest();
        avalancheTest();
        blockSizeAnalysis();
        reducedBruteForceExplanation();

        MigrationEngine engine;

        cout << "Algorithm migration assessment\n";
        cout << left
             << setw(12) << "Algorithm"
             << setw(18) << "Effective key"
             << setw(14) << "Block"
             << setw(10) << "Status"
             << "Engineering reason\n";
        cout << string(100, '-') << '\n';

        for (const auto& profile : engine.assess()) {
            printProfile(profile);
        }

        cout << "\nEnterprise design interpretation\n";
        cout << "DES is rejected for new security-sensitive deployments because\n";
        cout << "its 56-bit effective key space no longer provides adequate brute-\n";
        cout << "force resistance. The 64-bit block also creates limits for large\n";
        cout << "data volumes. 3DES can preserve compatibility in legacy systems,\n";
        cout << "but it carries the same 64-bit block constraint and much higher\n";
        cout << "computational cost. AES provides a substantially larger security\n";
        cout << "margin and a 128-bit block size.\n";

        return 0;
    } catch (const exception& error) {
        cerr << "Fatal error: " << error.what() << '\n';
        return 1;
    }
}
