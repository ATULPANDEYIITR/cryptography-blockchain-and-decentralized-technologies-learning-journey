#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

/*
 * Substitution Cipher Case Study
 * ==============================
 *
 * Industry-style scenario:
 *
 * A historical records system contains archived messages that were protected
 * with a monoalphabetic substitution cipher. The modern security team needs
 * to:
 *
 * 1. Represent substitution keys safely.
 * 2. Encrypt and decrypt legitimate records.
 * 3. Validate keys and input.
 * 4. Analyze ciphertext statistics.
 * 5. Identify repeated-letter patterns.
 * 6. Demonstrate why the historical protection is unsuitable for modern
 *    confidentiality.
 * 7. Build an educational cryptanalysis workflow.
 *
 * Compile:
 *     g++ -std=c++17 -O2 substitution_ciphers.cpp -o substitution_ciphers
 */

namespace crypto_case_study {

constexpr std::size_t ALPHABET_SIZE = 26;
const std::string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


// -----------------------------------------------------------------------------
// 1. GENERAL UTILITIES
// -----------------------------------------------------------------------------

bool isLetter(char character) {
    return std::isalpha(static_cast<unsigned char>(character)) != 0 &&
           std::toupper(static_cast<unsigned char>(character)) >= 'A' &&
           std::toupper(static_cast<unsigned char>(character)) <= 'Z';
}

char toUpperLetter(char character) {
    return static_cast<char>(
        std::toupper(static_cast<unsigned char>(character))
    );
}

int letterIndex(char character) {
    char upper = toUpperLetter(character);
    return upper - 'A';
}

int mod(int value, int modulus) {
    return ((value % modulus) + modulus) % modulus;
}

int gcd(int a, int b) {
    a = std::abs(a);
    b = std::abs(b);

    while (b != 0) {
        int remainder = a % b;
        a = b;
        b = remainder;
    }

    return a;
}

int modularInverse(int value, int modulus) {
    value = mod(value, modulus);

    for (int candidate = 1; candidate < modulus; ++candidate) {
        if (mod(value * candidate, modulus) == 1) {
            return candidate;
        }
    }

    throw std::invalid_argument(
        "No modular inverse exists for the supplied value."
    );
}

bool isValidSubstitutionKey(const std::string& key) {
    if (key.size() != ALPHABET_SIZE) {
        return false;
    }

    std::set<char> uniqueLetters;

    for (char character : key) {
        char upper = toUpperLetter(character);

        if (ALPHABET.find(upper) == std::string::npos) {
            return false;
        }

        uniqueLetters.insert(upper);
    }

    return uniqueLetters.size() == ALPHABET_SIZE;
}


// -----------------------------------------------------------------------------
// 2. SUBSTITUTION KEY
// -----------------------------------------------------------------------------

class SubstitutionKey {
private:
    std::string encryptionKey;
    std::string decryptionKey;

public:
    explicit SubstitutionKey(const std::string& key) {
        if (!isValidSubstitutionKey(key)) {
            throw std::invalid_argument(
                "A substitution key must contain every A-Z letter exactly once."
            );
        }

        encryptionKey.reserve(ALPHABET_SIZE);
        decryptionKey.assign(ALPHABET_SIZE, ' ');

        for (char character : key) {
            encryptionKey.push_back(toUpperLetter(character));
        }

        for (std::size_t plaintextIndex = 0;
             plaintextIndex < ALPHABET_SIZE;
             ++plaintextIndex) {

            char ciphertextLetter = encryptionKey[plaintextIndex];
            int ciphertextIndex = letterIndex(ciphertextLetter);

            decryptionKey[ciphertextIndex] =
                static_cast<char>('A' + plaintextIndex);
        }
    }

    const std::string& encryption() const {
        return encryptionKey;
    }

    const std::string& decryption() const {
        return decryptionKey;
    }
};


// -----------------------------------------------------------------------------
// 3. MONOALPHABETIC CIPHER
// -----------------------------------------------------------------------------

class SubstitutionCipher {
private:
    SubstitutionKey key;

    std::string transform(
        const std::string& input,
        const std::string& mapping
    ) const {
        std::string output;
        output.reserve(input.size());

        for (char character : input) {
            if (!isLetter(character)) {
                output.push_back(character);
                continue;
            }

            int index = letterIndex(character);
            char transformed = mapping[index];

            if (std::islower(static_cast<unsigned char>(character))) {
                transformed = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(transformed))
                );
            }

            output.push_back(transformed);
        }

        return output;
    }

public:
    explicit SubstitutionCipher(const SubstitutionKey& substitutionKey)
        : key(substitutionKey) {}

    std::string encrypt(const std::string& plaintext) const {
        return transform(plaintext, key.encryption());
    }

    std::string decrypt(const std::string& ciphertext) const {
        return transform(ciphertext, key.decryption());
    }
};


// -----------------------------------------------------------------------------
// 4. FREQUENCY ANALYSIS
// -----------------------------------------------------------------------------

struct FrequencyRecord {
    char letter;
    int count;
    double percentage;
};

std::array<int, ALPHABET_SIZE> countLetters(const std::string& text) {
    std::array<int, ALPHABET_SIZE> counts{};

    for (char character : text) {
        if (isLetter(character)) {
            ++counts[letterIndex(character)];
        }
    }

    return counts;
}

std::vector<FrequencyRecord> frequencyAnalysis(
    const std::string& text
) {
    const auto counts = countLetters(text);

    int total = std::accumulate(
        counts.begin(),
        counts.end(),
        0
    );

    std::vector<FrequencyRecord> records;

    for (int index = 0; index < static_cast<int>(ALPHABET_SIZE); ++index) {
        if (counts[index] == 0) {
            continue;
        }

        double percentage =
            static_cast<double>(counts[index]) /
            static_cast<double>(total) * 100.0;

        records.push_back({
            static_cast<char>('A' + index),
            counts[index],
            percentage
        });
    }

    std::sort(
        records.begin(),
        records.end(),
        [](const FrequencyRecord& left, const FrequencyRecord& right) {
            if (left.count != right.count) {
                return left.count > right.count;
            }

            return left.letter < right.letter;
        }
    );

    return records;
}

void printFrequencyAnalysis(const std::string& text) {
    auto records = frequencyAnalysis(text);

    std::cout << "\nLetter frequency analysis\n";
    std::cout << "-------------------------\n";
    std::cout << std::left
              << std::setw(10) << "Letter"
              << std::setw(10) << "Count"
              << std::setw(12) << "Percent"
              << '\n';

    for (const auto& record : records) {
        std::cout << std::left
                  << std::setw(10) << record.letter
                  << std::setw(10) << record.count
                  << std::fixed
                  << std::setprecision(2)
                  << std::setw(12) << record.percentage
                  << '\n';
    }
}


// -----------------------------------------------------------------------------
// 5. INDEX OF COINCIDENCE
// -----------------------------------------------------------------------------

double indexOfCoincidence(const std::string& text) {
    auto counts = countLetters(text);

    int total = std::accumulate(
        counts.begin(),
        counts.end(),
        0
    );

    if (total < 2) {
        return 0.0;
    }

    long long numerator = 0;

    for (int count : counts) {
        numerator += static_cast<long long>(count) * (count - 1);
    }

    long long denominator =
        static_cast<long long>(total) * (total - 1);

    return static_cast<double>(numerator) /
           static_cast<double>(denominator);
}


// -----------------------------------------------------------------------------
// 6. WORD PATTERN ANALYSIS
// -----------------------------------------------------------------------------

std::vector<int> wordPattern(const std::string& word) {
    std::map<char, int> mapping;
    std::vector<int> pattern;

    int nextIdentifier = 0;

    for (char character : word) {
        char upper = toUpperLetter(character);

        auto iterator = mapping.find(upper);

        if (iterator == mapping.end()) {
            mapping[upper] = nextIdentifier;
            pattern.push_back(nextIdentifier);
            ++nextIdentifier;
        } else {
            pattern.push_back(iterator->second);
        }
    }

    return pattern;
}

std::string patternToString(const std::vector<int>& pattern) {
    std::ostringstream output;

    output << "(";

    for (std::size_t index = 0; index < pattern.size(); ++index) {
        output << pattern[index];

        if (index + 1 < pattern.size()) {
            output << ", ";
        }
    }

    output << ")";

    return output.str();
}


// -----------------------------------------------------------------------------
// 7. SIMPLE N-GRAM SCORING
// -----------------------------------------------------------------------------

const std::map<std::string, double> COMMON_BIGRAMS = {
    {"TH", 5.0}, {"HE", 5.0}, {"IN", 4.5}, {"ER", 4.5},
    {"AN", 4.0}, {"RE", 4.0}, {"ON", 4.0}, {"AT", 3.8},
    {"EN", 3.8}, {"ND", 3.7}, {"TI", 3.6}, {"ES", 3.6},
    {"OR", 3.5}, {"TE", 3.5}, {"OF", 3.4}, {"ED", 3.3},
    {"IS", 3.2}, {"IT", 3.2}, {"AL", 3.0}, {"AR", 3.0},
    {"ST", 3.0}, {"TO", 3.0}, {"NT", 3.0}, {"NG", 2.8}
};

const std::map<std::string, double> COMMON_TRIGRAMS = {
    {"THE", 8.0}, {"AND", 7.0}, {"ING", 7.0}, {"HER", 5.0},
    {"ENT", 4.5}, {"THA", 4.2}, {"NTH", 4.2}, {"WAS", 4.0},
    {"ETH", 4.0}, {"FOR", 4.0}, {"HAT", 3.8}, {"ION", 3.8},
    {"TIO", 3.6}, {"VER", 3.5}, {"EST", 3.5}, {"TER", 3.3}
};

std::string lettersOnly(const std::string& text) {
    std::string result;

    for (char character : text) {
        if (isLetter(character)) {
            result.push_back(toUpperLetter(character));
        }
    }

    return result;
}

double ngramScore(const std::string& text) {
    std::string letters = lettersOnly(text);
    double score = 0.0;

    for (std::size_t index = 0; index + 1 < letters.size(); ++index) {
        std::string bigram = letters.substr(index, 2);

        auto iterator = COMMON_BIGRAMS.find(bigram);

        if (iterator != COMMON_BIGRAMS.end()) {
            score += iterator->second;
        }
    }

    for (std::size_t index = 0; index + 2 < letters.size(); ++index) {
        std::string trigram = letters.substr(index, 3);

        auto iterator = COMMON_TRIGRAMS.find(trigram);

        if (iterator != COMMON_TRIGRAMS.end()) {
            score += iterator->second;
        }
    }

    return score;
}


// -----------------------------------------------------------------------------
// 8. CAESAR CIPHER
// -----------------------------------------------------------------------------

class CaesarCipher {
private:
    int shift;

    std::string transform(
        const std::string& text,
        int direction
    ) const {
        std::string result;
        result.reserve(text.size());

        for (char character : text) {
            if (!isLetter(character)) {
                result.push_back(character);
                continue;
            }

            int index = letterIndex(character);
            int transformedIndex =
                mod(index + direction * shift, 26);

            char transformed =
                static_cast<char>('A' + transformedIndex);

            if (std::islower(static_cast<unsigned char>(character))) {
                transformed = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(transformed))
                );
            }

            result.push_back(transformed);
        }

        return result;
    }

public:
    explicit CaesarCipher(int requestedShift)
        : shift(mod(requestedShift, 26)) {}

    std::string encrypt(const std::string& plaintext) const {
        return transform(plaintext, 1);
    }

    std::string decrypt(const std::string& ciphertext) const {
        return transform(ciphertext, -1);
    }
};


// -----------------------------------------------------------------------------
// 9. AFFINE CIPHER
// -----------------------------------------------------------------------------

class AffineCipher {
private:
    int a;
    int b;
    int inverseA;

public:
    AffineCipher(int multiplier, int offset)
        : a(multiplier), b(mod(offset, 26)) {

        if (gcd(a, 26) != 1) {
            throw std::invalid_argument(
                "Affine multiplier must be coprime with 26."
            );
        }

        inverseA = modularInverse(a, 26);
    }

    std::string encrypt(const std::string& plaintext) const {
        std::string result;

        for (char character : plaintext) {
            if (!isLetter(character)) {
                result.push_back(character);
                continue;
            }

            int x = letterIndex(character);
            int y = mod(a * x + b, 26);

            char transformed =
                static_cast<char>('A' + y);

            if (std::islower(static_cast<unsigned char>(character))) {
                transformed = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(transformed))
                );
            }

            result.push_back(transformed);
        }

        return result;
    }

    std::string decrypt(const std::string& ciphertext) const {
        std::string result;

        for (char character : ciphertext) {
            if (!isLetter(character)) {
                result.push_back(character);
                continue;
            }

            int y = letterIndex(character);
            int x = mod(inverseA * (y - b), 26);

            char transformed =
                static_cast<char>('A' + x);

            if (std::islower(static_cast<unsigned char>(character))) {
                transformed = static_cast<char>(
                    std::tolower(static_cast<unsigned char>(transformed))
                );
            }

            result.push_back(transformed);
        }

        return result;
    }

    int getA() const {
        return a;
    }

    int getB() const {
        return b;
    }

    int getInverseA() const {
        return inverseA;
    }
};


// -----------------------------------------------------------------------------
// 10. ARCHIVED MESSAGE RECORD
// -----------------------------------------------------------------------------

struct ArchivedMessage {
    int recordId;
    std::string owner;
    std::string plaintext;
    std::string ciphertext;
};


// -----------------------------------------------------------------------------
// 11. ARCHIVE SECURITY SERVICE
// -----------------------------------------------------------------------------

class ArchiveSecurityService {
private:
    SubstitutionCipher cipher;
    std::vector<ArchivedMessage> records;

public:
    explicit ArchiveSecurityService(const SubstitutionKey& key)
        : cipher(key) {}

    int addRecord(
        int recordId,
        const std::string& owner,
        const std::string& plaintext
    ) {
        if (recordId <= 0) {
            throw std::invalid_argument(
                "Record ID must be positive."
            );
        }

        if (owner.empty()) {
            throw std::invalid_argument(
                "Record owner cannot be empty."
            );
        }

        if (plaintext.empty()) {
            throw std::invalid_argument(
                "Plaintext cannot be empty."
            );
        }

        auto duplicate = std::find_if(
            records.begin(),
            records.end(),
            [recordId](const ArchivedMessage& record) {
                return record.recordId == recordId;
            }
        );

        if (duplicate != records.end()) {
            throw std::invalid_argument(
                "A record with this ID already exists."
            );
        }

        ArchivedMessage record{
            recordId,
            owner,
            plaintext,
            cipher.encrypt(plaintext)
        };

        records.push_back(record);

        return recordId;
    }

    const std::vector<ArchivedMessage>& getRecords() const {
        return records;
    }

    std::string decryptRecord(int recordId) const {
        auto iterator = std::find_if(
            records.begin(),
            records.end(),
            [recordId](const ArchivedMessage& record) {
                return record.recordId == recordId;
            }
        );

        if (iterator == records.end()) {
            throw std::out_of_range(
                "Requested record does not exist."
            );
        }

        return cipher.decrypt(iterator->ciphertext);
    }

    void printArchive() const {
        std::cout << "\nArchive records\n";
        std::cout << "===============\n";

        for (const auto& record : records) {
            std::cout << "Record ID : " << record.recordId << '\n';
            std::cout << "Owner     : " << record.owner << '\n';
            std::cout << "Plaintext : " << record.plaintext << '\n';
            std::cout << "Ciphertext: " << record.ciphertext << '\n';
            std::cout << '\n';
        }
    }
};


// -----------------------------------------------------------------------------
// 12. SECURITY ANALYZER
// -----------------------------------------------------------------------------

class SecurityAnalyzer {
public:
    static void analyze(
        const std::string& ciphertext
    ) {
        std::cout << "\nSecurity analysis\n";
        std::cout << "=================\n";

        auto records = frequencyAnalysis(ciphertext);

        if (!records.empty()) {
            std::cout << "Most frequent symbol: "
                      << records.front().letter
                      << " (" << records.front().count
                      << " occurrences)\n";
        }

        std::cout << "Index of coincidence: "
                  << std::fixed
                  << std::setprecision(4)
                  << indexOfCoincidence(ciphertext)
                  << '\n';

        std::cout << "N-gram language score: "
                  << ngramScore(ciphertext)
                  << '\n';

        std::cout
            << "Assessment: a fixed substitution preserves substantial "
               "statistical structure from natural language.\n";

        std::cout
            << "This is an educational analysis, not a modern security "
               "evaluation framework.\n";
    }
};


// -----------------------------------------------------------------------------
// 13. TESTING
// -----------------------------------------------------------------------------

void require(
    bool condition,
    const std::string& message
) {
    if (!condition) {
        throw std::runtime_error(
            "Test failed: " + message
        );
    }
}

void runTests() {
    const std::string plaintext =
        "Attack at dawn! 123.";

    CaesarCipher caesar(3);

    require(
        caesar.decrypt(caesar.encrypt(plaintext)) == plaintext,
        "Caesar round trip"
    );

    AffineCipher affine(5, 8);

    require(
        affine.decrypt(affine.encrypt(plaintext)) == plaintext,
        "Affine round trip"
    );

    SubstitutionKey key(
        "QWERTYUIOPASDFGHJKLZXCVBNM"
    );

    SubstitutionCipher substitution(key);

    require(
        substitution.decrypt(substitution.encrypt(plaintext)) == plaintext,
        "Substitution round trip"
    );

    require(
        modularInverse(5, 26) == 21,
        "Modular inverse"
    );

    auto pattern = wordPattern("HELLO");

    require(
        pattern == std::vector<int>{0, 1, 2, 2, 3},
        "HELLO pattern"
    );

    require(
        gcd(5, 26) == 1,
        "GCD"
    );

    try {
        SubstitutionKey invalid("ABC");
        (void)invalid;
        throw std::runtime_error(
            "Invalid substitution key was accepted."
        );
    } catch (const std::invalid_argument&) {
        // Expected failure.
    }

    try {
        AffineCipher invalidAffine(2, 5);
        (void)invalidAffine;
        throw std::runtime_error(
            "Invalid affine parameter was accepted."
        );
    } catch (const std::invalid_argument&) {
        // Expected failure.
    }

    std::cout << "\nAll C++ tests passed.\n";
}


// -----------------------------------------------------------------------------
// 14. CASE STUDY EXECUTION
// -----------------------------------------------------------------------------

void runCaseStudy() {
    std::cout << "SUBSTITUTION CIPHER ARCHIVE CASE STUDY\n";
    std::cout << "======================================\n";

    /*
     * The key is a permutation of the alphabet.
     *
     * Plaintext:
     *     ABCDEFGHIJKLMNOPQRSTUVWXYZ
     *
     * Ciphertext:
     *     QWERTYUIOPASDFGHJKLZXCVBNM
     *
     * The mapping is deterministic and therefore reversible.
     */
    SubstitutionKey key(
        "QWERTYUIOPASDFGHJKLZXCVBNM"
    );

    SubstitutionCipher cipher(key);

    std::string message =
        "The security team is reviewing an archived substitution cipher.";

    std::string ciphertext =
        cipher.encrypt(message);

    std::string recovered =
        cipher.decrypt(ciphertext);

    std::cout << "\nOriginal message:\n";
    std::cout << message << '\n';

    std::cout << "\nEncrypted message:\n";
    std::cout << ciphertext << '\n';

    std::cout << "\nRecovered message:\n";
    std::cout << recovered << '\n';

    require(
        recovered == message,
        "Archive encryption/decryption integrity"
    );

    /*
     * A realistic archive can contain multiple records. The service
     * encapsulates validation, encryption, storage, and retrieval.
     */
    ArchiveSecurityService archive(key);

    archive.addRecord(
        1001,
        "Operations",
        "The backup server is ready."
    );

    archive.addRecord(
        1002,
        "Research",
        "The substitution key is stored separately."
    );

    archive.addRecord(
        1003,
        "Audit",
        "Historical ciphertext requires statistical analysis."
    );

    archive.printArchive();

    std::cout << "Decrypting record 1002:\n";
    std::cout << archive.decryptRecord(1002) << '\n';

    /*
     * Analyze all ciphertext together. Aggregating enough text makes
     * frequency analysis more informative than analyzing a tiny message.
     */
    std::string combinedCiphertext;

    for (const auto& record : archive.getRecords()) {
        combinedCiphertext += record.ciphertext;
        combinedCiphertext += ' ';
    }

    printFrequencyAnalysis(combinedCiphertext);

    SecurityAnalyzer::analyze(combinedCiphertext);

    /*
     * Repeated-letter structure is an important leakage channel.
     *
     * "LETTER" has a repeated-letter pattern:
     * L E T T E R
     * 0 1 2 2 1 3
     */
    std::cout << "\nPattern analysis\n";
    std::cout << "================\n";

    for (const std::string& word : {
        "HELLO",
        "LETTER",
        "ATTACK",
        "MEET"
    }) {
        std::cout
            << std::left
            << std::setw(10)
            << word
            << " -> "
            << patternToString(wordPattern(word))
            << '\n';
    }
}


// -----------------------------------------------------------------------------
// 15. CAESAR AND AFFINE DEMONSTRATIONS
// -----------------------------------------------------------------------------

void demonstrateClassicalVariants() {
    std::cout << "\nClassical substitution variants\n";
    std::cout << "===============================\n";

    std::string message =
        "Classical cryptography uses mathematical transformations.";

    CaesarCipher caesar(3);
    std::string caesarCiphertext =
        caesar.encrypt(message);

    std::cout << "\nCaesar:\n";
    std::cout << "Encrypted: " << caesarCiphertext << '\n';
    std::cout << "Decrypted: "
              << caesar.decrypt(caesarCiphertext)
              << '\n';

    AffineCipher affine(5, 8);
    std::string affineCiphertext =
        affine.encrypt(message);

    std::cout << "\nAffine:\n";
    std::cout << "Encrypted: " << affineCiphertext << '\n';
    std::cout << "Decrypted: "
              << affine.decrypt(affineCiphertext)
              << '\n';

    std::cout << "Affine parameters: a="
              << affine.getA()
              << ", b="
              << affine.getB()
              << ", inverse(a)="
              << affine.getInverseA()
              << '\n';
}


// -----------------------------------------------------------------------------
// 16. FAILURE AND EDGE CASES
// -----------------------------------------------------------------------------

void demonstrateFailureConditions() {
    std::cout << "\nFailure conditions and edge cases\n";
    std::cout << "================================\n";

    CaesarCipher normalizedShift(29);

    std::cout
        << "Shift 29 behaves as shift "
        << 29 % 26
        << ".\n";

    std::cout
        << "Punctuation is preserved: "
        << normalizedShift.encrypt("!!! 123 ???")
        << '\n';

    std::cout
        << "Empty input remains empty: '"
        << normalizedShift.encrypt("")
        << "'\n";

    try {
        SubstitutionKey invalid(
            "ABCDEFGHIJKLMNOPQRSTUVWXYA"
        );

        (void)invalid;
    } catch (const std::invalid_argument& error) {
        std::cout
            << "Invalid key rejected: "
            << error.what()
            << '\n';
    }

    try {
        ArchiveSecurityService archive(
            SubstitutionKey(
                "QWERTYUIOPASDFGHJKLZXCVBNM"
            )
        );

        archive.addRecord(
            0,
            "Audit",
            "Invalid ID"
        );
    } catch (const std::invalid_argument& error) {
        std::cout
            << "Invalid archive record rejected: "
            << error.what()
            << '\n';
    }
}


// -----------------------------------------------------------------------------
// 17. MAIN
// -----------------------------------------------------------------------------

} // namespace crypto_case_study


int main() {
    using namespace crypto_case_study;

    try {
        runCaseStudy();
        demonstrateClassicalVariants();
        demonstrateFailureConditions();
        runTests();

        std::cout
            << "\nCase study completed successfully.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << '\n';

        return 1;
    }
}
