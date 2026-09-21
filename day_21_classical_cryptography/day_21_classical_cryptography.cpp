/*
 * Classical Cryptography: C++17 Technical Case Study
 *
 * Case study:
 *   A historical communications analysis system receives messages protected
 *   by a Caesar, Vigenere, or columnar-transposition cipher. It can encrypt
 *   and decrypt known messages, calculate statistical characteristics, and
 *   perform educational cryptanalysis.
 *
 * The implementation deliberately uses only the C++ standard library.
 *
 * Compile:
 *   g++ -std=c++17 -O2 classical_cryptography.cpp -o classical_cryptography
 *
 * The program is educational. Classical ciphers are not suitable for
 * protecting modern confidential data.
 */

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace std;

constexpr int MODULUS = 26;
const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";


/* --------------------------------------------------------------------------
 * Basic utilities
 * -------------------------------------------------------------------------- */

string normalizeLetters(const string& text) {
    string result;

    for (unsigned char character : text) {
        char upper = static_cast<char>(toupper(character));

        if (upper >= 'A' && upper <= 'Z') {
            result.push_back(upper);
        }
    }

    return result;
}

int letterToNumber(char letter) {
    char upper = static_cast<char>(
        toupper(static_cast<unsigned char>(letter))
    );

    if (upper < 'A' || upper > 'Z') {
        throw invalid_argument("Expected an alphabetic A-Z character.");
    }

    return upper - 'A';
}

char numberToLetter(int number) {
    number %= MODULUS;

    if (number < 0) {
        number += MODULUS;
    }

    return static_cast<char>('A' + number);
}

int gcdExtended(
    int a,
    int b,
    int& x,
    int& y
) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }

    int x1;
    int y1;

    int gcd = gcdExtended(b, a % b, x1, y1);

    x = y1;
    y = x1 - (a / b) * y1;

    return gcd;
}

int modularInverse(int value, int modulus) {
    value %= modulus;

    if (value < 0) {
        value += modulus;
    }

    int x;
    int y;

    int gcd = gcdExtended(value, modulus, x, y);

    if (gcd != 1) {
        throw invalid_argument(
            "A modular inverse does not exist."
        );
    }

    x %= modulus;

    if (x < 0) {
        x += modulus;
    }

    return x;
}


/* --------------------------------------------------------------------------
 * Caesar cipher
 * -------------------------------------------------------------------------- */

string caesarEncrypt(
    const string& text,
    int shift
) {
    string result;

    for (char character : text) {
        if (isalpha(static_cast<unsigned char>(character))) {
            bool uppercase =
                isupper(static_cast<unsigned char>(character));

            int number = letterToNumber(character);
            char encrypted = numberToLetter(number + shift);

            result.push_back(
                uppercase
                    ? encrypted
                    : static_cast<char>(tolower(
                        static_cast<unsigned char>(encrypted)
                    ))
            );
        } else {
            result.push_back(character);
        }
    }

    return result;
}

string caesarDecrypt(
    const string& ciphertext,
    int shift
) {
    return caesarEncrypt(ciphertext, -shift);
}


/* --------------------------------------------------------------------------
 * Affine cipher
 * -------------------------------------------------------------------------- */

string affineEncrypt(
    const string& text,
    int a,
    int b
) {
    if (std::gcd(a, MODULUS) != 1) {
        throw invalid_argument(
            "Affine multiplier must be relatively prime to 26."
        );
    }

    string result;

    for (char character : text) {
        if (!isalpha(static_cast<unsigned char>(character))) {
            result.push_back(character);
            continue;
        }

        bool uppercase =
            isupper(static_cast<unsigned char>(character));

        int x = letterToNumber(character);
        int y = (a * x + b) % MODULUS;

        char encrypted = numberToLetter(y);

        result.push_back(
            uppercase
                ? encrypted
                : static_cast<char>(tolower(
                    static_cast<unsigned char>(encrypted)
                ))
        );
    }

    return result;
}

string affineDecrypt(
    const string& ciphertext,
    int a,
    int b
) {
    if (std::gcd(a, MODULUS) != 1) {
        throw invalid_argument(
            "Affine multiplier must be relatively prime to 26."
        );
    }

    int inverseA = modularInverse(a, MODULUS);
    string result;

    for (char character : ciphertext) {
        if (!isalpha(static_cast<unsigned char>(character))) {
            result.push_back(character);
            continue;
        }

        bool uppercase =
            isupper(static_cast<unsigned char>(character));

        int y = letterToNumber(character);
        int x = inverseA * (y - b);

        char decrypted = numberToLetter(x);

        result.push_back(
            uppercase
                ? decrypted
                : static_cast<char>(tolower(
                    static_cast<unsigned char>(decrypted)
                ))
        );
    }

    return result;
}


/* --------------------------------------------------------------------------
 * Vigenere cipher
 * -------------------------------------------------------------------------- */

string normalizeKeyword(const string& keyword) {
    string normalized = normalizeLetters(keyword);

    if (normalized.empty()) {
        throw invalid_argument("Keyword cannot be empty.");
    }

    return normalized;
}

string vigenereEncrypt(
    const string& text,
    const string& keyword
) {
    string normalizedKeyword = normalizeKeyword(keyword);
    string result;

    size_t keyIndex = 0;

    for (char character : text) {
        if (!isalpha(static_cast<unsigned char>(character))) {
            result.push_back(character);
            continue;
        }

        bool uppercase =
            isupper(static_cast<unsigned char>(character));

        int plaintextValue = letterToNumber(character);
        int keyValue =
            letterToNumber(
                normalizedKeyword[keyIndex %
                                  normalizedKeyword.size()]
            );

        char encrypted =
            numberToLetter(plaintextValue + keyValue);

        result.push_back(
            uppercase
                ? encrypted
                : static_cast<char>(tolower(
                    static_cast<unsigned char>(encrypted)
                ))
        );

        ++keyIndex;
    }

    return result;
}

string vigenereDecrypt(
    const string& ciphertext,
    const string& keyword
) {
    string normalizedKeyword = normalizeKeyword(keyword);
    string result;

    size_t keyIndex = 0;

    for (char character : ciphertext) {
        if (!isalpha(static_cast<unsigned char>(character))) {
            result.push_back(character);
            continue;
        }

        bool uppercase =
            isupper(static_cast<unsigned char>(character));

        int ciphertextValue = letterToNumber(character);
        int keyValue =
            letterToNumber(
                normalizedKeyword[keyIndex %
                                  normalizedKeyword.size()]
            );

        char decrypted =
            numberToLetter(ciphertextValue - keyValue);

        result.push_back(
            uppercase
                ? decrypted
                : static_cast<char>(tolower(
                    static_cast<unsigned char>(decrypted)
                ))
        );

        ++keyIndex;
    }

    return result;
}


/* --------------------------------------------------------------------------
 * Columnar transposition
 * -------------------------------------------------------------------------- */

vector<size_t> columnOrder(const string& keyword) {
    string normalized = normalizeLetters(keyword);

    if (normalized.empty()) {
        throw invalid_argument(
            "Transposition keyword cannot be empty."
        );
    }

    vector<pair<char, size_t>> entries;

    for (size_t index = 0; index < normalized.size(); ++index) {
        entries.push_back({normalized[index], index});
    }

    stable_sort(
        entries.begin(),
        entries.end(),
        [](const auto& left, const auto& right) {
            return left.first < right.first;
        }
    );

    vector<size_t> order;

    for (const auto& entry : entries) {
        order.push_back(entry.second);
    }

    return order;
}

string columnarEncrypt(
    const string& text,
    const string& keyword
) {
    string plaintext = normalizeLetters(text);
    string normalizedKeyword = normalizeLetters(keyword);

    if (normalizedKeyword.empty()) {
        throw invalid_argument("Keyword cannot be empty.");
    }

    size_t columns = normalizedKeyword.size();

    while (plaintext.size() % columns != 0) {
        plaintext.push_back('X');
    }

    vector<string> rows;

    for (size_t index = 0;
         index < plaintext.size();
         index += columns) {
        rows.push_back(
            plaintext.substr(index, columns)
        );
    }

    vector<size_t> order =
        columnOrder(normalizedKeyword);

    string ciphertext;

    for (size_t column : order) {
        for (const string& row : rows) {
            ciphertext.push_back(row[column]);
        }
    }

    return ciphertext;
}

string columnarDecrypt(
    const string& ciphertext,
    const string& keyword
) {
    string normalizedCiphertext =
        normalizeLetters(ciphertext);

    string normalizedKeyword =
        normalizeLetters(keyword);

    if (normalizedKeyword.empty()) {
        throw invalid_argument("Keyword cannot be empty.");
    }

    size_t columns = normalizedKeyword.size();

    if (normalizedCiphertext.size() % columns != 0) {
        throw invalid_argument(
            "Ciphertext length must be divisible by the number of columns."
        );
    }

    size_t rowsCount =
        normalizedCiphertext.size() / columns;

    vector<string> grid(
        rowsCount,
        string(columns, ' ')
    );

    vector<size_t> order =
        columnOrder(normalizedKeyword);

    size_t position = 0;

    for (size_t column : order) {
        for (size_t row = 0; row < rowsCount; ++row) {
            grid[row][column] =
                normalizedCiphertext[position++];
        }
    }

    string plaintext;

    for (const string& row : grid) {
        plaintext += row;
    }

    while (!plaintext.empty() &&
           plaintext.back() == 'X') {
        plaintext.pop_back();
    }

    return plaintext;
}


/* --------------------------------------------------------------------------
 * Statistical analysis
 * -------------------------------------------------------------------------- */

struct FrequencyEntry {
    char letter;
    int count;
    double percentage;
};

vector<FrequencyEntry> frequencyTable(
    const string& text
) {
    string letters = normalizeLetters(text);
    array<int, 26> counts{};

    for (char character : letters) {
        ++counts[letterToNumber(character)];
    }

    vector<FrequencyEntry> result;

    for (int index = 0; index < 26; ++index) {
        double percentage =
            letters.empty()
                ? 0.0
                : 100.0 * counts[index] /
                  static_cast<double>(letters.size());

        result.push_back({
            static_cast<char>('A' + index),
            counts[index],
            percentage
        });
    }

    sort(
        result.begin(),
        result.end(),
        [](const FrequencyEntry& left,
           const FrequencyEntry& right) {
            if (left.count != right.count) {
                return left.count > right.count;
            }

            return left.letter < right.letter;
        }
    );

    return result;
}

double indexOfCoincidence(
    const string& text
) {
    string letters = normalizeLetters(text);

    if (letters.size() < 2) {
        return 0.0;
    }

    array<int, 26> counts{};

    for (char character : letters) {
        ++counts[letterToNumber(character)];
    }

    long long numerator = 0;

    for (int count : counts) {
        numerator +=
            static_cast<long long>(count) *
            (count - 1);
    }

    double denominator =
        static_cast<double>(letters.size()) *
        static_cast<double>(letters.size() - 1);

    return numerator / denominator;
}


/* --------------------------------------------------------------------------
 * Caesar cryptanalysis
 * -------------------------------------------------------------------------- */

const array<double, 26> ENGLISH_FREQUENCIES = {
    8.17, 1.49, 2.78, 4.25, 12.70,
    2.23, 2.02, 6.09, 6.97, 0.15,
    0.77, 4.03, 2.41, 6.75, 7.51,
    1.93, 0.10, 5.99, 6.33, 9.06,
    2.76, 0.98, 2.36, 0.15, 1.97,
    0.07
};

double chiSquaredScore(
    const string& text
) {
    string letters = normalizeLetters(text);

    if (letters.empty()) {
        return numeric_limits<double>::infinity();
    }

    array<int, 26> counts{};

    for (char character : letters) {
        ++counts[letterToNumber(character)];
    }

    double score = 0.0;

    for (int index = 0; index < 26; ++index) {
        double expected =
            letters.size() *
            ENGLISH_FREQUENCIES[index] /
            100.0;

        if (expected > 0.0) {
            double difference =
                counts[index] - expected;

            score +=
                difference * difference /
                expected;
        }
    }

    return score;
}

struct CaesarCandidate {
    int shift;
    string plaintext;
    double score;
};

vector<CaesarCandidate> crackCaesar(
    const string& ciphertext
) {
    vector<CaesarCandidate> candidates;

    for (int shift = 0; shift < 26; ++shift) {
        string plaintext =
            caesarDecrypt(ciphertext, shift);

        candidates.push_back({
            shift,
            plaintext,
            chiSquaredScore(plaintext)
        });
    }

    sort(
        candidates.begin(),
        candidates.end(),
        [](const CaesarCandidate& left,
           const CaesarCandidate& right) {
            return left.score < right.score;
        }
    );

    return candidates;
}


/* --------------------------------------------------------------------------
 * Repeated-pattern analysis for Vigenere
 * -------------------------------------------------------------------------- */

vector<int> repeatedNgramDistances(
    const string& ciphertext,
    size_t ngramLength
) {
    string letters = normalizeLetters(ciphertext);

    map<string, vector<int>> locations;

    if (letters.size() < ngramLength) {
        return {};
    }

    for (size_t index = 0;
         index + ngramLength <= letters.size();
         ++index) {
        string ngram =
            letters.substr(index, ngramLength);

        locations[ngram].push_back(
            static_cast<int>(index)
        );
    }

    vector<int> distances;

    for (const auto& [ngram, positions] : locations) {
        if (positions.size() < 2) {
            continue;
        }

        for (size_t index = 1;
             index < positions.size();
             ++index) {
            distances.push_back(
                positions[index] -
                positions[index - 1]
            );
        }
    }

    return distances;
}


/* --------------------------------------------------------------------------
 * Case-study domain model
 *
 * A Message stores the operational information needed by the historical
 * communications system. A CipherEngine supplies common operations.
 * -------------------------------------------------------------------------- */

enum class CipherType {
    Caesar,
    Vigenere,
    ColumnarTransposition
};

string cipherTypeName(CipherType type) {
    switch (type) {
        case CipherType::Caesar:
            return "Caesar";
        case CipherType::Vigenere:
            return "Vigenere";
        case CipherType::ColumnarTransposition:
            return "Columnar Transposition";
    }

    return "Unknown";
}

struct Message {
    int id;
    string sender;
    string recipient;
    CipherType cipher;
    string key;
    string plaintext;
    string ciphertext;
};

class CipherEngine {
public:
    static string encrypt(
        CipherType type,
        const string& plaintext,
        const string& key
    ) {
        switch (type) {
            case CipherType::Caesar: {
                int shift = parseIntegerKey(key);
                return caesarEncrypt(
                    plaintext,
                    shift
                );
            }

            case CipherType::Vigenere:
                return vigenereEncrypt(
                    plaintext,
                    key
                );

            case CipherType::ColumnarTransposition:
                return columnarEncrypt(
                    plaintext,
                    key
                );
        }

        throw invalid_argument(
            "Unsupported cipher type."
        );
    }

    static string decrypt(
        CipherType type,
        const string& ciphertext,
        const string& key
    ) {
        switch (type) {
            case CipherType::Caesar: {
                int shift = parseIntegerKey(key);
                return caesarDecrypt(
                    ciphertext,
                    shift
                );
            }

            case CipherType::Vigenere:
                return vigenereDecrypt(
                    ciphertext,
                    key
                );

            case CipherType::ColumnarTransposition:
                return columnarDecrypt(
                    ciphertext,
                    key
                );
        }

        throw invalid_argument(
            "Unsupported cipher type."
        );
    }

private:
    static int parseIntegerKey(
        const string& key
    ) {
        if (key.empty()) {
            throw invalid_argument(
                "Caesar key cannot be empty."
            );
        }

        size_t position = 0;

        int value = stoi(key, &position);

        if (position != key.size()) {
            throw invalid_argument(
                "Caesar key must be an integer."
            );
        }

        return value;
    }
};


/* --------------------------------------------------------------------------
 * Message repository
 *
 * This is deliberately an in-memory repository. It demonstrates how a
 * cryptographic component can be separated from application-level storage.
 * -------------------------------------------------------------------------- */

class MessageRepository {
public:
    void add(const Message& message) {
        if (messages.count(message.id) != 0) {
            throw invalid_argument(
                "Message ID already exists."
            );
        }

        messages.emplace(message.id, message);
    }

    optional<Message> find(int id) const {
        auto iterator = messages.find(id);

        if (iterator == messages.end()) {
            return nullopt;
        }

        return iterator->second;
    }

    vector<Message> all() const {
        vector<Message> result;

        for (const auto& [id, message] : messages) {
            result.push_back(message);
        }

        return result;
    }

private:
    map<int, Message> messages;
};


/* --------------------------------------------------------------------------
 * Case-study service
 * -------------------------------------------------------------------------- */

class CommunicationsService {
public:
    void createMessage(
        int id,
        const string& sender,
        const string& recipient,
        CipherType cipher,
        const string& key,
        const string& plaintext
    ) {
        Message message{
            id,
            sender,
            recipient,
            cipher,
            key,
            plaintext,
            CipherEngine::encrypt(
                cipher,
                plaintext,
                key
            )
        };

        repository.add(message);
    }

    void printMessage(int id) const {
        optional<Message> result =
            repository.find(id);

        if (!result.has_value()) {
            cout << "Message " << id
                 << " does not exist.\n";
            return;
        }

        const Message& message = result.value();

        cout << "\nMessage " << message.id << "\n";
        cout << "Sender    : " << message.sender << "\n";
        cout << "Recipient : " << message.recipient << "\n";
        cout << "Cipher    : "
             << cipherTypeName(message.cipher)
             << "\n";
        cout << "Ciphertext: "
             << message.ciphertext
             << "\n";
    }

    void verifyMessage(int id) const {
        optional<Message> result =
            repository.find(id);

        if (!result.has_value()) {
            throw runtime_error(
                "Cannot verify missing message."
            );
        }

        const Message& message = result.value();

        string recovered =
            CipherEngine::decrypt(
                message.cipher,
                message.ciphertext,
                message.key
            );

        bool matches =
            recovered == message.plaintext;

        cout << "\nVerification for message "
             << id << ": "
             << (matches ? "PASS" : "FAIL")
             << "\n";

        if (!matches) {
            cout << "Expected: "
                 << message.plaintext
                 << "\n";

            cout << "Recovered: "
                 << recovered
                 << "\n";
        }
    }

    void printStatistics(int id) const {
        optional<Message> result =
            repository.find(id);

        if (!result.has_value()) {
            throw runtime_error(
                "Cannot analyze missing message."
            );
        }

        const Message& message = result.value();

        cout << "\nStatistics for message "
             << id << "\n";

        cout << fixed << setprecision(4);
        cout << "Index of coincidence: "
             << indexOfCoincidence(
                    message.ciphertext
                )
             << "\n";

        cout << "Ciphertext frequency table:\n";

        auto table =
            frequencyTable(message.ciphertext);

        for (size_t index = 0;
             index < min<size_t>(8, table.size());
             ++index) {
            const auto& entry = table[index];

            cout << "  "
                 << entry.letter
                 << ": "
                 << entry.count
                 << " ("
                 << setprecision(2)
                 << entry.percentage
                 << "%)\n";
        }
    }

private:
    MessageRepository repository;
};


/* --------------------------------------------------------------------------
 * Complexity demonstration
 * -------------------------------------------------------------------------- */

void demonstrateComplexity() {
    cout << "\n=== Complexity Considerations ===\n";

    cout << "Caesar encryption: O(n)\n";
    cout << "Vigenere encryption: O(n)\n";
    cout << "Frequency counting: O(n)\n";
    cout << "Index of coincidence: O(n)\n";
    cout << "Columnar transposition: O(n log k) for key ordering plus O(n)\n";
    cout << "Caesar brute force: O(26n), effectively O(n) because 26 is constant\n";
    cout << "Vigenere key-length testing: O(n*k) for k tested lengths\n";

    cout << "\nMemory considerations:\n";
    cout << "Most transformations allocate a second string of approximately "
         << "the message size.\n";
    cout << "Streaming implementations could reduce peak memory when messages "
         << "are processed incrementally.\n";
}


/* --------------------------------------------------------------------------
 * Security and failure demonstrations
 * -------------------------------------------------------------------------- */

void demonstrateFailures() {
    cout << "\n=== Validation and Failure Conditions ===\n";

    try {
        affineEncrypt("HELLO", 13, 5);
    } catch (const exception& error) {
        cout << "Invalid affine key rejected: "
             << error.what()
             << "\n";
    }

    try {
        CipherEngine::encrypt(
            CipherType::Vigenere,
            "HELLO",
            ""
        );
    } catch (const exception& error) {
        cout << "Empty Vigenere key rejected: "
             << error.what()
             << "\n";
    }

    try {
        columnarDecrypt(
            "ABC",
            "ZEBRA"
        );
    } catch (const exception& error) {
        cout << "Invalid transposition ciphertext rejected: "
             << error.what()
             << "\n";
    }

    cout << "\nImportant security limitation:\n";
    cout << "The keys in this historical case study are deliberately "
         << "simple and stored alongside message records for demonstration. "
         << "A real secure system must not treat this architecture as a "
         << "secure key-management design.\n";
}


/* --------------------------------------------------------------------------
 * Full case study
 * -------------------------------------------------------------------------- */

void runCaseStudy() {
    cout << "\n";
    cout << "============================================================\n";
    cout << "CLASSICAL COMMUNICATIONS CASE STUDY\n";
    cout << "============================================================\n";

    CommunicationsService service;

    /*
     * A Caesar message demonstrates a tiny key space and simple reversal.
     */
    service.createMessage(
        1001,
        "COMMAND",
        "OUTPOST",
        CipherType::Caesar,
        "7",
        "Report arrives at dawn"
    );

    /*
     * Vigenere demonstrates a periodic key stream. The service does not
     * know that the cipher is statistically vulnerable; it simply applies
     * the configured transformation.
     */
    service.createMessage(
        1002,
        "ARCHIVE",
        "ANALYSIS",
        CipherType::Vigenere,
        "LEMON",
        "The historical records are ready"
    );

    /*
     * Columnar transposition demonstrates a fundamentally different
     * mechanism: symbols are rearranged rather than substituted.
     */
    service.createMessage(
        1003,
        "FIELD",
        "COMMAND",
        CipherType::ColumnarTransposition,
        "ZEBRA",
        "We are discovered"
    );

    service.printMessage(1001);
    service.printMessage(1002);
    service.printMessage(1003);

    service.verifyMessage(1001);
    service.verifyMessage(1002);
    service.verifyMessage(1003);

    service.printStatistics(1002);

    cout << "\n=== Caesar Cryptanalysis of Case-Study Message ===\n";

    auto candidates =
        crackCaesar(
            caesarEncrypt(
                "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
                "AND THEN RETURNS TO THE QUIET FOREST",
                7
            )
        );

    for (size_t index = 0;
         index < min<size_t>(5, candidates.size());
         ++index) {
        const auto& candidate = candidates[index];

        cout << "Shift "
             << setw(2)
             << candidate.shift
             << " | score "
             << setw(8)
             << fixed
             << setprecision(2)
             << candidate.score
             << " | "
             << candidate.plaintext
             << "\n";
    }

    cout << "\n=== Vigenere Pattern Analysis ===\n";

    string vigenerePlaintext =
        "THE HISTORY OF CLASSICAL CRYPTOGRAPHY CONTAINS MANY "
        "EXAMPLES OF CIPHERS THAT WERE ONCE CONSIDERED DIFFICULT "
        "BUT BECAME VULNERABLE WHEN THEIR STRUCTURAL PATTERNS "
        "WERE UNDERSTOOD BY CRYPTANALYSTS";

    string vigenereCiphertext =
        vigenereEncrypt(
            vigenerePlaintext,
            "LEMON"
        );

    auto distances =
        repeatedNgramDistances(
            vigenereCiphertext,
            3
        );

    cout << "Ciphertext: "
         << normalizeLetters(vigenereCiphertext)
         << "\n";

    cout << "Repeated trigram distances: ";

    for (size_t index = 0;
         index < min<size_t>(12, distances.size());
         ++index) {
        cout << distances[index];

        if (index + 1 <
            min<size_t>(12, distances.size())) {
            cout << ", ";
        }
    }

    cout << "\n";

    demonstrateComplexity();
    demonstrateFailures();
}


/* --------------------------------------------------------------------------
 * Automated tests
 * -------------------------------------------------------------------------- */

void runTests() {
    cout << "\n=== Automated Tests ===\n";

    {
        string plaintext =
            "Hello, Classical Cryptography!";

        for (int shift : {-100, -3, 0, 3, 100}) {
            string ciphertext =
                caesarEncrypt(
                    plaintext,
                    shift
                );

            string recovered =
                caesarDecrypt(
                    ciphertext,
                    shift
                );

            if (recovered != plaintext) {
                throw runtime_error(
                    "Caesar round-trip test failed."
                );
            }
        }
    }

    {
        string plaintext =
            "Affine modular arithmetic";

        string ciphertext =
            affineEncrypt(
                plaintext,
                5,
                8
            );

        string recovered =
            affineDecrypt(
                ciphertext,
                5,
                8
            );

        if (recovered != plaintext) {
            throw runtime_error(
                "Affine round-trip test failed."
            );
        }
    }

    {
        string plaintext =
            "Vigenere uses a repeating key";

        string ciphertext =
            vigenereEncrypt(
                plaintext,
                "LEMON"
            );

        string recovered =
            vigenereDecrypt(
                ciphertext,
                "LEMON"
            );

        if (recovered != plaintext) {
            throw runtime_error(
                "Vigenere round-trip test failed."
            );
        }
    }

    {
        string plaintext =
            "WEAREDISCOVERED";

        string ciphertext =
            columnarEncrypt(
                plaintext,
                "ZEBRA"
            );

        string recovered =
            columnarDecrypt(
                ciphertext,
                "ZEBRA"
            );

        if (recovered != plaintext) {
            throw runtime_error(
                "Columnar round-trip test failed."
            );
        }
    }

    {
        string plaintext =
            "ABCDEF";

        string ciphertext =
            caesarEncrypt(
                plaintext,
                3
            );

        if (ciphertext != "DEFGHI") {
            throw runtime_error(
                "Known-answer Caesar test failed."
            );
        }
    }

    cout << "All C++ tests passed.\n";
}


/* --------------------------------------------------------------------------
 * Main
 * -------------------------------------------------------------------------- */

int main() {
    try {
        cout << "Classical Cryptography Technical Study\n";

        cout << "\n=== Fundamental Arithmetic ===\n";

        cout << "5 inverse modulo 26: "
             << modularInverse(5, 26)
             << "\n";

        cout << "5 * inverse(5) mod 26: "
             << (5 * modularInverse(5, 26)) % 26
             << "\n";

        cout << "\n=== Caesar Demonstration ===\n";

        string caesarPlaintext =
            "Attack at dawn!";

        string caesarCiphertext =
            caesarEncrypt(
                caesarPlaintext,
                3
            );

        cout << "Plaintext : "
             << caesarPlaintext
             << "\n";

        cout << "Ciphertext: "
             << caesarCiphertext
             << "\n";

        cout << "Recovered : "
             << caesarDecrypt(
                    caesarCiphertext,
                    3
                )
             << "\n";

        cout << "\n=== Affine Demonstration ===\n";

        string affineCiphertext =
            affineEncrypt(
                "Classical cryptography",
                5,
                8
            );

        cout << "Ciphertext: "
             << affineCiphertext
             << "\n";

        cout << "Recovered : "
             << affineDecrypt(
                    affineCiphertext,
                    5,
                    8
                )
             << "\n";

        runCaseStudy();
        runTests();

        cout << "\n============================================================\n";
        cout << "PROGRAM COMPLETE\n";
        cout << "============================================================\n";

        return 0;
    }
    catch (const exception& error) {
        cerr << "Fatal error: "
             << error.what()
             << "\n";

        return 1;
    }
}
