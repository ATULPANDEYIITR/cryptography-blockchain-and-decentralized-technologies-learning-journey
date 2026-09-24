#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std;

/*
 * Classical Cipher Attack Case Study
 *
 * Scenario:
 * ---------
 * A historical intelligence archive contains a collection of short
 * messages protected with classical ciphers. The analysis system must:
 *
 *   1. identify likely cipher families,
 *   2. exploit their statistical weaknesses,
 *   3. recover simple keys where feasible,
 *   4. preserve uncertainty when the evidence is insufficient,
 *   5. report complexity and attack limitations.
 *
 * This program demonstrates:
 *   - Caesar exhaustive search
 *   - affine exhaustive search
 *   - frequency analysis
 *   - index of coincidence
 *   - Vigenere key-length analysis
 *   - Rail Fence transposition
 *   - columnar transposition
 *   - crib reasoning
 *   - validation and self-tests
 *
 * The system uses only the C++17 standard library.
 */

namespace Crypto {

const string ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const array<double, 26> ENGLISH_FREQUENCIES = {
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
    0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
    0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
    0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074
};

int mod(int value, int modulus = 26) {
    value %= modulus;
    if (value < 0) {
        value += modulus;
    }
    return value;
}

int gcd(int a, int b) {
    return std::gcd(a, b);
}

int letterIndex(char c) {
    c = static_cast<char>(toupper(static_cast<unsigned char>(c)));
    return c - 'A';
}

char letterAt(int index) {
    return static_cast<char>('A' + mod(index));
}

string normalizeLetters(const string& text) {
    string result;

    for (unsigned char c : text) {
        if (isalpha(c)) {
            char upper = static_cast<char>(toupper(c));

            if (upper >= 'A' && upper <= 'Z') {
                result.push_back(upper);
            }
        }
    }

    return result;
}

int modularInverse(int a, int modulus = 26) {
    a = mod(a, modulus);

    for (int x = 1; x < modulus; ++x) {
        if ((a * x) % modulus == 1) {
            return x;
        }
    }

    return -1;
}

void section(const string& title) {
    cout << "\n" << string(78, '=') << '\n';
    cout << title << '\n';
    cout << string(78, '=') << '\n';
}

// -------------------------------------------------------------------------
// Caesar
// -------------------------------------------------------------------------

string caesarEncrypt(const string& text, int shift) {
    string result;

    for (char c : text) {
        if (isalpha(static_cast<unsigned char>(c))) {
            char upper = static_cast<char>(toupper(
                static_cast<unsigned char>(c)
            ));

            if (upper >= 'A' && upper <= 'Z') {
                result.push_back(letterAt(letterIndex(upper) + shift));
            } else {
                result.push_back(c);
            }
        } else {
            result.push_back(c);
        }
    }

    return result;
}

string caesarDecrypt(const string& text, int shift) {
    return caesarEncrypt(text, -shift);
}

double chiSquaredScore(const string& text) {
    string letters = normalizeLetters(text);

    if (letters.empty()) {
        return numeric_limits<double>::infinity();
    }

    array<int, 26> counts{};
    counts.fill(0);

    for (char c : letters) {
        counts[letterIndex(c)]++;
    }

    double score = 0.0;
    const double n = static_cast<double>(letters.size());

    for (int i = 0; i < 26; ++i) {
        double expected = ENGLISH_FREQUENCIES[i] * n;
        double observed = counts[i];

        if (expected > 0.0) {
            double difference = observed - expected;
            score += (difference * difference) / expected;
        }
    }

    return score;
}

struct CaesarResult {
    int shift;
    string plaintext;
    double score;
};

CaesarResult crackCaesar(const string& ciphertext) {
    CaesarResult best{
        0,
        "",
        numeric_limits<double>::infinity()
    };

    for (int shift = 0; shift < 26; ++shift) {
        string plaintext = caesarDecrypt(ciphertext, shift);
        double score = chiSquaredScore(plaintext);

        if (score < best.score) {
            best.shift = shift;
            best.plaintext = plaintext;
            best.score = score;
        }
    }

    return best;
}

// -------------------------------------------------------------------------
// Affine cipher
// -------------------------------------------------------------------------

string affineEncrypt(
    const string& text,
    int a,
    int b
) {
    if (gcd(a, 26) != 1) {
        throw invalid_argument(
            "Affine multiplier must be coprime with 26."
        );
    }

    string result;

    for (char c : text) {
        if (isalpha(static_cast<unsigned char>(c))) {
            char upper = static_cast<char>(toupper(
                static_cast<unsigned char>(c)
            ));

            if (upper >= 'A' && upper <= 'Z') {
                int x = letterIndex(upper);
                result.push_back(letterAt(a * x + b));
            } else {
                result.push_back(c);
            }
        } else {
            result.push_back(c);
        }
    }

    return result;
}

string affineDecrypt(
    const string& text,
    int a,
    int b
) {
    int inverse = modularInverse(a);

    if (inverse == -1) {
        throw invalid_argument(
            "Affine multiplier has no modular inverse."
        );
    }

    string result;

    for (char c : text) {
        if (isalpha(static_cast<unsigned char>(c))) {
            char upper = static_cast<char>(toupper(
                static_cast<unsigned char>(c)
            ));

            if (upper >= 'A' && upper <= 'Z') {
                int y = letterIndex(upper);
                result.push_back(letterAt(inverse * (y - b)));
            } else {
                result.push_back(c);
            }
        } else {
            result.push_back(c);
        }
    }

    return result;
}

struct AffineResult {
    int a;
    int b;
    string plaintext;
    double score;
};

AffineResult crackAffine(const string& ciphertext) {
    AffineResult best{
        1,
        0,
        "",
        numeric_limits<double>::infinity()
    };

    for (int a = 0; a < 26; ++a) {
        if (gcd(a, 26) != 1) {
            continue;
        }

        for (int b = 0; b < 26; ++b) {
            string plaintext = affineDecrypt(ciphertext, a, b);
            double score = chiSquaredScore(plaintext);

            if (score < best.score) {
                best = {a, b, plaintext, score};
            }
        }
    }

    return best;
}

// -------------------------------------------------------------------------
// Frequency analysis
// -------------------------------------------------------------------------

vector<pair<char, int>> frequencyTable(const string& text) {
    array<int, 26> counts{};
    counts.fill(0);

    for (char c : normalizeLetters(text)) {
        counts[letterIndex(c)]++;
    }

    vector<pair<char, int>> frequencies;

    for (int i = 0; i < 26; ++i) {
        if (counts[i] > 0) {
            frequencies.push_back({
                letterAt(i),
                counts[i]
            });
        }
    }

    sort(
        frequencies.begin(),
        frequencies.end(),
        [](const auto& left, const auto& right) {
            return left.second > right.second;
        }
    );

    return frequencies;
}

double indexOfCoincidence(const string& text) {
    string letters = normalizeLetters(text);

    if (letters.size() < 2) {
        return 0.0;
    }

    array<long long, 26> counts{};
    counts.fill(0);

    for (char c : letters) {
        counts[letterIndex(c)]++;
    }

    long long numerator = 0;

    for (long long count : counts) {
        numerator += count * (count - 1);
    }

    long long n = static_cast<long long>(letters.size());
    return static_cast<double>(numerator) /
           static_cast<double>(n * (n - 1));
}

// -------------------------------------------------------------------------
// Vigenere
// -------------------------------------------------------------------------

string validateKeyword(const string& keyword) {
    string result = normalizeLetters(keyword);

    if (result.empty()) {
        throw invalid_argument(
            "Keyword must contain alphabetic characters."
        );
    }

    return result;
}

string vigenereEncrypt(
    const string& text,
    const string& keyword
) {
    string key = validateKeyword(keyword);
    string result;

    size_t keyIndex = 0;

    for (char c : text) {
        if (isalpha(static_cast<unsigned char>(c))) {
            char upper = static_cast<char>(toupper(
                static_cast<unsigned char>(c)
            ));

            if (upper >= 'A' && upper <= 'Z') {
                int shift = letterIndex(
                    key[keyIndex % key.size()]
                );

                result.push_back(
                    letterAt(letterIndex(upper) + shift)
                );

                ++keyIndex;
            } else {
                result.push_back(c);
            }
        } else {
            result.push_back(c);
        }
    }

    return result;
}

string vigenereDecrypt(
    const string& text,
    const string& keyword
) {
    string key = validateKeyword(keyword);
    string result;

    size_t keyIndex = 0;

    for (char c : text) {
        if (isalpha(static_cast<unsigned char>(c))) {
            char upper = static_cast<char>(toupper(
                static_cast<unsigned char>(c)
            ));

            if (upper >= 'A' && upper <= 'Z') {
                int shift = letterIndex(
                    key[keyIndex % key.size()]
                );

                result.push_back(
                    letterAt(letterIndex(upper) - shift)
                );

                ++keyIndex;
            } else {
                result.push_back(c);
            }
        } else {
            result.push_back(c);
        }
    }

    return result;
}

vector<pair<string, vector<int>>> repeatedNgrams(
    const string& ciphertext,
    size_t n
) {
    string letters = normalizeLetters(ciphertext);
    map<string, vector<int>> positions;

    if (letters.size() < n) {
        return {};
    }

    for (size_t i = 0; i + n <= letters.size(); ++i) {
        positions[letters.substr(i, n)].push_back(
            static_cast<int>(i)
        );
    }

    vector<pair<string, vector<int>>> repeated;

    for (const auto& [gram, values] : positions) {
        if (values.size() >= 2) {
            repeated.push_back({gram, values});
        }
    }

    return repeated;
}

vector<int> factors(int number) {
    vector<int> result;

    for (int candidate = 2; candidate <= number; ++candidate) {
        if (number % candidate == 0) {
            result.push_back(candidate);
        }
    }

    return result;
}

map<int, int> kasiskiAnalysis(
    const string& ciphertext,
    size_t n = 3
) {
    map<int, int> factorCounts;
    auto repeats = repeatedNgrams(ciphertext, n);

    for (const auto& [gram, positions] : repeats) {
        (void)gram;

        for (size_t i = 1; i < positions.size(); ++i) {
            int distance = positions[i] - positions[i - 1];

            for (int factor : factors(distance)) {
                if (factor <= 20) {
                    factorCounts[factor]++;
                }
            }
        }
    }

    return factorCounts;
}

double averageICForLength(
    const string& ciphertext,
    int keyLength
) {
    string letters = normalizeLetters(ciphertext);
    vector<double> values;

    for (int position = 0; position < keyLength; ++position) {
        string column;

        for (
            size_t i = position;
            i < letters.size();
            i += keyLength
        ) {
            column.push_back(letters[i]);
        }

        if (column.size() > 1) {
            values.push_back(indexOfCoincidence(column));
        }
    }

    if (values.empty()) {
        return 0.0;
    }

    return accumulate(
        values.begin(),
        values.end(),
        0.0
    ) / values.size();
}

vector<pair<int, double>> rankKeyLengths(
    const string& ciphertext,
    int maximumLength
) {
    vector<pair<int, double>> result;

    for (int length = 1; length <= maximumLength; ++length) {
        result.push_back({
            length,
            averageICForLength(ciphertext, length)
        });
    }

    sort(
        result.begin(),
        result.end(),
        [](const auto& left, const auto& right) {
            return left.second > right.second;
        }
    );

    return result;
}

string solveVigenereByFrequency(
    const string& ciphertext,
    int keyLength
) {
    string letters = normalizeLetters(ciphertext);
    string key;

    for (int position = 0; position < keyLength; ++position) {
        string column;

        for (
            size_t i = position;
            i < letters.size();
            i += keyLength
        ) {
            column.push_back(letters[i]);
        }

        int bestShift = 0;
        double bestScore =
            numeric_limits<double>::infinity();

        for (int shift = 0; shift < 26; ++shift) {
            string decrypted;

            for (char c : column) {
                decrypted.push_back(
                    letterAt(letterIndex(c) - shift)
                );
            }

            double score = chiSquaredScore(decrypted);

            if (score < bestScore) {
                bestScore = score;
                bestShift = shift;
            }
        }

        key.push_back(letterAt(bestShift));
    }

    return key;
}

// -------------------------------------------------------------------------
// Rail Fence
// -------------------------------------------------------------------------

string railFenceEncrypt(
    const string& text,
    int rails
) {
    if (rails < 1) {
        throw invalid_argument("Rails must be positive.");
    }

    string letters = normalizeLetters(text);

    if (rails == 1 || rails >= static_cast<int>(letters.size())) {
        return letters;
    }

    vector<string> rows(rails);

    int row = 0;
    int direction = 1;

    for (char c : letters) {
        rows[row].push_back(c);

        if (row == 0) {
            direction = 1;
        } else if (row == rails - 1) {
            direction = -1;
        }

        row += direction;
    }

    string result;

    for (const string& currentRow : rows) {
        result += currentRow;
    }

    return result;
}

string railFenceDecrypt(
    const string& ciphertext,
    int rails
) {
    if (rails < 1) {
        throw invalid_argument("Rails must be positive.");
    }

    string cipher = normalizeLetters(ciphertext);

    if (rails == 1 || rails >= static_cast<int>(cipher.size())) {
        return cipher;
    }

    vector<int> pattern;
    int row = 0;
    int direction = 1;

    for (size_t i = 0; i < cipher.size(); ++i) {
        pattern.push_back(row);

        if (row == 0) {
            direction = 1;
        } else if (row == rails - 1) {
            direction = -1;
        }

        row += direction;
    }

    vector<int> counts(rails, 0);

    for (int rail : pattern) {
        counts[rail]++;
    }

    vector<vector<char>> rows(rails);
    size_t cursor = 0;

    for (int rail = 0; rail < rails; ++rail) {
        rows[rail].assign(
            cipher.begin() + static_cast<long>(cursor),
            cipher.begin() +
                static_cast<long>(cursor + counts[rail])
        );

        cursor += counts[rail];
    }

    vector<int> offsets(rails, 0);
    string plaintext;

    for (int rail : pattern) {
        plaintext.push_back(
            rows[rail][offsets[rail]++]
        );
    }

    return plaintext;
}

// -------------------------------------------------------------------------
// Columnar transposition
// -------------------------------------------------------------------------

vector<int> columnOrder(const string& keyword) {
    vector<int> order(keyword.size());

    iota(order.begin(), order.end(), 0);

    stable_sort(
        order.begin(),
        order.end(),
        [&](int left, int right) {
            return keyword[left] < keyword[right];
        }
    );

    return order;
}

string columnarEncrypt(
    const string& text,
    const string& keyword
) {
    string key = validateKeyword(keyword);
    string letters = normalizeLetters(text);

    size_t columns = key.size();
    vector<string> rows;

    for (size_t i = 0; i < letters.size(); i += columns) {
        rows.push_back(
            letters.substr(i, columns)
        );
    }

    string result;

    for (int column : columnOrder(key)) {
        for (const string& row : rows) {
            if (static_cast<size_t>(column) < row.size()) {
                result.push_back(row[column]);
            }
        }
    }

    return result;
}

string columnarDecrypt(
    const string& ciphertext,
    const string& keyword
) {
    string key = validateKeyword(keyword);
    string cipher = normalizeLetters(ciphertext);

    size_t columns = key.size();

    size_t fullRows = cipher.size() / columns;
    size_t remainder = cipher.size() % columns;

    vector<size_t> columnLengths(
        columns,
        fullRows
    );

    for (size_t column = 0; column < remainder; ++column) {
        columnLengths[column]++;
    }

    vector<vector<char>> columnData(columns);

    size_t cursor = 0;

    for (int column : columnOrder(key)) {
        size_t length = columnLengths[column];

        columnData[column] = vector<char>(
            cipher.begin() + static_cast<long>(cursor),
            cipher.begin() +
                static_cast<long>(cursor + length)
        );

        cursor += length;
    }

    string plaintext;

    size_t totalRows =
        fullRows + (remainder ? 1 : 0);

    for (size_t row = 0; row < totalRows; ++row) {
        for (size_t column = 0; column < columns; ++column) {
            if (row < columnData[column].size()) {
                plaintext.push_back(
                    columnData[column][row]
                );
            }
        }
    }

    return plaintext;
}

// -------------------------------------------------------------------------
// Crib attack
// -------------------------------------------------------------------------

optional<int> caesarCribTest(
    const string& cipherFragment,
    const string& plaintextFragment
) {
    string cipher = normalizeLetters(cipherFragment);
    string plain = normalizeLetters(plaintextFragment);

    if (
        cipher.empty() ||
        cipher.size() != plain.size()
    ) {
        return nullopt;
    }

    set<int> shifts;

    for (size_t i = 0; i < cipher.size(); ++i) {
        shifts.insert(
            mod(
                letterIndex(cipher[i]) -
                letterIndex(plain[i])
            )
        );
    }

    if (shifts.size() == 1) {
        return *shifts.begin();
    }

    return nullopt;
}

} // namespace Crypto


// -------------------------------------------------------------------------
// Case-study system
// -------------------------------------------------------------------------

class CryptanalysisReport {
public:
    string cipherFamily;
    string attack;
    string recoveredKey;
    string plaintext;
    string limitations;

    void print() const {
        cout << "\nCipher family : " << cipherFamily << '\n';
        cout << "Attack        : " << attack << '\n';
        cout << "Recovered key : " << recoveredKey << '\n';
        cout << "Plaintext     : " << plaintext << '\n';
        cout << "Limitations   : " << limitations << '\n';
    }
};

class HistoricalCipherAnalyzer {
public:
    CryptanalysisReport analyzeCaesar(
        const string& ciphertext
    ) const {
        auto result = Crypto::crackCaesar(ciphertext);

        return {
            "Caesar",
            "Exhaustive key search + chi-squared frequency score",
            to_string(result.shift),
            result.plaintext,
            "Short or non-English plaintext can produce ambiguous rankings."
        };
    }

    CryptanalysisReport analyzeAffine(
        const string& ciphertext
    ) const {
        auto result = Crypto::crackAffine(ciphertext);

        return {
            "Affine",
            "Exhaustive valid-key search + chi-squared score",
            "a=" + to_string(result.a) +
                ", b=" + to_string(result.b),
            result.plaintext,
            "The attack depends on plaintext having sufficiently English-like statistics."
        };
    }

    void printStructuralMeasurements(
        const string& ciphertext
    ) const {
        cout << "\nFrequency ranking:\n";

        for (const auto& [letter, count] :
             Crypto::frequencyTable(ciphertext)) {
            cout << "  " << letter << ": " << count << '\n';
        }

        cout << fixed << setprecision(5);
        cout << "Index of coincidence: "
             << Crypto::indexOfCoincidence(ciphertext)
             << '\n';
    }
};


// -------------------------------------------------------------------------
// Demonstrations
// -------------------------------------------------------------------------

void demonstrateCaesar(
    HistoricalCipherAnalyzer& analyzer
) {
    section("1. Caesar attack");

    const string plaintext =
        "THE SECURITY OF A CLASSICAL CIPHER DEPENDS ON THE SECRECY OF ITS KEY";

    const int shift = 7;
    const string ciphertext =
        Crypto::caesarEncrypt(plaintext, shift);

    cout << "Ciphertext:\n" << ciphertext << '\n';

    auto report = analyzer.analyzeCaesar(ciphertext);
    report.print();
}

void demonstrateAffine(
    HistoricalCipherAnalyzer& analyzer
) {
    section("2. Affine attack");

    const string plaintext =
        "CLASSICAL CRYPTOGRAPHY SHOWS HOW MATHEMATICAL STRUCTURE CAN LEAK INFORMATION";

    const int a = 5;
    const int b = 8;

    const string ciphertext =
        Crypto::affineEncrypt(plaintext, a, b);

    cout << "Ciphertext:\n" << ciphertext << '\n';

    auto report = analyzer.analyzeAffine(ciphertext);
    report.print();
}

void demonstrateVigenere() {
    section("3. Vigenere attack");

    const string plaintext =
        "THE REPEATED KEY CREATES STATISTICAL STRUCTURE THAT CAN BE STUDIED "
        "USING COINCIDENCE TESTS AND FREQUENCY ANALYSIS";

    const string key = "LEMON";

    const string ciphertext =
        Crypto::vigenereEncrypt(plaintext, key);

    cout << "Ciphertext:\n" << ciphertext << '\n';

    auto repeats =
        Crypto::repeatedNgrams(ciphertext, 3);

    cout << "\nRepeated trigrams:\n";

    for (const auto& [gram, positions] : repeats) {
        cout << "  " << gram << ": ";

        for (int position : positions) {
            cout << position << ' ';
        }

        cout << '\n';
    }

    cout << "\nKasiski factor counts:\n";

    for (const auto& [factor, count] :
         Crypto::kasiskiAnalysis(ciphertext, 3)) {
        cout << "  " << factor << ": " << count << '\n';
    }

    cout << "\nCandidate key lengths by average IC:\n";

    for (const auto& [length, ic] :
         Crypto::rankKeyLengths(ciphertext, 12)) {
        cout << "  length " << setw(2) << length
             << " -> " << fixed << setprecision(5)
             << ic << '\n';
    }

    const string estimatedKey =
        Crypto::solveVigenereByFrequency(
            ciphertext,
            static_cast<int>(key.size())
        );

    cout << "\nActual key    : " << key << '\n';
    cout << "Estimated key : " << estimatedKey << '\n';

    cout << "Estimated text:\n"
         << Crypto::vigenereDecrypt(
                ciphertext,
                estimatedKey
            )
         << '\n';
}

void demonstrateTransposition() {
    section("4. Transposition case");

    const string plaintext =
        "TRANSPOSITION CHANGES POSITION RATHER THAN LETTER IDENTITY";

    const string railCipher =
        Crypto::railFenceEncrypt(plaintext, 3);

    cout << "Rail Fence ciphertext:\n"
         << railCipher << '\n';

    cout << "Rail Fence decrypted:\n"
         << Crypto::railFenceDecrypt(railCipher, 3)
         << '\n';

    const string keyword = "ZEBRA";

    const string columnCipher =
        Crypto::columnarEncrypt(
            plaintext,
            keyword
        );

    cout << "\nColumnar ciphertext:\n"
         << columnCipher << '\n';

    cout << "Columnar decrypted:\n"
         << Crypto::columnarDecrypt(
                columnCipher,
                keyword
            )
         << '\n';

    cout << "\nStructural observation:\n"
         << "Transposition rearranges symbols rather than replacing them, "
         << "so global letter frequencies are preserved.\n";
}

void demonstrateCribAttack() {
    section("5. Known-plaintext / crib attack");

    const string plaintextFragment = "ATTACK";
    const string ciphertextFragment =
        Crypto::caesarEncrypt(
            plaintextFragment,
            11
        );

    cout << "Known plaintext : "
         << plaintextFragment << '\n';

    cout << "Cipher fragment : "
         << ciphertextFragment << '\n';

    auto recovered =
        Crypto::caesarCribTest(
            ciphertextFragment,
            plaintextFragment
        );

    if (recovered.has_value()) {
        cout << "Recovered shift : "
             << *recovered << '\n';
    } else {
        cout << "No single Caesar shift explains the fragments.\n";
    }
}

void demonstrateFrequency(
    HistoricalCipherAnalyzer& analyzer
) {
    section("6. Frequency-analysis laboratory");

    const string plaintext =
        "ENGLISH TEXT HAS NONUNIFORM LETTER FREQUENCIES WHICH CREATE "
        "STATISTICAL SIGNALS FOR CLASSICAL CRYPTANALYSIS";

    const string ciphertext =
        Crypto::caesarEncrypt(
            plaintext,
            11
        );

    analyzer.printStructuralMeasurements(
        ciphertext
    );

    cout << "\nA monoalphabetic transformation does not "
         << "destroy frequency relationships.\n";
}

void demonstrateComplexity() {
    section("7. Search-space reasoning");

    unsigned long long factorial26 = 1;

    for (int i = 2; i <= 26; ++i) {
        if (
            factorial26 >
            numeric_limits<unsigned long long>::max() /
                static_cast<unsigned long long>(i)
        ) {
            break;
        }

        factorial26 *=
            static_cast<unsigned long long>(i);
    }

    cout << "Caesar keyspace: 26\n";
    cout << "Affine keyspace: 312\n";
    cout << "26! substitution keys: "
         << factorial26 << '\n';

    cout << fixed << setprecision(2);
    cout << "log2(26!) approximately: "
         << lgammal(27.0L) / logl(2.0L)
         << " bits\n";

    cout << "\nThe distinction is architectural. "
         << "A small keyspace can justify enumeration. "
         << "A huge keyspace requires structure-aware search.\n";
}

void demonstrateFailureModes() {
    section("8. Failure conditions and limitations");

    cout << "Empty IC: "
         << Crypto::indexOfCoincidence("")
         << '\n';

    cout << "Single-character IC: "
         << Crypto::indexOfCoincidence("A")
         << '\n';

    try {
        Crypto::affineEncrypt(
            "ABC",
            13,
            5
        );
    } catch (const exception& error) {
        cout << "Invalid affine key: "
             << error.what() << '\n';
    }

    try {
        Crypto::vigenereEncrypt(
            "ABC",
            "12345"
        );
    } catch (const exception& error) {
        cout << "Invalid Vigenere key: "
             << error.what() << '\n';
    }

    try {
        Crypto::railFenceEncrypt(
            "ABC",
            0
        );
    } catch (const exception& error) {
        cout << "Invalid rail count: "
             << error.what() << '\n';
    }

    cout << "\nStatistical attacks become less dependable when "
         << "ciphertexts are very short, plaintext language is unusual, "
         << "or the assumptions behind the scoring model do not hold.\n";
}

// -------------------------------------------------------------------------
// Verification
// -------------------------------------------------------------------------

void runSelfTests() {
    section("9. Self-tests");

    const string message =
        "HELLO WORLD";

    assert(
        Crypto::caesarDecrypt(
            Crypto::caesarEncrypt(message, 13),
            13
        ) == message
    );

    assert(
        Crypto::affineDecrypt(
            Crypto::affineEncrypt(message, 5, 8),
            5,
            8
        ) == message
    );

    assert(
        Crypto::vigenereDecrypt(
            Crypto::vigenereEncrypt(message, "KEY"),
            "KEY"
        ) == message
    );

    const string normalized =
        Crypto::normalizeLetters(message);

    assert(
        Crypto::railFenceDecrypt(
            Crypto::railFenceEncrypt(message, 3),
            3
        ) == normalized
    );

    assert(
        Crypto::columnarDecrypt(
            Crypto::columnarEncrypt(
                message,
                "ZEBRA"
            ),
            "ZEBRA"
        ) == normalized
    );

    assert(
        Crypto::modularInverse(5, 26) == 21
    );

    cout << "All cryptographic transformation tests passed.\n";
}


// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

int main() {
    cout << "Classical Cipher Attack Case Study\n";
    cout << "C++17 cryptanalysis laboratory\n";

    HistoricalCipherAnalyzer analyzer;

    demonstrateCaesar(analyzer);
    demonstrateAffine(analyzer);
    demonstrateVigenere();
    demonstrateTransposition();
    demonstrateCribAttack();
    demonstrateFrequency(analyzer);
    demonstrateComplexity();
    demonstrateFailureModes();
    runSelfTests();

    section("10. Attack selection model");

    vector<pair<string, string>> attackModels = {
        {
            "Caesar",
            "Exhaustive 26-key search with frequency scoring"
        },
        {
            "Affine",
            "Exhaustive valid modular-key search"
        },
        {
            "Monoalphabetic substitution",
            "Frequency, word patterns, constraints and heuristic search"
        },
        {
            "Vigenere",
            "Kasiski examination, IC and column frequency analysis"
        },
        {
            "Transposition",
            "Permutation and structural analysis"
        },
        {
            "Known plaintext",
            "Crib-based reduction of the possible key relationships"
        }
    };

    for (const auto& [family, attack] : attackModels) {
        cout << left
             << setw(30) << family
             << " | "
             << attack
             << '\n';
    }

    cout << "\nCase-study conclusion:\n";
    cout << "Classical cipher attacks succeed because the historical "
         << "constructions expose structural information. The analyst "
         << "does not need to guess blindly: key-space size, frequency "
         << "distributions, repeated fragments, periodicity, and known "
         << "plaintext relationships provide measurable constraints.\n";

    return 0;
}
