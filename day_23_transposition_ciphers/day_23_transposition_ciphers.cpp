/*
 * TRANSPOSITION CIPHER CASE STUDY
 * ===============================
 *
 * Modern C++17 implementation of a small secure-message workflow based on
 * classical transposition techniques.
 *
 * Case study:
 *
 *     A historical communications archive stores short messages that were
 *     transformed using a keyed columnar transposition. The program models
 *     the complete workflow:
 *
 *         1. Normalize input
 *         2. Validate configuration
 *         3. Generate deterministic key ordering
 *         4. Encrypt
 *         5. Serialize ciphertext
 *         6. Decrypt
 *         7. Validate round-trip integrity
 *         8. Analyze preserved character frequencies
 *         9. Benchmark the implementation
 *        10. Demonstrate a small structural attack
 *
 * Build:
 *
 *     g++ -std=c++17 -O2 transposition_case_study.cpp -o transposition
 *
 * Run:
 *
 *     ./transposition
 *
 * The program intentionally uses only the C++ standard library.
 *
 * Important security qualification:
 *
 * Classical transposition ciphers are historical cryptographic mechanisms.
 * They should not be used as modern protection for sensitive information.
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <exception>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using namespace std;


// ============================================================================
// 1. GENERAL UTILITIES
// ============================================================================

string normalizeText(const string& input) {
    string result;

    for (unsigned char character : input) {
        if (character >= 'a' && character <= 'z') {
            result.push_back(
                static_cast<char>(character - 'a' + 'A')
            );
        } else if (character >= 'A' && character <= 'Z') {
            result.push_back(static_cast<char>(character));
        }
    }

    return result;
}

bool sameCharacterMultiset(
    const string& left,
    const string& right
) {
    if (left.size() != right.size()) {
        return false;
    }

    map<char, size_t> leftCounts;
    map<char, size_t> rightCounts;

    for (char character : left) {
        ++leftCounts[character];
    }

    for (char character : right) {
        ++rightCounts[character];
    }

    return leftCounts == rightCounts;
}

void printDivider(const string& title) {
    cout << "\n";
    cout << string(78, '=') << "\n";
    cout << title << "\n";
    cout << string(78, '=') << "\n";
}


// ============================================================================
// 2. KEY ORDER GENERATION
// ============================================================================

vector<size_t> keyOrder(const string& key) {
    string cleaned = normalizeText(key);

    if (cleaned.empty()) {
        throw invalid_argument(
            "Key must contain at least one alphabetic character."
        );
    }

    vector<size_t> order(cleaned.size());

    iota(order.begin(), order.end(), 0);

    // The secondary comparison by original index makes duplicate letters
    // deterministic. For example, BALLOON has repeated L and O characters.
    stable_sort(
        order.begin(),
        order.end(),
        [&](size_t left, size_t right) {
            return cleaned[left] < cleaned[right];
        }
    );

    return order;
}


// ============================================================================
// 3. KEYED COLUMNAR ENCRYPTION
// ============================================================================

class KeyedColumnarCipher {
private:
    string key_;
    vector<size_t> order_;

public:
    explicit KeyedColumnarCipher(string key)
        : key_(normalizeText(key)),
          order_(keyOrder(key_)) {
        if (key_.empty()) {
            throw invalid_argument("Key cannot be empty.");
        }
    }

    const string& key() const {
        return key_;
    }

    const vector<size_t>& order() const {
        return order_;
    }

    string encrypt(const string& plaintext) const {
        if (plaintext.empty()) {
            return "";
        }

        const size_t columns = key_.size();
        const size_t rows =
            (plaintext.size() + columns - 1) / columns;

        string ciphertext;
        ciphertext.reserve(plaintext.size());

        // The message is logically written row by row.
        //
        // Example with five columns:
        //
        //     A B C D E
        //     F G H I J
        //     K L M
        //
        // Encryption reads columns according to the alphabetic ordering
        // of the key rather than their original left-to-right positions.
        for (size_t column : order_) {
            for (size_t row = 0; row < rows; ++row) {
                const size_t position =
                    row * columns + column;

                if (position < plaintext.size()) {
                    ciphertext.push_back(plaintext[position]);
                }
            }
        }

        return ciphertext;
    }

    string decrypt(const string& ciphertext) const {
        if (ciphertext.empty()) {
            return "";
        }

        const size_t columns = key_.size();
        const size_t rows =
            (ciphertext.size() + columns - 1) / columns;

        const size_t remainder =
            ciphertext.size() % columns;

        // In an incomplete final row, the first "remainder" columns contain
        // one extra character.
        vector<size_t> columnLengths(columns, rows);

        if (remainder != 0) {
            for (size_t column = remainder;
                 column < columns;
                 ++column) {
                columnLengths[column] = rows - 1;
            }
        }

        vector<string> columnData(columns);

        size_t offset = 0;

        // Ciphertext was generated in key order, so reconstruct columns in
        // exactly the same order.
        for (size_t column : order_) {
            const size_t length = columnLengths[column];

            columnData[column] =
                ciphertext.substr(offset, length);

            offset += length;
        }

        string plaintext;
        plaintext.reserve(ciphertext.size());

        // Read the reconstructed grid row by row.
        for (size_t row = 0; row < rows; ++row) {
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
};


// ============================================================================
// 4. RAIL FENCE
// ============================================================================

string railFenceEncrypt(
    const string& plaintext,
    size_t rails
) {
    if (rails == 0) {
        throw invalid_argument("Rails must be positive.");
    }

    if (rails <= 1 || plaintext.size() <= 1 ||
        rails >= plaintext.size()) {
        return plaintext;
    }

    vector<string> railData(rails);

    size_t row = 0;
    int direction = 1;

    for (char character : plaintext) {
        railData[row].push_back(character);

        if (row == 0) {
            direction = 1;
        } else if (row == rails - 1) {
            direction = -1;
        }

        row = static_cast<size_t>(
            static_cast<int>(row) + direction
        );
    }

    string ciphertext;
    ciphertext.reserve(plaintext.size());

    for (const string& rail : railData) {
        ciphertext += rail;
    }

    return ciphertext;
}

string railFenceDecrypt(
    const string& ciphertext,
    size_t rails
) {
    if (rails == 0) {
        throw invalid_argument("Rails must be positive.");
    }

    if (rails <= 1 || ciphertext.size() <= 1 ||
        rails >= ciphertext.size()) {
        return ciphertext;
    }

    vector<size_t> path;
    path.reserve(ciphertext.size());

    size_t row = 0;
    int direction = 1;

    for (size_t index = 0;
         index < ciphertext.size();
         ++index) {

        path.push_back(row);

        if (row == 0) {
            direction = 1;
        } else if (row == rails - 1) {
            direction = -1;
        }

        row = static_cast<size_t>(
            static_cast<int>(row) + direction
        );
    }

    vector<size_t> counts(rails, 0);

    for (size_t currentRow : path) {
        ++counts[currentRow];
    }

    vector<string> railData(rails);

    size_t offset = 0;

    for (size_t currentRail = 0;
         currentRail < rails;
         ++currentRail) {

        railData[currentRail] =
            ciphertext.substr(
                offset,
                counts[currentRail]
            );

        offset += counts[currentRail];
    }

    vector<size_t> positions(rails, 0);

    string plaintext;
    plaintext.reserve(ciphertext.size());

    for (size_t currentRail : path) {
        plaintext.push_back(
            railData[currentRail][positions[currentRail]]
        );

        ++positions[currentRail];
    }

    return plaintext;
}


// ============================================================================
// 5. ROUTE TRANSPOSITION
// ============================================================================

string routeEncrypt(
    const string& plaintext,
    size_t rows,
    size_t columns
) {
    if (rows == 0 || columns == 0) {
        throw invalid_argument(
            "Rows and columns must be positive."
        );
    }

    if (plaintext.size() > rows * columns) {
        throw invalid_argument(
            "Plaintext exceeds matrix capacity."
        );
    }

    vector<vector<char>> matrix(
        rows,
        vector<char>(columns, '\0')
    );

    size_t index = 0;

    for (size_t row = 0; row < rows; ++row) {
        for (size_t column = 0;
             column < columns;
             ++column) {

            if (index < plaintext.size()) {
                matrix[row][column] =
                    plaintext[index++];
            }
        }
    }

    string ciphertext;
    ciphertext.reserve(plaintext.size());

    for (size_t column = 0;
         column < columns;
         ++column) {

        for (size_t row = 0;
             row < rows;
             ++row) {

            if (matrix[row][column] != '\0') {
                ciphertext.push_back(
                    matrix[row][column]
                );
            }
        }
    }

    return ciphertext;
}

string routeDecrypt(
    const string& ciphertext,
    size_t rows,
    size_t columns
) {
    if (rows == 0 || columns == 0) {
        throw invalid_argument(
            "Rows and columns must be positive."
        );
    }

    if (ciphertext.size() > rows * columns) {
        throw invalid_argument(
            "Ciphertext exceeds matrix capacity."
        );
    }

    vector<vector<char>> matrix(
        rows,
        vector<char>(columns, '\0')
    );

    size_t index = 0;

    for (size_t column = 0;
         column < columns;
         ++column) {

        for (size_t row = 0;
             row < rows;
             ++row) {

            if (index < ciphertext.size()) {
                matrix[row][column] =
                    ciphertext[index++];
            }
        }
    }

    string plaintext;
    plaintext.reserve(ciphertext.size());

    for (size_t row = 0;
         row < rows;
         ++row) {

        for (size_t column = 0;
             column < columns;
             ++column) {

            if (matrix[row][column] != '\0') {
                plaintext.push_back(
                    matrix[row][column]
                );
            }
        }
    }

    return plaintext;
}


// ============================================================================
// 6. FREQUENCY ANALYSIS
// ============================================================================

map<char, size_t> frequencyTable(const string& text) {
    map<char, size_t> counts;

    for (char character : text) {
        ++counts[character];
    }

    return counts;
}

void printFrequencyTable(const string& text) {
    const auto frequencies = frequencyTable(text);

    for (const auto& [character, count] : frequencies) {
        cout << character << ": " << count << "\n";
    }
}


// ============================================================================
// 7. SIMPLE LANGUAGE SCORE
// ============================================================================

int ngramScore(const string& text) {
    static const vector<string> commonNgrams = {
        "TH", "HE", "IN", "ER", "AN", "RE",
        "ON", "AT", "EN", "ND", "TI", "ES",
        "OR", "TE", "OF", "ED", "THE", "AND",
        "ING", "HER", "ENT", "THA"
    };

    int score = 0;

    for (const string& ngram : commonNgrams) {
        size_t position = 0;

        while (true) {
            position = text.find(ngram, position);

            if (position == string::npos) {
                break;
            }

            score +=
                ngram.size() == 3
                    ? 2
                    : 1;

            ++position;
        }
    }

    return score;
}


// ============================================================================
// 8. STRUCTURAL ATTACK
// ============================================================================

struct Candidate {
    size_t columns;
    int score;
    string plaintext;
};

vector<Candidate> tryColumnCounts(
    const string& ciphertext,
    size_t minimumColumns,
    size_t maximumColumns
) {
    vector<Candidate> candidates;

    if (ciphertext.empty()) {
        return candidates;
    }

    maximumColumns = min(
        maximumColumns,
        ciphertext.size()
    );

    for (size_t columns = max<size_t>(2, minimumColumns);
         columns <= maximumColumns;
         ++columns) {

        // This deliberately ignores the original key. It asks only whether
        // a particular grid width could produce a language-like candidate.
        //
        // This is a structural attack rather than a complete cryptanalytic
        // solution.
        string candidate;

        const size_t rows =
            (ciphertext.size() + columns - 1) / columns;

        const size_t remainder =
            ciphertext.size() % columns;

        vector<size_t> lengths(columns, rows);

        if (remainder != 0) {
            for (size_t column = remainder;
                 column < columns;
                 ++column) {
                lengths[column] = rows - 1;
            }
        }

        vector<string> columnData(columns);

        size_t offset = 0;

        // Assume ciphertext was read in normal column order.
        for (size_t column = 0;
             column < columns;
             ++column) {

            columnData[column] =
                ciphertext.substr(
                    offset,
                    lengths[column]
                );

            offset += lengths[column];
        }

        for (size_t row = 0; row < rows; ++row) {
            for (size_t column = 0;
                 column < columns;
                 ++column) {

                if (row < columnData[column].size()) {
                    candidate.push_back(
                        columnData[column][row]
                    );
                }
            }
        }

        candidates.push_back({
            columns,
            ngramScore(candidate),
            candidate
        });
    }

    sort(
        candidates.begin(),
        candidates.end(),
        [](const Candidate& left, const Candidate& right) {
            return left.score > right.score;
        }
    );

    return candidates;
}


// ============================================================================
// 9. CASE-STUDY DATA MODEL
// ============================================================================

struct MessageRecord {
    size_t id;
    string sender;
    string plaintext;
    string ciphertext;
};

class MessageArchive {
private:
    KeyedColumnarCipher cipher_;
    vector<MessageRecord> records_;
    size_t nextId_ = 1;

public:
    explicit MessageArchive(const string& key)
        : cipher_(key) {}

    size_t store(
        const string& sender,
        const string& message
    ) {
        const string plaintext =
            normalizeText(message);

        if (plaintext.empty()) {
            throw invalid_argument(
                "Message must contain alphabetic content."
            );
        }

        const string ciphertext =
            cipher_.encrypt(plaintext);

        const size_t id = nextId_++;

        records_.push_back({
            id,
            sender,
            plaintext,
            ciphertext
        });

        return id;
    }

    string recover(size_t id) const {
        auto iterator = find_if(
            records_.begin(),
            records_.end(),
            [id](const MessageRecord& record) {
                return record.id == id;
            }
        );

        if (iterator == records_.end()) {
            throw out_of_range(
                "Message ID does not exist."
            );
        }

        return cipher_.decrypt(
            iterator->ciphertext
        );
    }

    const vector<MessageRecord>& records() const {
        return records_;
    }

    const KeyedColumnarCipher& cipher() const {
        return cipher_;
    }
};


// ============================================================================
// 10. INTEGRITY CHECK
// ============================================================================

bool validateRoundTrip(
    const KeyedColumnarCipher& cipher,
    const string& plaintext
) {
    const string ciphertext =
        cipher.encrypt(plaintext);

    const string recovered =
        cipher.decrypt(ciphertext);

    return recovered == plaintext;
}


// ============================================================================
// 11. BENCHMARK
// ============================================================================

void benchmark(
    const KeyedColumnarCipher& cipher
) {
    printDivider("PERFORMANCE BENCHMARK");

    string plaintext;

    const string seed =
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";

    for (size_t index = 0; index < 5000; ++index) {
        plaintext += seed;
    }

    const auto start =
        chrono::high_resolution_clock::now();

    const string ciphertext =
        cipher.encrypt(plaintext);

    const string recovered =
        cipher.decrypt(ciphertext);

    const auto finish =
        chrono::high_resolution_clock::now();

    const chrono::duration<double, milli> elapsed =
        finish - start;

    cout << "Characters processed: "
         << plaintext.size()
         << "\n";

    cout << "Recovered correctly: "
         << boolalpha
         << (recovered == plaintext)
         << "\n";

    cout << fixed
         << setprecision(3)
         << "Elapsed time: "
         << elapsed.count()
         << " ms\n";

    cout << "\nDirect transposition is approximately O(n) for a fixed key width.\n";
    cout << "Memory consumption is approximately O(n) for this implementation.\n";
}


// ============================================================================
// 12. TESTING
// ============================================================================

void require(
    bool condition,
    const string& description
) {
    if (!condition) {
        throw runtime_error(
            "TEST FAILED: " + description
        );
    }

    cout << "PASS: " << description << "\n";
}

void runTests() {
    printDivider("AUTOMATED TESTS");

    const vector<string> messages = {
        "",
        "A",
        "AB",
        "HELLO",
        "HELLOWORLD",
        "WEAREDISCOVEREDFLEEATONCE",
        "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    };

    for (const string& message : messages) {
        for (size_t rails = 1;
             rails <= min<size_t>(
                 6,
                 max<size_t>(1, message.size())
             );
             ++rails) {

            const string ciphertext =
                railFenceEncrypt(message, rails);

            const string recovered =
                railFenceDecrypt(ciphertext, rails);

            require(
                recovered == message,
                "Rail Fence round trip"
            );
        }
    }

    for (const string& message : messages) {
        for (size_t columns = 1;
             columns <= 6;
             ++columns) {

            KeyedColumnarCipher cipher(
                string(columns, 'A')
            );

            // Duplicate key letters are intentionally supported. Stable
            // ordering makes the operation deterministic.
            const string ciphertext =
                cipher.encrypt(message);

            const string recovered =
                cipher.decrypt(ciphertext);

            require(
                recovered == message,
                "Keyed columnar round trip"
            );
        }
    }

    KeyedColumnarCipher zebra("ZEBRA");

    for (const string& message : messages) {
        require(
            validateRoundTrip(zebra, message),
            "ZEBRA keyed columnar round trip"
        );
    }

    for (const string& message : messages) {
        if (message.size() <= 12) {
            const size_t rows = 4;
            const size_t columns = 4;

            if (message.size() <= rows * columns) {
                const string ciphertext =
                    routeEncrypt(
                        message,
                        rows,
                        columns
                    );

                const string recovered =
                    routeDecrypt(
                        ciphertext,
                        rows,
                        columns
                    );

                require(
                    recovered == message,
                    "Route transposition round trip"
                );
            }
        }
    }

    const string permutationText = "ABCDEFGHIJK";
    const vector<size_t> permutation = {
        2, 0, 5, 1, 7, 3, 9, 4, 10, 6, 8
    };

    string encrypted;

    for (size_t index : permutation) {
        encrypted.push_back(
            permutationText[index]
        );
    }

    vector<size_t> inverse(permutation.size());

    for (size_t encryptedPosition = 0;
         encryptedPosition < permutation.size();
         ++encryptedPosition) {

        inverse[permutation[encryptedPosition]] =
            encryptedPosition;
    }

    string recovered;

    for (size_t index : inverse) {
        recovered.push_back(
            encrypted[index]
        );
    }

    require(
        recovered == permutationText,
        "Permutation inversion"
    );

    cout << "\nAll C++ tests completed successfully.\n";
}


// ============================================================================
// 13. MAIN CASE STUDY
// ============================================================================

int main() {
    try {
        printDivider("TRANSPOSITION CIPHER CASE STUDY");

        cout << "The case study models a historical message archive using\n";
        cout << "a keyed columnar transposition cipher.\n";

        // --------------------------------------------------------------------
        // Stage 1: Configure the cipher.
        // --------------------------------------------------------------------

        const string key = "ZEBRA";

        KeyedColumnarCipher cipher(key);

        cout << "\nKey: " << cipher.key() << "\n";

        cout << "Column order: ";

        for (size_t index : cipher.order()) {
            cout << index << ' ';
        }

        cout << "\n";

        // --------------------------------------------------------------------
        // Stage 2: Store several messages.
        // --------------------------------------------------------------------

        MessageArchive archive(key);

        const size_t firstId =
            archive.store(
                "Operator-A",
                "Meet at the northern checkpoint at dawn."
            );

        const size_t secondId =
            archive.store(
                "Operator-B",
                "Transfer the documents after sunset."
            );

        const size_t thirdId =
            archive.store(
                "Operator-C",
                "Archive the completed report."
            );

        cout << "\nStored message IDs:\n";
        cout << firstId << ", "
             << secondId << ", "
             << thirdId << "\n";

        // --------------------------------------------------------------------
        // Stage 3: Inspect ciphertext.
        // --------------------------------------------------------------------

        printDivider("ARCHIVE RECORDS");

        for (const MessageRecord& record :
             archive.records()) {

            cout << "ID:        "
                 << record.id << "\n";

            cout << "Sender:    "
                 << record.sender << "\n";

            cout << "Plaintext: "
                 << record.plaintext << "\n";

            cout << "Ciphertext:"
                 << record.ciphertext << "\n";

            cout << "\n";
        }

        // --------------------------------------------------------------------
        // Stage 4: Recover a message.
        // --------------------------------------------------------------------

        printDivider("MESSAGE RECOVERY");

        const string recovered =
            archive.recover(firstId);

        cout << "Recovered message ID "
             << firstId
             << ":\n"
             << recovered
             << "\n";

        // --------------------------------------------------------------------
        // Stage 5: Verify frequency preservation.
        // --------------------------------------------------------------------

        printDivider("FREQUENCY PRESERVATION");

        const MessageRecord& firstRecord =
            archive.records().front();

        cout << boolalpha
             << "Same character multiset: "
             << sameCharacterMultiset(
                    firstRecord.plaintext,
                    firstRecord.ciphertext
                )
             << "\n\n";

        cout << "Plaintext frequencies:\n";
        printFrequencyTable(
            firstRecord.plaintext
        );

        cout << "\nCiphertext frequencies:\n";
        printFrequencyTable(
            firstRecord.ciphertext
        );

        // --------------------------------------------------------------------
        // Stage 6: Compare with Rail Fence.
        // --------------------------------------------------------------------

        printDivider("ALGORITHM COMPARISON");

        const string comparisonText =
            normalizeText(
                "We are discovered flee at once."
            );

        const string railCiphertext =
            railFenceEncrypt(
                comparisonText,
                3
            );

        const string columnCiphertext =
            cipher.encrypt(comparisonText);

        cout << "Plaintext:        "
             << comparisonText
             << "\n";

        cout << "Rail Fence:       "
             << railCiphertext
             << "\n";

        cout << "Keyed Columnar:   "
             << columnCiphertext
             << "\n";

        // --------------------------------------------------------------------
        // Stage 7: Structural cryptanalysis demonstration.
        // --------------------------------------------------------------------

        printDivider("STRUCTURAL CRYPTANALYSIS");

        const string attackPlaintext =
            normalizeText(
                "Transposition rearranges letters while preserving "
                "their individual identities."
            );

        const string attackCiphertext =
            routeEncrypt(
                attackPlaintext,
                7,
                (attackPlaintext.size() + 6) / 7
            );

        cout << "Ciphertext generated from a route construction:\n";
        cout << attackCiphertext << "\n";

        cout << "\nTesting candidate column counts against a generic\n";
        cout << "columnar-transposition model:\n";

        const vector<Candidate> candidates =
            tryColumnCounts(
                attackCiphertext,
                2,
                12
            );

        const size_t displayCount =
            min<size_t>(5, candidates.size());

        for (size_t index = 0;
             index < displayCount;
             ++index) {

            const Candidate& candidate =
                candidates[index];

            cout << "columns="
                 << candidate.columns
                 << " score="
                 << candidate.score
                 << " candidate="
                 << candidate.plaintext.substr(0, 70)
                 << "\n";
        }

        cout << "\nThis attack is deliberately limited. A route cipher and a\n";
        cout << "columnar cipher have different structural assumptions, so\n";
        cout << "a generic candidate search is not guaranteed to recover the\n";
        cout << "original route.\n";

        // --------------------------------------------------------------------
        // Stage 8: Error handling.
        // --------------------------------------------------------------------

        printDivider("ERROR HANDLING");

        try {
            KeyedColumnarCipher invalid("");
        } catch (const exception& error) {
            cout << "Handled invalid key: "
                 << error.what()
                 << "\n";
        }

        try {
            routeEncrypt(
                "TOOLONG",
                2,
                2
            );
        } catch (const exception& error) {
            cout << "Handled capacity error: "
                 << error.what()
                 << "\n";
        }

        // --------------------------------------------------------------------
        // Stage 9: Performance.
        // --------------------------------------------------------------------

        benchmark(cipher);

        // --------------------------------------------------------------------
        // Stage 10: Complete automated validation.
        // --------------------------------------------------------------------

        runTests();

        printDivider("CASE STUDY COMPLETE");

        cout << "The archive workflow successfully demonstrated:\n";
        cout << "  - keyed column ordering\n";
        cout << "  - encryption and decryption\n";
        cout << "  - incomplete final rows\n";
        cout << "  - message storage and retrieval\n";
        cout << "  - frequency preservation\n";
        cout << "  - algorithm comparison\n";
        cout << "  - structural analysis\n";
        cout << "  - validation\n";
        cout << "  - error handling\n";
        cout << "  - performance measurement\n";

        return 0;
    }
    catch (const exception& error) {
        cerr << "Fatal error: "
             << error.what()
             << "\n";

        return 1;
    }
}
