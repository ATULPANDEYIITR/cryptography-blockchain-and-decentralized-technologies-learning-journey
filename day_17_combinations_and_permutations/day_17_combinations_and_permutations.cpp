/*
 * Combinations and Permutations
 * ==============================
 *
 * C++17 industry-style case study:
 * Secure event-code and committee planning system
 *
 * The program demonstrates:
 *   - factorials
 *   - permutations
 *   - combinations
 *   - repetition
 *   - exact counting with arbitrary-size decimal strings
 *   - enumeration
 *   - duplicate handling
 *   - constrained selection
 *   - committee generation
 *   - event-code generation
 *   - validation
 *   - complexity considerations
 *   - modular design
 *
 * Compile:
 *   g++ -std=c++17 -O2 combinations_permutations.cpp -o combinations
 */

#include <algorithm>
#include <boost/multiprecision/cpp_int.hpp>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <numeric>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using boost::multiprecision::cpp_int;

// -----------------------------------------------------------------------------
// Basic mathematical functions
// -----------------------------------------------------------------------------

cpp_int factorial(std::size_t n) {
    cpp_int result = 1;

    for (std::size_t value = 2; value <= n; ++value) {
        result *= value;
    }

    return result;
}

cpp_int permutationCount(std::size_t n, std::size_t r) {
    if (r > n) {
        throw std::invalid_argument("r must not exceed n");
    }

    cpp_int result = 1;

    for (std::size_t value = n - r + 1; value <= n; ++value) {
        result *= value;

        // Avoid unsigned wraparound after n when the loop reaches n.
        if (value == n) {
            break;
        }
    }

    return result;
}

cpp_int combinationCount(std::size_t n, std::size_t r) {
    if (r > n) {
        throw std::invalid_argument("r must not exceed n");
    }

    // C(n,r) = C(n,n-r).
    r = std::min(r, n - r);

    cpp_int result = 1;

    for (std::size_t i = 1; i <= r; ++i) {
        result *= n - r + i;
        result /= i;
    }

    return result;
}

cpp_int permutationWithRepetition(std::size_t alphabetSize, std::size_t length) {
    cpp_int result = 1;

    for (std::size_t i = 0; i < length; ++i) {
        result *= alphabetSize;
    }

    return result;
}

// -----------------------------------------------------------------------------
// Data model for event-code generation
// -----------------------------------------------------------------------------

struct CodePolicy {
    std::size_t letterCount{};
    std::size_t digitCount{};
    bool allowRepeatedLetters{false};
    bool allowRepeatedDigits{false};

    void validate(
        std::size_t letterAlphabetSize,
        std::size_t digitAlphabetSize
    ) const {
        if (!allowRepeatedLetters && letterCount > letterAlphabetSize) {
            throw std::invalid_argument(
                "requested more distinct letters than the alphabet contains"
            );
        }

        if (!allowRepeatedDigits && digitCount > digitAlphabetSize) {
            throw std::invalid_argument(
                "requested more distinct digits than the alphabet contains"
            );
        }
    }
};

class EventCodeGenerator {
private:
    std::string letters_;
    std::string digits_;

    static void generateDistinct(
        const std::string& source,
        std::size_t required,
        std::string& current,
        std::vector<bool>& used,
        const std::function<void(const std::string&)>& consumer
    ) {
        if (current.size() == required) {
            consumer(current);
            return;
        }

        for (std::size_t index = 0; index < source.size(); ++index) {
            if (used[index]) {
                continue;
            }

            used[index] = true;
            current.push_back(source[index]);

            generateDistinct(
                source,
                required,
                current,
                used,
                consumer
            );

            current.pop_back();
            used[index] = false;
        }
    }

    static void generateRepeated(
        const std::string& source,
        std::size_t required,
        std::string& current,
        const std::function<void(const std::string&)>& consumer
    ) {
        if (current.size() == required) {
            consumer(current);
            return;
        }

        for (char symbol : source) {
            current.push_back(symbol);

            generateRepeated(
                source,
                required,
                current,
                consumer
            );

            current.pop_back();
        }
    }

public:
    EventCodeGenerator(std::string letters, std::string digits)
        : letters_(std::move(letters)),
          digits_(std::move(digits)) {
        if (letters_.empty() || digits_.empty()) {
            throw std::invalid_argument(
                "letter and digit alphabets must not be empty"
            );
        }
    }

    cpp_int count(const CodePolicy& policy) const {
        policy.validate(letters_.size(), digits_.size());

        cpp_int letterWays;

        if (policy.allowRepeatedLetters) {
            letterWays =
                permutationWithRepetition(
                    letters_.size(),
                    policy.letterCount
                );
        } else {
            letterWays =
                permutationCount(
                    letters_.size(),
                    policy.letterCount
                );
        }

        cpp_int digitWays;

        if (policy.allowRepeatedDigits) {
            digitWays =
                permutationWithRepetition(
                    digits_.size(),
                    policy.digitCount
                );
        } else {
            digitWays =
                permutationCount(
                    digits_.size(),
                    policy.digitCount
                );
        }

        // Multiplication principle:
        // each valid letter sequence can be combined with each valid
        // digit sequence.
        return letterWays * digitWays;
    }

    void generate(
        const CodePolicy& policy,
        const std::function<void(const std::string&)>& consumer
    ) const {
        policy.validate(letters_.size(), digits_.size());

        std::string letterPart;
        std::string digitPart;

        auto consumeLetters =
            [&](const std::string& generatedLetters) {
                auto consumeDigits =
                    [&](const std::string& generatedDigits) {
                        consumer(generatedLetters + generatedDigits);
                    };

                if (policy.allowRepeatedDigits) {
                    generateRepeated(
                        digits_,
                        policy.digitCount,
                        digitPart,
                        consumeDigits
                    );
                } else {
                    std::vector<bool> used(digits_.size(), false);

                    generateDistinct(
                        digits_,
                        policy.digitCount,
                        digitPart,
                        used,
                        consumeDigits
                    );
                }
            };

        if (policy.allowRepeatedLetters) {
            generateRepeated(
                letters_,
                policy.letterCount,
                letterPart,
                consumeLetters
            );
        } else {
            std::vector<bool> used(letters_.size(), false);

            generateDistinct(
                letters_,
                policy.letterCount,
                letterPart,
                used,
                consumeLetters
            );
        }
    }
};

// -----------------------------------------------------------------------------
// Committee planning
// -----------------------------------------------------------------------------

class CommitteePlanner {
private:
    std::vector<std::string> people_;

public:
    explicit CommitteePlanner(std::vector<std::string> people)
        : people_(std::move(people)) {
        if (people_.empty()) {
            throw std::invalid_argument("committee roster cannot be empty");
        }

        std::set<std::string> uniquePeople(
            people_.begin(),
            people_.end()
        );

        if (uniquePeople.size() != people_.size()) {
            throw std::invalid_argument(
                "committee roster must contain unique names"
            );
        }
    }

    cpp_int countCommittees(std::size_t committeeSize) const {
        if (committeeSize > people_.size()) {
            return 0;
        }

        return combinationCount(people_.size(), committeeSize);
    }

    std::vector<std::vector<std::string>>
    generateCommittees(std::size_t committeeSize) const {
        if (committeeSize > people_.size()) {
            return {};
        }

        std::vector<std::vector<std::string>> result;
        std::vector<std::string> current;

        std::function<void(std::size_t)> backtrack =
            [&](std::size_t start) {
                if (current.size() == committeeSize) {
                    result.push_back(current);
                    return;
                }

                const std::size_t remainingNeeded =
                    committeeSize - current.size();

                for (
                    std::size_t index = start;
                    index <= people_.size() - remainingNeeded;
                    ++index
                ) {
                    current.push_back(people_[index]);
                    backtrack(index + 1);
                    current.pop_back();
                }
            };

        backtrack(0);
        return result;
    }
};

// -----------------------------------------------------------------------------
// Constrained subset counting
// -----------------------------------------------------------------------------

std::uint64_t countSubsetsWithTarget(
    const std::vector<int>& values,
    int target
) {
    if (target < 0) {
        return 0;
    }

    std::vector<std::uint64_t> dp(
        static_cast<std::size_t>(target) + 1,
        0
    );

    dp[0] = 1;

    for (int value : values) {
        if (value < 0) {
            throw std::invalid_argument(
                "this dynamic-programming implementation "
                "requires non-negative values"
            );
        }

        if (value > target) {
            continue;
        }

        // Descending order prevents using the same item more than once.
        for (int sum = target; sum >= value; --sum) {
            dp[static_cast<std::size_t>(sum)] +=
                dp[static_cast<std::size_t>(sum - value)];
        }
    }

    return dp[static_cast<std::size_t>(target)];
}

// -----------------------------------------------------------------------------
// Multiset permutation counting
// -----------------------------------------------------------------------------

cpp_int multisetPermutationCount(const std::string& text) {
    std::map<char, std::size_t> frequency;

    for (char character : text) {
        ++frequency[character];
    }

    cpp_int result = factorial(text.size());

    for (const auto& [character, count] : frequency) {
        (void)character;
        result /= factorial(count);
    }

    return result;
}

// -----------------------------------------------------------------------------
// Probability
// -----------------------------------------------------------------------------

struct Fraction {
    cpp_int numerator;
    cpp_int denominator;
};

cpp_int gcdBigInt(cpp_int a, cpp_int b) {
    while (b != 0) {
        cpp_int remainder = a % b;
        a = b;
        b = remainder;
    }

    return a < 0 ? -a : a;
}

Fraction reduceFraction(cpp_int numerator, cpp_int denominator) {
    if (denominator == 0) {
        throw std::invalid_argument("denominator cannot be zero");
    }

    cpp_int divisor = gcdBigInt(numerator, denominator);

    return {
        numerator / divisor,
        denominator / divisor
    };
}

Fraction hypergeometricProbability(
    std::size_t population,
    std::size_t successes,
    std::size_t sample,
    std::size_t requiredSuccesses
) {
    if (successes > population || sample > population) {
        throw std::invalid_argument("invalid population parameters");
    }

    if (
        requiredSuccesses > successes ||
        sample < requiredSuccesses ||
        sample - requiredSuccesses > population - successes
    ) {
        return {0, 1};
    }

    cpp_int favorable =
        combinationCount(successes, requiredSuccesses) *
        combinationCount(
            population - successes,
            sample - requiredSuccesses
        );

    cpp_int total = combinationCount(population, sample);

    return reduceFraction(favorable, total);
}

// -----------------------------------------------------------------------------
// Output helpers
// -----------------------------------------------------------------------------

void printCommittee(
    const std::vector<std::string>& committee
) {
    std::cout << "{ ";

    for (std::size_t i = 0; i < committee.size(); ++i) {
        std::cout << committee[i];

        if (i + 1 < committee.size()) {
            std::cout << ", ";
        }
    }

    std::cout << " }";
}

void printSection(const std::string& title) {
    std::cout << "\n";
    std::cout << std::string(78, '=') << "\n";
    std::cout << title << "\n";
    std::cout << std::string(78, '=') << "\n";
}

// -----------------------------------------------------------------------------
// Demonstration 1: basic formulas
// -----------------------------------------------------------------------------

void demonstrateBasicCounting() {
    printSection("1. Basic counting");

    std::cout << "5! = " << factorial(5) << "\n";
    std::cout << "P(5,3) = " << permutationCount(5, 3) << "\n";
    std::cout << "C(5,3) = " << combinationCount(5, 3) << "\n";

    std::cout
        << "P(5,3) / 3! = "
        << permutationCount(5, 3) / factorial(3)
        << "\n";

    std::cout
        << "10^4 repeated-symbol codes = "
        << permutationWithRepetition(10, 4)
        << "\n";
}

// -----------------------------------------------------------------------------
// Demonstration 2: real event-code system
// -----------------------------------------------------------------------------

void demonstrateEventCodes() {
    printSection("2. Event registration code system");

    /*
     * A registration platform needs short codes.
     *
     * Policy:
     *   - two distinct letters
     *   - three distinct digits
     *   - letters appear before digits
     *
     * This models a common system-design problem: determining capacity
     * before generating actual identifiers.
     */
    EventCodeGenerator generator(
        "ABCD",
        "12345"
    );

    CodePolicy policy{
        2,
        3,
        false,
        false
    };

    cpp_int capacity = generator.count(policy);

    std::cout
        << "Total valid codes: "
        << capacity
        << "\n";

    std::cout << "First ten generated codes:\n";

    std::size_t printed = 0;

    generator.generate(
        policy,
        [&](const std::string& code) {
            if (printed < 10) {
                std::cout << "  " << code << "\n";
            }

            ++printed;
        }
    );

    std::cout
        << "Actual generated count: "
        << printed
        << "\n";

    if (capacity != printed) {
        throw std::runtime_error(
            "counting formula and enumeration disagree"
        );
    }
}

// -----------------------------------------------------------------------------
// Demonstration 3: repetition
// -----------------------------------------------------------------------------

void demonstrateRepetition() {
    printSection("3. Repetition versus no repetition");

    EventCodeGenerator generator(
        "ABC",
        "0123456789"
    );

    CodePolicy repeated{
        3,
        4,
        true,
        true
    };

    CodePolicy unique{
        3,
        4,
        false,
        false
    };

    std::cout
        << "3 letters + 4 digits with repetition: "
        << generator.count(repeated)
        << "\n";

    std::cout
        << "3 letters + 4 digits without repetition: ";

    // This policy is intentionally invalid because there are only
    // three letters, but exactly three distinct letters is valid.
    // The digit alphabet has enough distinct symbols.
    std::cout
        << generator.count(unique)
        << "\n";

    std::cout
        << "Repetition changes multiplication from decreasing choices "
        << "to a constant number of choices per position.\n";
}

// -----------------------------------------------------------------------------
// Demonstration 4: committee selection
// -----------------------------------------------------------------------------

void demonstrateCommittees() {
    printSection("4. Committee planning");

    CommitteePlanner planner({
        "Asha",
        "Bharat",
        "Chen",
        "Divya",
        "Elena",
        "Farah"
    });

    const std::size_t committeeSize = 3;

    std::cout
        << "Number of 3-person committees: "
        << planner.countCommittees(committeeSize)
        << "\n";

    auto committees =
        planner.generateCommittees(committeeSize);

    std::cout << "Generated committees:\n";

    for (const auto& committee : committees) {
        std::cout << "  ";
        printCommittee(committee);
        std::cout << "\n";
    }

    if (
        cpp_int(committees.size()) !=
        planner.countCommittees(committeeSize)
    ) {
        throw std::runtime_error(
            "committee enumeration and counting disagree"
        );
    }

    std::cout
        << "\nA committee is a combination because "
        << "the order of members is irrelevant.\n";
}

// -----------------------------------------------------------------------------
// Demonstration 5: repeated characters
// -----------------------------------------------------------------------------

void demonstrateMultiset() {
    printSection("5. Multiset permutations");

    const std::string word = "LEVEL";

    std::cout
        << "Distinct permutations of "
        << word
        << ": "
        << multisetPermutationCount(word)
        << "\n";

    std::cout
        << "Formula: 5! / (2! * 2! * 1!) = 30\n";

    std::cout
        << "Duplicate objects must not be treated as independently "
        << "identifiable when counting distinct arrangements.\n";
}

// -----------------------------------------------------------------------------
// Demonstration 6: probability
// -----------------------------------------------------------------------------

void demonstrateProbability() {
    printSection("6. Probability using combinations");

    /*
     * Five cards are drawn from a standard 52-card deck.
     *
     * There are 13 hearts and 39 non-hearts.
     * We want exactly two hearts.
     *
     * Favorable:
     *   C(13,2) * C(39,3)
     *
     * Total:
     *   C(52,5)
     */
    Fraction probability =
        hypergeometricProbability(
            52,
            13,
            5,
            2
        );

    std::cout
        << "P(exactly two hearts in five cards) = "
        << probability.numerator
        << "/"
        << probability.denominator
        << "\n";
}

// -----------------------------------------------------------------------------
// Demonstration 7: constrained selection
// -----------------------------------------------------------------------------

void demonstrateConstrainedSelection() {
    printSection("7. Constrained selection with dynamic programming");

    std::vector<int> costs{
        2, 3, 5, 7, 11
    };

    const int target = 10;

    const auto count =
        countSubsetsWithTarget(costs, target);

    std::cout
        << "Number of subsets summing to "
        << target
        << ": "
        << count
        << "\n";

    std::cout
        << "Dynamic programming uses O(n * target) states "
        << "instead of enumerating all 2^n subsets.\n";
}

// -----------------------------------------------------------------------------
// Demonstration 8: circular permutations
// -----------------------------------------------------------------------------

void demonstrateCircularPermutations() {
    printSection("8. Circular arrangements");

    for (std::size_t n = 1; n <= 6; ++n) {
        std::cout
            << n
            << " people around a circular table: "
            << factorial(n - 1)
            << "\n";
    }

    std::cout
        << "Rotations are considered equivalent, so one person "
        << "can be fixed as an anchor.\n";
}

// -----------------------------------------------------------------------------
// Demonstration 9: invalid inputs
// -----------------------------------------------------------------------------

void demonstrateValidation() {
    printSection("9. Validation and failure conditions");

    try {
        std::cout << combinationCount(3, 5) << "\n";
    } catch (const std::exception& error) {
        std::cout
            << "Invalid C(3,5): "
            << error.what()
            << "\n";
    }

    try {
        EventCodeGenerator generator("AB", "12");

        CodePolicy invalidPolicy{
            3,
            1,
            false,
            false
        };

        generator.count(invalidPolicy);
    } catch (const std::exception& error) {
        std::cout
            << "Invalid code policy: "
            << error.what()
            << "\n";
    }
}

// -----------------------------------------------------------------------------
// Demonstration 10: complexity
// -----------------------------------------------------------------------------

void demonstrateComplexity() {
    printSection("10. Complexity considerations");

    std::cout
        << "factorial(n): O(n) multiplications\n";

    std::cout
        << "P(n,r): O(r) multiplicative steps\n";

    std::cout
        << "C(n,r): O(min(r,n-r)) multiplicative steps\n";

    std::cout
        << "Enumerating all permutations: O(n! * n) output-sensitive\n";

    std::cout
        << "Enumerating all r-combinations: O(C(n,r) * r)\n";

    std::cout
        << "Subset-sum dynamic programming: O(n * target) time and "
        << "O(target) memory\n";

    std::cout
        << "Counting is fundamentally different from enumeration: "
        << "a huge number can often be represented by one exact integer "
        << "without constructing every arrangement.\n";
}

// -----------------------------------------------------------------------------
// Self-tests
// -----------------------------------------------------------------------------

void runTests() {
    printSection("11. Self-tests");

    for (std::size_t n = 0; n <= 10; ++n) {
        if (factorial(n) <= 0) {
            throw std::runtime_error("factorial test failed");
        }

        for (std::size_t r = 0; r <= n; ++r) {
            cpp_int p = permutationCount(n, r);
            cpp_int c = combinationCount(n, r);

            if (p != c * factorial(r)) {
                throw std::runtime_error(
                    "P(n,r) = C(n,r) * r! test failed"
                );
            }

            if (c != combinationCount(n, n - r)) {
                throw std::runtime_error(
                    "combination symmetry test failed"
                );
            }
        }
    }

    if (multisetPermutationCount("AAB") != 3) {
        throw std::runtime_error(
            "multiset permutation test failed"
        );
    }

    if (countSubsetsWithTarget({2, 3, 5, 7, 11}, 10) != 2) {
        throw std::runtime_error(
            "subset-sum test failed"
        );
    }

    Fraction probability =
        hypergeometricProbability(52, 13, 5, 2);

    if (
        probability.numerator <= 0 ||
        probability.denominator <= 0
    ) {
        throw std::runtime_error(
            "probability test failed"
        );
    }

    std::cout << "All tests passed.\n";
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "COMBINATIONS AND PERMUTATIONS\n"
            << "C++17 Industry-Style Case Study\n";

        demonstrateBasicCounting();
        demonstrateEventCodes();
        demonstrateRepetition();
        demonstrateCommittees();
        demonstrateMultiset();
        demonstrateProbability();
        demonstrateConstrainedSelection();
        demonstrateCircularPermutations();
        demonstrateValidation();
        demonstrateComplexity();
        runTests();

        printSection("Case study completed");
        std::cout
            << "The program completed all demonstrations and tests "
            << "successfully.\n";

        return 0;
    }
    catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
