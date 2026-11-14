#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <cstdint>
#include <limits>

using namespace std;

/*
 * Introduction to Elliptic Curves
 *
 * C++17 finite-field elliptic curve and group-order engine.
 * Uses y^2 = x^3 + ax + b (mod p).
 *
 * Educational implementation.
 * Modular multiplication uses __int128, supported by GCC and Clang.
 */

using Integer = long long;
using Wide = __int128_t;

class CurveException : public runtime_error {
public:
    explicit CurveException(const string& message)
        : runtime_error(message) {}
};

class PointException : public CurveException {
public:
    explicit PointException(const string& message)
        : CurveException(message) {}
};

enum class PointType {
    Affine,
    Infinity
};

struct Point {
    PointType type;
    Integer x;
    Integer y;

    static Point infinity() {
        return {PointType::Infinity, 0, 0};
    }

    static Point affine(Integer x, Integer y) {
        return {PointType::Affine, x, y};
    }

    bool isInfinity() const {
        return type == PointType::Infinity;
    }

    string toString() const {
        if (isInfinity()) return "O";

        return "(" + to_string(x) + ", " +
               to_string(y) + ")";
    }

    bool operator==(const Point& other) const {
        if (type != other.type) return false;

        if (isInfinity()) return true;

        return x == other.x && y == other.y;
    }
};

class FiniteField {
private:
    Integer modulus;

public:
    explicit FiniteField(Integer p) : modulus(p) {
        if (p < 5 || !isPrime(p)) {
            throw CurveException(
                "Field modulus must be prime and >= 5."
            );
        }
    }

    static bool isPrime(Integer n) {
        if (n < 2) return false;
        if (n % 2 == 0) return n == 2;

        for (Integer d = 3; d <= n / d; d += 2) {
            if (n % d == 0) return false;
        }

        return true;
    }

    Integer p() const {
        return modulus;
    }

    Integer normalize(Integer value) const {
        value %= modulus;

        if (value < 0) value += modulus;

        return value;
    }

    Integer add(Integer a, Integer b) const {
        return static_cast<Integer>(
            (static_cast<Wide>(normalize(a)) +
             normalize(b)) % modulus
        );
    }

    Integer subtract(Integer a, Integer b) const {
        return normalize(normalize(a) - normalize(b));
    }

    Integer multiply(Integer a, Integer b) const {
        return static_cast<Integer>(
            (static_cast<Wide>(normalize(a)) *
             normalize(b)) % modulus
        );
    }

    Integer power(Integer base, Integer exponent) const {
        if (exponent < 0) {
            throw CurveException("Negative exponent.");
        }

        Integer result = 1;
        base = normalize(base);

        while (exponent > 0) {
            if (exponent & 1LL) {
                result = multiply(result, base);
            }

            base = multiply(base, base);
            exponent >>= 1LL;
        }

        return result;
    }

    Integer inverse(Integer value) const {
        Integer a = normalize(value);

        if (a == 0) {
            throw CurveException(
                "Zero has no modular inverse."
            );
        }

        Integer oldR = a;
        Integer r = modulus;
        Integer oldS = 1;
        Integer s = 0;

        while (r != 0) {
            Integer quotient = oldR / r;

            Integer nextR = oldR - quotient * r;
            oldR = r;
            r = nextR;

            Integer nextS = oldS - quotient * s;
            oldS = s;
            s = nextS;
        }

        if (oldR != 1) {
            throw CurveException(
                "Element is not invertible."
            );
        }

        return normalize(oldS);
    }
};

class EllipticCurve {
private:
    FiniteField field;
    Integer a;
    Integer b;

public:
    EllipticCurve(Integer a, Integer b, Integer prime)
        : field(prime),
          a(field.normalize(a)),
          b(field.normalize(b)) {

        Integer discriminant = field.add(
            field.multiply(4, field.power(this->a, 3)),
            field.multiply(27, field.power(this->b, 2))
        );

        if (discriminant == 0) {
            throw CurveException(
                "Singular elliptic curve."
            );
        }
    }

    Integer modulus() const {
        return field.p();
    }

    bool contains(const Point& point) const {
        if (point.isInfinity()) return true;

        Integer x = field.normalize(point.x);
        Integer y = field.normalize(point.y);

        Integer left = field.power(y, 2);

        Integer right = field.add(
            field.add(field.power(x, 3),
                      field.multiply(a, x)),
            b
        );

        return left == right;
    }

    Point normalize(const Point& point) const {
        if (point.isInfinity()) return Point::infinity();

        return Point::affine(
            field.normalize(point.x),
            field.normalize(point.y)
        );
    }

    void validate(const Point& point) const {
        if (!contains(point)) {
            throw PointException(
                "Point does not belong to the curve: " +
                point.toString()
            );
        }
    }

    Point negate(const Point& point) const {
        validate(point);

        if (point.isInfinity()) return point;

        return Point::affine(
            point.x,
            field.normalize(-point.y)
        );
    }

    Point add(const Point& first, const Point& second) const {
        validate(first);
        validate(second);

        Point p1 = normalize(first);
        Point p2 = normalize(second);

        if (p1.isInfinity()) return p2;
        if (p2.isInfinity()) return p1;

        Integer x1 = p1.x;
        Integer y1 = p1.y;
        Integer x2 = p2.x;
        Integer y2 = p2.y;

        if (x1 == x2 &&
            field.add(y1, y2) == 0) {
            return Point::infinity();
        }

        Integer numerator;
        Integer denominator;

        if (p1 == p2) {
            numerator = field.add(
                field.multiply(3, field.power(x1, 2)),
                a
            );

            denominator = field.multiply(2, y1);
        } else {
            numerator = field.subtract(y2, y1);
            denominator = field.subtract(x2, x1);
        }

        Integer slope = field.multiply(
            numerator,
            field.inverse(denominator)
        );

        Integer x3 = field.subtract(
            field.subtract(field.power(slope, 2), x1),
            x2
        );

        Integer y3 = field.subtract(
            field.multiply(
                slope,
                field.subtract(x1, x3)
            ),
            y1
        );

        Point result = Point::affine(x3, y3);

        validate(result);

        return result;
    }

    Point multiply(Integer scalar, const Point& point) const {
        validate(point);

        if (scalar < 0) {
            if (scalar == numeric_limits<Integer>::min()) {
                throw CurveException(
                    "Scalar magnitude exceeds supported range."
                );
            }

            return multiply(-scalar, negate(point));
        }

        Point result = Point::infinity();
        Point current = normalize(point);

        // Binary double-and-add algorithm.
        while (scalar > 0) {
            if (scalar & 1LL) {
                result = add(result, current);
            }

            current = add(current, current);
            scalar >>= 1LL;
        }

        return result;
    }

    vector<Point> enumeratePoints() const {
        vector<Point> points;

        for (Integer x = 0; x < modulus(); ++x) {
            for (Integer y = 0; y < modulus(); ++y) {
                Point point = Point::affine(x, y);

                if (contains(point)) {
                    points.push_back(point);
                }
            }
        }

        return points;
    }

    Integer groupOrder() const {
        return static_cast<Integer>(
            enumeratePoints().size() + 1
        );
    }

    Integer pointOrder(const Point& point) const {
        validate(point);

        if (point.isInfinity()) return 1;

        Point current = Point::infinity();
        Integer limit = groupOrder();

        for (Integer i = 1; i <= limit; ++i) {
            current = add(current, point);

            if (current.isInfinity()) return i;
        }

        throw CurveException("Point order not found.");
    }

    vector<Point> multiples(const Point& generator) const {
        validate(generator);

        vector<Point> results;
        Point current = Point::infinity();

        for (Integer i = 0; i <= groupOrder(); ++i) {
            results.push_back(current);
            current = add(current, generator);

            if (i > 0 && current.isInfinity()) break;
        }

        return results;
    }
};

enum class CheckStatus {
    Passed,
    Failed
};

struct StatusCheck {
    string name;
    CheckStatus status;
};

enum class ReviewDecision {
    Approved,
    ChangesRequested,
    Pending,
    Dismissed
};

struct ReviewRecord {
    string reviewer;
    ReviewDecision decision;
};

struct GovernancePolicy {
    int requiredApprovals = 2;
    bool requirePassingChecks = true;
    bool requireResolvedReviews = true;
    bool restrictDirectPush = true;
    bool restrictForcePush = true;
    bool restrictDeletion = true;
    bool requireLinearHistory = false;
};

struct MergeRequest {
    string identifier;
    string sourceBranch;
    string targetBranch;
    bool open = true;
    bool draft = false;
    bool conflicts = false;
    bool linearHistory = true;

    vector<ReviewRecord> reviews;
    vector<StatusCheck> checks;
    set<string> unresolvedConversations;
};

struct EligibilityResult {
    bool eligible = false;
    vector<string> reasons;
};

class RepositoryGovernance {
private:
    GovernancePolicy policy;

public:
    explicit RepositoryGovernance(GovernancePolicy p)
        : policy(p) {}

    EligibilityResult evaluate(
        const MergeRequest& request
    ) const {
        EligibilityResult result;

        if (!request.open) {
            result.reasons.push_back("Pull Request is closed.");
        }

        if (request.draft) {
            result.reasons.push_back("Draft Pull Request cannot merge.");
        }

        if (request.conflicts) {
            result.reasons.push_back("Merge conflicts exist.");
        }

        if (request.sourceBranch == request.targetBranch) {
            result.reasons.push_back(
                "Source and target branches must differ."
            );
        }

        if (policy.requireLinearHistory &&
            !request.linearHistory) {
            result.reasons.push_back(
                "Linear history requirement is not satisfied."
            );
        }

        if (policy.requirePassingChecks) {
            for (const auto& check : request.checks) {
                if (check.status != CheckStatus::Passed) {
                    result.reasons.push_back(
                        "Status check failed or pending: " +
                        check.name
                    );
                }
            }

            if (request.checks.empty()) {
                result.reasons.push_back(
                    "Required status checks are missing."
                );
            }
        }

        if (policy.requireResolvedReviews &&
            !request.unresolvedConversations.empty()) {
            result.reasons.push_back(
                "Review conversations remain unresolved."
            );
        }

        set<string> approvedReviewers;

        for (const auto& review : request.reviews) {
            if (review.decision == ReviewDecision::Approved) {
                approvedReviewers.insert(review.reviewer);
            }
        }

        for (const auto& review : request.reviews) {
            if (review.decision ==
                ReviewDecision::ChangesRequested) {
                result.reasons.push_back(
                    "Changes requested by " + review.reviewer
                );
            }
        }

        if (static_cast<int>(approvedReviewers.size()) <
            policy.requiredApprovals) {
            result.reasons.push_back(
                "Insufficient eligible approvals."
            );
        }

        result.eligible = result.reasons.empty();

        return result;
    }

    bool directPushAllowed() const {
        return !policy.restrictDirectPush;
    }

    bool forcePushAllowed() const {
        return !policy.restrictForcePush;
    }

    bool branchDeletionAllowed() const {
        return !policy.restrictDeletion;
    }
};

void demonstrateEllipticCurves() {
    cout << "\n=== ELLIPTIC CURVE MATHEMATICS ===\n";

    EllipticCurve curve(2, 2, 17);

    Point generator = Point::affine(5, 1);

    curve.validate(generator);

    cout << "Curve: y^2 = x^3 + 2x + 2 mod 17\n";
    cout << "Generator: " << generator.toString() << "\n";
    cout << "Group order: " << curve.groupOrder() << "\n";
    cout << "Generator order: "
         << curve.pointOrder(generator) << "\n";

    cout << "\nPoint multiples:\n";

    auto multiples = curve.multiples(generator);

    for (size_t i = 0; i < multiples.size(); ++i) {
        cout << i << "G = "
             << multiples[i].toString() << "\n";
    }

    cout << "\nDiffie-Hellman demonstration:\n";

    Integer alicePrivate = 5;
    Integer bobPrivate = 7;

    Point alicePublic = curve.multiply(
        alicePrivate, generator
    );

    Point bobPublic = curve.multiply(
        bobPrivate, generator
    );

    Point aliceShared = curve.multiply(
        alicePrivate, bobPublic
    );

    Point bobShared = curve.multiply(
        bobPrivate, alicePublic
    );

    cout << "Alice public: " << alicePublic.toString() << "\n";
    cout << "Bob public: " << bobPublic.toString() << "\n";
    cout << "Alice shared: " << aliceShared.toString() << "\n";
    cout << "Bob shared: " << bobShared.toString() << "\n";

    if (!(aliceShared == bobShared)) {
        throw CurveException("Shared-secret mismatch.");
    }

    Point inverse = curve.negate(generator);

    if (!curve.add(generator, inverse).isInfinity()) {
        throw CurveException("Inverse property failed.");
    }

    if (!(curve.add(generator, Point::infinity()) == generator)) {
        throw CurveException("Identity property failed.");
    }

    cout << "Group identity and inverse tests passed.\n";

    try {
        curve.validate(Point::affine(1, 1));
    } catch (const PointException& error) {
        cout << "Invalid point rejected: "
             << error.what() << "\n";
    }
}

void demonstrateGovernance() {
    cout << "\n=== REPOSITORY GOVERNANCE ENGINE ===\n";

    GovernancePolicy policy;
    policy.requiredApprovals = 2;
    policy.requirePassingChecks = true;
    policy.requireResolvedReviews = true;
    policy.requireLinearHistory = true;

    RepositoryGovernance engine(policy);

    MergeRequest request;

    request.identifier = "PR-104";
    request.sourceBranch = "feature/ec-arithmetic";
    request.targetBranch = "main";
    request.open = true;
    request.draft = false;
    request.conflicts = false;
    request.linearHistory = true;

    request.reviews = {
        {"reviewer-1", ReviewDecision::Approved},
        {"reviewer-2", ReviewDecision::Approved}
    };

    request.checks = {
        {"unit-tests", CheckStatus::Passed},
        {"static-analysis", CheckStatus::Passed},
        {"integration-tests", CheckStatus::Passed}
    };

    EligibilityResult result = engine.evaluate(request);

    cout << "Merge request: " << request.identifier << "\n";
    cout << "Eligible: " << boolalpha << result.eligible << "\n";

    for (const string& reason : result.reasons) {
        cout << "Blocked: " << reason << "\n";
    }

    request.conflicts = true;

    result = engine.evaluate(request);

    cout << "\nAfter introducing a conflict:\n";
    cout << "Eligible: " << result.eligible << "\n";

    for (const string& reason : result.reasons) {
        cout << "Blocked: " << reason << "\n";
    }

    cout << "\nDirect push allowed: "
         << engine.directPushAllowed() << "\n";

    cout << "Force push allowed: "
         << engine.forcePushAllowed() << "\n";

    cout << "Branch deletion allowed: "
         << engine.branchDeletionAllowed() << "\n";
}

int main() {
    try {
        demonstrateEllipticCurves();
        demonstrateGovernance();

        cout << "\nAll demonstrations completed.\n";
        return 0;

    } catch (const exception& error) {
        cerr << "Fatal error: " << error.what() << "\n";
        return 1;
    }
}
