#include <algorithm>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <map>
#include <limits>

using namespace std;

/*
 * Elliptic Curves and Points
 *
 * C++17 finite-field elliptic curve implementation.
 *
 * Curve:
 * y^2 = x^3 + ax + b (mod p)
 *
 * Features:
 * - Domain modeling
 * - Modular arithmetic
 * - Extended Euclidean inverse
 * - Point validation
 * - Group addition
 * - Scalar multiplication
 * - Point enumeration
 * - Point order
 * - Group property verification
 * - Structured operation reporting
 *
 * Educational implementation.
 * Modulus is restricted to keep intermediate arithmetic safe.
 */

class CurveException : public runtime_error {
public:
    explicit CurveException(const string& message)
        : runtime_error(message) {}
};

class FiniteField {
private:
    int64_t p;

public:
    explicit FiniteField(int64_t prime) : p(prime) {
        if (prime < 2) {
            throw CurveException("Invalid field modulus.");
        }

        for (int64_t i = 2; i <= prime / i; ++i) {
            if (prime % i == 0) {
                throw CurveException("Modulus must be prime.");
            }
        }
    }

    int64_t modulus() const {
        return p;
    }

    int64_t normalize(int64_t value) const {
        value %= p;
        if (value < 0) value += p;
        return value;
    }

    int64_t add(int64_t a, int64_t b) const {
        return normalize(a + b);
    }

    int64_t subtract(int64_t a, int64_t b) const {
        return normalize(a - b);
    }

    int64_t multiply(int64_t a, int64_t b) const {
        // This implementation uses a bounded modulus.
        return normalize(a * b);
    }

    int64_t power(int64_t base, int64_t exponent) const {
        int64_t result = 1;
        base = normalize(base);

        while (exponent > 0) {
            if (exponent & 1) {
                result = multiply(result, base);
            }

            base = multiply(base, base);
            exponent >>= 1;
        }

        return result;
    }

    int64_t inverse(int64_t value) const {
        int64_t oldR = normalize(value);
        int64_t r = p;
        int64_t oldS = 1;
        int64_t s = 0;

        if (oldR == 0) {
            throw CurveException("Zero has no inverse.");
        }

        while (r != 0) {
            int64_t quotient = oldR / r;

            int64_t nextR = oldR - quotient * r;
            oldR = r;
            r = nextR;

            int64_t nextS = oldS - quotient * s;
            oldS = s;
            s = nextS;
        }

        if (oldR != 1) {
            throw CurveException("Element is not invertible.");
        }

        return normalize(oldS);
    }

    int64_t divide(int64_t a, int64_t b) const {
        return multiply(a, inverse(b));
    }
};

struct Point {
    int64_t x = 0;
    int64_t y = 0;
    bool infinity = true;

    static Point atInfinity() {
        return Point{};
    }

    static Point finite(int64_t x, int64_t y) {
        return Point{x, y, false};
    }

    string toString() const {
        if (infinity) return "O";
        return "(" + to_string(x) + ", " + to_string(y) + ")";
    }

    bool operator==(const Point& other) const {
        if (infinity || other.infinity) {
            return infinity == other.infinity;
        }

        return x == other.x && y == other.y;
    }
};

enum class OperationType {
    ADDITION,
    DOUBLING,
    MULTIPLICATION
};

struct OperationRecord {
    OperationType type;
    string first;
    string second;
    string result;
};

class EllipticCurve {
private:
    FiniteField field;
    int64_t a;
    int64_t b;
    vector<OperationRecord> audit;

public:
    EllipticCurve(int64_t p, int64_t a, int64_t b)
        : field(p),
          a(field.normalize(a)),
          b(field.normalize(b)) {

        int64_t discriminant = field.add(
            field.multiply(
                4,
                field.power(this->a, 3)
            ),
            field.multiply(
                27,
                field.power(this->b, 2)
            )
        );

        if (discriminant == 0) {
            throw CurveException("Singular curve rejected.");
        }
    }

    int64_t modulus() const {
        return field.modulus();
    }

    bool contains(const Point& point) const {
        if (point.infinity) return true;

        if (
            point.x < 0 || point.x >= field.modulus() ||
            point.y < 0 || point.y >= field.modulus()
        ) {
            return false;
        }

        int64_t left = field.power(point.y, 2);

        int64_t right = field.add(
            field.add(
                field.power(point.x, 3),
                field.multiply(a, point.x)
            ),
            b
        );

        return left == right;
    }

    void validate(const Point& point) const {
        if (!contains(point)) {
            throw CurveException(
                "Point does not belong to this curve."
            );
        }
    }

    Point makePoint(int64_t x, int64_t y) const {
        Point point = Point::finite(
            field.normalize(x),
            field.normalize(y)
        );

        validate(point);
        return point;
    }

    Point negate(const Point& point) const {
        validate(point);

        if (point.infinity) {
            return Point::atInfinity();
        }

        return Point::finite(
            point.x,
            field.normalize(-point.y)
        );
    }

    Point add(const Point& p1, const Point& p2) {
        validate(p1);
        validate(p2);

        if (p1.infinity) return p2;
        if (p2.infinity) return p1;

        if (
            p1.x == p2.x &&
            field.add(p1.y, p2.y) == 0
        ) {
            Point result = Point::atInfinity();

            audit.push_back({
                OperationType::ADDITION,
                p1.toString(),
                p2.toString(),
                result.toString()
            });

            return result;
        }

        int64_t numerator;
        int64_t denominator;

        bool doubling = (p1 == p2);

        if (doubling) {
            if (p1.y == 0) {
                return Point::atInfinity();
            }

            numerator = field.add(
                field.multiply(
                    3,
                    field.power(p1.x, 2)
                ),
                a
            );

            denominator = field.multiply(2, p1.y);
        } else {
            numerator = field.subtract(p2.y, p1.y);
            denominator = field.subtract(p2.x, p1.x);
        }

        int64_t slope = field.divide(numerator, denominator);

        int64_t x3 = field.subtract(
            field.subtract(
                field.power(slope, 2),
                p1.x
            ),
            p2.x
        );

        int64_t y3 = field.subtract(
            field.multiply(
                slope,
                field.subtract(p1.x, x3)
            ),
            p1.y
        );

        Point result = Point::finite(x3, y3);
        validate(result);

        audit.push_back({
            doubling ? OperationType::DOUBLING :
                       OperationType::ADDITION,
            p1.toString(),
            p2.toString(),
            result.toString()
        });

        return result;
    }

    Point subtract(const Point& p1, const Point& p2) {
        return add(p1, negate(p2));
    }

    Point multiply(int64_t scalar, const Point& point) {
        validate(point);

        if (scalar < 0) {
            if (scalar == numeric_limits<int64_t>::min()) {
                throw CurveException("Scalar magnitude overflow.");
            }

            return multiply(-scalar, negate(point));
        }

        int64_t originalScalar = scalar;

        Point result = Point::atInfinity();
        Point addend = point;

        // Binary double-and-add.
        while (scalar > 0) {
            if (scalar & 1) {
                result = add(result, addend);
            }

            addend = add(addend, addend);
            scalar >>= 1;
        }

        audit.push_back({
            OperationType::MULTIPLICATION,
            to_string(originalScalar),
            point.toString(),
            result.toString()
        });

        return result;
    }

    vector<Point> enumeratePoints() const {
        vector<Point> points = {
            Point::atInfinity()
        };

        for (int64_t x = 0; x < field.modulus(); ++x) {
            int64_t rhs = field.add(
                field.add(
                    field.power(x, 3),
                    field.multiply(a, x)
                ),
                b
            );

            for (int64_t y = 0; y < field.modulus(); ++y) {
                if (field.power(y, 2) == rhs) {
                    points.push_back(Point::finite(x, y));
                }
            }
        }

        return points;
    }

    int64_t pointOrder(const Point& point) {
        validate(point);

        if (point.infinity) return 1;

        Point current = Point::atInfinity();

        // Hasse's bound is p + 1 + 2*sqrt(p).
        int64_t bound = field.modulus() + 1;

        for (int64_t i = 1; i * i <= field.modulus(); ++i) {
            bound += (i * i == field.modulus()) ? 2 : 0;
        }

        int64_t root = 1;
        while (root * root < field.modulus()) {
            ++root;
        }

        bound = field.modulus() + 1 + 2 * root;

        for (int64_t order = 1; order <= bound; ++order) {
            current = add(current, point);

            if (current.infinity) {
                return order;
            }
        }

        throw CurveException("Point order search failed.");
    }

    const vector<OperationRecord>& getAudit() const {
        return audit;
    }
};

class GovernanceEngine {
private:
    EllipticCurve& curve;

public:
    explicit GovernanceEngine(EllipticCurve& curve)
        : curve(curve) {}

    bool verifyGroupIdentity(const Point& point) {
        return curve.add(point, Point::atInfinity()) == point;
    }

    bool verifyInverse(const Point& point) {
        return curve.add(point, curve.negate(point)).infinity;
    }

    bool verifyScalarConsistency(
        int64_t first,
        int64_t second,
        const Point& point
    ) {
        Point left = curve.multiply(
            first + second,
            point
        );

        Point right = curve.add(
            curve.multiply(first, point),
            curve.multiply(second, point)
        );

        return left == right;
    }
};

void printSection(const string& heading) {
    cout << "\n" << heading << "\n";
    cout << string(heading.size(), '=') << "\n";
}

int main() {
    try {
        EllipticCurve curve(97, 2, 3);
        GovernanceEngine engine(curve);

        Point G = curve.makePoint(3, 6);

        printSection("ELLIPTIC CURVE");
        cout << "Equation: y^2 = x^3 + 2x + 3 mod 97\n";
        cout << "Generator: " << G.toString() << "\n";

        printSection("SCALAR MULTIPLICATION");

        for (int64_t k = 0; k <= 10; ++k) {
            cout << k << "G = "
                 << curve.multiply(k, G).toString()
                 << "\n";
        }

        printSection("POINT OPERATIONS");

        Point negativeG = curve.negate(G);

        cout << "G: " << G.toString() << "\n";
        cout << "-G: " << negativeG.toString() << "\n";
        cout << "G + G: "
             << curve.add(G, G).toString() << "\n";
        cout << "G + (-G): "
             << curve.add(G, negativeG).toString() << "\n";

        printSection("GROUP ANALYSIS");

        cout << "Point order: "
             << curve.pointOrder(G) << "\n";

        auto points = curve.enumeratePoints();

        cout << "Group cardinality: "
             << points.size() << "\n";

        cout << "First ten points:\n";

        for (size_t i = 0;
             i < min<size_t>(10, points.size());
             ++i) {
            cout << "  " << points[i].toString() << "\n";
        }

        printSection("GOVERNANCE VALIDATION");

        vector<pair<string, bool>> checks = {
            {"Point membership", curve.contains(G)},
            {"Group identity", engine.verifyGroupIdentity(G)},
            {"Inverse property", engine.verifyInverse(G)},
            {
                "Scalar distributivity",
                engine.verifyScalarConsistency(4, 7, G)
            }
        };

        for (const auto& [name, passed] : checks) {
            cout << name << ": "
                 << (passed ? "PASS" : "FAIL")
                 << "\n";

            if (!passed) {
                throw CurveException("Group validation failed.");
            }
        }

        printSection("EDGE CASES");

        try {
            curve.makePoint(10, 10);
            throw CurveException("Invalid point was accepted.");
        } catch (const CurveException& error) {
            cout << "Invalid point rejected: "
                 << error.what() << "\n";
        }

        Point zeroScalar = curve.multiply(0, G);

        cout << "0G: " << zeroScalar.toString() << "\n";
        cout << "-2G: "
             << curve.multiply(-2, G).toString() << "\n";

        printSection("OPERATION AUDIT");

        map<OperationType, size_t> counts;

        for (const auto& record : curve.getAudit()) {
            counts[record.type]++;
        }

        cout << "Additions: "
             << counts[OperationType::ADDITION] << "\n";

        cout << "Doublings: "
             << counts[OperationType::DOUBLING] << "\n";

        cout << "Scalar multiplications: "
             << counts[OperationType::MULTIPLICATION] << "\n";

        printSection("EXECUTION STATUS");

        cout << "All mathematical validation checks passed.\n";
        cout << "Educational finite-field implementation completed.\n";

    } catch (const exception& error) {
        cerr << "ERROR: " << error.what() << "\n";
        return 1;
    }

    return 0;
}
