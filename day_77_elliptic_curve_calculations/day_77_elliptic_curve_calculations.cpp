#include <iostream>
#include <vector>
#include <stdexcept>
#include <string>
#include <cstdint>
#include <algorithm>
#include <limits>

using namespace std;

using int64 = long long;
using int128 = __int128_t;

class ECCException : public runtime_error {
public:
    explicit ECCException(const string& message)
        : runtime_error(message) {}
};

struct Point {
    int64 x = 0;
    int64 y = 0;
    bool infinity = true;

    static Point atInfinity() {
        return Point{};
    }

    static Point create(int64 x, int64 y) {
        return Point{x, y, false};
    }

    string toString() const {
        if (infinity) return "O";

        return "(" + to_string(x) +
               ", " + to_string(y) + ")";
    }

    bool operator==(const Point& other) const {
        if (infinity || other.infinity) {
            return infinity == other.infinity;
        }

        return x == other.x && y == other.y;
    }
};

class EllipticCurve {
private:
    int64 a;
    int64 b;
    int64 p;

    int64 normalize(int128 value) const {
        int64 result = static_cast<int64>(value % p);

        if (result < 0) result += p;

        return result;
    }

    static bool isPrime(int64 n) {
        if (n < 2) return false;

        if (n == 2 || n == 3) return true;

        if (n % 2 == 0) return false;

        for (int64 i = 3; i <= n / i; i += 2) {
            if (n % i == 0) return false;
        }

        return true;
    }

    int64 inverse(int64 value) const {
        int64 oldR = p;
        int64 r = normalize(value);

        int64 oldS = 0;
        int64 s = 1;

        while (r != 0) {
            int64 quotient = oldR / r;

            int64 nextR = oldR - quotient * r;
            oldR = r;
            r = nextR;

            int64 nextS = oldS - quotient * s;
            oldS = s;
            s = nextS;
        }

        if (oldR != 1) {
            throw ECCException(
                "Modular inverse does not exist."
            );
        }

        return normalize(oldS);
    }

public:
    EllipticCurve(int64 a, int64 b, int64 p) {
        if (p < 3 || !isPrime(p)) {
            throw ECCException(
                "Modulus must be a prime >= 3."
            );
        }

        this->p = p;
        this->a = normalizeParameter(a, p);
        this->b = normalizeParameter(b, p);

        int64 discriminant = (
            4 * modularPower(this->a, 3, p) +
            27 * modularPower(this->b, 2, p)
        ) % p;

        if (discriminant == 0) {
            throw ECCException("Singular curve.");
        }
    }

    static int64 normalizeParameter(int64 value, int64 modulus) {
        int64 result = value % modulus;
        return result < 0 ? result + modulus : result;
    }

    static int64 modularPower(
        int64 base,
        int64 exponent,
        int64 modulus
    ) {
        int64 result = 1;

        base = normalizeParameter(base, modulus);

        while (exponent > 0) {
            if (exponent & 1) {
                result = static_cast<int64>(
                    static_cast<int128>(result) * base % modulus
                );
            }

            base = static_cast<int64>(
                static_cast<int128>(base) * base % modulus
            );

            exponent >>= 1;
        }

        return result;
    }

    bool contains(const Point& point) const {
        if (point.infinity) return true;

        if (
            point.x < 0 || point.x >= p ||
            point.y < 0 || point.y >= p
        ) {
            return false;
        }

        int64 lhs = modularPower(point.y, 2, p);

        int64 rhs = normalize(
            static_cast<int128>(
                modularPower(point.x, 3, p)
            ) + static_cast<int128>(a) * point.x + b
        );

        return lhs == rhs;
    }

    void validate(const Point& point) const {
        if (!contains(point)) {
            throw ECCException(
                "Point does not belong to the curve: " +
                point.toString()
            );
        }
    }

    Point negate(const Point& point) const {
        validate(point);

        if (point.infinity) return point;

        return Point::create(
            point.x,
            normalize(-static_cast<int128>(point.y))
        );
    }

    Point add(const Point& p1, const Point& p2) const {
        validate(p1);
        validate(p2);

        if (p1.infinity) return p2;
        if (p2.infinity) return p1;

        if (
            p1.x == p2.x &&
            normalize(
                static_cast<int128>(p1.y) + p2.y
            ) == 0
        ) {
            return Point::atInfinity();
        }

        int64 numerator;
        int64 denominator;

        if (p1 == p2) {
            if (p1.y == 0) {
                return Point::atInfinity();
            }

            numerator = normalize(
                3 * static_cast<int128>(p1.x) * p1.x + a
            );

            denominator = normalize(
                2 * static_cast<int128>(p1.y)
            );
        } else {
            numerator = normalize(
                static_cast<int128>(p2.y) - p1.y
            );

            denominator = normalize(
                static_cast<int128>(p2.x) - p1.x
            );
        }

        int64 slope = normalize(
            static_cast<int128>(numerator) *
            inverse(denominator)
        );

        int64 x3 = normalize(
            static_cast<int128>(slope) * slope -
            p1.x - p2.x
        );

        int64 y3 = normalize(
            static_cast<int128>(slope) *
            (p1.x - x3) - p1.y
        );

        Point result = Point::create(x3, y3);

        validate(result);

        return result;
    }

    Point subtract(const Point& p1, const Point& p2) const {
        return add(p1, negate(p2));
    }

    Point multiply(int64 scalar, const Point& point) const {
        validate(point);

        if (scalar < 0) {
            if (scalar == numeric_limits<int64>::min()) {
                throw ECCException("Scalar magnitude overflow.");
            }

            return multiply(-scalar, negate(point));
        }

        Point result = Point::atInfinity();
        Point addend = point;

        // Binary double-and-add: O(log scalar).
        while (scalar > 0) {
            if (scalar & 1) {
                result = add(result, addend);
            }

            addend = add(addend, addend);
            scalar >>= 1;
        }

        return result;
    }

    vector<Point> enumeratePoints() const {
        vector<Point> points;

        points.push_back(Point::atInfinity());

        for (int64 x = 0; x < p; ++x) {
            int64 rhs = normalize(
                static_cast<int128>(x) * x * x +
                static_cast<int128>(a) * x + b
            );

            for (int64 y = 0; y < p; ++y) {
                if (modularPower(y, 2, p) == rhs) {
                    points.push_back(Point::create(x, y));
                }
            }
        }

        return points;
    }

    int64 pointOrder(const Point& point) const {
        validate(point);

        if (point.infinity) return 1;

        Point current = Point::atInfinity();

        int64 bound = p + 1 + 2 * static_cast<int64>(
            __builtin_sqrt(static_cast<double>(p))
        );

        for (int64 i = 1; i <= bound; ++i) {
            current = add(current, point);

            if (current.infinity) return i;
        }

        throw ECCException("Point order not found.");
    }

    int64 getModulus() const {
        return p;
    }

    int64 getA() const {
        return a;
    }

    int64 getB() const {
        return b;
    }

    int64 countPoints() const {
        return static_cast<int64>(enumeratePoints().size());
    }
};

class ECDH {
private:
    const EllipticCurve& curve;
    Point generator;

public:
    ECDH(const EllipticCurve& curve, const Point& generator)
        : curve(curve), generator(generator) {

        curve.validate(generator);

        if (generator.infinity) {
            throw ECCException(
                "Generator cannot be infinity."
            );
        }
    }

    Point publicKey(int64 privateKey) const {
        if (privateKey <= 0) {
            throw ECCException("Invalid private key.");
        }

        return curve.multiply(privateKey, generator);
    }

    Point sharedSecret(
        int64 privateKey,
        const Point& publicKey
    ) const {
        if (privateKey <= 0) {
            throw ECCException("Invalid private key.");
        }

        curve.validate(publicKey);

        if (publicKey.infinity) {
            throw ECCException("Invalid public key.");
        }

        Point secret = curve.multiply(
            privateKey,
            publicKey
        );

        if (secret.infinity) {
            throw ECCException("Invalid shared secret.");
        }

        return secret;
    }
};

void runTests(
    const EllipticCurve& curve,
    const Point& generator
) {
    if (!curve.contains(generator)) {
        throw ECCException("Generator validation failed.");
    }

    if (!(curve.add(generator, Point::atInfinity()) == generator)) {
        throw ECCException("Identity test failed.");
    }

    if (!curve.add(generator, curve.negate(generator)).infinity) {
        throw ECCException("Inverse test failed.");
    }

    if (!curve.multiply(0, generator).infinity) {
        throw ECCException("Zero scalar test failed.");
    }

    if (!(curve.multiply(1, generator) == generator)) {
        throw ECCException("Unit scalar test failed.");
    }

    if (
        !(curve.multiply(3, generator) ==
          curve.add(curve.multiply(2, generator), generator))
    ) {
        throw ECCException("Associative calculation test failed.");
    }

    cout << "All arithmetic tests passed.\n";
}

int main() {
    try {
        // y^2 = x^3 + 2x + 2 mod 17.
        EllipticCurve curve(2, 2, 17);

        Point generator = Point::create(5, 1);

        curve.validate(generator);

        cout << "ELLIPTIC CURVE CALCULATIONS\n";
        cout << "Equation: y^2 = x^3 + 2x + 2 mod 17\n";

        runTests(curve, generator);

        cout << "\nPOINT OPERATIONS\n";

        cout << "G: " << generator.toString() << '\n';
        cout << "2G: "
             << curve.multiply(2, generator).toString() << '\n';

        cout << "3G: "
             << curve.multiply(3, generator).toString() << '\n';

        cout << "-G: "
             << curve.negate(generator).toString() << '\n';

        cout << "G-G: "
             << curve.subtract(generator, generator).toString()
             << '\n';

        cout << "\nPOINT ENUMERATION\n";

        vector<Point> points = curve.enumeratePoints();

        for (size_t i = 0; i < points.size(); ++i) {
            cout << i + 1 << ". "
                 << points[i].toString() << '\n';
        }

        cout << "Curve cardinality: "
             << points.size() << '\n';

        cout << "\nPOINT ORDER\n";

        int64 order = curve.pointOrder(generator);

        cout << "Order of G: " << order << '\n';

        cout << "\nSCALAR MULTIPLICATION\n";

        for (int64 k = 1; k <= order; ++k) {
            cout << k << "G = "
                 << curve.multiply(k, generator).toString()
                 << '\n';
        }

        cout << "\nECDH DEMONSTRATION\n";

        ECDH protocol(curve, generator);

        int64 alicePrivate = 5;
        int64 bobPrivate = 7;

        Point alicePublic = protocol.publicKey(alicePrivate);
        Point bobPublic = protocol.publicKey(bobPrivate);

        Point aliceSecret = protocol.sharedSecret(
            alicePrivate,
            bobPublic
        );

        Point bobSecret = protocol.sharedSecret(
            bobPrivate,
            alicePublic
        );

        if (!(aliceSecret == bobSecret)) {
            throw ECCException("ECDH verification failed.");
        }

        cout << "Alice public key: "
             << alicePublic.toString() << '\n';

        cout << "Bob public key: "
             << bobPublic.toString() << '\n';

        cout << "Shared secret: "
             << aliceSecret.toString() << '\n';

        cout << "Shared points match: YES\n";

        cout << "\nExecution completed successfully.\n";

    } catch (const exception& error) {
        cerr << "Execution error: "
             << error.what() << '\n';

        return 1;
    }

    return 0;
}
