/*
 * Elliptic Curve Cryptography
 *
 * C++17 educational implementation.
 *
 * Scenario:
 * A secure device network uses elliptic-curve point operations
 * to establish shared secrets and validate digital signatures.
 *
 * A small prime-field curve is intentionally used so that
 * all arithmetic fits safely within uint64_t.
 *
 * This is NOT a production cryptographic implementation.
 * The small field provides no meaningful security.
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;


// ------------------------------------------------------------
// 1. Domain configuration
// ------------------------------------------------------------

class ECCException : public runtime_error {
public:
    explicit ECCException(const string& message)
        : runtime_error(message) {}
};

enum class KeyStatus {
    ACTIVE,
    ROTATED,
    REVOKED
};

struct Curve {
    uint64_t p;
    uint64_t a;
    uint64_t b;
};

struct Point {
    uint64_t x;
    uint64_t y;
    bool infinity = false;

    static Point identity() {
        return {0, 0, true};
    }

    bool operator==(const Point& other) const {
        if (infinity || other.infinity) {
            return infinity == other.infinity;
        }

        return x == other.x && y == other.y;
    }

    bool operator!=(const Point& other) const {
        return !(*this == other);
    }
};

struct CurveParameters {
    Curve curve{17, 2, 2};

    Point generator{5, 1, false};

    // The generator has order 19.
    uint64_t order = 19;
};


// ------------------------------------------------------------
// 2. Modular arithmetic
// ------------------------------------------------------------

uint64_t mod(uint64_t value, uint64_t modulus) {
    return value % modulus;
}

uint64_t modSigned(int64_t value, uint64_t modulus) {
    int64_t result = value % static_cast<int64_t>(modulus);

    if (result < 0) {
        result += static_cast<int64_t>(modulus);
    }

    return static_cast<uint64_t>(result);
}

uint64_t modInverse(uint64_t value, uint64_t modulus) {
    if (value == 0) {
        throw ECCException("Zero has no modular inverse.");
    }

    int64_t t = 0;
    int64_t newT = 1;

    int64_t r = static_cast<int64_t>(modulus);
    int64_t newR = static_cast<int64_t>(value % modulus);

    while (newR != 0) {
        int64_t quotient = r / newR;

        int64_t temporaryT = t - quotient * newT;
        t = newT;
        newT = temporaryT;

        int64_t temporaryR = r - quotient * newR;
        r = newR;
        newR = temporaryR;
    }

    if (r != 1) {
        throw ECCException("Modular inverse does not exist.");
    }

    return modSigned(t, modulus);
}


// ------------------------------------------------------------
// 3. Curve validation
// ------------------------------------------------------------

class EllipticCurve {
private:
    Curve parameters;

public:
    explicit EllipticCurve(const Curve& curve)
        : parameters(curve) {

        if (curve.p < 5) {
            throw ECCException("Field modulus is too small.");
        }

        if (curve.p > 1000000) {
            throw ECCException("Educational implementation limit exceeded.");
        }

        if ((4 * curve.a * curve.a * curve.a +
             27 * curve.b * curve.b) % curve.p == 0) {
            throw ECCException("Singular elliptic curve.");
        }
    }

    uint64_t field() const {
        return parameters.p;
    }

    bool isOnCurve(const Point& point) const {
        if (point.infinity) return true;

        if (point.x >= parameters.p ||
            point.y >= parameters.p) {
            return false;
        }

        uint64_t lhs = mod(point.y * point.y, parameters.p);

        uint64_t rhs = mod(
            point.x * point.x * point.x +
            parameters.a * point.x +
            parameters.b,
            parameters.p
        );

        return lhs == rhs;
    }

    Point negate(const Point& point) const {
        if (point.infinity) return point;

        return {
            point.x,
            mod(parameters.p - point.y, parameters.p),
            false
        };
    }

    // --------------------------------------------------------
    // 4. Point addition
    // --------------------------------------------------------

    Point add(const Point& left, const Point& right) const {
        if (!isOnCurve(left) || !isOnCurve(right)) {
            throw ECCException("Point is not on the curve.");
        }

        if (left.infinity) return right;
        if (right.infinity) return left;

        const uint64_t p = parameters.p;

        if (
            left.x == right.x &&
            mod(left.y + right.y, p) == 0
        ) {
            return Point::identity();
        }

        uint64_t numerator;
        uint64_t denominator;

        if (left == right) {
            if (left.y == 0) {
                return Point::identity();
            }

            numerator = mod(
                3 * left.x * left.x + parameters.a,
                p
            );

            denominator = mod(2 * left.y, p);
        } else {
            numerator = mod(
                right.y + p - left.y,
                p
            );

            denominator = mod(
                right.x + p - left.x,
                p
            );
        }

        uint64_t slope = mod(
            numerator * modInverse(denominator, p),
            p
        );

        uint64_t x = mod(
            slope * slope + 2 * p - left.x - right.x,
            p
        );

        uint64_t y = mod(
            slope * (left.x + p - x) + p - left.y,
            p
        );

        Point result{x, y, false};

        if (!isOnCurve(result)) {
            throw ECCException("Point addition integrity failure.");
        }

        return result;
    }

    // --------------------------------------------------------
    // 5. Scalar multiplication
    // --------------------------------------------------------

    Point multiply(uint64_t scalar, Point point) const {
        if (!isOnCurve(point)) {
            throw ECCException("Invalid multiplication point.");
        }

        Point result = Point::identity();

        // Double-and-add algorithm: O(log scalar).
        while (scalar > 0) {
            if (scalar & 1ULL) {
                result = add(result, point);
            }

            point = add(point, point);
            scalar >>= 1;
        }

        return result;
    }
};


// ------------------------------------------------------------
// 6. Key generation and device identity
// ------------------------------------------------------------

struct KeyPair {
    uint64_t privateKey;
    Point publicKey;
};

class KeyGenerator {
private:
    const EllipticCurve& curve;
    const Point generator;
    const uint64_t order;

public:
    KeyGenerator(
        const EllipticCurve& curve,
        const Point& generator,
        uint64_t order
    ) :
        curve(curve),
        generator(generator),
        order(order) {}

    KeyPair generate(uint64_t suppliedScalar) const {
        if (suppliedScalar == 0 || suppliedScalar >= order) {
            throw ECCException("Private scalar outside valid range.");
        }

        return {
            suppliedScalar,
            curve.multiply(suppliedScalar, generator)
        };
    }
};


// ------------------------------------------------------------
// 7. Public-key validation
// ------------------------------------------------------------

bool validatePublicKey(
    const EllipticCurve& curve,
    const Point& publicKey,
    uint64_t order
) {
    if (publicKey.infinity || !curve.isOnCurve(publicKey)) {
        return false;
    }

    return curve.multiply(order, publicKey).infinity;
}


// ------------------------------------------------------------
// 8. ECDH
// ------------------------------------------------------------

Point establishSharedPoint(
    const EllipticCurve& curve,
    const KeyPair& local,
    const Point& remote,
    uint64_t order
) {
    if (
        local.privateKey == 0 ||
        local.privateKey >= order ||
        !validatePublicKey(curve, remote, order)
    ) {
        throw ECCException("ECDH key validation failed.");
    }

    Point shared = curve.multiply(
        local.privateKey,
        remote
    );

    if (shared.infinity) {
        throw ECCException("Invalid shared point.");
    }

    return shared;
}


// ------------------------------------------------------------
// 9. ECDSA
// ------------------------------------------------------------

struct Signature {
    uint64_t r;
    uint64_t s;
};

Signature signMessage(
    const EllipticCurve& curve,
    const Point& generator,
    uint64_t order,
    uint64_t privateKey,
    uint64_t messageHash,
    uint64_t nonce
) {
    if (
        privateKey == 0 || privateKey >= order ||
        nonce == 0 || nonce >= order
    ) {
        throw ECCException("Invalid signing parameters.");
    }

    Point point = curve.multiply(nonce, generator);

    uint64_t r = point.x % order;

    if (r == 0) {
        throw ECCException("Invalid signature component r.");
    }

    uint64_t inverse = modInverse(nonce, order);

    uint64_t s = mod(
        inverse * (messageHash + r * privateKey),
        order
    );

    if (s == 0) {
        throw ECCException("Invalid signature component s.");
    }

    // Low-S normalization.
    if (s > order / 2) {
        s = order - s;
    }

    return {r, s};
}

bool verifySignature(
    const EllipticCurve& curve,
    const Point& generator,
    const Point& publicKey,
    uint64_t order,
    uint64_t messageHash,
    const Signature& signature
) {
    try {
        if (!validatePublicKey(curve, publicKey, order)) {
            return false;
        }

        if (
            signature.r == 0 || signature.r >= order ||
            signature.s == 0 || signature.s > order / 2
        ) {
            return false;
        }

        uint64_t inverse = modInverse(signature.s, order);

        uint64_t u1 = mod(messageHash * inverse, order);
        uint64_t u2 = mod(signature.r * inverse, order);

        Point first = curve.multiply(u1, generator);
        Point second = curve.multiply(u2, publicKey);

        Point result = curve.add(first, second);

        if (result.infinity) return false;

        return result.x % order == signature.r;

    } catch (const exception&) {
        return false;
    }
}


// ------------------------------------------------------------
// 10. Device key registry and lifecycle
// ------------------------------------------------------------

struct DeviceKey {
    string deviceId;
    KeyPair pair;
    KeyStatus status;
    uint64_t version;
};

class DeviceRegistry {
private:
    map<string, DeviceKey> devices;

public:
    void registerDevice(
        const string& id,
        const KeyPair& pair
    ) {
        if (id.empty() || id.size() > 64) {
            throw ECCException("Invalid device identifier.");
        }

        if (devices.count(id)) {
            throw ECCException("Duplicate device.");
        }

        devices.emplace(
            id,
            DeviceKey{id, pair, KeyStatus::ACTIVE, 1}
        );
    }

    void rotate(
        const string& id,
        const KeyPair& replacement
    ) {
        auto it = devices.find(id);

        if (
            it == devices.end() ||
            it->second.status != KeyStatus::ACTIVE
        ) {
            throw ECCException("Device key is inactive.");
        }

        string newId = id + "-v2";

        if (devices.count(newId)) {
            throw ECCException("Replacement identifier exists.");
        }

        // Register replacement before transitioning old key.
        registerDevice(newId, replacement);

        it->second.status = KeyStatus::ROTATED;
    }

    void revoke(const string& id) {
        auto it = devices.find(id);

        if (
            it == devices.end() ||
            it->second.status != KeyStatus::ACTIVE
        ) {
            throw ECCException("Cannot revoke inactive key.");
        }

        it->second.status = KeyStatus::REVOKED;
    }

    const DeviceKey& getActive(const string& id) const {
        auto it = devices.find(id);

        if (
            it == devices.end() ||
            it->second.status != KeyStatus::ACTIVE
        ) {
            throw ECCException("Device key unavailable.");
        }

        return it->second;
    }
};


// ------------------------------------------------------------
// 11. Network security policy
// ------------------------------------------------------------

struct NetworkPolicy {
    bool requireValidPublicKey = true;
    bool requireSignature = true;
    bool rejectRevokedDevices = true;
};

class NetworkGateway {
private:
    const EllipticCurve& curve;
    const Point generator;
    uint64_t order;
    NetworkPolicy policy;

public:
    NetworkGateway(
        const EllipticCurve& curve,
        const Point& generator,
        uint64_t order,
        NetworkPolicy policy
    ) :
        curve(curve),
        generator(generator),
        order(order),
        policy(policy) {}

    bool authorize(
        const Point& publicKey,
        uint64_t messageHash,
        const Signature& signature
    ) const {
        if (
            policy.requireValidPublicKey &&
            !validatePublicKey(curve, publicKey, order)
        ) {
            return false;
        }

        if (
            policy.requireSignature &&
            !verifySignature(
                curve,
                generator,
                publicKey,
                order,
                messageHash,
                signature
            )
        ) {
            return false;
        }

        return true;
    }
};


// ------------------------------------------------------------
// 12. Integration scenario and edge-case tests
// ------------------------------------------------------------

int main() {
    try {
        cout << "ELLIPTIC CURVE CRYPTOGRAPHY\n";
        cout << "Educational finite-field implementation\n\n";

        CurveParameters parameters;

        EllipticCurve curve(parameters.curve);

        const Point generator = parameters.generator;
        const uint64_t order = parameters.order;

        if (!curve.isOnCurve(generator)) {
            throw ECCException("Invalid generator.");
        }

        cout << "Generator validation: PASS\n";

        if (!curve.multiply(order, generator).infinity) {
            throw ECCException("Incorrect generator order.");
        }

        cout << "Group order validation: PASS\n";

        KeyGenerator keyGenerator(curve, generator, order);

        // Device identities.
        KeyPair alice = keyGenerator.generate(5);
        KeyPair bob = keyGenerator.generate(7);

        if (
            !validatePublicKey(curve, alice.publicKey, order) ||
            !validatePublicKey(curve, bob.publicKey, order)
        ) {
            throw ECCException("Public-key validation failed.");
        }

        cout << "Device key validation: PASS\n";

        // ECDH.
        Point sharedAlice = establishSharedPoint(
            curve, alice, bob.publicKey, order
        );

        Point sharedBob = establishSharedPoint(
            curve, bob, alice.publicKey, order
        );

        if (sharedAlice != sharedBob) {
            throw ECCException("ECDH agreement failed.");
        }

        cout << "ECDH shared point: ("
             << sharedAlice.x << ", "
             << sharedAlice.y << ")\n";

        // ECDSA.
        const uint64_t messageHash = 11;

        Signature signature = signMessage(
            curve,
            generator,
            order,
            alice.privateKey,
            messageHash,
            3
        );

        bool valid = verifySignature(
            curve,
            generator,
            alice.publicKey,
            order,
            messageHash,
            signature
        );

        if (!valid) {
            throw ECCException("Signature verification failed.");
        }

        cout << "ECDSA signature: PASS\n";

        // Tampering detection.
        bool tampered = verifySignature(
            curve,
            generator,
            alice.publicKey,
            order,
            12,
            signature
        );

        if (tampered) {
            throw ECCException("Tampered message accepted.");
        }

        cout << "Tampered message rejection: PASS\n";

        // Device governance.
        DeviceRegistry registry;

        registry.registerDevice("device-alice", alice);
        registry.registerDevice("device-bob", bob);

        KeyPair replacement = keyGenerator.generate(9);

        registry.rotate("device-alice", replacement);

        registry.revoke("device-alice-v2");

        try {
            registry.getActive("device-alice-v2");
            throw ECCException("Revoked key was accessible.");
        } catch (const ECCException& error) {
            if (
                string(error.what()) ==
                "Revoked key was accessible."
            ) {
                throw;
            }

            cout << "Revoked key rejection: PASS\n";
        }

        // Gateway policy.
        NetworkGateway gateway(
            curve,
            generator,
            order,
            NetworkPolicy{}
        );

        if (!gateway.authorize(
            alice.publicKey,
            messageHash,
            signature
        )) {
            throw ECCException("Gateway authorization failed.");
        }

        cout << "Gateway authorization: PASS\n";

        // Invalid private key.
        try {
            keyGenerator.generate(0);
            throw ECCException("Zero private key accepted.");
        } catch (const ECCException& error) {
            if (string(error.what()) == "Zero private key accepted.") {
                throw;
            }

            cout << "Invalid private key rejection: PASS\n";
        }

        // Invalid curve point.
        try {
            curve.add(
                Point{1, 1, false},
                generator
            );

            throw ECCException("Invalid point accepted.");
        } catch (const ECCException& error) {
            if (string(error.what()) == "Invalid point accepted.") {
                throw;
            }

            cout << "Invalid point rejection: PASS\n";
        }

        // Identity behavior.
        Point identity = Point::identity();

        if (
            curve.add(generator, identity) != generator ||
            curve.add(generator, curve.negate(generator)) != identity
        ) {
            throw ECCException("Group identity test failed.");
        }

        cout << "Group identity tests: PASS\n";

        cout << "\nAll ECC demonstrations passed.\n";

    } catch (const exception& error) {
        cerr << "ECC execution failed: "
             << error.what() << '\n';

        return 1;
    }

    return 0;
}
