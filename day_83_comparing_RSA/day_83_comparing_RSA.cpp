#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std;

/*
 * Comparing RSA, Diffie-Hellman and ECC.
 *
 * C++17 implementation:
 * - Mathematical RSA demonstration
 * - Finite-field Diffie-Hellman
 * - Elliptic curve point arithmetic
 * - Repository-style cryptographic governance
 * - Algorithm suitability evaluation
 * - Merge-style policy decisions for cryptographic deployment
 *
 * All mathematical examples use deliberately small parameters.
 * This program is educational and must not protect production data.
 */


// ============================================================
// 1. DOMAIN TYPES
// ============================================================

enum class Algorithm {
    RSA,
    DIFFIE_HELLMAN,
    ECC
};

enum class Purpose {
    ENCRYPTION,
    KEY_AGREEMENT,
    DIGITAL_SIGNATURE
};

string algorithmName(Algorithm algorithm) {

    switch (algorithm) {
        case Algorithm::RSA:
            return "RSA";

        case Algorithm::DIFFIE_HELLMAN:
            return "Diffie-Hellman";

        case Algorithm::ECC:
            return "ECC";
    }

    throw invalid_argument("Unknown algorithm.");
}

string purposeName(Purpose purpose) {

    switch (purpose) {
        case Purpose::ENCRYPTION:
            return "Encryption";

        case Purpose::KEY_AGREEMENT:
            return "Key Agreement";

        case Purpose::DIGITAL_SIGNATURE:
            return "Digital Signature";
    }

    throw invalid_argument("Unknown purpose.");
}


// ============================================================
// 2. MODULAR ARITHMETIC
// ============================================================

using Integer = int64_t;
using WideInteger = __int128_t;

Integer normalize(WideInteger value, Integer modulus) {

    if (modulus <= 0) {
        throw invalid_argument("Modulus must be positive.");
    }

    value %= modulus;

    if (value < 0) {
        value += modulus;
    }

    return static_cast<Integer>(value);
}

Integer modularMultiply(Integer a, Integer b, Integer modulus) {

    return normalize(
        static_cast<WideInteger>(a) * b,
        modulus
    );
}

Integer modularPower(
    Integer base,
    Integer exponent,
    Integer modulus
) {

    if (modulus <= 1 || exponent < 0) {
        throw invalid_argument("Invalid modular exponentiation input.");
    }

    Integer result = 1 % modulus;
    base = normalize(base, modulus);

    while (exponent > 0) {

        if (exponent & 1) {
            result = modularMultiply(result, base, modulus);
        }

        base = modularMultiply(base, base, modulus);
        exponent >>= 1;
    }

    return result;
}

bool isPrime(Integer number) {

    if (number < 2) {
        return false;
    }

    if (number == 2 || number == 3) {
        return true;
    }

    if (number % 2 == 0) {
        return false;
    }

    for (Integer divisor = 3;
         divisor <= number / divisor;
         divisor += 2) {

        if (number % divisor == 0) {
            return false;
        }
    }

    return true;
}

Integer modularInverse(Integer a, Integer modulus) {

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
        throw invalid_argument("Modular inverse does not exist.");
    }

    return normalize(oldS, modulus);
}


// ============================================================
// 3. RSA DOMAIN
// ============================================================

struct RSAKeyPair {
    Integer p;
    Integer q;
    Integer modulus;
    Integer publicExponent;
    Integer privateExponent;
    Integer totient;
};

class RSAEngine {

public:

    static RSAKeyPair generate(
        Integer p,
        Integer q,
        Integer e
    ) {

        if (!isPrime(p) || !isPrime(q) || p == q) {
            throw invalid_argument("Invalid RSA prime factors.");
        }

        Integer n = p * q;
        Integer phi = (p - 1) * (q - 1);

        if (e <= 1 || e >= phi || gcd(e, phi) != 1) {
            throw invalid_argument("Invalid RSA public exponent.");
        }

        Integer d = modularInverse(e, phi);

        return {
            p, q, n, e, d, phi
        };
    }

    static Integer encrypt(
        Integer message,
        const RSAKeyPair& key
    ) {

        if (message < 0 || message >= key.modulus) {
            throw invalid_argument("Message outside RSA range.");
        }

        return modularPower(
            message,
            key.publicExponent,
            key.modulus
        );
    }

    static Integer decrypt(
        Integer ciphertext,
        const RSAKeyPair& key
    ) {

        if (ciphertext < 0 || ciphertext >= key.modulus) {
            throw invalid_argument("Ciphertext outside RSA range.");
        }

        return modularPower(
            ciphertext,
            key.privateExponent,
            key.modulus
        );
    }

    static void demonstrate() {

        cout << "\nRSA MATHEMATICAL DEMONSTRATION\n";

        auto key = generate(61, 53, 17);

        Integer message = 65;

        Integer ciphertext = encrypt(message, key);
        Integer recovered = decrypt(ciphertext, key);

        cout << "Modulus: " << key.modulus << '\n';
        cout << "Public exponent: " << key.publicExponent << '\n';
        cout << "Private exponent: " << key.privateExponent << '\n';
        cout << "Ciphertext: " << ciphertext << '\n';
        cout << "Recovered message: " << recovered << '\n';

        if (recovered != message) {
            throw runtime_error("RSA round-trip failed.");
        }
    }
};


// ============================================================
// 4. FINITE-FIELD DIFFIE-HELLMAN
// ============================================================

struct DHParameters {
    Integer prime;
    Integer generator;
};

class DiffieHellmanEngine {

public:

    static void validate(const DHParameters& parameters) {

        if (!isPrime(parameters.prime)) {
            throw invalid_argument("DH modulus must be prime.");
        }

        if (
            parameters.generator <= 1 ||
            parameters.generator >= parameters.prime
        ) {
            throw invalid_argument("Invalid DH generator.");
        }
    }

    static Integer publicValue(
        Integer privateKey,
        const DHParameters& parameters
    ) {

        validate(parameters);

        if (
            privateKey <= 0 ||
            privateKey >= parameters.prime - 1
        ) {
            throw invalid_argument("Invalid DH private key.");
        }

        return modularPower(
            parameters.generator,
            privateKey,
            parameters.prime
        );
    }

    static Integer sharedSecret(
        Integer privateKey,
        Integer peerPublicKey,
        const DHParameters& parameters
    ) {

        validate(parameters);

        if (
            peerPublicKey <= 1 ||
            peerPublicKey >= parameters.prime - 1
        ) {
            throw invalid_argument("Invalid DH peer public value.");
        }

        return modularPower(
            peerPublicKey,
            privateKey,
            parameters.prime
        );
    }

    static void demonstrate() {

        cout << "\nDIFFIE-HELLMAN DEMONSTRATION\n";

        DHParameters parameters{23, 5};

        Integer alicePrivate = 6;
        Integer bobPrivate = 15;

        Integer alicePublic = publicValue(
            alicePrivate,
            parameters
        );

        Integer bobPublic = publicValue(
            bobPrivate,
            parameters
        );

        Integer aliceSecret = sharedSecret(
            alicePrivate,
            bobPublic,
            parameters
        );

        Integer bobSecret = sharedSecret(
            bobPrivate,
            alicePublic,
            parameters
        );

        cout << "Alice public value: " << alicePublic << '\n';
        cout << "Bob public value: " << bobPublic << '\n';
        cout << "Alice secret: " << aliceSecret << '\n';
        cout << "Bob secret: " << bobSecret << '\n';

        if (aliceSecret != bobSecret) {
            throw runtime_error("DH agreement failed.");
        }
    }
};


// ============================================================
// 5. ELLIPTIC CURVE DOMAIN
// ============================================================

struct Point {

    optional<Integer> x;
    optional<Integer> y;

    static Point infinity() {
        return {nullopt, nullopt};
    }

    bool isInfinity() const {
        return !x.has_value() && !y.has_value();
    }

    bool operator==(const Point& other) const {
        return x == other.x && y == other.y;
    }
};

class EllipticCurve {

private:

    Integer p;
    Integer a;
    Integer b;

public:

    EllipticCurve(Integer prime, Integer coefficientA,
                  Integer coefficientB)
        : p(prime),
          a(normalize(coefficientA, prime)),
          b(normalize(coefficientB, prime)) {

        if (!isPrime(p)) {
            throw invalid_argument("Curve field must be prime.");
        }

        Integer discriminant = normalize(
            4 * modularPower(a, 3, p) +
            27 * modularPower(b, 2, p),
            p
        );

        if (discriminant == 0) {
            throw invalid_argument("Singular elliptic curve.");
        }
    }

    bool isOnCurve(const Point& point) const {

        if (point.isInfinity()) {
            return true;
        }

        if (!point.x.has_value() || !point.y.has_value()) {
            return false;
        }

        Integer x = *point.x;
        Integer y = *point.y;

        Integer left = modularMultiply(y, y, p);

        Integer right = normalize(
            static_cast<WideInteger>(
                modularMultiply(
                    modularMultiply(x, x, p),
                    x,
                    p
                )
            ) + modularMultiply(a, x, p) + b,
            p
        );

        return left == right;
    }

    Point add(const Point& first, const Point& second) const {

        if (!isOnCurve(first) || !isOnCurve(second)) {
            throw invalid_argument("Point is not on the curve.");
        }

        if (first.isInfinity()) {
            return second;
        }

        if (second.isInfinity()) {
            return first;
        }

        Integer x1 = normalize(*first.x, p);
        Integer y1 = normalize(*first.y, p);

        Integer x2 = normalize(*second.x, p);
        Integer y2 = normalize(*second.y, p);

        if (x1 == x2 && normalize(y1 + y2, p) == 0) {
            return Point::infinity();
        }

        Integer numerator;
        Integer denominator;

        if (first == second) {

            if (y1 == 0) {
                return Point::infinity();
            }

            numerator = normalize(
                3 * modularMultiply(x1, x1, p) + a,
                p
            );

            denominator = normalize(2 * y1, p);

        } else {

            numerator = normalize(y2 - y1, p);
            denominator = normalize(x2 - x1, p);
        }

        Integer slope = modularMultiply(
            numerator,
            modularInverse(denominator, p),
            p
        );

        Integer x3 = normalize(
            modularMultiply(slope, slope, p) - x1 - x2,
            p
        );

        Integer y3 = normalize(
            modularMultiply(slope, normalize(x1 - x3, p), p) - y1,
            p
        );

        Point result{x3, y3};

        if (!isOnCurve(result)) {
            throw runtime_error("Invalid curve arithmetic result.");
        }

        return result;
    }

    Point multiply(Integer scalar, Point point) const {

        if (scalar < 0) {
            throw invalid_argument("Negative scalar is unsupported.");
        }

        if (!isOnCurve(point)) {
            throw invalid_argument("Invalid curve point.");
        }

        Point result = Point::infinity();

        while (scalar > 0) {

            if (scalar & 1) {
                result = add(result, point);
            }

            point = add(point, point);
            scalar >>= 1;
        }

        return result;
    }
};

class ECCEngine {

public:

    static void demonstrate() {

        cout << "\nELLIPTIC CURVE CRYPTOGRAPHY DEMONSTRATION\n";

        EllipticCurve curve(17, 2, 2);

        Point generator{5, 1};

        if (!curve.isOnCurve(generator)) {
            throw runtime_error("Invalid generator.");
        }

        Integer alicePrivate = 5;
        Integer bobPrivate = 7;

        Point alicePublic = curve.multiply(
            alicePrivate, generator
        );

        Point bobPublic = curve.multiply(
            bobPrivate, generator
        );

        Point aliceSecret = curve.multiply(
            alicePrivate, bobPublic
        );

        Point bobSecret = curve.multiply(
            bobPrivate, alicePublic
        );

        cout << "Alice public point: ("
             << *alicePublic.x << ", "
             << *alicePublic.y << ")\n";

        cout << "Bob public point: ("
             << *bobPublic.x << ", "
             << *bobPublic.y << ")\n";

        if (!(aliceSecret == bobSecret)) {
            throw runtime_error("ECDH agreement failed.");
        }

        cout << "Shared point: ("
             << *aliceSecret.x << ", "
             << *aliceSecret.y << ")\n";

        cout << "ECDH agreement successful.\n";

        if (!curve.multiply(19, generator).isInfinity()) {
            throw runtime_error("Generator order validation failed.");
        }
    }
};


// ============================================================
// 6. CRYPTOGRAPHIC GOVERNANCE MODEL
// ============================================================

struct CryptographicConfiguration {

    Algorithm algorithm;
    Purpose purpose;

    int parameterSize;

    bool authenticated;
    bool approvedParameters;
    bool forwardSecrecy;
};

struct EvaluationResult {

    bool approved = false;
    vector<string> findings;
};

class CryptographicGovernance {

private:

    map<Algorithm, int> minimumSizes{
        {Algorithm::RSA, 3072},
        {Algorithm::DIFFIE_HELLMAN, 3072},
        {Algorithm::ECC, 256}
    };

public:

    EvaluationResult evaluate(
        const CryptographicConfiguration& configuration
    ) const {

        EvaluationResult result;

        auto iterator = minimumSizes.find(configuration.algorithm);

        if (iterator == minimumSizes.end()) {
            throw invalid_argument("Unsupported algorithm.");
        }

        if (configuration.parameterSize <= 0) {
            throw invalid_argument("Invalid parameter size.");
        }

        if (configuration.parameterSize < iterator->second) {

            result.findings.push_back(
                "Parameter size is below the governance minimum."
            );
        }

        if (!configuration.approvedParameters) {

            result.findings.push_back(
                "Cryptographic parameters are not approved."
            );
        }

        if (!configuration.authenticated) {

            result.findings.push_back(
                "Peer authentication is missing."
            );
        }

        if (
            configuration.algorithm == Algorithm::DIFFIE_HELLMAN &&
            configuration.purpose != Purpose::KEY_AGREEMENT
        ) {

            result.findings.push_back(
                "DH is a key-agreement mechanism."
            );
        }

        if (
            configuration.algorithm == Algorithm::ECC &&
            configuration.purpose == Purpose::ENCRYPTION
        ) {

            result.findings.push_back(
                "ECC requires a standardized hybrid encryption construction."
            );
        }

        if (
            configuration.algorithm == Algorithm::RSA &&
            configuration.purpose == Purpose::KEY_AGREEMENT
        ) {

            result.findings.push_back(
                "RSA is not a DH-style key-agreement mechanism."
            );
        }

        result.approved = result.findings.empty();

        return result;
    }
};


// ============================================================
// 7. CRYPTOGRAPHIC DEPLOYMENT DECISION ENGINE
// ============================================================

struct DeploymentRequest {

    string application;
    CryptographicConfiguration configuration;
    bool complianceRequired;
    bool auditComplete;
};

class DeploymentEngine {

private:

    CryptographicGovernance governance;

public:

    bool authorize(const DeploymentRequest& request) const {

        if (request.application.empty()) {
            throw invalid_argument("Application identifier is required.");
        }

        if (!request.auditComplete) {
            return false;
        }

        EvaluationResult evaluation = governance.evaluate(
            request.configuration
        );

        if (!evaluation.approved) {

            cout << "\nDeployment rejected for "
                 << request.application << '\n';

            for (const string& finding : evaluation.findings) {
                cout << " - " << finding << '\n';
            }

            return false;
        }

        if (
            request.complianceRequired &&
            !request.configuration.approvedParameters
        ) {
            return false;
        }

        return true;
    }
};


// ============================================================
// 8. COMPARATIVE REPORT
// ============================================================

void displayComparison() {

    cout << "\nALGORITHM COMPARISON\n";
    cout << string(85, '=') << '\n';

    cout << left
         << setw(20) << "Algorithm"
         << setw(34) << "Mathematical problem"
         << setw(30) << "Primary capability"
         << '\n';

    cout << string(85, '-') << '\n';

    cout << setw(20) << "RSA"
         << setw(34) << "Integer factorization"
         << setw(30) << "Encryption / signatures"
         << '\n';

    cout << setw(20) << "Diffie-Hellman"
         << setw(34) << "Discrete logarithm"
         << setw(30) << "Key agreement"
         << '\n';

    cout << setw(20) << "ECC"
         << setw(34) << "Elliptic curve logarithm"
         << setw(30) << "ECDH / ECDSA"
         << '\n';

    cout << "\nApproximate classical security equivalence:\n";
    cout << "RSA-3072: approximately 128 bits\n";
    cout << "Finite-field DH-3072: approximately 128 bits\n";
    cout << "ECC P-256: approximately 128 bits\n";

    cout << "\nAll three are vulnerable to sufficiently capable "
         << "cryptographically relevant quantum computers.\n";
}


// ============================================================
// 9. TESTING
// ============================================================

void runTests() {

    if (!isPrime(97) || isPrime(100)) {
        throw runtime_error("Primality tests failed.");
    }

    if (modularInverse(3, 11) != 4) {
        throw runtime_error("Modular inverse test failed.");
    }

    auto rsa = RSAEngine::generate(61, 53, 17);

    Integer message = 42;

    if (
        RSAEngine::decrypt(
            RSAEngine::encrypt(message, rsa),
            rsa
        ) != message
    ) {
        throw runtime_error("RSA test failed.");
    }

    DHParameters parameters{23, 5};

    Integer alicePrivate = 6;
    Integer bobPrivate = 15;

    Integer alicePublic = DiffieHellmanEngine::publicValue(
        alicePrivate, parameters
    );

    Integer bobPublic = DiffieHellmanEngine::publicValue(
        bobPrivate, parameters
    );

    if (
        DiffieHellmanEngine::sharedSecret(
            alicePrivate, bobPublic, parameters
        )
        !=
        DiffieHellmanEngine::sharedSecret(
            bobPrivate, alicePublic, parameters
        )
    ) {
        throw runtime_error("DH test failed.");
    }

    EllipticCurve curve(17, 2, 2);
    Point generator{5, 1};

    Point alice = curve.multiply(5, generator);
    Point bob = curve.multiply(7, generator);

    if (!(curve.multiply(5, bob) == curve.multiply(7, alice))) {
        throw runtime_error("ECC test failed.");
    }

    cout << "\nAll C++17 mathematical tests passed.\n";
}


// ============================================================
// 10. APPLICATION ENTRY POINT
// ============================================================

int main() {

    try {

        cout << "RSA vs DIFFIE-HELLMAN vs ECC\n";
        cout << string(65, '=') << '\n';

        displayComparison();

        RSAEngine::demonstrate();
        DiffieHellmanEngine::demonstrate();
        ECCEngine::demonstrate();

        cout << "\nCRYPTOGRAPHIC GOVERNANCE\n";

        DeploymentEngine deployment;

        DeploymentRequest approvedRequest{
            "enterprise-signing-service",
            {
                Algorithm::RSA,
                Purpose::DIGITAL_SIGNATURE,
                3072,
                true,
                true,
                false
            },
            true,
            true
        };

        DeploymentRequest rejectedRequest{
            "legacy-key-exchange-service",
            {
                Algorithm::DIFFIE_HELLMAN,
                Purpose::KEY_AGREEMENT,
                2048,
                false,
                true,
                true
            },
            true,
            true
        };

        cout << "RSA deployment: "
             << (deployment.authorize(approvedRequest)
                 ? "AUTHORIZED" : "REJECTED")
             << '\n';

        cout << "DH deployment: "
             << (deployment.authorize(rejectedRequest)
                 ? "AUTHORIZED" : "REJECTED")
             << '\n';

        runTests();

        cout << "\nSECURITY LIMITATIONS\n";
        cout << "- Small demonstration parameters are insecure.\n";
        cout << "- This implementation is not constant-time.\n";
        cout << "- Production implementations need vetted cryptographic libraries.\n";
        cout << "- DH and ECDH require authenticated public-key exchange.\n";
        cout << "- Use HKDF for shared-secret key derivation.\n";
        cout << "- Use authenticated encryption for application data.\n";
        cout << "- Consider post-quantum cryptography for long-term security.\n";

    } catch (const exception& error) {

        cerr << "Execution error: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
