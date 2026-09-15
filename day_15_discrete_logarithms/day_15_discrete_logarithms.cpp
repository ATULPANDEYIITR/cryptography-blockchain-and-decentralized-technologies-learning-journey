#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/*
 * Discrete logarithm case study:
 *
 * Scenario:
 * A small educational key-exchange service uses a finite multiplicative
 * group. A server publishes a prime modulus p and generator g. Each client
 * creates a private exponent and publishes g^x mod p.
 *
 * The case study develops:
 *   1. modular arithmetic
 *   2. group-order analysis
 *   3. discrete-log recovery
 *   4. baby-step giant-step
 *   5. Pollard-rho discrete logarithm
 *   6. Diffie-Hellman-style key exchange
 *   7. attack validation
 *   8. performance measurements
 *   9. security-oriented parameter checks
 *
 * All parameters are deliberately small and insecure. The purpose is
 * algorithmic study, not production cryptography.
 *
 * Compile:
 *   g++ -std=c++17 -O2 discrete_log_case_study.cpp -o discrete_log_case_study
 */

using Integer = std::uint64_t;
using SignedInteger = std::int64_t;

// -----------------------------------------------------------------------------
// 1. Result type and basic arithmetic
// -----------------------------------------------------------------------------

struct ExtendedGcdResult {
    Integer gcd;
    SignedInteger x;
    SignedInteger y;
};

ExtendedGcdResult extended_gcd(Integer a, Integer b) {
    SignedInteger old_r = static_cast<SignedInteger>(a);
    SignedInteger r = static_cast<SignedInteger>(b);

    SignedInteger old_s = 1;
    SignedInteger s = 0;

    SignedInteger old_t = 0;
    SignedInteger t = 1;

    while (r != 0) {
        const SignedInteger quotient = old_r / r;

        const SignedInteger new_r = old_r - quotient * r;
        old_r = r;
        r = new_r;

        const SignedInteger new_s = old_s - quotient * s;
        old_s = s;
        s = new_s;

        const SignedInteger new_t = old_t - quotient * t;
        old_t = t;
        t = new_t;
    }

    return {
        static_cast<Integer>(old_r < 0 ? -old_r : old_r),
        old_s,
        old_t
    };
}

Integer gcd_integer(Integer a, Integer b) {
    while (b != 0) {
        const Integer remainder = a % b;
        a = b;
        b = remainder;
    }

    return a;
}

Integer mod_normalize(Integer value, Integer modulus) {
    return value % modulus;
}

Integer modular_inverse(Integer value, Integer modulus) {
    value %= modulus;

    const auto result = extended_gcd(value, modulus);

    if (result.gcd != 1) {
        throw std::invalid_argument(
            "Modular inverse does not exist"
        );
    }

    SignedInteger inverse = result.x % static_cast<SignedInteger>(modulus);

    if (inverse < 0) {
        inverse += static_cast<SignedInteger>(modulus);
    }

    return static_cast<Integer>(inverse);
}

// -----------------------------------------------------------------------------
// 2. Overflow-aware modular multiplication
// -----------------------------------------------------------------------------

/*
 * For the educational values used here, unsigned __int128 avoids overflow
 * when multiplying two 64-bit residues.
 *
 * The function keeps multiplication separate from modular exponentiation so
 * that the arithmetic layer can be replaced by a safer big-integer backend
 * for cryptographic-scale parameters.
 */
Integer modular_multiply(
    Integer a,
    Integer b,
    Integer modulus
) {
    using WideInteger = unsigned __int128;

    return static_cast<Integer>(
        (static_cast<WideInteger>(a) *
         static_cast<WideInteger>(b)) %
        static_cast<WideInteger>(modulus)
    );
}

Integer modular_power(
    Integer base,
    Integer exponent,
    Integer modulus
) {
    if (modulus == 0) {
        throw std::invalid_argument(
            "Modulus cannot be zero"
        );
    }

    Integer result = 1 % modulus;
    base %= modulus;

    while (exponent > 0) {
        if (exponent & 1ULL) {
            result = modular_multiply(
                result,
                base,
                modulus
            );
        }

        base = modular_multiply(
            base,
            base,
            modulus
        );

        exponent >>= 1ULL;
    }

    return result;
}

// -----------------------------------------------------------------------------
// 3. Multiplicative order
// -----------------------------------------------------------------------------

Integer multiplicative_order(
    Integer base,
    Integer modulus
) {
    if (gcd_integer(base, modulus) != 1) {
        throw std::invalid_argument(
            "Base must be invertible modulo modulus"
        );
    }

    Integer value = 1;

    for (Integer order = 1; order <= modulus; ++order) {
        value = modular_multiply(
            value,
            base,
            modulus
        );

        if (value == 1) {
            return order;
        }
    }

    throw std::runtime_error(
        "Could not determine multiplicative order"
    );
}

// -----------------------------------------------------------------------------
// 4. Integer factorization
// -----------------------------------------------------------------------------

std::map<Integer, Integer> factorize(Integer value) {
    std::map<Integer, Integer> factors;

    Integer divisor = 2;

    while (divisor * divisor <= value) {
        while (value % divisor == 0) {
            ++factors[divisor];
            value /= divisor;
        }

        divisor = (divisor == 2) ? 3 : divisor + 2;
    }

    if (value > 1) {
        ++factors[value];
    }

    return factors;
}

void print_factorization(
    const std::map<Integer, Integer>& factors
) {
    bool first = true;

    for (const auto& [prime, exponent] : factors) {
        if (!first) {
            std::cout << " * ";
        }

        first = false;
        std::cout << prime;

        if (exponent > 1) {
            std::cout << "^" << exponent;
        }
    }
}

// -----------------------------------------------------------------------------
// 5. Brute-force discrete logarithm
// -----------------------------------------------------------------------------

std::optional<Integer> brute_force_discrete_log(
    Integer base,
    Integer target,
    Integer modulus,
    Integer order
) {
    Integer value = 1;

    target %= modulus;

    for (Integer exponent = 0;
         exponent < order;
         ++exponent) {

        if (value == target) {
            return exponent;
        }

        value = modular_multiply(
            value,
            base,
            modulus
        );
    }

    return std::nullopt;
}

// -----------------------------------------------------------------------------
// 6. Baby-step giant-step
// -----------------------------------------------------------------------------

std::optional<Integer> baby_step_giant_step(
    Integer base,
    Integer target,
    Integer modulus,
    Integer order
) {
    if (gcd_integer(base, modulus) != 1) {
        throw std::invalid_argument(
            "Base must be invertible"
        );
    }

    /*
     * We choose m = ceil(sqrt(order)).
     *
     * Any x < order can be represented as
     *
     *     x = i*m + j
     *
     * with small i and j.
     *
     * From
     *
     *     g^(i*m+j) = h
     *
     * we obtain
     *
     *     g^j = h * g^(-i*m).
     */
    const Integer m =
        static_cast<Integer>(
            std::ceil(
                std::sqrt(
                    static_cast<long double>(order)
                )
            )
        );

    std::unordered_map<Integer, Integer> baby_steps;
    baby_steps.reserve(
        static_cast<std::size_t>(m * 2 + 1)
    );

    Integer current = 1;

    for (Integer j = 0; j < m; ++j) {
        baby_steps.emplace(current, j);

        current = modular_multiply(
            current,
            base,
            modulus
        );
    }

    const Integer base_to_m =
        modular_power(
            base,
            m,
            modulus
        );

    const Integer factor =
        modular_inverse(
            base_to_m,
            modulus
        );

    Integer gamma = target % modulus;

    for (Integer i = 0; i <= m; ++i) {
        const auto found =
            baby_steps.find(gamma);

        if (found != baby_steps.end()) {
            const Integer candidate =
                i * m + found->second;

            if (
                candidate < order &&
                modular_power(
                    base,
                    candidate,
                    modulus
                ) == target % modulus
            ) {
                return candidate;
            }
        }

        gamma = modular_multiply(
            gamma,
            factor,
            modulus
        );
    }

    return std::nullopt;
}

// -----------------------------------------------------------------------------
// 7. Pollard-rho discrete logarithm
// -----------------------------------------------------------------------------

struct RhoState {
    Integer value;
    Integer alpha;
    Integer beta;
};

RhoState rho_step(
    const RhoState& state,
    Integer base,
    Integer target,
    Integer modulus,
    Integer order
) {
    const Integer partition =
        state.value % 3;

    if (partition == 0) {
        return {
            modular_multiply(
                state.value,
                base,
                modulus
            ),
            (state.alpha + 1) % order,
            state.beta
        };
    }

    if (partition == 1) {
        return {
            modular_multiply(
                state.value,
                target,
                modulus
            ),
            state.alpha,
            (state.beta + 1) % order
        };
    }

    return {
        modular_multiply(
            state.value,
            state.value,
            modulus
        ),
        (2 * state.alpha) % order,
        (2 * state.beta) % order
    };
}

std::optional<Integer> pollard_rho_discrete_log(
    Integer base,
    Integer target,
    Integer modulus,
    Integer order,
    Integer max_iterations = 100000
) {
    /*
     * The invariant is:
     *
     *     state.value = base^alpha * target^beta mod modulus
     *
     * When two states collide, the unknown logarithm can be extracted
     * from the relationship between their alpha and beta values.
     */
    for (Integer seed = 1; seed <= 15; ++seed) {
        const Integer initial =
            modular_power(
                base,
                seed,
                modulus
            );

        RhoState tortoise{
            initial,
            seed % order,
            0
        };

        RhoState hare = tortoise;

        for (Integer iteration = 0;
             iteration < max_iterations;
             ++iteration) {

            tortoise = rho_step(
                tortoise,
                base,
                target,
                modulus,
                order
            );

            hare = rho_step(
                rho_step(
                    hare,
                    base,
                    target,
                    modulus,
                    order
                ),
                base,
                target,
                modulus,
                order
            );

            if (tortoise.value != hare.value) {
                continue;
            }

            const Integer numerator =
                (tortoise.alpha +
                 order -
                 hare.alpha) %
                order;

            const Integer denominator =
                (hare.beta +
                 order -
                 tortoise.beta) %
                order;

            const Integer divisor =
                gcd_integer(
                    denominator,
                    order
                );

            if (
                divisor == 0 ||
                numerator % divisor != 0
            ) {
                break;
            }

            const Integer reduced_order =
                order / divisor;

            const Integer reduced_denominator =
                denominator / divisor;

            const Integer reduced_numerator =
                numerator / divisor;

            Integer inverse;

            try {
                inverse =
                    modular_inverse(
                        reduced_denominator,
                        reduced_order
                    );
            } catch (const std::invalid_argument&) {
                break;
            }

            const Integer base_solution =
                modular_multiply(
                    reduced_numerator,
                    inverse,
                    reduced_order
                );

            for (Integer offset = 0;
                 offset < divisor;
                 ++offset) {

                const Integer candidate =
                    (
                        base_solution +
                        offset * reduced_order
                    ) % order;

                if (
                    modular_power(
                        base,
                        candidate,
                        modulus
                    ) == target % modulus
                ) {
                    return candidate;
                }
            }

            break;
        }
    }

    return std::nullopt;
}

// -----------------------------------------------------------------------------
// 8. Chinese remainder theorem
// -----------------------------------------------------------------------------

std::pair<Integer, Integer> chinese_remainder(
    const std::vector<
        std::pair<Integer, Integer>
    >& congruences
) {
    Integer result = 0;
    Integer product = 1;

    for (const auto& [residue, modulus] : congruences) {
        if (gcd_integer(product, modulus) != 1) {
            throw std::invalid_argument(
                "CRT moduli must be pairwise coprime"
            );
        }

        const Integer inverse =
            modular_inverse(
                product,
                modulus
            );

        const Integer adjustment =
            (
                (residue + modulus - result % modulus) %
                modulus
            );

        const Integer correction =
            modular_multiply(
                adjustment,
                inverse,
                modulus
            );

        result += product * correction;
        product *= modulus;
        result %= product;
    }

    return {result, product};
}

// -----------------------------------------------------------------------------
// 9. Educational Pohlig-Hellman
// -----------------------------------------------------------------------------

std::optional<Integer> prime_order_discrete_log(
    Integer base,
    Integer target,
    Integer modulus,
    Integer prime_order
) {
    Integer value = 1;

    for (Integer exponent = 0;
         exponent < prime_order;
         ++exponent) {

        if (value == target % modulus) {
            return exponent;
        }

        value = modular_multiply(
            value,
            base,
            modulus
        );
    }

    return std::nullopt;
}

std::optional<Integer> pohlig_hellman(
    Integer base,
    Integer target,
    Integer modulus
) {
    const Integer order =
        multiplicative_order(
            base,
            modulus
        );

    const auto factors =
        factorize(order);

    std::vector<
        std::pair<Integer, Integer>
    > congruences;

    for (const auto& [prime, exponent] : factors) {
        Integer recovered = 0;
        Integer prime_power = 1;

        for (Integer digit = 0;
             digit < exponent;
             ++digit) {

            const Integer current_power =
                modular_power(
                    base,
                    recovered,
                    modulus
                );

            const Integer current_inverse =
                modular_inverse(
                    current_power,
                    modulus
                );

            const Integer residual =
                modular_multiply(
                    target,
                    current_inverse,
                    modulus
                );

            const Integer exponent_reduction =
                order /
                modular_power(
                    prime,
                    digit + 1,
                    order
                );

            const Integer reduced_target =
                modular_power(
                    residual,
                    exponent_reduction,
                    modulus
                );

            const Integer reduced_base =
                modular_power(
                    base,
                    exponent_reduction,
                    modulus
                );

            const auto digit_value =
                prime_order_discrete_log(
                    reduced_base,
                    reduced_target,
                    modulus,
                    prime
                );

            if (!digit_value.has_value()) {
                return std::nullopt;
            }

            recovered +=
                digit_value.value() *
                prime_power;

            prime_power *= prime;
        }

        congruences.push_back({
            recovered,
            prime_power
        });
    }

    const auto reconstructed =
        chinese_remainder(
            congruences
        );

    if (reconstructed.second != order) {
        throw std::runtime_error(
            "Incomplete CRT reconstruction"
        );
    }

    if (
        modular_power(
            base,
            reconstructed.first,
            modulus
        ) != target % modulus
    ) {
        return std::nullopt;
    }

    return reconstructed.first;
}

// -----------------------------------------------------------------------------
// 10. Key exchange domain model
// -----------------------------------------------------------------------------

class KeyExchangeDomain {
private:
    Integer modulus_;
    Integer generator_;

public:
    KeyExchangeDomain(
        Integer modulus,
        Integer generator
    )
        : modulus_(modulus),
          generator_(generator) {

        if (modulus_ < 3) {
            throw std::invalid_argument(
                "Modulus is too small"
            );
        }

        if (gcd_integer(
                generator_,
                modulus_
            ) != 1) {
            throw std::invalid_argument(
                "Generator must be invertible"
            );
        }
    }

    Integer modulus() const {
        return modulus_;
    }

    Integer generator() const {
        return generator_;
    }

    Integer public_value(
        Integer private_exponent
    ) const {
        return modular_power(
            generator_,
            private_exponent,
            modulus_
        );
    }

    Integer shared_value(
        Integer peer_public,
        Integer private_exponent
    ) const {
        if (peer_public == 0 ||
            peer_public >= modulus_) {
            throw std::invalid_argument(
                "Peer public value is outside the field"
            );
        }

        return modular_power(
            peer_public,
            private_exponent,
            modulus_
        );
    }
};

// -----------------------------------------------------------------------------
// 11. Security-oriented validation
// -----------------------------------------------------------------------------

struct SecurityReport {
    bool invertible_generator;
    bool generator_is_full_order;
    bool order_is_smooth;
    Integer group_order;
    std::map<Integer, Integer> factors;
};

SecurityReport inspect_domain(
    Integer modulus,
    Integer generator
) {
    SecurityReport report{};

    report.invertible_generator =
        gcd_integer(
            generator,
            modulus
        ) == 1;

    if (!report.invertible_generator) {
        return report;
    }

    report.group_order =
        multiplicative_order(
            generator,
            modulus
        );

    report.generator_is_full_order =
        report.group_order == modulus - 1;

    report.factors =
        factorize(
            report.group_order
        );

    /*
     * A simple educational smoothness test:
     * call the order "smooth" if every prime factor is at most 50.
     *
     * This is not a cryptographic security test. It simply demonstrates
     * why factorization of the group order matters to Pohlig-Hellman.
     */
    report.order_is_smooth = true;

    for (const auto& [prime, exponent] : report.factors) {
        (void)exponent;

        if (prime > 50) {
            report.order_is_smooth = false;
        }
    }

    return report;
}

// -----------------------------------------------------------------------------
// 12. Service simulation
// -----------------------------------------------------------------------------

class DiscreteLogAuditService {
public:
    struct AuditResult {
        Integer observed_public_value;
        std::optional<Integer> recovered_private_exponent;
        bool verification_passed;
        double milliseconds;
    };

    AuditResult audit_public_value(
        const KeyExchangeDomain& domain,
        Integer observed_public_value,
        Integer expected_order
    ) const {
        const auto start =
            std::chrono::steady_clock::now();

        const auto recovered =
            baby_step_giant_step(
                domain.generator(),
                observed_public_value,
                domain.modulus(),
                expected_order
            );

        const auto finish =
            std::chrono::steady_clock::now();

        const double elapsed =
            std::chrono::duration<double, std::milli>(
                finish - start
            ).count();

        bool verification = false;

        if (recovered.has_value()) {
            verification =
                modular_power(
                    domain.generator(),
                    recovered.value(),
                    domain.modulus()
                ) == observed_public_value;
        }

        return {
            observed_public_value,
            recovered,
            verification,
            elapsed
        };
    }
};

// -----------------------------------------------------------------------------
// 13. Case-study demonstrations
// -----------------------------------------------------------------------------

void demonstrate_basic_problem() {
    std::cout << "\n=== Basic discrete logarithm ===\n";

    const Integer p = 29;
    const Integer g = 2;
    const Integer secret = 11;

    const Integer h =
        modular_power(
            g,
            secret,
            p
        );

    const Integer order =
        multiplicative_order(
            g,
            p
        );

    std::cout << "Equation: "
              << g
              << "^x = "
              << h
              << " (mod "
              << p
              << ")\n";

    const auto answer =
        brute_force_discrete_log(
            g,
            h,
            p,
            order
        );

    if (answer.has_value()) {
        std::cout << "Recovered x = "
                  << answer.value()
                  << "\n";
    }
}

void demonstrate_domain_inspection() {
    std::cout << "\n=== Domain inspection ===\n";

    const Integer p = 101;
    const Integer g = 2;

    const SecurityReport report =
        inspect_domain(
            p,
            g
        );

    std::cout << "Group order = "
              << report.group_order
              << "\n";

    std::cout << "Factorization = ";
    print_factorization(report.factors);
    std::cout << "\n";

    std::cout << "Full-order generator = "
              << std::boolalpha
              << report.generator_is_full_order
              << "\n";

    std::cout << "Educational smoothness flag = "
              << report.order_is_smooth
              << "\n";
}

void demonstrate_attack_and_defense() {
    std::cout << "\n=== Key exchange and discrete-log audit ===\n";

    /*
     * This is an intentionally weak domain.
     *
     * p = 1009 is small enough that BSGS can recover private exponents
     * immediately. Real cryptographic groups are selected so that generic
     * discrete-log attacks are computationally impractical.
     */
    const KeyExchangeDomain domain(
        1009,
        11
    );

    const Integer alice_private = 731;
    const Integer bob_private = 427;

    const Integer alice_public =
        domain.public_value(
            alice_private
        );

    const Integer bob_public =
        domain.public_value(
            bob_private
        );

    const Integer alice_shared =
        domain.shared_value(
            bob_public,
            alice_private
        );

    const Integer bob_shared =
        domain.shared_value(
            alice_public,
            bob_private
        );

    std::cout << "Alice public = "
              << alice_public
              << "\n";

    std::cout << "Bob public = "
              << bob_public
              << "\n";

    std::cout << "Alice shared = "
              << alice_shared
              << "\n";

    std::cout << "Bob shared = "
              << bob_shared
              << "\n";

    std::cout << "Shared values match = "
              << std::boolalpha
              << (alice_shared == bob_shared)
              << "\n";

    const Integer order =
        multiplicative_order(
            domain.generator(),
            domain.modulus()
        );

    DiscreteLogAuditService service;

    const auto audit =
        service.audit_public_value(
            domain,
            alice_public,
            order
        );

    std::cout << "Observed public value = "
              << audit.observed_public_value
              << "\n";

    std::cout << "Recovered private exponent = ";

    if (audit.recovered_private_exponent.has_value()) {
        std::cout
            << audit.recovered_private_exponent.value();
    } else {
        std::cout << "not found";
    }

    std::cout << "\n";

    std::cout << "Verification passed = "
              << audit.verification_passed
              << "\n";

    std::cout << "Attack runtime = "
              << std::fixed
              << std::setprecision(4)
              << audit.milliseconds
              << " ms\n";
}

void demonstrate_pohlig_hellman() {
    std::cout << "\n=== Pohlig-Hellman ===\n";

    const Integer p = 101;
    const Integer g = 2;
    const Integer secret = 73;

    const Integer h =
        modular_power(
            g,
            secret,
            p
        );

    const Integer order =
        multiplicative_order(
            g,
            p
        );

    const auto factors =
        factorize(
            order
        );

    std::cout << "Group order = "
              << order
              << "\n";

    std::cout << "Order factorization = ";
    print_factorization(factors);
    std::cout << "\n";

    const auto recovered =
        pohlig_hellman(
            g,
            h,
            p
        );

    std::cout << "Target = "
              << h
              << "\n";

    std::cout << "Recovered = ";

    if (recovered.has_value()) {
        std::cout << recovered.value();
    } else {
        std::cout << "not found";
    }

    std::cout << "\n";
}

void compare_algorithms() {
    std::cout << "\n=== Algorithm comparison ===\n";

    const Integer p = 10007;
    const Integer g = 5;
    const Integer secret = 4321;

    const Integer order =
        multiplicative_order(
            g,
            p
        );

    const Integer h =
        modular_power(
            g,
            secret,
            p
        );

    const auto start_brute =
        std::chrono::steady_clock::now();

    const auto brute =
        brute_force_discrete_log(
            g,
            h,
            p,
            order
        );

    const auto finish_brute =
        std::chrono::steady_clock::now();

    const auto start_bsgs =
        std::chrono::steady_clock::now();

    const auto bsgs =
        baby_step_giant_step(
            g,
            h,
            p,
            order
        );

    const auto finish_bsgs =
        std::chrono::steady_clock::now();

    const auto start_rho =
        std::chrono::steady_clock::now();

    const auto rho =
        pollard_rho_discrete_log(
            g,
            h,
            p,
            order
        );

    const auto finish_rho =
        std::chrono::steady_clock::now();

    const auto brute_ms =
        std::chrono::duration<double, std::milli>(
            finish_brute - start_brute
        ).count();

    const auto bsgs_ms =
        std::chrono::duration<double, std::milli>(
            finish_bsgs - start_bsgs
        ).count();

    const auto rho_ms =
        std::chrono::duration<double, std::milli>(
            finish_rho - start_rho
        ).count();

    std::cout
        << "Brute force: ";

    if (brute.has_value()) {
        std::cout << brute.value();
    } else {
        std::cout << "not found";
    }

    std::cout
        << ", "
        << brute_ms
        << " ms\n";

    std::cout
        << "BSGS: ";

    if (bsgs.has_value()) {
        std::cout << bsgs.value();
    } else {
        std::cout << "not found";
    }

    std::cout
        << ", "
        << bsgs_ms
        << " ms\n";

    std::cout
        << "Pollard rho: ";

    if (rho.has_value()) {
        std::cout << rho.value();
    } else {
        std::cout << "not found";
    }

    std::cout
        << ", "
        << rho_ms
        << " ms\n";

    std::cout << "\nComplexity model:\n";
    std::cout << "  Brute force: O(n) time, O(1) memory\n";
    std::cout << "  BSGS: O(sqrt(n)) time, O(sqrt(n)) memory\n";
    std::cout << "  Pollard rho: O(sqrt(n)) expected time, O(1) memory\n";
    std::cout << "  Pohlig-Hellman: determined by factorization of group order\n";
}

void demonstrate_edge_conditions() {
    std::cout << "\n=== Edge conditions ===\n";

    const Integer p = 29;
    const Integer g = 4;
    const Integer order =
        multiplicative_order(
            g,
            p
        );

    const Integer unreachable_target = 2;

    const auto result =
        baby_step_giant_step(
            g,
            unreachable_target,
            p,
            order
        );

    std::cout << "ord(4) mod 29 = "
              << order
              << "\n";

    std::cout << "Target 2 belongs to generated subgroup = "
              << std::boolalpha
              << result.has_value()
              << "\n";

    try {
        modular_inverse(
            6,
            15
        );
    } catch (const std::exception& error) {
        std::cout << "Expected inverse failure: "
                  << error.what()
                  << "\n";
    }

    try {
        KeyExchangeDomain invalid_domain(
            15,
            6
        );

        (void)invalid_domain;
    } catch (const std::exception& error) {
        std::cout << "Expected domain validation failure: "
                  << error.what()
                  << "\n";
    }
}

// -----------------------------------------------------------------------------
// 14. Automated validation
// -----------------------------------------------------------------------------

void run_tests() {
    struct TestCase {
        Integer modulus;
        Integer base;
        Integer exponent;
    };

    const std::vector<TestCase> tests{
        {23, 5, 12},
        {29, 2, 11},
        {1009, 11, 731},
        {10007, 5, 4321}
    };

    for (const auto& test : tests) {
        const Integer target =
            modular_power(
                test.base,
                test.exponent,
                test.modulus
            );

        const Integer order =
            multiplicative_order(
                test.base,
                test.modulus
            );

        const auto result =
            baby_step_giant_step(
                test.base,
                target,
                test.modulus,
                order
            );

        if (
            !result.has_value() ||
            result.value() != test.exponent % order
        ) {
            throw std::runtime_error(
                "BSGS test failed"
            );
        }

        if (
            modular_power(
                test.base,
                result.value(),
                test.modulus
            ) != target
        ) {
            throw std::runtime_error(
                "Verification test failed"
            );
        }
    }

    const auto crt =
        chinese_remainder({
            {2, 3},
            {3, 5},
            {2, 7}
        });

    if (
        crt.first != 23 ||
        crt.second != 105
    ) {
        throw std::runtime_error(
            "CRT test failed"
        );
    }

    std::cout
        << "\nAll C++ self-tests passed.\n";
}

// -----------------------------------------------------------------------------
// 15. Main
// -----------------------------------------------------------------------------

int main() {
    try {
        std::cout
            << "============================================================\n"
            << "DISCRETE LOGARITHM CASE STUDY\n"
            << "============================================================\n";

        demonstrate_basic_problem();
        demonstrate_domain_inspection();
        demonstrate_attack_and_defense();
        demonstrate_pohlig_hellman();
        compare_algorithms();
        demonstrate_edge_conditions();
        run_tests();

        std::cout
            << "\nProduction considerations:\n"
            << "  - Do not use these small parameters for security.\n"
            << "  - Use standardized cryptographic groups.\n"
            << "  - Use audited cryptographic libraries.\n"
            << "  - Validate public values and subgroup membership.\n"
            << "  - Avoid leaking private exponents through timing or errors.\n"
            << "  - Use constant-time primitives when required by the protocol.\n";

        return 0;
    } catch (const std::exception& error) {
        std::cerr
            << "Fatal error: "
            << error.what()
            << "\n";

        return 1;
    }
}
