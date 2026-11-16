# Elliptic Curve Calculations

## 1. Technical Scope

Elliptic Curve Cryptography (ECC) uses the algebraic structure of elliptic curves over finite fields to construct mathematical operations suitable for public-key cryptography.

This implementation studies elliptic curve calculations over prime finite fields, including point arithmetic, scalar multiplication, point enumeration, point order, and the mathematical foundation of Elliptic Curve Diffie-Hellman (ECDH).

The five implementations use a common educational curve:

\[
E: y^2 \equiv x^3+2x+2 \pmod{17}
\]

Its parameters are:

| Parameter | Value |
|---|---:|
| Curve coefficient \(a\) | 2 |
| Curve coefficient \(b\) | 2 |
| Prime modulus \(p\) | 17 |
| Generator \(G\) | (5, 1) |
| Number of curve points | 19 |
| Generator order | 19 |

The example deliberately uses a small finite field so that intermediate calculations can be inspected and verified manually. It is not cryptographically secure.

## 2. Mathematical Foundations

### 2.1 Elliptic Curve Equation

An elliptic curve over a prime finite field has the short Weierstrass representation:

\[
y^2 \equiv x^3+ax+b \pmod p
\]

Where:

- \(x,y\): coordinates of a curve point.
- \(a,b\): curve coefficients.
- \(p\): prime modulus.
- \(\mathbb F_p\): finite field containing integers from \(0\) through \(p-1\).

The curve must be nonsingular.

Its discriminant condition is:

\[
4a^3+27b^2 \not\equiv 0 \pmod p
\]

A zero discriminant indicates a singular curve and invalidates the intended elliptic curve group structure.

### 2.2 Prime Finite Fields

A finite field provides a bounded arithmetic environment.

For modulus 17:

\[
\mathbb F_{17} =
\{0,1,2,\ldots,16\}
\]

Arithmetic results are reduced modulo 17.

For example:

\[
15+6 \equiv 4 \pmod {17}
\]

\[
5 \times 7 \equiv 1 \pmod {17}
\]

Division is performed using multiplicative inverses rather than ordinary integer division.

### 2.3 Modular Multiplicative Inverse

The multiplicative inverse of \(a\) modulo \(p\) is an integer \(a^{-1}\) satisfying:

\[
a a^{-1}\equiv 1\pmod p
\]

For a prime modulus, every nonzero field element has an inverse.

The extended Euclidean algorithm finds integers \(x,y\) satisfying:

\[
ax+py=\gcd(a,p)
\]

When the greatest common divisor is one:

\[
a^{-1}\equiv x\pmod p
\]

The implementations use this mechanism in point addition and doubling.

## 3. Elliptic Curve Points

A point is an ordered coordinate pair:

\[
P=(x,y)
\]

A point belongs to the curve when:

\[
y^2\equiv x^3+ax+b\pmod p
\]

The implementation validates:

- Coordinate existence.
- Coordinate boundaries.
- Curve membership.
- Field modulus.
- Curve nonsingularity.

### 3.1 Point at Infinity

Elliptic curve arithmetic includes a special identity element called the point at infinity:

\[
O
\]

It satisfies:

\[
P+O=P
\]

\[
O+P=P
\]

\[
P+(-P)=O
\]

The implementations represent this point separately from ordinary coordinate pairs.

This avoids incorrectly treating a normal coordinate as an identity element.

### 3.2 Point Negation

For a point:

\[
P=(x,y)
\]

Its additive inverse is:

\[
-P=(x,-y\bmod p)
\]

For the example curve:

\[
G=(5,1)
\]

Therefore:

\[
-G=(5,16)
\]

And:

\[
G+(-G)=O
\]

## 4. Point Addition and Doubling

### 4.1 Addition of Different Points

Given two distinct points:

\[
P=(x_1,y_1)
\]

\[
Q=(x_2,y_2)
\]

The slope is:

\[
\lambda=
\frac{y_2-y_1}{x_2-x_1}\pmod p
\]

Division is implemented through modular inversion:

\[
\lambda=
(y_2-y_1)(x_2-x_1)^{-1}\pmod p
\]

The resulting point is:

\[
R=P+Q=(x_3,y_3)
\]

Where:

\[
x_3=\lambda^2-x_1-x_2\pmod p
\]

\[
y_3=\lambda(x_1-x_3)-y_1\pmod p
\]

### 4.2 Point Doubling

When both input points are identical:

\[
P=Q
\]

The slope becomes:

\[
\lambda=
\frac{3x_1^2+a}{2y_1}\pmod p
\]

The resulting coordinates follow the same formulas used in point addition.

A special case occurs when:

\[
y_1=0
\]

In that situation:

\[
2P=O
\]

The implementations handle this explicitly instead of attempting to calculate an inverse of zero.

### 4.3 Example Calculation

For:

\[
G=(5,1)
\]

On:

\[
y^2=x^3+2x+2\pmod {17}
\]

Doubling produces:

\[
2G=(6,3)
\]

The slope is:

\[
\lambda=
\frac{3(5)^2+2}{2(1)}
\pmod {17}
\]

\[
\lambda=\frac{77}{2}\pmod {17}
\]

Since:

\[
77\equiv 9\pmod {17}
\]

And:

\[
2^{-1}\equiv 9\pmod {17}
\]

Therefore:

\[
\lambda\equiv 9\times9
\equiv13\pmod {17}
\]

The resulting coordinates are:

\[
x_3=13^2-5-5\equiv6\pmod {17}
\]

\[
y_3=13(5-6)-1\equiv3\pmod {17}
\]

Hence:

\[
2G=(6,3)
\]

## 5. Scalar Multiplication

Scalar multiplication is one of the central operations in elliptic curve cryptography.

For an integer \(k\) and point \(P\):

\[
Q=kP
\]

It means repeated elliptic curve addition.

For example:

\[
3G=G+G+G
\]

A direct repeated-addition implementation requires approximately \(O(k)\) point additions.

The implementations instead use the double-and-add algorithm.

### 5.1 Double-and-Add

The algorithm represents the scalar in binary.

For example:

\[
13=(1101)_2
\]

Therefore:

\[
13P=8P+4P+P
\]

The algorithm repeatedly:

- Examines the least significant bit.
- Adds the current point when that bit is one.
- Doubles the current point.
- Shifts the scalar to the right.

Its arithmetic complexity is:

\[
O(\log k)
\]

This is substantially more efficient than repeated addition for large scalars.

The implementation also supports:

\[
0P=O
\]

And:

\[
(-k)P=k(-P)
\]

Negative scalar multiplication is handled through point negation.

## 6. Point Enumeration and Group Order

Point enumeration identifies all coordinate pairs satisfying the curve equation.

For every field element \(x\), the implementation checks possible values of \(y\).

The point at infinity is included separately.

For the educational curve, the complete point set contains 19 elements.

The group cardinality is:

\[
|E(\mathbb F_p)|=19
\]

### 6.1 Point Order

The order of a point is the smallest positive integer \(n\) satisfying:

\[
nP=O
\]

For the selected generator:

\[
\operatorname{ord}(G)=19
\]

Therefore:

\[
19G=O
\]

And:

\[
18G=-G
\]

The implementation determines point order through repeated point addition, bounded using Hasse's theorem.

### 6.2 Hasse's Theorem

For an elliptic curve over a finite field:

\[
\left|
|E(\mathbb F_p)|-(p+1)
\right|
\leq 2\sqrt p
\]

This provides a useful bound on the number of points.

It also provides a bound for the educational point-order calculation.

## 7. Elliptic Curve Diffie-Hellman

ECDH establishes a shared mathematical secret between two parties using private and public keys.

Both parties agree on:

- An elliptic curve.
- A finite field.
- A generator point \(G\).
- A suitable subgroup.

### 7.1 Key Generation

Alice selects a private scalar:

\[
d_A
\]

Her public key is:

\[
Q_A=d_AG
\]

Bob selects:

\[
d_B
\]

His public key is:

\[
Q_B=d_BG
\]

The private scalars must remain confidential.

### 7.2 Shared Secret

Alice calculates:

\[
S_A=d_AQ_B
\]

Bob calculates:

\[
S_B=d_BQ_A
\]

Using scalar multiplication:

\[
S_A=d_A(d_BG)
\]

\[
S_B=d_B(d_AG)
\]

Therefore:

\[
S_A=S_B=(d_Ad_B)G
\]

Both parties obtain the same shared point.

### 7.3 Demonstration Parameters

The programs use:

| Parameter | Alice | Bob |
|---|---:|---:|
| Private scalar | 5 | 7 |
| Public point | 5G | 7G |

The common secret is:

\[
S=35G
\]

Since:

\[
35\equiv16\pmod {19}
\]

The shared point is:

\[
S=16G=(10,11)
\]

The programs verify that both parties obtain the same point.

This example demonstrates the mathematics only. Real ECDH implementations must use standardized curves, validated public keys, suitable subgroup parameters, and a key derivation function.

## 8. Implementation Architecture

### 8.1 Python

File: `elliptic_curve.py`

Python provides a compact mathematical implementation with explicit domain modeling.

The implementation contains:

| Component | Responsibility |
|---|---|
| `Point` | Immutable point representation |
| `EllipticCurve` | Curve arithmetic and validation |
| `mod_inverse` | Modular inversion |
| `extended_gcd` | Extended Euclidean algorithm |
| `ECDH` | Shared-secret calculation |
| `run_tests` | Arithmetic invariant verification |
| `save_report` | JSON report persistence |

Python uses arbitrary-precision integers, avoiding ordinary fixed-width integer overflow.

The point representation uses `None` coordinates for the point at infinity.

The implementation uses exceptions to distinguish invalid curve parameters, invalid points, and invalid scalars.

### 8.2 JavaScript

File: `elliptic_curve.js`

JavaScript uses `BigInt` because ordinary JavaScript `Number` values cannot represent arbitrary large integers exactly.

Its architecture emphasizes event-driven execution.

| Component | Responsibility |
|---|---|
| `ECPoint` | Immutable point representation |
| `EllipticCurve` | Finite-field arithmetic |
| `ECDHProtocol` | Public-key and shared-secret operations |
| `CalculationEngine` | Asynchronous calculation orchestration |
| `EventEmitter` | Calculation notifications |
| `modInverse` | Modular inversion |
| `modPow` | Modular exponentiation |

The calculation engine emits successful operations and errors as events.

This separates arithmetic execution from monitoring and reporting.

The implementation writes its execution report to `ecc_report.json`.

The mathematical operations use `BigInt` throughout to prevent accidental precision loss from mixed numeric representations.

### 8.3 C++17

File: `elliptic_curve.cpp`

The C++ implementation emphasizes explicit domain modeling, modular arithmetic, and performance-conscious operations.

| Component | Responsibility |
|---|---|
| `Point` | Point and infinity representation |
| `EllipticCurve` | Arithmetic engine |
| `ECDH` | Key-exchange calculation |
| `ECCException` | Error handling |
| `runTests` | Mathematical invariant verification |

The implementation uses:

- `struct` for point representation.
- `class` for curve and protocol behavior.
- STL vectors for point enumeration.
- `__int128` for intermediate multiplication.
- Exceptions for invalid mathematical states.

The arithmetic implementation uses signed 64-bit values for stored parameters and a wider intermediate type for multiplication.

Its supported numeric range is limited by the selected integer representation.

For larger cryptographic parameters, arbitrary-precision arithmetic or a dedicated cryptographic library is required.

### 8.4 Java 17

File: `EllipticCurveCalculations.java`

The Java implementation emphasizes enterprise-oriented separation of responsibilities.

| Component | Responsibility |
|---|---|
| `Point` record | Immutable point data |
| `CurveParameters` record | Curve configuration |
| `PrimeField` | Finite-field operations |
| `EllipticCurve` | Point arithmetic |
| `ECDHService` | Key-exchange operations |
| `GovernanceService` | Validation and operation reporting |
| `OperationResult` | Structured execution result |

Java's `BigInteger` supports arbitrary-precision arithmetic.

Records provide immutable representations of mathematical values.

The service classes separate arithmetic implementation from protocol operations and validation reporting.

The use of explicit exceptions makes invalid inputs distinguishable from successful mathematical results.

## 9. PostgreSQL Data Model

File: `elliptic_curve.sql`

The database implementation models curve configuration, points, calculation execution, and key-exchange sessions.

### 9.1 Entity Relationships

The relational structure is:

    Curves
       |
       +---- Curve_Points
       |
       +---- Calculation_Jobs
       |          |
       |          +---- Calculation_Results
       |
       +---- Key_Exchange_Sessions

### 9.2 Tables

| Table | Purpose |
|---|---|
| `curves` | Curve coefficients and field parameters |
| `curve_points` | Validated points associated with curves |
| `calculation_jobs` | Calculation requests and execution states |
| `calculation_results` | Persisted calculation outputs |
| `key_exchange_sessions` | ECDH demonstration records |

Foreign keys preserve relationships between curves, points, jobs, and results.

Check constraints prevent inconsistent representations of the point at infinity.

A unique constraint prevents duplicate ordinary coordinate pairs for a curve.

### 9.3 Database Functions

The SQL implementation provides:

| Function | Purpose |
|---|---|
| `mod_normalize` | Normalize modular values |
| `mod_inverse` | Calculate modular inverses |
| `mod_power` | Modular exponentiation |
| `is_prime_number` | Prime modulus validation |
| `validate_curve` | Curve nonsingularity and field validation |
| `point_is_valid` | Point membership validation |
| `point_negate` | Additive inverse |
| `point_add` | Point addition and doubling |
| `point_subtract` | Point subtraction |
| `scalar_multiply` | Double-and-add scalar multiplication |
| `calculate_point_order` | Point order calculation |
| `record_calculation` | Create calculation jobs |

The `complete_calculation` procedure records successful results and updates the corresponding job state.

### 9.4 Integrity and Transactions

The point-validation trigger prevents invalid coordinate pairs from being stored.

The calculation-result constraints distinguish ordinary points from the point at infinity.

The calculation workflow uses a transaction to ensure that job creation and successful result persistence are handled together.

A failed transaction can be rolled back without leaving a partially completed calculation.

The reporting view joins job records with their associated curve and calculation result.

### 9.5 Performance Considerations

The SQL implementation includes indexes for:

- Curve-to-point lookup.
- Calculation status and timestamp filtering.
- Operation-based reporting.
- JSONB execution metadata.

Point enumeration has quadratic search complexity in the size of the field:

\[
O(p^2)
\]

The double-and-add algorithm reduces scalar multiplication to:

\[
O(\log k)
\]

point additions.

The SQL implementation is intended for small educational fields. Its procedural arithmetic and row-level validation are not optimized for large-scale cryptographic processing.

## 10. Execution Instructions

### Python

Run:

`python elliptic_curve.py`

The script performs curve validation, point arithmetic, enumeration, point-order calculation, and ECDH verification.

It produces `ecc_report.json`.

### JavaScript

Run:

`node elliptic_curve.js`

The application uses only Node.js standard-library modules.

It produces `ecc_report.json`.

### C++17

Compile:

`g++ -std=c++17 -O2 -Wall -Wextra elliptic_curve.cpp -o elliptic_curve`

Execute:

`./elliptic_curve`

On Windows, execute:

`elliptic_curve.exe`

### Java 17

Compile:

`javac EllipticCurveCalculations.java`

Execute:

`java EllipticCurveCalculations`

### PostgreSQL

Execute the SQL script using PostgreSQL 15 or later.

The script creates the `ecc_lab` schema, mathematical functions, relational tables, triggers, procedures, sample records, and demonstration queries.

The script drops and recreates `ecc_lab`. Existing data in that schema will therefore be deleted.

## 11. Validation and Edge Cases

The implementations account for the following mathematical conditions:

| Condition | Expected behavior |
|---|---|
| Invalid prime modulus | Reject curve |
| Singular curve | Reject parameters |
| Invalid coordinates | Reject point |
| Point at infinity | Preserve identity behavior |
| Addition with infinity | Return the other point |
| Addition of inverse points | Return infinity |
| Doubling with zero y-coordinate | Return infinity |
| Scalar equal to zero | Return infinity |
| Negative scalar | Multiply the negated point |
| Noninvertible denominator | Raise arithmetic error |
| Invalid ECDH public point | Reject exchange |
| Degenerate shared point | Reject exchange |
| Repeated database completion | Reject duplicate completion |

Arithmetic invariants include:

\[
P+O=P
\]

\[
P+(-P)=O
\]

\[
1P=P
\]

\[
0P=O
\]

\[
(a+b)P=aP+bP
\]

The ECDH implementations also verify:

\[
d_AQ_B=d_BQ_A
\]

## 12. Security Considerations and Limitations

These implementations are mathematical learning artifacts, not production cryptographic systems.

Important limitations include:

**Small parameters:** The modulus 17 provides no meaningful cryptographic security.

**Private-key handling:** The demonstration uses fixed private scalars. Production private keys must be generated using a cryptographically secure random-number generator.

**Subgroup validation:** A valid curve point is not automatically a valid public key for a particular protocol. Production implementations must validate subgroup membership and other public-key requirements.

**Side-channel resistance:** Ordinary double-and-add algorithms can expose information through execution time, branching, and memory behavior. These implementations are not constant-time.

**Point encoding:** Production systems require standardized point serialization, decoding, and canonical representation checks.

**Key derivation:** ECDH produces a shared point. A production protocol should derive cryptographic key material from an appropriately encoded shared secret using a secure key derivation function.

**Authentication:** ECDH alone does not authenticate the communicating parties. Authentication and protocol-level protections are necessary to prevent man-in-the-middle attacks.

**Integer safety:** C++ uses bounded integer representations, while Python and Java use arbitrary-precision integers. JavaScript uses `BigInt`. None of these educational implementations provides a complete production cryptographic environment.

**Database confidentiality:** Private-key storage in the sample database is purely demonstrative. Production systems should avoid persisting raw private keys and shared secrets in ordinary relational records.

The principal distinction is between understanding the mathematical correctness of elliptic curve operations and implementing a secure cryptographic protocol. Mathematical correctness alone does not establish production security.
