#!/usr/bin/env python3
"""
Elliptic Curve Calculations over Prime Finite Fields.

Implements:
- Curve validation
- Point membership
- Point addition and doubling
- Point negation
- Point subtraction
- Scalar multiplication
- Point enumeration
- Point order calculation
- Elliptic Curve Diffie-Hellman demonstration
- Arithmetic validation and edge-case testing

Educational implementation only. Not suitable for production cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import json
import logging
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)

logger = logging.getLogger("elliptic_curve")


class EllipticCurveError(Exception):
    """Base exception for elliptic curve operations."""


class InvalidCurveError(EllipticCurveError):
    """Raised when curve parameters are invalid."""


class InvalidPointError(EllipticCurveError):
    """Raised when a point does not belong to the curve."""


class InvalidScalarError(EllipticCurveError):
    """Raised when a scalar is invalid."""


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return gcd(a,b) and Bezout coefficients."""
    if b == 0:
        return a, 1, 0

    gcd, x1, y1 = extended_gcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def mod_inverse(value: int, modulus: int) -> int:
    """
    Calculate the multiplicative inverse modulo modulus.

    An inverse exists only when gcd(value, modulus) = 1.
    """
    value %= modulus

    gcd, x, _ = extended_gcd(value, modulus)

    if gcd != 1:
        raise ArithmeticError(
            f"No modular inverse for {value} modulo {modulus}"
        )

    return x % modulus


@dataclass(frozen=True)
class Point:
    """An elliptic curve point, including the point at infinity."""

    x: Optional[int] = None
    y: Optional[int] = None

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __str__(self) -> str:
        if self.is_infinity:
            return "O"
        return f"({self.x}, {self.y})"


INFINITY = Point()


class EllipticCurve:
    """
    Elliptic curve over a prime finite field.

    Curve equation:
        y^2 = x^3 + ax + b (mod p)

    The prime field is F_p.
    """

    def __init__(self, a: int, b: int, p: int):
        if not isinstance(p, int) or p < 3:
            raise InvalidCurveError("Modulus must be an integer >= 3.")

        if not self._is_prime(p):
            raise InvalidCurveError("Modulus must be prime.")

        self.p = p
        self.a = a % p
        self.b = b % p

        discriminant = (
            4 * pow(self.a, 3, p)
            + 27 * pow(self.b, 2, p)
        ) % p

        if discriminant == 0:
            raise InvalidCurveError(
                "Singular curves are not permitted."
            )

    @staticmethod
    def _is_prime(n: int) -> bool:
        if n < 2:
            return False

        if n in (2, 3):
            return True

        if n % 2 == 0:
            return False

        divisor = 3

        while divisor * divisor <= n:
            if n % divisor == 0:
                return False
            divisor += 2

        return True

    def contains(self, point: Point) -> bool:
        if point.is_infinity:
            return True

        if point.x is None or point.y is None:
            return False

        if not (0 <= point.x < self.p):
            return False

        if not (0 <= point.y < self.p):
            return False

        left = pow(point.y, 2, self.p)

        right = (
            pow(point.x, 3, self.p)
            + self.a * point.x
            + self.b
        ) % self.p

        return left == right

    def validate_point(self, point: Point) -> None:
        if not isinstance(point, Point) or not self.contains(point):
            raise InvalidPointError(
                f"Point {point} does not belong to the curve."
            )

    def negate(self, point: Point) -> Point:
        self.validate_point(point)

        if point.is_infinity:
            return INFINITY

        return Point(
            point.x,
            (-point.y) % self.p
        )

    def add(self, p1: Point, p2: Point) -> Point:
        """Add two points using affine elliptic curve arithmetic."""

        self.validate_point(p1)
        self.validate_point(p2)

        if p1.is_infinity:
            return p2

        if p2.is_infinity:
            return p1

        x1, y1 = p1.x, p1.y
        x2, y2 = p2.x, p2.y

        # Inverse points add to the point at infinity.
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return INFINITY

        if p1 == p2:
            if y1 == 0:
                return INFINITY

            numerator = (
                3 * x1 * x1 + self.a
            ) % self.p

            denominator = (2 * y1) % self.p

        else:
            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p

        slope = (
            numerator * mod_inverse(denominator, self.p)
        ) % self.p

        x3 = (slope * slope - x1 - x2) % self.p

        y3 = (
            slope * (x1 - x3) - y1
        ) % self.p

        result = Point(x3, y3)

        self.validate_point(result)

        return result

    def subtract(self, p1: Point, p2: Point) -> Point:
        return self.add(p1, self.negate(p2))

    def multiply(self, scalar: int, point: Point) -> Point:
        """
        Scalar multiplication using double-and-add.

        Complexity: O(log(scalar)) point additions.
        """
        if not isinstance(scalar, int):
            raise InvalidScalarError("Scalar must be an integer.")

        self.validate_point(point)

        if scalar < 0:
            return self.multiply(-scalar, self.negate(point))

        result = INFINITY
        addend = point

        while scalar:
            if scalar & 1:
                result = self.add(result, addend)

            addend = self.add(addend, addend)
            scalar >>= 1

        return result

    def enumerate_points(self) -> list[Point]:
        """Enumerate every affine point and the point at infinity."""
        points = [INFINITY]

        for x in range(self.p):
            rhs = (
                pow(x, 3, self.p)
                + self.a * x
                + self.b
            ) % self.p

            for y in range(self.p):
                if pow(y, 2, self.p) == rhs:
                    points.append(Point(x, y))

        return points

    def point_order(self, point: Point) -> int:
        """Find the smallest positive n such that nP = O."""
        self.validate_point(point)

        if point.is_infinity:
            return 1

        result = INFINITY

        for order in range(1, self.p + 2 + 2 * int(self.p ** 0.5)):
            result = self.add(result, point)

            if result.is_infinity:
                return order

        raise EllipticCurveError("Point order was not found.")

    def count_points(self) -> int:
        return len(self.enumerate_points())

    def describe(self) -> dict:
        return {
            "equation": f"y^2 = x^3 + {self.a}x + {self.b} mod {self.p}",
            "field": f"F_{self.p}",
            "discriminant": (
                4 * pow(self.a, 3, self.p)
                + 27 * pow(self.b, 2, self.p)
            ) % self.p,
            "number_of_points": self.count_points()
        }


class ECDH:
    """Educational Elliptic Curve Diffie-Hellman demonstration."""

    def __init__(self, curve: EllipticCurve, generator: Point):
        curve.validate_point(generator)

        if generator.is_infinity:
            raise InvalidPointError(
                "Generator cannot be the point at infinity."
            )

        self.curve = curve
        self.generator = generator

    def public_key(self, private_key: int) -> Point:
        if not isinstance(private_key, int) or private_key <= 0:
            raise InvalidScalarError(
                "Private key must be a positive integer."
            )

        return self.curve.multiply(
            private_key,
            self.generator
        )

    def shared_secret(
        self,
        private_key: int,
        public_key: Point
    ) -> Point:

        if private_key <= 0:
            raise InvalidScalarError("Private key must be positive.")

        self.curve.validate_point(public_key)

        if public_key.is_infinity:
            raise InvalidPointError("Invalid public key.")

        secret = self.curve.multiply(
            private_key,
            public_key
        )

        if secret.is_infinity:
            raise InvalidPointError("Degenerate shared secret.")

        return secret


def run_tests(curve: EllipticCurve, generator: Point) -> None:
    """Validate core arithmetic invariants."""

    assert curve.contains(generator)

    assert curve.add(generator, INFINITY) == generator

    assert curve.add(
        generator,
        curve.negate(generator)
    ).is_infinity

    assert curve.subtract(generator, generator).is_infinity

    assert curve.multiply(0, generator).is_infinity

    assert curve.multiply(1, generator) == generator

    assert curve.multiply(2, generator) == curve.add(
        generator, generator
    )

    assert curve.contains(curve.multiply(7, generator))

    assert curve.add(
        curve.add(generator, generator),
        generator
    ) == curve.multiply(3, generator)

    logger.info("All arithmetic tests passed.")


def save_report(report: dict, filename: str = "ecc_report.json") -> None:
    """Write a JSON report using UTF-8."""

    path = Path(filename)

    with path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    logger.info("Report saved to %s", path.resolve())


def main() -> None:
    # Small educational curve:
    # y^2 = x^3 + 2x + 2 mod 17
    curve = EllipticCurve(a=2, b=2, p=17)

    generator = Point(5, 1)

    curve.validate_point(generator)

    run_tests(curve, generator)

    print("\nELLIPTIC CURVE PARAMETERS")
    print(json.dumps(curve.describe(), indent=4))

    print("\nPOINT OPERATIONS")

    doubled = curve.add(generator, generator)
    tripled = curve.multiply(3, generator)

    print("Generator:", generator)
    print("2G:", doubled)
    print("3G:", tripled)
    print("-G:", curve.negate(generator))
    print("G + (-G):", curve.add(
        generator,
        curve.negate(generator)
    ))

    print("\nPOINT ENUMERATION")

    points = curve.enumerate_points()

    for index, point in enumerate(points):
        print(f"{index + 1:02d}. {point}")

    print("\nPOINT ORDER")
    order = curve.point_order(generator)
    print("Order of G:", order)

    print("\nSCALAR MULTIPLICATION")

    for scalar in range(1, order + 1):
        print(f"{scalar}G = {curve.multiply(scalar, generator)}")

    print("\nECDH DEMONSTRATION")

    protocol = ECDH(curve, generator)

    alice_private = 5
    bob_private = 7

    alice_public = protocol.public_key(alice_private)
    bob_public = protocol.public_key(bob_private)

    alice_secret = protocol.shared_secret(
        alice_private,
        bob_public
    )

    bob_secret = protocol.shared_secret(
        bob_private,
        alice_public
    )

    assert alice_secret == bob_secret

    print("Alice public key:", alice_public)
    print("Bob public key:", bob_public)
    print("Alice shared point:", alice_secret)
    print("Bob shared point:", bob_secret)
    print("Shared points match:", alice_secret == bob_secret)

    report = {
        "curve": curve.describe(),
        "generator": str(generator),
        "generator_order": order,
        "point_count": len(points),
        "alice_public_key": str(alice_public),
        "bob_public_key": str(bob_public),
        "shared_point": str(alice_secret),
        "tests": "passed"
    }

    save_report(report)

    print("\nExecution completed successfully.")


if __name__ == "__main__":
    main()
