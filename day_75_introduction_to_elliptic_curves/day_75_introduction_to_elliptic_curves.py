#!/usr/bin/env python3
"""
Introduction to Elliptic Curves
Finite-field arithmetic, point operations, scalar multiplication,
curve validation, and cryptographic demonstrations.

Educational implementation only. Not suitable for production cryptography.
"""

from dataclasses import dataclass
from typing import Optional
from math import gcd
import logging
import json
from pathlib import Path


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("elliptic_curves")


class CurveError(Exception):
    """Base exception for elliptic curve operations."""


class InvalidCurveError(CurveError):
    pass


class InvalidPointError(CurveError):
    pass


class NonInvertibleError(CurveError):
    pass


@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None and self.y is None

    def __str__(self):
        if self.is_infinity:
            return "O"
        return f"({self.x}, {self.y})"


INFINITY = Point(None, None)


class EllipticCurve:
    """
    Short Weierstrass curve:

        y² = x³ + ax + b (mod p)

    The implementation uses a prime finite field.
    """

    def __init__(self, a: int, b: int, p: int):
        if not isinstance(p, int) or isinstance(p, bool) or p < 5:
            raise InvalidCurveError("Prime modulus must be an integer >= 5.")

        if not self.is_prime(p):
            raise InvalidCurveError("Modulus must be prime.")

        if not isinstance(a, int) or isinstance(a, bool):
            raise InvalidCurveError("Coefficient a must be an integer.")

        if not isinstance(b, int) or isinstance(b, bool):
            raise InvalidCurveError("Coefficient b must be an integer.")

        self.a = a % p
        self.b = b % p
        self.p = p

        discriminant = (4 * pow(self.a, 3, p) +
                        27 * pow(self.b, 2, p)) % p

        if discriminant == 0:
            raise InvalidCurveError(
                "Singular elliptic curves are not supported."
            )

    @staticmethod
    def is_prime(n: int) -> bool:
        if n < 2:
            return False
        if n % 2 == 0:
            return n == 2

        divisor = 3
        while divisor * divisor <= n:
            if n % divisor == 0:
                return False
            divisor += 2

        return True

    def inverse(self, value: int) -> int:
        """Compute a modular multiplicative inverse."""
        value %= self.p

        if value == 0 or gcd(value, self.p) != 1:
            raise NonInvertibleError(
                f"{value} has no multiplicative inverse modulo {self.p}."
            )

        return pow(value, -1, self.p)

    def contains(self, point: Point) -> bool:
        if not isinstance(point, Point):
            return False

        if point.is_infinity:
            return True

        if point.x is None or point.y is None:
            return False

        if not isinstance(point.x, int) or not isinstance(point.y, int):
            return False

        x = point.x % self.p
        y = point.y % self.p

        left = pow(y, 2, self.p)
        right = (pow(x, 3, self.p) +
                 self.a * x + self.b) % self.p

        return left == right

    def validate_point(self, point: Point):
        if not self.contains(point):
            raise InvalidPointError(
                f"Point {point} does not belong to the curve."
            )

    def normalize(self, point: Point) -> Point:
        if point.is_infinity:
            return INFINITY

        return Point(point.x % self.p, point.y % self.p)

    def negate(self, point: Point) -> Point:
        self.validate_point(point)

        if point.is_infinity:
            return INFINITY

        return Point(point.x % self.p, (-point.y) % self.p)

    def add(self, p1: Point, p2: Point) -> Point:
        """Elliptic curve group addition."""
        self.validate_point(p1)
        self.validate_point(p2)

        p1 = self.normalize(p1)
        p2 = self.normalize(p2)

        if p1.is_infinity:
            return p2

        if p2.is_infinity:
            return p1

        x1, y1 = p1.x, p1.y
        x2, y2 = p2.x, p2.y

        # A point and its inverse sum to the identity.
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return INFINITY

        if p1 == p2:
            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = (2 * y1) % self.p
        else:
            numerator = (y2 - y1) % self.p
            denominator = (x2 - x1) % self.p

        slope = (
            numerator * self.inverse(denominator)
        ) % self.p

        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p

        result = Point(x3, y3)
        self.validate_point(result)

        return result

    def subtract(self, p1: Point, p2: Point) -> Point:
        return self.add(p1, self.negate(p2))

    def multiply(self, scalar: int, point: Point) -> Point:
        """
        Double-and-add scalar multiplication.

        Time complexity: O(log |scalar|) group operations.
        """
        if not isinstance(scalar, int) or isinstance(scalar, bool):
            raise ValueError("Scalar must be an integer.")

        self.validate_point(point)

        if scalar < 0:
            return self.multiply(-scalar, self.negate(point))

        result = INFINITY
        current = self.normalize(point)

        while scalar > 0:
            if scalar & 1:
                result = self.add(result, current)

            current = self.add(current, current)
            scalar >>= 1

        return result

    def enumerate_points(self) -> list[Point]:
        """Enumerate all affine points on a small finite-field curve."""
        points = []

        for x in range(self.p):
            for y in range(self.p):
                point = Point(x, y)

                if self.contains(point):
                    points.append(point)

        return points

    def group_order(self) -> int:
        return len(self.enumerate_points()) + 1

    def point_order(self, point: Point) -> int:
        """Find the order of a point by repeated addition."""
        self.validate_point(point)

        if point.is_infinity:
            return 1

        current = INFINITY

        for order in range(1, self.group_order() + 1):
            current = self.add(current, point)

            if current.is_infinity:
                return order

        raise CurveError("Point order could not be determined.")

    def square_roots(self, value: int) -> list[int]:
        """Educational square-root enumeration for small fields."""
        value %= self.p

        return [
            y for y in range(self.p)
            if pow(y, 2, self.p) == value
        ]

    def find_points(self, x: int) -> list[Point]:
        x %= self.p

        rhs = (pow(x, 3, self.p) +
               self.a * x + self.b) % self.p

        return [
            Point(x, y)
            for y in self.square_roots(rhs)
        ]

    def describe(self) -> dict:
        return {
            "equation": f"y^2 = x^3 + {self.a}x + {self.b} mod {self.p}",
            "field": f"F_{self.p}",
            "discriminant_mod_p": (
                4 * pow(self.a, 3, self.p) +
                27 * pow(self.b, 2, self.p)
            ) % self.p,
            "group_order": self.group_order()
        }


def demonstrate():
    # A small educational elliptic curve over F17.
    curve = EllipticCurve(a=2, b=2, p=17)
    generator = Point(5, 1)

    curve.validate_point(generator)

    print("\nELLIPTIC CURVE")
    print(json.dumps(curve.describe(), indent=2))

    print("\nPOINT OPERATIONS")
    print("Generator G:", generator)
    print("2G:", curve.multiply(2, generator))
    print("3G:", curve.multiply(3, generator))
    print("5G:", curve.multiply(5, generator))
    print("-G:", curve.negate(generator))
    print("G + (-G):", curve.add(generator, curve.negate(generator)))

    print("\nGROUP INFORMATION")
    print("Number of affine points:", len(curve.enumerate_points()))
    print("Group order:", curve.group_order())
    print("Generator order:", curve.point_order(generator))

    print("\nSCALAR MULTIPLICATION")
    for scalar in range(1, 8):
        print(f"{scalar}G = {curve.multiply(scalar, generator)}")

    print("\nEXAMPLE PUBLIC-KEY COMPUTATION")
    alice_private = 5
    bob_private = 7

    alice_public = curve.multiply(alice_private, generator)
    bob_public = curve.multiply(bob_private, generator)

    alice_shared = curve.multiply(alice_private, bob_public)
    bob_shared = curve.multiply(bob_private, alice_public)

    print("Alice public point:", alice_public)
    print("Bob public point:", bob_public)
    print("Alice shared point:", alice_shared)
    print("Bob shared point:", bob_shared)

    assert alice_shared == bob_shared

    print("\nPOINT ENUMERATION")
    for point in curve.enumerate_points():
        print(point)

    print("\nVALIDATION TESTS")

    invalid_points = [
        Point(1, 1),
        Point(20, 20),
    ]

    for point in invalid_points:
        try:
            curve.validate_point(point)
        except InvalidPointError as error:
            print("Rejected:", error)

    try:
        EllipticCurve(0, 0, 17)
    except InvalidCurveError as error:
        print("Rejected singular curve:", error)

    try:
        EllipticCurve(2, 2, 15)
    except InvalidCurveError as error:
        print("Rejected composite modulus:", error)

    # Group identity and inverse properties.
    assert curve.add(generator, INFINITY) == generator
    assert curve.add(INFINITY, generator) == generator
    assert curve.add(generator, curve.negate(generator)) == INFINITY

    # Scalar multiplication consistency.
    assert curve.multiply(5, generator) == curve.add(
        curve.multiply(2, generator),
        curve.multiply(3, generator)
    )

    # Associativity check for selected valid points.
    p1 = generator
    p2 = curve.multiply(2, generator)
    p3 = curve.multiply(3, generator)

    assert curve.add(curve.add(p1, p2), p3) == (
        curve.add(p1, curve.add(p2, p3))
    )

    print("\nAll assertions passed.")

    return curve


if __name__ == "__main__":
    try:
        demonstrate()
    except (CurveError, ValueError, ArithmeticError) as error:
        logger.exception("Execution failed: %s", error)
        raise
