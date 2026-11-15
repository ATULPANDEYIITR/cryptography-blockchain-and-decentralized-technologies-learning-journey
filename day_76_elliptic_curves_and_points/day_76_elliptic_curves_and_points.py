#!/usr/bin/env python3
"""
Elliptic Curves and Points
=========================
Educational implementation of elliptic curves over finite prime fields.

Features:
- Finite-field arithmetic
- Elliptic curve validation
- Point membership verification
- Point addition and point doubling
- Point negation
- Scalar multiplication using double-and-add
- Point-at-infinity handling
- Point enumeration
- Point order calculation
- Group-law validation
- Basic encoding and decoding
- Unit tests and edge-case demonstrations

This implementation is educational, not production cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import logging
import json
import unittest


logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger("elliptic_curves")


class CurveError(Exception):
    """Base exception for elliptic curve operations."""


class InvalidCurveError(CurveError):
    """Raised when curve parameters are invalid."""


class InvalidPointError(CurveError):
    """Raised when a point does not belong to the curve."""


class PointEncodingError(CurveError):
    """Raised when point encoding is invalid."""


class PointState(Enum):
    FINITE = "finite"
    INFINITY = "infinity"


@dataclass(frozen=True)
class Point:
    x: Optional[int] = None
    y: Optional[int] = None

    @property
    def state(self) -> PointState:
        if self.x is None and self.y is None:
            return PointState.INFINITY
        return PointState.FINITE

    @classmethod
    def infinity(cls) -> Point:
        return cls(None, None)

    def __str__(self) -> str:
        if self.state == PointState.INFINITY:
            return "O (point at infinity)"
        return f"({self.x}, {self.y})"


INFINITY = Point.infinity()


def is_prime(number: int) -> bool:
    """Deterministic trial-division primality test."""
    if number < 2:
        return False
    if number in (2, 3):
        return True
    if number % 2 == 0:
        return False

    divisor = 3
    while divisor * divisor <= number:
        if number % divisor == 0:
            return False
        divisor += 2

    return True


class FiniteField:
    """Arithmetic in the finite field F_p."""

    def __init__(self, prime: int):
        if not is_prime(prime):
            raise InvalidCurveError("Field modulus must be prime.")
        self.p = prime

    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p

    def subtract(self, a: int, b: int) -> int:
        return (a - b) % self.p

    def multiply(self, a: int, b: int) -> int:
        return (a * b) % self.p

    def inverse(self, value: int) -> int:
        value %= self.p

        if value == 0:
            raise ZeroDivisionError(
                "Zero has no multiplicative inverse."
            )

        return pow(value, -1, self.p)

    def divide(self, a: int, b: int) -> int:
        return self.multiply(a, self.inverse(b))

    def power(self, base: int, exponent: int) -> int:
        if exponent < 0:
            return self.power(self.inverse(base), -exponent)
        return pow(base, exponent, self.p)


class EllipticCurve:
    """
    Short Weierstrass curve:

        y² = x³ + ax + b (mod p)

    The discriminant must be nonzero modulo p.
    """

    def __init__(self, p: int, a: int, b: int):
        self.field = FiniteField(p)
        self.p = p
        self.a = a % p
        self.b = b % p

        discriminant = (
            4 * pow(self.a, 3, p)
            + 27 * pow(self.b, 2, p)
        ) % p

        if discriminant == 0:
            raise InvalidCurveError(
                "Singular elliptic curves are not supported."
            )

        self.infinity = INFINITY

    def contains(self, point: Point) -> bool:
        if point.state == PointState.INFINITY:
            return True

        if not isinstance(point.x, int) or not isinstance(point.y, int):
            return False

        if not (0 <= point.x < self.p):
            return False

        if not (0 <= point.y < self.p):
            return False

        x, y = point.x, point.y

        left = y * y % self.p
        right = (
            pow(x, 3, self.p)
            + self.a * x
            + self.b
        ) % self.p

        return left == right

    def validate_point(self, point: Point) -> None:
        if not isinstance(point, Point) or not self.contains(point):
            raise InvalidPointError(
                f"Point {point} does not belong to the curve."
            )

    def point(self, x: int, y: int) -> Point:
        candidate = Point(x % self.p, y % self.p)
        self.validate_point(candidate)
        return candidate

    def negate(self, point: Point) -> Point:
        self.validate_point(point)

        if point.state == PointState.INFINITY:
            return self.infinity

        return Point(point.x, (-point.y) % self.p)

    def add(self, p1: Point, p2: Point) -> Point:
        """Elliptic curve group addition."""
        self.validate_point(p1)
        self.validate_point(p2)

        if p1.state == PointState.INFINITY:
            return p2

        if p2.state == PointState.INFINITY:
            return p1

        x1, y1 = p1.x, p1.y
        x2, y2 = p2.x, p2.y

        # Opposite points add to the identity.
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return self.infinity

        if p1 == p2:
            if y1 == 0:
                return self.infinity

            numerator = 3 * x1 * x1 + self.a
            denominator = 2 * y1
        else:
            numerator = y2 - y1
            denominator = x2 - x1

        slope = self.field.divide(numerator, denominator)

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

        Time complexity: O(log |scalar|) point operations.
        This implementation is not constant-time.
        """
        self.validate_point(point)

        if scalar < 0:
            return self.multiply(-scalar, self.negate(point))

        result = self.infinity
        addend = point

        while scalar:
            if scalar & 1:
                result = self.add(result, addend)

            addend = self.add(addend, addend)
            scalar >>= 1

        return result

    def enumerate_points(self) -> list[Point]:
        """Enumerate all affine points and the identity."""
        points = [self.infinity]

        for x in range(self.p):
            rhs = (
                pow(x, 3, self.p)
                + self.a * x
                + self.b
            ) % self.p

            for y in range(self.p):
                if y * y % self.p == rhs:
                    points.append(Point(x, y))

        return points

    def point_order(self, point: Point) -> int:
        """Find the additive order by repeated addition."""
        self.validate_point(point)

        if point.state == PointState.INFINITY:
            return 1

        current = self.infinity

        for order in range(1, self.p + 2 * int(self.p**0.5) + 10):
            current = self.add(current, point)

            if current.state == PointState.INFINITY:
                return order

        raise CurveError("Point order search exceeded its bound.")

    def encode_uncompressed(self, point: Point) -> bytes:
        """Educational SEC1-style uncompressed point encoding."""
        self.validate_point(point)

        if point.state == PointState.INFINITY:
            return b"\x00"

        width = (self.p.bit_length() + 7) // 8

        return (
            b"\x04"
            + point.x.to_bytes(width, "big")
            + point.y.to_bytes(width, "big")
        )

    def decode_uncompressed(self, data: bytes) -> Point:
        """Decode and validate an uncompressed point."""
        if data == b"\x00":
            return self.infinity

        width = (self.p.bit_length() + 7) // 8

        if len(data) != 1 + 2 * width or data[0] != 4:
            raise PointEncodingError(
                "Invalid uncompressed point encoding."
            )

        x = int.from_bytes(data[1:1 + width], "big")
        y = int.from_bytes(data[1 + width:], "big")

        if x >= self.p or y >= self.p:
            raise PointEncodingError(
                "Encoded coordinates exceed the field modulus."
            )

        return self.point(x, y)


def demonstrate(curve: EllipticCurve, generator: Point) -> None:
    print("\nELLIPTIC CURVE PARAMETERS")
    print(f"Field modulus: {curve.p}")
    print(f"a: {curve.a}")
    print(f"b: {curve.b}")
    print(f"Equation: y² = x³ + {curve.a}x + {curve.b} mod {curve.p}")

    print("\nPOINT OPERATIONS")
    print(f"Generator G: {generator}")
    print(f"Negative G: {curve.negate(generator)}")
    print(f"G + G: {curve.add(generator, generator)}")
    print(f"G + (-G): {curve.add(generator, curve.negate(generator))}")
    print(f"3G: {curve.multiply(3, generator)}")
    print(f"5G: {curve.multiply(5, generator)}")
    print(f"Order of G: {curve.point_order(generator)}")

    print("\nPOINT ENUMERATION")
    points = curve.enumerate_points()
    print(f"Total points including infinity: {len(points)}")
    print("First ten points:")
    for point in points[:10]:
        print(f"  {point}")

    print("\nENCODING")
    encoded = curve.encode_uncompressed(generator)
    decoded = curve.decode_uncompressed(encoded)

    print(f"Encoded: {encoded.hex()}")
    print(f"Decoded: {decoded}")
    print(f"Round-trip successful: {decoded == generator}")

    print("\nSCALAR MULTIPLICATION")
    for scalar in range(0, 8):
        print(f"{scalar}G = {curve.multiply(scalar, generator)}")


class EllipticCurveTests(unittest.TestCase):

    def setUp(self):
        self.curve = EllipticCurve(97, 2, 3)
        self.generator = self.curve.point(3, 6)

    def test_membership(self):
        self.assertTrue(self.curve.contains(self.generator))
        self.assertTrue(self.curve.contains(INFINITY))

    def test_identity(self):
        self.assertEqual(
            self.curve.add(self.generator, INFINITY),
            self.generator
        )

    def test_inverse(self):
        self.assertEqual(
            self.curve.add(
                self.generator,
                self.curve.negate(self.generator)
            ),
            INFINITY
        )

    def test_commutativity(self):
        p = self.generator
        q = self.curve.multiply(2, p)
        self.assertEqual(
            self.curve.add(p, q),
            self.curve.add(q, p)
        )

    def test_associativity(self):
        p = self.generator
        q = self.curve.multiply(2, p)
        r = self.curve.multiply(3, p)

        self.assertEqual(
            self.curve.add(self.curve.add(p, q), r),
            self.curve.add(p, self.curve.add(q, r))
        )

    def test_scalar_multiplication(self):
        p = self.generator
        self.assertEqual(self.curve.multiply(0, p), INFINITY)
        self.assertEqual(self.curve.multiply(1, p), p)
        self.assertEqual(
            self.curve.multiply(-2, p),
            self.curve.negate(self.curve.multiply(2, p))
        )

    def test_point_order(self):
        order = self.curve.point_order(self.generator)
        self.assertGreater(order, 0)
        self.assertEqual(
            self.curve.multiply(order, self.generator),
            INFINITY
        )

    def test_encoding(self):
        encoded = self.curve.encode_uncompressed(self.generator)
        decoded = self.curve.decode_uncompressed(encoded)
        self.assertEqual(decoded, self.generator)

    def test_invalid_point(self):
        with self.assertRaises(InvalidPointError):
            self.curve.point(10, 10)

    def test_invalid_curve(self):
        with self.assertRaises(InvalidCurveError):
            EllipticCurve(97, 0, 0)

    def test_field_inverse(self):
        for value in range(1, self.curve.p):
            self.assertEqual(
                self.curve.field.multiply(
                    value,
                    self.curve.field.inverse(value)
                ),
                1
            )


def main():
    curve = EllipticCurve(p=97, a=2, b=3)
    generator = curve.point(3, 6)

    demonstrate(curve, generator)

    print("\nUNIT TESTS")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(
        EllipticCurveTests
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    if not result.wasSuccessful():
        raise SystemExit(1)

    print("\nAll tests passed.")

    report = {
        "modulus": curve.p,
        "curve_a": curve.a,
        "curve_b": curve.b,
        "generator": [generator.x, generator.y],
        "point_order": curve.point_order(generator),
        "group_size": len(curve.enumerate_points()),
    }

    print("\nSTRUCTURED REPORT")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
