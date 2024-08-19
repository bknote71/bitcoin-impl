# 유한체 (FieldElement)
# - 유한개의 체(Field)
# - 체? 특정 공간에서의 각 점에서의 상태값

# 위수 p (소수)
# Fp = {0, 1, .. p - 1}
# - 집합은 덧셈, 곱셈에 대하여 닫혀있다. (1)
# - 덧셈과 곱셈에 대한 항등원 + 역원이 집합 내에 있다. (2, 3, 4, 5)


class FieldElement:

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = f"Num {num} not in field range o to {prime - 1}"
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self) -> str:
        return f"FieldELement_{self.prime}({self.num})"

    def __eq__(self, other: object) -> bool:
        if other is None:
            return False

        # value가 FieldElement의 인스턴스인지 확인
        if not isinstance(other, FieldElement):
            return False

        return self.num == other.num and self.prime == other.prime

    # + 연산자
    def __add__(self, other: object):
        if not isinstance(other, FieldElement):
            raise TypeError("Cannot add two numbers in different Types")

        # 위수가 다르면, 무의미
        if self.prime != other.prime:
            raise TypeError("Cannot add two numbers in different Fields")

        num = (self.num + other.num) % self.prime
        # __class__(): 자기 자신 클래스의 인스턴스 반환
        return self.__class__(num, self.prime)

    # - 연산자
    def __sub__(self, other: object):
        if not isinstance(other, FieldElement):
            raise TypeError("Cannot sub two numbers in different Types")

        if self.prime != other.prime:
            raise TypeError("Cannot sub two numbers in different Fields")

        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    # * 연산자
    def __mul__(self, other: object):
        if not isinstance(other, FieldElement):
            raise TypeError("Cannot mul two numbers in different Types")

        if self.prime != other.prime:
            raise TypeError("Cannot mul two numbers in different Fields")

        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    # ** 연산자
    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    # 페르마의 소정리 (p는 소수)
    # n ^ (p - 1) % p = 1
    # 나눗셈은 곱의 역연산 a/b == a*b^-1
    # 페르마의 소정리에 의해 b^-1 == b^(p - 2)
    # - b^-1 = b^-1*1 = b^-1*b^(p-1) % p = b^(p-2) % p

    # truediv(/)
    # floordiv(//)
    def __truediv__(self, other: object):
        if not isinstance(other, FieldElement):
            raise TypeError("Cannot div two numbers in different Types")

        if self.prime != other.prime:
            raise TypeError("Cannot div two numbers in different Fields")

        # pow(a, b, c) == a^b % c
        num = self.num * pow(other.num, self.prime - 2, self.prime) % self.prime
        return self.__class__(num, self.prime)


from unittest import TestCase


class FieldElementTest(TestCase):

    def test_ne(self):
        a = FieldElement(2, 31)
        b = FieldElement(2, 31)
        c = FieldElement(15, 31)
        self.assertEqual(a, b)
        self.assertTrue(a != c)
        self.assertFalse(a != b)

    def test_add(self):
        a = FieldElement(2, 31)
        b = FieldElement(15, 31)
        self.assertEqual(a + b, FieldElement(17, 31))
        a = FieldElement(17, 31)
        b = FieldElement(21, 31)
        self.assertEqual(a + b, FieldElement(7, 31))

    def test_sub(self):
        a = FieldElement(29, 31)
        b = FieldElement(4, 31)
        self.assertEqual(a - b, FieldElement(25, 31))
        a = FieldElement(15, 31)
        b = FieldElement(30, 31)
        self.assertEqual(a - b, FieldElement(16, 31))

    def test_mul(self):
        a = FieldElement(24, 31)
        b = FieldElement(19, 31)
        self.assertEqual(a * b, FieldElement(22, 31))

    def test_pow(self):
        a = FieldElement(17, 31)
        self.assertEqual(a**3, FieldElement(15, 31))
        a = FieldElement(5, 31)
        b = FieldElement(18, 31)
        self.assertEqual(a**5 * b, FieldElement(16, 31))

    def test_div(self):
        a = FieldElement(3, 31)
        b = FieldElement(24, 31)
        self.assertEqual(a / b, FieldElement(4, 31))
        a = FieldElement(17, 31)
        self.assertEqual(a**-3, FieldElement(29, 31))
        a = FieldElement(4, 31)
        b = FieldElement(11, 31)
        self.assertEqual(a**-4 * b, FieldElement(13, 31))


# 타원곡선: y^2 = x^3 + ax + b
# - x축 대칭 + 제곱이기 때문에 완만한 형태의 그래프 (y를 구하기 위해 sqrt하면 완만해짐)
# - 비트코인에서 사용되는 타원곡선은 secp256k1: y^2 = x^3 + 7 (a=0, b=7)


# 타원곡선 위에 있는 한 점 정의
class Point:
    def __init__(self, x, y, a, b) -> None:
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        # (x, y)가 타원 곡선 위에 있는지 확인
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError(f"({x}, {y}) is not on the curve")

    # == 연산자
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Point):
            return False
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    # != 연산자
    def __ne__(self, other: object) -> bool:
        return not (self == other)
