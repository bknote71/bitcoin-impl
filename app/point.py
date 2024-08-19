# 타원곡선: y^2 = x^3 + ax + b
# - x축 대칭 + 제곱이기 때문에 완만한 형태의 그래프 (y를 구하기 위해 sqrt하면 완만해짐)
# - 비트코인에서 사용되는 타원곡선은 secp256k1: y^2 = x^3 + 7 (a=0, b=7)


# 타원곡선 위에 있는 한 점 정의
# 두 점의 덧셈을 정의하는 데 매우 유용
# - 모든 타원 곡선에 대해 몇 가지 예외 케이스를 제외하고 곡선과 함께 그려진 직선은 반드시 곡선과 한 점 또는 세 점에서 만난다.
# - 예외 케이스: 직선이 y축과 평행 or 한 점에 접하는 접선


# 타원곡선에서의 점 덧셈 정의
# - A + B: 두 점 A와 B를 지나는 직선이 타원과 만나는 교점을 x축으로 대칭시킨 점
# - 점 덧셈의 결과를 쉽게 예측할 수 없다는 것이 중요한 성질이다.

# 점 덧셈 성질
# - 항등원(I: 무한원점), 역원(-A) 존재
# - 교환법칙 성립: A + B = B + A
# - 결합법칙 성립: (A + B) + C = A + (B + C)

# 점 덧셈의 3가지 케이스
# 1. 두 점이 x 축에 수직인 직선 위에 있는 경우
# 2. 두 점이 x 축에 수직인 직선 위에 있지 않은 경우
# 3. 두 점이 같은 경우

# 항등원 더하기: 무한원점(0) = None값
# 역원 더하기(-y):  == 0
from unittest import TestCase


class Point:
    def __init__(self, x, y, a, b) -> None:
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        if self.x is None and self.y is None:
            return

        # (x, y)가 타원 곡선 위에 있는지 확인
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError(f"({x}, {y}) is not on the curve")

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        else:
            return "Point({},{})_{}_{}".format(self.x, self.y, self.a, self.b)

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

    def __add__(self, other: object):
        if not isinstance(other, Point):
            raise TypeError("not a Point Type")

        if self.a != other.a or self.b != other.b:
            raise TypeError(f"Points {self}, {other} are not on the same curve.")

        # 무한원점 (항등원)
        if self.x is None:
            return other

        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return __class__(None, None, self.a, self.b)

        # x1 != x2인 경우 (1차 방정식 적용)
        # s = (y2 - y1)/(x2 - x1) (기울기)
        # x3 = s^2 - x1 - x2
        # y3 = s(x1 - x3) - y1
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        # 접선이 x축에 수직인 경우
        # 두 점이 같고 y 좌표가 0이면 접하는 것이고, 무한원점을 반환
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        # p1 = p2
        # p1 + p2 = I(0)
        # - 접선을 의미
        # s = (3*x1^2 + a)/2y1
        # x3 = s^2 - 3x2
        # y3 = s(x1 - x3) - y1
        if self == other:
            s = (3 * self.x**2 + self.a) / 2 * self.y
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)


class PointTest(TestCase):

    def test_ne(self):
        a = Point(x=3, y=-7, a=5, b=7)
        b = Point(x=18, y=77, a=5, b=7)
        self.assertTrue(a != b)
        self.assertFalse(a != a)

    def test_add0(self):
        a = Point(x=None, y=None, a=5, b=7)
        b = Point(x=2, y=5, a=5, b=7)
        c = Point(x=2, y=-5, a=5, b=7)
        self.assertEqual(a + b, b)
        self.assertEqual(b + a, b)
        self.assertEqual(b + c, a)

    def test_add1(self):
        a = Point(x=3, y=7, a=5, b=7)
        b = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + b, Point(x=2, y=-5, a=5, b=7))

    def test_add2(self):
        a = Point(x=-1, y=-1, a=5, b=7)
        self.assertEqual(a + a, Point(x=18, y=77, a=5, b=7))
