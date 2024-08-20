import hashlib
import hmac
from random import randint
from sys import byteorder
from app.fieldelement import FieldElement
from app.helper import encode_base58_checksum, hash160
from app.point import Point

# 비트코인에서 사용하는 타원 곡선
# - 타원곡선 점의 스칼라 곱셈 -> 역산이 어려운 점을 이용하여 공개키 생성
# - 공개키 암호를 위한 타원곡선은 다음 매개변수로 정의.
# - 곡선 y^2 = x^3 + ax + b 에서 a와 b
# - 유한체의 위수인 소수 p
# - 생성점 G와 x, y 좌표값
# - G로 생성한 군의 위수 n (nG = 0)

# 비트코인은 secp256k1 타원곡선 사용
# a = 0, b = 7 (y^2 = x^3 + 7)
# p = 2^256 - 2^32 - 977
# Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
# Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
# n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# 특징
# - 방정식이 간단
# - 위수 p가 2^256에 가까운 수. 군에 속하는 '곡선 위 점은 256 비트로 표현'
# - 군의 위수 n도 2^256에 가까운 값 ('스칼라도 256비트로 표현')
# - 군의 위수가 매우 크기 때문에 모든 군의 원소를 나열하면서 비밀키를 찾는 방법은 사실상 불가능

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


# secp256k1과 함께 사용할 유한체
class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num, prime=P)

    def __repr__(self):
        return "{:x}".format(self.num).zfill(64)

    # secp256k1의 p값을 갖는 유한체에서 w**2 = v를 만족하는 w 값은 v**(p+1)/4이다.
    # 제곱근은 양수와 음수의 2개의 근이 있으므로 나머지 근은 p - w로 구할 수 있다.
    def sqrt(self):
        return self ** ((P + 1) / 4)


class Signature:
    def __init__(self, r, s) -> None:
        self.r = r
        self.s = s

    def __repr__(self):
        return "Signature({:x},{:x})".format(self.r, self.s)

    # DER: 서명을 직렬화하는 표준
    # - 0x30 + 서명길이(보통0x44, 0x45) + r시작(0x02) + r(길이+value) + s시작(0x02) + s(길이+value)
    # - 0x80보다 크거나 같다? 음수임을 의미. ECDSA 서명에서 모든 숫자는 양수이기 때문에 앞에 0x00을 붙여서 양수로 인식
    def der(self):
        rbin: bytes = self.r.to_bytes(32, byteorder="big")
        rbin = rbin.lstrip(b"\x00")
        if rbin[0] & 0x80:
            rbin = b"\x00" + rbin
        result = bytes([0x02, len(rbin)]) + rbin

        sbin: bytes = self.s.to_bytes(32, byteorder="big")
        sbin = rbin.lstrip(b"\x00")
        if sbin[0] & 0x80:
            sbin = b"\x00" + sbin
        result += bytes([0x02, len(rbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, s) -> "Signature":
        return Signature(None, None)


# 위수 N
class S256Point(Point):

    def __init__(self, x, y, a=None, b=None):
        # a, b, x, y 모두 S256Field 유한체로 변경
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return "S256Point(infinity)"
        else:
            return "S256Point({}, {})".format(self.x, self.y)

    # 군의 위수 n으로 __rmul__을 효율적으로 코딩이 가능
    def __rmul__(self, coefficient):
        # 나머지 연산이 가능한 이유는 n번마다 다시 0(무한원점)으로 되돌아오기 때문
        # 스칼라 곱셈 처음 시작이 0(무한원점)인 것을 생각하면 된다.
        coef = coefficient % N
        return super().__rmul__(coef)

    # 서명 검증 with z, sig
    # - secp256k1 곡선 위 점인 공개키 P와 서명해시 z로 주어진 서명 (r, s)가 유효한지 검증할 수 있다.
    def verify(self, z, sig: Signature):
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total: S256Point = u * G + v * self  # uG + vP == R이 같으면 유효
        return total.x.num == sig.r

    # 직렬화 + 역직렬화
    # SEC: ECDSA 공개키를 직렬화하는 표준안
    # - 비압축(65바이트): 0x04 + x좌표(32바이트 big엔디안) + y좌표(32바이트 big엔디안)
    # - 압축(33바이트): y값이 짝수면 0x02, 홀수면 0x03 (1바이트) + x좌표(32바이트 big엔디안)
    #        - y좌표는 x좌표를 통해 구할 수 있기 때문에 적지 않는다.
    def sec(self, compressed=True) -> bytes:
        """return the binary version of the SEC format"""
        if compressed:
            if self.y.num % 2 == 0:
                return b"\x02" + self.x.num.to_bytes(32, "big")
            else:
                return b"\x03" + self.x.num.to_bytes(32, "big")
        else:
            return (
                b"\x04"
                + self.x.num.to_bytes(32, "big")
                + self.y.num.to_bytes(32, "big")
            )

    # sec 포멧 역직렬화
    @classmethod
    def parse(cls, sec_bin: bytes):
        if sec_bin[0] == 4:  # 0x04(비압축)
            x = int.from_bytes(sec_bin[1:33], "big")
            y = int.from_bytes(sec_bin[33:65], "big")
            return S256Point(x, y)

        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], "big"))
        # y^2 = x^3 + 7 이용하여 y 구하기
        alpha = x**3 + S256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            even_beta = beta

        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)

    # 비트코인 주소형식(with 공개키): 공개키(SEC) 기반의 '가독성 + 길이압축 + 보안성'을 만족해야 함.
    # - ripemd160 해시 사용
    #   - ripemd160(sha256(s))
    #   - SEC 형식을 20바이트로 줄일 수 있다.
    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b"\x6f"
        else:
            prefix = b"\x00"

        return encode_base58_checksum(prefix + h160)


G = S256Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

# 공개키 암호 연산
# - P = eG (e와 G를 알면 P를 쉽게 계산하지만, P와 G를 알 때, e를 계산하기 쉽지 않다: 비대칭성)
# - (e 역산의 어려움) 이러한 특징이 '서명과 검증 알고리즘의 핵심 기반'

# e: 비밀키 (256비트 숫자)
# P: 공개키 (x, y 각각 256 비트 숫자로 구성된 (x, y) 좌표값)

# 서명(생성)과 검증
# - (중요) 서명자는 비밀키를 드러내지 않고 '비밀키의 소유를 검증자에게 증명'한다.
# - 서명과 검증은 트랜잭션에서 사용. 비트코인을 다른 주소로 보내는 사람이 필요한 '비밀키를 소유하고 있음을 증명'하는 용도

# 비트코인에서 사용하는 서명 알고리즘: 타원곡선 디지털 서명 알고리즘(ECDSA)
# 비밀키는 다음을 만족한다: eG = P
# P = eG = ((k - u)/v)G, e = (k - u)/v
# - 서명자는 위의 식을 만족하는 모든 (u, v) 조합 중 한 가지로 선정한다.
# - 조합을 찾았다면 e를 찾았다는 의미 (이산 로그 문제의 해를 찾아 비밀키를 알아내ㄴ 것)
# - u와 v를 제공하기 위해서는 위와 같이 이산 로그 문제의 해를 찾거나 비밀키(e)를 알고 있어야 한다.
# - 이산 로그 문제의 해를 찾는 것은 어려운 일이므로 u, v를 제공하는 사람이 비밀키 e를 알고 있다고 가정하는 것이 타당.
# - 정상 u, v 라면? -> 비밀키를 알고있구나! (비밀키의 소유 증명)

# 서명 해시(z)를 포함한다.
# - 해시? 임의 길이 데이터 -> 고정 크기 데이터로 변경 (+ 거의 유일한 데이터 + 같은 입력 같은 출력)
# - 메시지의 요약본

# u = z/s, v = r/s
# - u와 v로부터 r을 얻는다.

# 서명에서 검증자에게 공개해야 할 정보는 r과 s이다(서명). (+ z와 P가 공개됨)
# 서명은 32바이트 길이의 서명해시(z)를 자신이 보장한다는 증명서와 같다.
# 서명 해시: hash256 = sha256 2번 적용

# 서명 검증 절차
# 1. 서명으로 (r, s)가 주어지고 보내온 메시지의 해시값으로 z 또한 주어진다. 그리고 P는 서명자의 공개키이다.
# 2. u=z/s, v=r/s 를 계산 (적합한 u, v인지 확인해야 함)
# 3. uG + vP = R을 계산 (주어진 값들이 유효한지 검증해야 함. r, s가 적합한지 -> u, v가 적합한지 비밀키의 소유 증명)
# 4. R의 x좌표가 r과 같다면 서명은 유효하다.

# 서명 생성 절차
# 1. 서명해시 z가 주어지고 비밀키 e는 이미 알고 있다. (eG = P)
# 2. '임의의 k'를 선택
# 3. R = kG 로부터 R의 x좌표값 r을 계산한다.
# 4. s = (z +re)/k 를 계산한다.
# 5. 서명은 (r, s)이다.

# 공개키 P(S256Point)는 검증자에게 보내야 하고 z 또한 검증자가 알아야 한다.
# - P는 서명과 함께 전송해야 한다.


# 비밀키를 보관할 PrivateKey 클래스
class PrivateKey:

    def __init__(self, secret: int) -> None:
        self.secret = secret  # == e (비밀키)
        self.point: S256Point = secret * G  # 공개키 P

    def hex(self):
        return "{:x}".format(self.secret).zfill(64)

    # 비밀키e와 z로 r, s 생성
    def sign(self, z):
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        # 비트코인 트랜잭션을 전파하는 노드는 가변성문제로 N/2보다 작은 s값만을 전파한다.
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    # k 값 선정의 중요성
    # - 서명마다 k는 반드시 다른 값이어야 한다.
    # - 즉 한 번 사용한 ㄱ밧을 재사용하면 안된다. 재사용한 k로 인해 비밀키가 드러나게 된다.

    # 예) 두 번의 서명 z1과 z2에서 비밀키는 e이고, k는 재사용했다고 가정
    # e = (s2z1-s1ze)/(rs1-rs2) 의 공식으로 비밀키를 알아낼 수 있다고 한다.
    # 이를 방지하기 위해 비밀키와 z를 통해 k를 유일하게 생성하는 표준안(RFC6979)이 만들어졌다.
    def deterministic_k(self, z):
        k = b"\x00" * 32
        v = b"\x01" * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, "big")
        secret_bytes = self.secret.to_bytes(32, "big")
        s256 = hashlib.sha256
        k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, "big")
            if candidate >= 1 and candidate < N:
                return candidate  # <2>
            k = hmac.new(k, v + b"\x00", s256).digest()
            v = hmac.new(k, v, s256).digest()

    # 비밀키 WIF 형식
    # - 직렬화할 경우는 별로 없다. 왜냐하면 비밀키는 네트워크로 전파하지 않기 때문
    # - 그럼에도 해야 한다면 WIF 형식을 사용
    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, "big")
        if testnet:
            prefix = b"\xef"
        else:
            prefix = b"\x80"
        if compressed:
            suffix = b"\x01"
        else:
            suffix = b""
        return encode_base58_checksum(prefix + secret_bytes + suffix)
