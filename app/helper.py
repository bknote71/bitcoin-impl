import hashlib
from re import A
from sys import prefix
from unittest import TestSuite, TextTestRunner

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def hash256(s):  # sha256  2번 적용: 256비트(32바이트)
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def hash160(s):
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()


def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])


def encode_base58(s):
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, "big")
    prefix = "1" * count
    result = ""
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder="big")
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(
            "bad address: {} {}".format(checksum, hash256(combined[:-4])[:4])
        )
    return combined[1:-4]


# 빅엔디안/리틀엔디안 변환
# - 어디에서 빅엔디안 혹은 리틀엔디안이 사용된다는 명확한 규칙은 없다.
# - 예) SEC 형식에서는 빅엔디안, 비트코인 주소와 WIF 형식에서도 빅엔디안, ..
def little_endian_to_int(b):
    return int.from_bytes(b, byteorder="little")


def int_to_little_endian(n: int, length):
    return n.to_bytes(length, byteorder="little")
