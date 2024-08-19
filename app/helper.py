import hashlib
from unittest import TestSuite, TextTestRunner


def run(test):
    suite = TestSuite()
    suite.addTest(test)
    TextTestRunner().run(suite)


def hash256(s):  # sha256  2번 적용: 256비트(32바이트)
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()
