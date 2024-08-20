import io
from logging import Logger

# 스크립트? 비트코인이 어떤 조건에서 소비되는지 기술하는 프로그래밍 언어
# - '계약'을 구현
# - 스택 기반의 언어 (반복을 위한 루프 x)

# 스크립트가 유효하기 위해서 모든 명령어가 실행된 후 스택 위에는 0이 아닌 원소가 남아있어야 한다.
# 스택 위에 아무것도 없거나 0이 남아있다면 유효하지 않은 것으로 간주된다.
# 스크립트가 유효하지 않으면 해제 스크립트 부분을 포함하는 트랜잭션이 네트워크에서 거절되어 전파되지 않는다.

# 중요 연산자
# - OP_DUP: 동일한 원소 복사 후 스택 위에 올림
# - OP_HASH160: ripemd160(sha256)
# - OP_CHECKSIG: 스택 위 2개의 원소를 가져와서 첫 번째 원소는 공개키로, 두 번째 원소는 서명으로 간주하여 서명을 공개키로 검증한다.

# p2pk
# - 비트코인은 공개키로 보낸다. 비밀키 소유자는 서명을 통해 비트코인을 해제하고 사용할 수 있다.
# - 즉 잠금 스크립트는 비밀키 소유자만 할당된 비트코인에 접근할 수 있도록 하는 것 (목적지를 정하는 것)
# - 해제 스크립트는 받은 비트코인을 해제하는 부분

# 결합: OP_CHECKSIG + pubkey + signature (공개키와 서명을 스크립트 안에 포함시켜 트랜잭션을 만들어 전송한다.)
# signature(서명)과 pubkey(공개키)를 스택위에 올리고 checksig 연산 실행
# - '공개키로 서명이 올바른지 확인'
# - 올바르면 1, 올바르지 않으면 0

# (중요: 해제 스크립트 명령어는 잠금 스크립트 명령어 위에 위치하여 먼저 실행되게 된다.)
# - 해제 + 잠금 순서

from app.helper import (
    encode_varint,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
)
from op import OP_CODE_FUNCTIONS, OP_CODE_NAMES


# 실행할 명령어의 집합
class Script:
    def __init__(self, cmds=None):

        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    # 스크립트 실행을 위해 잠금 스크립트와 해제 스크립트를 결합해야 한다.
    # 금고(ScriptPubKey)와 열쇠(ScriptSig)는 서로 다른 트랜잭션에 있다.
    # 금고는 비트코인을 받았던 트랜잭션에 있고, 열쇠는 비트코인을 소비하는 트랜잭션에 있다.
    # 해제 스클비트는 잠금 스크립트로 잠긴 코인을 해제하기 때문에 2 개의 스크립트를 하나로 만드는 방법이 필요하다.
    # 즉 둘을 하나로 실행시킨다. (중요: 해제 스크립트 명령어는 잠금 스크립트 명령어 위에 위치하여 먼저 실행되게 된다.)
    def __add__(self, other: "Script"):
        return Script(self.cmds + other.cmds)

    # 스크립트 파싱 (잠금, 해제 스크립트 모두 같은 방식)
    # 1. varint로 총 길이 파악
    # 2. 커맨드 파싱
    # - 처음 읽은 한 바이트 값이 n
    # - 1 ~75 범위라면 n바이트 길이만큼 읽어서 한 원소로 간주
    # - 아니라면 오피코드

    @classmethod
    def parse(cls, s: io.BytesIO) -> "Script":

        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            current_byte = current[0]
            count += 1
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            # OP_PUSHDATA1 (다음 한 바이트를 더 읽어 파싱할 원소의 길이를 얻는다.)
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            ("parsing script failed")
        return cls(cmds)

    def raw_serialize(self):
        result = b""
        for cmd in self.cmds:
            if type(cmd) == int:  # 연산자가 오피코드라면
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif length < 75 and length < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError("too long an cmd")
                result += cmd
        return result

    def serialize(self) -> bytes:
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z):
        # create a copy as we may need to add to this list if we have a
        # RedeemScript
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                # do what the opcode says
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    # op_if/op_notif require the cmds array
                    if not operation(stack, cmds):
                        return False
                elif cmd in (107, 108):
                    # op_toaltstack/op_fromaltstack require the altstack
                    if not operation(stack, altstack):
                        return False
                elif cmd in (172, 173, 174, 175):
                    # these are signing operations, they need a sig_hash
                    # to check against
                    if not operation(stack, z):
                        return False
                else:
                    if not operation(stack):
                        return False
            else:
                # add the cmd to the stack
                stack.append(cmd)
        if len(stack) == 0:
            return False
        if stack.pop() == b"":
            return False
        return True


def p2pkh_script(h160):
    """Takes a hash160 and returns the p2pkh ScriptPubKey"""
    # OP_DUP, OP_HASH160, 20byte pubkey' hash, OP_EQUALVERIFY, OP_CHECKSIG
    return Script([0x76, 0xA9, h160, 0x88, 0xAC])
