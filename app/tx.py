# 트랜잭션? 한 엔티티에서 다른 엔티티로의 가치 이동 (거래)
# 트랜잭션 구성 요소
# - 버전: 어떤 부가 기능을 트랜잭션이 사용할 수 있는지를 규정
# - 입력: 사용할 비트코인을 정의
# - 출력: 종착지 정의
# - 록타임(locktime): 트랜잭션의 유효시점을 규정
from io import BytesIO
from typing import Any
import requests

from app import script
from app.helper import *
from app.script import Script, p2pkh_script
from app.signature import PrivateKey


class Tx:
    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False) -> None:
        self.version: int = version
        self.tx_ins: list[TxIn] = tx_ins
        self.tx_outs: list[TxOut] = tx_outs
        self.locktime: int = locktime
        self.testnet: bool = testnet

    def __repr__(self):
        tx_ins = ""
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + "\n"
        tx_outs = ""
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + "\n"
        return "tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}".format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def id(self):
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()

    def hash(self):
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize())[::-1]

    # 직렬화된 트렌젝션 전체 크기가 엄청 크다면, 다 받을 때까지 prase 메서드를 호출할 수 없다.
    # 따라서 전체(bytes)를 받는 것이 아닌 stream으로부터 데이터를 받아 파싱할 수 있다.
    @classmethod
    def parse(cls, stream: io.BytesIO, testnet=False) -> "Tx":
        # 트랜잭션 버전 (보통 1이지만 2인 경우도 있음) (리틀엔디안)
        version = little_endian_to_int(stream.read(4))
        num_inputs = read_varint(stream)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(stream))

        num_outputs = read_varint(stream)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(stream))

        locktime = little_endian_to_int(stream.read(4))
        return cls(version, inputs, outputs, locktime, False)

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value()
        for tx_outs in self.tx_outs:
            output_sum -= tx_outs.amount

        return input_sum - output_sum

    # 트랜잭션 검증
    # - 트랜잭션을 수신한 모든 노드는 트랜잭션이 네트워크 규칙에 부합되도록 만들어졌는지 확인한다. (이 과정을 검증)
    # 1. 트랜잭션의 입력이 가리키는 비트코인이 존재하고 사용 가능한가? (UTXO 인가? 이중 지불 방지)
    # 2. 입력 비트코인의 합은 출력 비트코인의 합보다 크거나 같은가? (수수료가 0보다 크거나 같은가?)
    # 3. 입력의 해제 스클비트는 참조하는 트랜잭션 출력의 잠금 스크립트를 해제하는가? (스크립트 유효 확인 = 서명 검증)

    # 1. 입력 비트코인 존재?
    # - 이중 지불 방지
    # - 트랜잭션 자체로부터 이중 지불 여부를 확인할 수 없다.
    # - 확인할 수 있는 유일한 방법은 전체 트랜잭션 집합으로부터 계산된 UTXO 집합을 검사하는 방법
    # - 비트코인에서 입력이 가리키는 UTXO가 UTXO 집합에 존재한다면 유효한 것. (비트코인은 존재하고 이중지불되지 않은 것)
    # - 트랜잭션이 검증되면 입력이 가리키는 모든 UTXO를 집합에서 제거한다. (당연. 이중 지불 방지)
    # - 전체 블록체인을 가지고 있지 않은 라이트 노드는 이중 지불 여부 확인을 포함해서 많은 정보를 다른 풀 노드에 의존해야 한다.

    # 2. 수수료가 0보다 크거나 같아야 한다.
    # - 트랜잭션이 새 코인을 만들지 않도록 하는 것 (한 가지 예외는 코인베이스 트랜잭션)
    # - 입력에는 명시적인 비트코인 금액 정보가 없으므로 이를 UTXO 집합에서 찾아야 한다. (풀 노드한테 검색)

    # 3. 서명 검증 (스크립트 검증)
    # - 스크립트(스택)안에 포함된 서명과 공개키. (쉽게 알아낸다.)
    # - 서명해시(z)를 구해야 한다. (입력이 여러 개라면 각각의 입력에 대해 아래 방법으로 서명해시를 구해야 한다.)
    #   - a. 모든 해제 스크립트를 비운다.
    #   - b. 삭제된 해제 스크립트 자리에 사용할 UTXO의 잠금 스크립트 삽입
    #   - c. 해시 유형을 덧붙인다.
    #   -> 최종 변경된 트랜잭션의 hash256 해시값을 구하고 다시 32바이트 빅엔디언 정수로 변환하면 서명해시 z이다.
    def sig_hash(self, input_index):
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=tx_in.script_pubkey(self.testnet),  # 잠금스크립트 삽입
                    sequence=tx_in.sequence,
                ).serialize()
            else:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    sequence=tx_in.sequence,
                ).serialize()
        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)  # 유형을 덧붙인다.
        h256 = hash256(s)
        return int.from_bytes(h256, "big")

    # 입력 검증
    def verify_input(self, input_index):
        tx_in: TxIn = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=self.testnet)
        z = self.sig_hash(input_index)
        combined: Script = tx_in.script_sig + script_pubkey
        return combined.evaluate(z)

    # 모든 입력 검증
    def verify(self):
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    # 트랜잭션 생성
    # 1. 비트코인을 어느 주소로 보내고자 하는가?
    # 2. 어느 UTXO를 사용할 수 있는가?
    # 3. 얼마나 빨리 트랜잭션이 블록체인에 기록(포함)되어 처리되기를 원하는가?

    # 해제 트랜잭션 생성
    def sign_input(self, input_index, private_key: PrivateKey, compressed=True):
        z = self.sig_hash(input_index)
        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
        sec = private_key.point.sec(compressed)
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        return self.verify_input(input_index)


# 입력: 이전 트랜잭션의 출력을 가리킨다.
# - 입력에서 본인이 소유한 비트코인을 정확히 가리키기 위한 2가지 사항
#   - 이전에 내가 수신한 비트코인을 가리키는 참조 정보 + 그 비트코인이 나의 소유라는 증명
#   - 대부분의 입력은 소유자 개인키로 만든 전자서명을 포함한다.
# - 입력은 여러 개가 있을 수 있다: varint 형식으로 표현된 필드 길이 정보로 시작

# 입력 개수: varints 형식(가변 정수)
# - 가변 정수? (0 ~ 2^64 - 1) 사이 정수값을 가변 바이트로 표현한다.
# - 접두사에 정수(범위를 나타내는) 클래스 기록

# 각 입력은 4개의 하부필드
# - 이전 트랜잭션의 해시값(32): (hash256 해시값은 거의 유일하기 때문에 충돌이 거의 없어 이전 트랜잭션 식별 가능(ID))
# - 이전 트랜잭션의 출력번호(Previous Tx index)(4): 각 트랜잭션은 적어도 하나 이상의 출력을 가지기 때문에 필요한 출력 인덱스
# - 해제 스크립트(ScriptSig)(varint): 잠긴 상자의 자물쇠를 해제하는 열쇠. 즉 트랜잭션 출력의 소유자만이 할 수 있는 무언가. (비트코인을 사용할 수 있는 열쇠)
# - 시퀀스(4): 매우 빈번한 거래를 록타임 필드와 함께 표현하기 위해 사용. 현재는 RBF? OP_CHEC.. 로 사용


# 입력에서 가리키는 비트코인을 소비하는 양에 대한 정보 필요. (이전 트랜잭션 조사)
# 비트코인을 사용하기 위해 제대로된 해제 스크립트 필요
# 모든 노드들은 트랜잭션에서 소비하고자 하는 비트코인이 블록체인 상에 존재하는지(1)
# 제대로 비트코인을 사용할 수 있는 열쇠(해제 스크립트)가 있는지(2) 등을 검증해야 한다.


class TxIn:
    def __init__(
        self, prev_tx, prev_index, script_sig=None, sequence=0xFFFFFFFF
    ) -> None:
        self.prev_tx: bytes = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return "{}:{}".format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    # 죄다 리틀엔디안
    @classmethod
    def parse(cls, s: io.BytesIO) -> "TxIn":
        # [::-1] 데이터 순서 뒤집기(리틀엔디안 <-> 빅엔디안)
        prev_tx = s.read(32)[::-1]
        prev_index: int = little_endian_to_int(s.read(4))
        script_sig: Script = Script.parse(s)
        sequence: int = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self) -> bytes:
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    # 이전 트랜잭션을 가져오고, 해당 트랜잭션의 출력상의 금액, 잠금 스크립트를 가져온다.
    # str = bytes변수.hex()
    # bytes = bytes.fromhex(문자열)
    def fetch_tx(self, testnet=False) -> Tx:
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey


# 출력: 비트코인의 거래 후 종착지 정의
# - 각 트랜잭션은 하나 이상의 출력 (한 번의 트랜잭션으로 여러 사람에게 보낼 수 있다.)
# - 출력도 varint 형식으로 표현된 필드 길이 정보로 시작

# 각 출력은 2개의 하부필드
# - 비트코인 금액(8바이트 리틀엔디언 직렬화)
# - 잠금 스크립트:
#   - 해제 스크립트처럼 비트코인의 스마트 계약 언어인 Script로 쓰인다.
#   - 잠긴 금고 (금고 열쇠 소유자만 열 수 있는 금고)


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey: Script = script_pubkey

    def __repr__(self):
        return "{}:{}".format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s: io.BytesIO) -> "TxOut":
        amount = little_endian_to_int(s.read(8))
        script_pubkey: Script = Script.parse(s)
        return cls(amount, script_pubkey)

    def serialize(self) -> bytes:
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result


# UXTO: 미사용 트랜잭션 출력의 전체 집합
# - 현 시점에서 사용 가능한 모든 비트코인을 의미
# - 현재 유통 중인 모든 비트코인
# - 네트워크 상의 풀 노드는 UXTO 집합을 '항상 최신 상태'로 유지해야 한다.
# - 인덱싱된 UXTO 집합을 활용하면 새 트랜잭션의 검증을 쉽게 할 수 있다.
# - 예) 이중 지불을 막을 수 있다. (입력이 UXTO 집합에 없는 이전 트랜잭션의 출력을 가리키고 있따면? 탈락)
# - 트랜잭션 검증을 위해 이전 트랜잭션 출력으로부터 비트코인 금액(1)과 잠금 스크립트(2)를 매우 자주 확인해야 한다.

# 록타임
# - 블록체인 포함 지연
# - 빈번한 거래 상황을 위해 고안 (보안상의 문제)
# - 트랜잭션은 록타임이 의미하는 시점에 도달하기 전에는 블록체인에 포함될 수 없고, 따라서 비트코인을 소비할 수 없다.

# - 0xffffffff 이면 록타임 무시
# - 4바이트의 리틀 엔디언으로 직렬화

# 록타임의 문제
# - 록타임에 도달했을 때 트랜잭션의 수신자가 트랜잭션이 유효한지 확신할 수 없다.
# - 시간이 많이 지나 부도 가능성이 있는 은행 수표
# - 보내는 사람이 록타임 이전에 동일한 입력을 사용하는 트랜잭션을 만들고, 이것이 블록체인에 포함되면 '이미 소비된 UXTO'를 가진 '무효 트랜잭션'을 가지게 될 수 있는 것

# 트랜잭션 수수료: (트랜잭션 입력의 합) - (트랜잭션 출력의 합)
# 모든 트랜잭션의 입력 합은 출력의 합보다 같거나 커야 한다. (수수료는 0보다 크거나 같아야 한다.)
# 수수료: 채굴자가 트랜잭션을 블록에 포함시키도록 하는 인센티브
# - 블록에 포함되지 않는 트랜잭션은 블록체인의 부분이 아니고 확정되지 않은 상태이다. (유효하지 않음)
# - 이러한 수수료를 채굴자가 가져간다.

# 입력은 금액 필드를 갖고 있지 않기 때문에 금액은 입력이 가리키는 이전 트랜잭션의 출력에서 찾아야 한다.
# 이를 위해 블록체인을 참조해야 하고, 'UXTO 집합'을 찾아야 한다.
# 풀 노드를 가지고 있지 않다면 믿을 수 있는 제 3자가 제공하는 풀노드로부터 이 정보를 얻어야 한다.


class TxFetcher:
    cache: dict[str, Tx] = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return "http://testnet.programmingbitcoin.com"
        else:
            return "http://mainnet.programmingbitcoin.com"

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = f"{cls.get_url(testnet)}/tx/{tx_id}.hex"
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError(f"unexpected response: {response.text}")
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError("not the same id: {} vs {}".format(tx.id(), tx_id))

            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]


# 트랜잭션 생성 예제 (중요)
print("트랜잭션 생성")
prev_tx = bytes.fromhex(
    "75a1c4bc671f55f626dda1074c7725991e6f68b8fcefcfca7b64405ca3b45f1c"
)
prev_index = 1
target_address = "mzkLcgaxrGLs427tEgyTgQ9WPb4i3oNhpz"
target_amount = 0.01
change_address = "mzkLcgaxrGLs427tEgyTgQ9WPb4i3oNhpz"
change_amount = 0.009
secret = 8675309
priv = PrivateKey(secret=secret)  # my secret key
tx_ins = []
tx_ins.append(TxIn(prev_tx, prev_index))
tx_outs = []
h160 = decode_base58(target_address)
script_pubkey = p2pkh_script(h160)  # 잠금 스크립트 생성
target_satoshis = int(target_amount * 100000000)
tx_outs.append(TxOut(target_satoshis, script_pubkey))
h160 = decode_base58(change_address)
script_pubkey = p2pkh_script(h160)
change_satoshis = int(change_amount * 100000000)
tx_outs.append(TxOut(change_satoshis, script_pubkey))
tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
# tx id : 0a4098a83ce3fd6a83d5395ad80c7c2d2ba5ed9ffc4c77a7da7b04c795f20289
print("tx_obj ", tx_obj)
print(tx_obj.sign_input(0, priv))  # 해제 스크립트 생성
# 입력값에 대한 해제 스크립트를 삽입한 경우 tx id의 값이 달라짐
# tx id : deaafb19edbeb6e12c355ef06bc10c62be6dcebf6e82cdd84c152b0d28a212d8
print("tx_obj ", tx_obj)
print(tx_obj.serialize().hex())
