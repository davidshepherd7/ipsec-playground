import socket
from dataclasses import dataclass
from typing import Tuple, Dict, List, Optional, Union, Any, NoReturn, Iterable, TypeVar
from enum import Enum
import traceback
import inspect
import itertools as it


def assert_unreachable(proof: NoReturn) -> NoReturn:
    """A type and runtime assertion that this code is never hit."""
    assert False, "Unhandled type: {}".format(type(proof).__name__)


class ExchangeType(Enum):
    IKE_SA_INIT = 34
    IKE_AUTH = 35
    CREATE_CHILD_SA = 36
    INFORMATIONAL = 37
    # 38 	IKE_SESSION_RESUME 	[RFC5723]
    # 39 	GSA_AUTH 	[draft-yeung-g-ikev2]
    # 40 	GSA_REGISTRATION 	[draft-yeung-g-ikev2]
    # 41 	GSA_REKEY 	[draft-yeung-g-ikev2]
    # 43 	IKE_INTERMEDIATE 	[draft-ietf-ipsecme-ikev2-intermediate]


class NextPayload(Enum):
    NO_NEXT_PAYLOAD = 0
    SECURITY_ASSOCIATION = 33
    KEY_EXCHANGE = 34
    IDENTIFICATION_INITIATOR = 35
    IDENTIFICATION_RESPONDER = 36
    CERTIFICATE = 37
    CERTIFICATE_REQUEST = 38
    AUTHENTICATION = 39
    NONCE = 40
    NOTIFY = 41
    DELETE = 42
    VENDOR_ID = 43
    TRAFFIC_SELECTOR_INITIATOR = 44
    TRAFFIC_SELECTOR_RESPONDER = 45
    ENCRYPTED_AND_AUTHENTICATED = 46
    CONFIGURATION = 47
    EXTENSIBLE_AUTHENTICATION = 48
    # 49 	Generic Secure Password Method 	GSPM 	[RFC6467]
    # 50 	Group Identification 	IDg 	[draft-yeung-g-ikev2]
    # 51 	Group Security Association 	GSA 	[draft-yeung-g-ikev2]
    # 52 	Key Download 	KD 	[draft-yeung-g-ikev2]
    # 53 	Encrypted and Authenticated Fragment 	SKF 	[RFC7383]
    # 54 	Puzzle Solution 	PS


class TransformType(Enum):
    ENCRYPTION_ALGORITHM = 1
    PSEUDORANDOM_FUNCTION = 2
    INTEGRITY_ALGORITHM = 3
    DIFFIE_HELLMAN_GROUP = 4
    EXTENDED_SEQUENCE_NUMBERS = 5

    # TODO(david): Would be nice to not crash on new types?


class EncryptionTransformId(Enum):
    ENCR_DES_IV64 = 1
    ENCR_DES = 2
    ENCR_3DES = 3
    ENCR_RC5 = 4
    ENCR_IDEA = 5
    ENCR_CAST = 6
    ENCR_BLOWFISH = 7
    ENCR_3IDEA = 8
    ENCR_DES_IV32 = 9
    ENCR_NULL = 11
    ENCR_AES_CBC = 12
    ENCR_AES_CTR = 13
    ENCR_AES_CCM_8 = 14
    ENCR_AES_CCM_12 = 15
    ENCR_AES_CCM_16 = 16
    ENCR_AES_GCM_8 = 18
    ENCR_AES_GCM_12 = 19
    ENCR_AES_GCM_16 = 20
    ENCR_NULL_AUTH_AES_GMAC = 21
    ENCR_CAMELLIA_CBC = 23
    ENCR_CAMELLIA_CTR = 24
    ENCR_CAMELLIA_CCM_8 = 25
    ENCR_CAMELLIA_CCM_12 = 26
    ENCR_CAMELLIA_CCM_16 = 27
    ENCR_CHACHA20_POLY1305 = 28
    ENCR_AES_CCM_8_IIV = 29
    ENCR_AES_GCM_16_IIV = 30
    ENCR_CHACHA20_POLY1305_IIV = 31
    ENCR_KUZNYECHIK_MGM_KTREE = 32
    ENCR_MAGMA_MGM_KTREE = 33
    ENCR_KUZNYECHIK_MGM_MAC_KTREE = 34
    ENCR_MAGMA_MGM_MAC_KTREE = 35


class PrfTransformId(Enum):
    PRF_HMAC_MD5 = 1
    PRF_HMAC_SHA1 = 2
    PRF_HMAC_TIGER = 3
    PRF_AES128_XCBC = 4
    PRF_HMAC_SHA2_256 = 5
    PRF_HMAC_SHA2_384 = 6
    PRF_HMAC_SHA2_512 = 7
    PRF_AES128_CMAC = 8
    PRF_HMAC_STRIBOG_512 = 9


class IntegrityTransformId(Enum):
    NONE = 0
    AUTH_HMAC_MD5_96 = 1
    AUTH_HMAC_SHA1_96 = 2
    AUTH_DES_MAC = 3
    AUTH_KPDK_MD5 = 4
    AUTH_AES_XCBC_96 = 5
    AUTH_HMAC_MD5_128 = 6
    AUTH_HMAC_SHA1_160 = 7
    AUTH_AES_CMAC_96 = 8
    AUTH_AES_128_GMAC = 9
    AUTH_AES_192_GMAC = 10
    AUTH_AES_256_GMAC = 11
    AUTH_HMAC_SHA2_256_128 = 12
    AUTH_HMAC_SHA2_384_192 = 13
    AUTH_HMAC_SHA2_512_256 = 14


class DhTransformId(Enum):
    NONE = 0
    MODP_GROUP_768_BIT = 1
    MODP_GROUP_1024_BIT = 2
    MODP_GROUP_1536_BIT = 5
    MODP_GROUP_2048_BIT = 14
    MODP_GROUP_3072_BIT = 15
    MODP_GROUP_4096_BIT = 16
    MODP_GROUP_6144_BIT = 17
    MODP_GROUP_8192_BIT = 18
    RANDOM_ECP_GROUP_256_BIT = 19
    RANDOM_ECP_GROUP_384_BIT = 20
    RANDOM_ECP_GROUP_521_BIT = 21
    MODP_GROUP_1024_BIT_WITH_160_BIT_PRIME_ORDER_SUBGROUP = 22
    MODP_GROUP_2048_BIT_WITH_224_BIT_PRIME_ORDER_SUBGROUP = 23
    MODP_GROUP_2048_BIT_WITH_256_BIT_PRIME_ORDER_SUBGROUP = 24
    RANDOM_ECP_GROUP_192_BIT = 25
    RANDOM_ECP_GROUP_224_BIT = 26
    BRAINPOOLP224R1 = 27
    BRAINPOOLP256R1 = 28
    BRAINPOOLP384R1 = 29
    BRAINPOOLP512R1 = 30
    CURVE25519 = 31
    CURVE448 = 32
    GOST3410_2012_256 = 33
    GOST3410_2012_512 = 34


class EsnTransformId(Enum):
    NO_EXTENDED_SEQUENCE_NUMBERS = 0
    EXTENDED_SEQUENCE_NUMBERS = 1


@dataclass(frozen=True)
class IkeHeader:
    initiator_spi: int
    responder_spi: int
    next_payload: NextPayload
    major_version: int
    minor_version: int
    exchange_type: ExchangeType
    flags: int  # TODO(david)
    message_id: int
    length: int

    @staticmethod
    def parse(data: bytes) -> "IkeHeader":
        assert len(data) == 28
        return IkeHeader(
            initiator_spi=int.from_bytes(data[0:8], "big"),
            responder_spi=int.from_bytes(data[8:16], "big"),
            next_payload=NextPayload(int.from_bytes(data[16:17], "big")),
            major_version=data[17] >> 4,
            minor_version=data[17] & 0b00001111,
            exchange_type=ExchangeType(int.from_bytes(data[18:19], "big")),
            flags=int.from_bytes(data[19:20], "big"),
            message_id=int.from_bytes(data[20:24], "big"),
            length=int.from_bytes(data[24:28], "big"),
        )


class AttributeType(Enum):
    KEY_LENGTH = 14


@dataclass(frozen=True)
class EncryptionTransform:
    tranform_id: EncryptionTransformId
    attributes: Dict[AttributeType, int]


@dataclass(frozen=True)
class PrfTransform:
    tranform_id: PrfTransformId
    attributes: Dict[AttributeType, int]


@dataclass(frozen=True)
class IntegrityTransform:
    tranform_id: IntegrityTransformId
    attributes: Dict[AttributeType, int]


@dataclass(frozen=True)
class DhTransform:
    tranform_id: DhTransformId
    attributes: Dict[AttributeType, int]


@dataclass(frozen=True)
class EsnTransform:
    tranform_id: EsnTransformId
    attributes: Dict[AttributeType, int]


Transform = Union[
    EncryptionTransform,
    IntegrityTransform,
    PrfTransform,
    DhTransform,
    EsnTransform,
]


@dataclass(frozen=True)
class ESPProposal:
    encryption: List[EncryptionTransform]
    integrity: List[IntegrityTransform]
    dh: List[DhTransform]
    esn: List[EsnTransform]


@dataclass(frozen=True)
class IKEProposal:
    encryption: List[EncryptionTransform]
    prf: List[PrfTransform]
    integrity: List[IntegrityTransform]
    dh: List[DhTransform]


SAProposal = Union[ESPProposal, IKEProposal]

T = TypeVar("T")


def chunk(xs: List[T], size: int) -> List[List[T]]:
    return [xs[i : i + size] for i in range(0, len(xs), size)]


DEBUG = True


def dump_bytes(data: bytes) -> None:
    if DEBUG:
        print(
            "From",
            inspect.stack()[1][3],
            " ".join("".join(x) for x in chunk(list(data.hex()), 2)),
        )


def dump_parsed(x: Any) -> None:
    if DEBUG:
        print("From", inspect.stack()[1][3], x)


def parse_attributes(attr_data: bytes) -> Dict[AttributeType, int]:
    dump_bytes(attr_data)
    attributes: Dict[AttributeType, int] = {}
    while len(attr_data) != 0:
        attribute_short_format = attr_data[0] & 0b10000000
        attribute_type = AttributeType(
            int.from_bytes([attr_data[0] & 0b01111111, attr_data[1]], "big")
        )
        if not attribute_short_format:
            assert False, "Untested"
            length = int.from_bytes(attr_data[2:4], "big")
            assert length >= 4
            attributes[attribute_type] = int.from_bytes(attr_data[4:length], "big")
            attr_data = attr_data[length:]
        else:
            attributes[attribute_type] = int.from_bytes(attr_data[2:4], "big")
            attr_data = attr_data[4:]

    dump_parsed(attributes)
    return attributes


def parse_transform(data: bytes) -> Tuple[bytes, Transform]:
    dump_bytes(data)
    assert int.from_bytes(data[0:1], "big") in (0, 3)
    assert int.from_bytes(data[1:2], "big") == 0
    length = int.from_bytes(data[2:4], "big")
    assert length >= 8
    transform_type = TransformType(int.from_bytes(data[4:5], "big"))
    assert int.from_bytes(data[5:6], "big") == 0
    transform_id = int.from_bytes(data[6:8], "big")
    attributes = parse_attributes(data[8:length])

    transform: Transform
    if transform_type is TransformType.ENCRYPTION_ALGORITHM:
        transform = EncryptionTransform(EncryptionTransformId(transform_id), attributes)
    elif transform_type is TransformType.INTEGRITY_ALGORITHM:
        transform = IntegrityTransform(IntegrityTransformId(transform_id), attributes)
    elif transform_type is TransformType.PSEUDORANDOM_FUNCTION:
        transform = PrfTransform(PrfTransformId(transform_id), attributes)
    elif transform_type is TransformType.DIFFIE_HELLMAN_GROUP:
        transform = DhTransform(DhTransformId(transform_id), attributes)
    elif transform_type is TransformType.EXTENDED_SEQUENCE_NUMBERS:
        transform = EsnTransform(EsnTransformId(transform_id), attributes)
    else:
        assert_unreachable(transform_type)

    dump_parsed(transform)
    return data[length:], transform


def parse_sa_proposal(data: bytes) -> Tuple[bytes, SAProposal]:
    dump_bytes(data)
    assert int.from_bytes(data[0:1], "big") in (0, 2)
    assert int.from_bytes(data[1:2], "big") == 0
    length = int.from_bytes(data[2:4], "big")
    assert length >= 9
    proposal_num = int.from_bytes(data[4:5], "big")
    protocol_id = int.from_bytes(data[5:6], "big")
    spi_size = int.from_bytes(data[6:7], "big")
    num_transforms = int.from_bytes(data[7:8], "big")
    spi = int.from_bytes(data[8 : 8 + spi_size], "big")

    data = data[8 + spi_size :]
    transforms: List[Transform] = []
    for i in range(num_transforms):
        data, transform = parse_transform(data)
        transforms.append(transform)

    encryptions = [t for t in transforms if isinstance(t, EncryptionTransform)]
    prfs = [t for t in transforms if isinstance(t, PrfTransform)]
    integrities = [t for t in transforms if isinstance(t, IntegrityTransform)]
    dhs = [t for t in transforms if isinstance(t, DhTransform)]
    esns = [t for t in transforms if isinstance(t, EsnTransform)]
    # TODO(david): Filter out NONE transforms + ignore?

    # TODO(david): Validate that the ones that are mandatory aren't empty lists?

    proposal: SAProposal
    if protocol_id == 1:
        assert len(esns) == 0
        proposal = IKEProposal(encryptions, prfs, integrities, dhs)
    elif protocol_id == 2:
        assert False
    elif protocol_id == 3:
        assert len(prfs) == 0
        proposal = ESPProposal(encryptions, integrities, dhs, esns)
    else:
        assert False

    return data, proposal


@dataclass(frozen=True)
class SecurityAssociationPayload:
    proposals: List[SAProposal]

    @staticmethod
    def parse(data: bytes) -> "SecurityAssociationPayload":
        proposals: List[SAProposal] = []
        while not len(data) == 0:
            data, proposal = parse_sa_proposal(data)
            proposals.append(proposal)

        return SecurityAssociationPayload(proposals=proposals)


IkePayload = Union[SecurityAssociationPayload]


def parse_ike_payload_header(data: bytes) -> Tuple[NextPayload, bool, int]:
    return (
        NextPayload(int.from_bytes(data[0:1], "big")),
        bool(data[1] & 0b10000000),
        int.from_bytes(data[2:4], "big"),
    )


def parse_packet(data: bytes) -> Tuple[IkeHeader, List[IkePayload]]:
    header = IkeHeader.parse(data[0:28])
    print("Saw header", header)
    assert header.initiator_spi != 0
    assert header.responder_spi == 0
    assert header.major_version == 2
    assert header.length == len(data)

    data = data[28:]
    payload_type = header.next_payload

    payloads: List[IkePayload] = []
    while True:
        next_payload_type, critical, length = parse_ike_payload_header(data[:4])
        print(next_payload_type, critical, length)

        assert length >= 4
        assert len(data) >= length
        raw_payload = data[4:length]
        if payload_type == NextPayload.SECURITY_ASSOCIATION:
            parsed_payload = SecurityAssociationPayload.parse(raw_payload)
            print(parsed_payload)
            payloads.append(parsed_payload)
        else:
            print(payload_type, raw_payload.hex())

        if next_payload_type == NextPayload.NO_NEXT_PAYLOAD:
            assert len(data) == length
            break
        else:
            payload_type = next_payload_type
            data = data[length:]

    return header, payloads


def main() -> None:
    print("hello world")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 500))
    # Note: if we switch to 4500 might get 4 null octets added to packets?

    while True:
        try:
            # TODO(david): Need to support reading incrementally from socket +
            # parsing as we go.
            data, addr = sock.recvfrom(8024)
            print("received message: %s" % data.hex())
            header, payloads = parse_packet(data)

        except Exception as e:
            print("Failed with exception", traceback.format_exc())
