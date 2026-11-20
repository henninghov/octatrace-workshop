"""Firmware-owned candidate setup-record carrier. Decoding grants no authority.

Signature/context verification, durable installation, custody, authenticated
channel admission and the original measured deadline belong to the caller.
"""
from dataclasses import dataclass
import hashlib
import re
import uuid

ERROR = 'Invalid setup transfer'
HEADER_BYTES = 68
BODY_MAX = 426
RECORD_MAX = HEADER_BYTES + BODY_MAX
FRAME_BYTES = 20
FRAME_HEADER = 8
STRIDE = FRAME_BYTES - FRAME_HEADER
KINDS = {'factory_credential': (1, 271), 'ownership_receipt': (2, 270),
         'phone_controller': (3, 270), 'core_link': (4, 270),
         'setup_challenge': (5, 426), 'setup_proof': (6, 151),
         'installation_report': (7, 384), 'phone_custody': (8, 32)}
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')


def deny():
    raise ValueError(ERROR)


def number(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        deny()
    return value


def uuid_bytes(value):
    if type(value) is not str or not UUID.fullmatch(value):
        deny()
    return uuid.UUID(value).bytes


@dataclass(frozen=True)
class UntrustedRecord:
    kind: str
    device_uuid: str
    correlation_uuid: str
    body: bytes


def encode(kind, device_uuid, correlation_uuid, body):
    if type(kind) is not str or kind not in KINDS:
        deny()
    code, maximum = KINDS[kind]
    if type(body) is not bytes or not 0 < len(body) <= maximum:
        deny()
    if kind == 'phone_custody' and (len(body) != 32 or not any(body)):
        deny()
    return (bytes([1, code]) + uuid_bytes(device_uuid) + uuid_bytes(correlation_uuid)
            + len(body).to_bytes(2, 'little') + hashlib.sha256(body).digest() + body)


def decode(data):
    if type(data) is not bytes or not HEADER_BYTES < len(data) <= RECORD_MAX or data[0] != 1:
        deny()
    names = {code: name for name, (code, _) in KINDS.items()}
    if data[1] not in names or int.from_bytes(data[34:36], 'little') != len(data) - HEADER_BYTES:
        deny()
    record = UntrustedRecord(names[data[1]], str(uuid.UUID(bytes=data[2:18])),
                             str(uuid.UUID(bytes=data[18:34])), data[HEADER_BYTES:])
    if encode(record.kind, record.device_uuid, record.correlation_uuid, record.body) != data:
        deny()
    return record


@dataclass(frozen=True)
class Fragment:
    transfer: int
    total: int
    index: int
    payload: bytes


def frames(data, transfer):
    decode(data)
    number(transfer, 65535)
    return tuple(b'OS\x01' + transfer.to_bytes(2, 'little') + len(data).to_bytes(2, 'little')
                 + bytes([index // STRIDE]) + data[index:index + STRIDE].ljust(STRIDE, b'\0')
                 for index in range(0, len(data), STRIDE))


def parse_frame(data):
    if type(data) is not bytes or len(data) != FRAME_BYTES or data[:3] != b'OS\x01':
        deny()
    transfer = number(int.from_bytes(data[3:5], 'little'), 65535)
    total = int.from_bytes(data[5:7], 'little')
    index = data[7]
    if not HEADER_BYTES < total <= RECORD_MAX or index >= (total + STRIDE - 1) // STRIDE:
        deny()
    used = min(STRIDE, total - index * STRIDE)
    if any(data[FRAME_HEADER + used:]):
        deny()
    return Fragment(transfer, total, index, data[FRAME_HEADER:FRAME_HEADER + used])


class Reassembly:
    """One admitted transfer, fixed capacity, one delivery, explicit close/wipe.

    Caller supplies independent intended device/correlation and live connection
    generation. It must close on deadline/cancel/disconnect; this is not a clock,
    retry scheduler, connection manager, ACK issuer or replay database.
    """
    def __init__(self, generation, transfer, device_uuid, correlation_uuid):
        self._generation = number(generation, 0xffffffffffffffff)
        self._transfer = number(transfer, 65535)
        uuid_bytes(device_uuid)
        uuid_bytes(correlation_uuid)
        self._device, self._correlation = device_uuid, correlation_uuid
        self._buffer = bytearray(RECORD_MAX)
        self._total = self._seen = 0
        self._closed = False

    def close(self):
        self._buffer[:] = bytes(RECORD_MAX)
        self._total = self._seen = 0
        self._closed = True

    def accept(self, generation, data):
        if self._closed or type(generation) is not int or generation != self._generation:
            deny()
        f = parse_frame(data)
        if f.transfer != self._transfer:
            deny()
        if self._total and f.total != self._total:
            self.close()
            deny()
        start = f.index * STRIDE
        if self._seen & (1 << f.index):
            if self._buffer[start:start + len(f.payload)] != f.payload:
                self.close()
                deny()
            return None
        self._total = f.total
        self._buffer[start:start + len(f.payload)] = f.payload
        self._seen |= 1 << f.index
        if self._seen != (1 << ((f.total + STRIDE - 1) // STRIDE)) - 1:
            return None
        try:
            record = decode(bytes(self._buffer[:self._total]))
            if record.device_uuid != self._device or record.correlation_uuid != self._correlation:
                deny()
        except ValueError:
            self.close()
            raise
        return record
