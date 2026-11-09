"""Factory identity credential only. No ownership, peer authentication or device IO.

Crypto callbacks are trusted adapters: valid_public_key(point65) and
verify(point65, signing_bytes, raw_signature64), both returning strict bool.
No private signing key is accepted by this module.
"""
from dataclasses import dataclass, field
import hashlib
import re
from types import MappingProxyType
import uuid

ERROR = 'Invalid device credential'
AAD = b'OCTATRACE-DEVICE-CREDENTIAL-1'
MAX_OBJECT = 271
MAX_SIGNING = 512
MAX_REVISION = 4294967295
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
LAYOUT = (
    ('v', 1, 'version'), ('purpose', 2, 'purpose'), ('environment', 3, 'environment'),
    ('credential_uuid', 4, 'uuid'), ('credential_revision', 5, 'revision'),
    ('device_uuid', 6, 'uuid'), ('role', 7, 'role'), ('key_revision', 8, 'revision'),
    ('public_key', 9, 'point'), ('serial', 10, 'serial'), ('article_uuid', 11, 'uuid'),
    ('article_revision_uuid', 12, 'uuid'), ('hardware_uid', 13, 'hardware'))


def fail():
    raise ValueError(ERROR)


def cbor(value, depth=0):
    if depth > 4:
        fail()
    def head(major, number):
        if not 0 <= number <= 0xffffffffffffffff:
            fail()
        first = major << 5
        if number < 24:
            return bytes([first | number])
        size = next(n for n in (1, 2, 4, 8) if number < 1 << (n * 8))
        return bytes([first | {1: 24, 2: 25, 4: 26, 8: 27}[size]]) + number.to_bytes(size, 'big')
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if type(value) in (bytes, str):
        data = value if type(value) is bytes else value.encode('utf8')
        if len(data) > MAX_SIGNING:
            fail()
        return head(2 if type(value) is bytes else 3, len(data)) + data
    if type(value) in (list, tuple):
        if len(value) > 32:
            fail()
        return head(4, len(value)) + b''.join(cbor(v, depth + 1) for v in value)
    if type(value) is dict:
        if len(value) > 32 or any(type(k) is not int for k in value):
            fail()
        pairs = sorted((cbor(k, depth + 1), cbor(v, depth + 1)) for k, v in value.items())
        return head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
    fail()


def uncbor(data):
    if type(data) is not bytes or not 0 < len(data) <= MAX_SIGNING:
        fail()
    cursor = 0
    def take(size):
        nonlocal cursor
        if size > len(data) - cursor:
            fail()
        result = data[cursor:cursor + size]
        cursor += size
        return result
    def read(depth):
        if depth > 4:
            fail()
        first = take(1)[0]
        major, additional = first >> 5, first & 31
        if additional < 24:
            size = additional
        elif additional in (24, 25, 26, 27):
            size = int.from_bytes(take({24: 1, 25: 2, 26: 4, 27: 8}[additional]), 'big')
        else:
            fail()
        if major in (0, 1):
            return size if major == 0 else -1 - size
        if major in (2, 3):
            value = take(size)
            if major == 2:
                return value
            try:
                return value.decode('utf8')
            except UnicodeError:
                fail()
        if major not in (4, 5) or size > 32:
            fail()
        if major == 4:
            return [read(depth + 1) for _ in range(size)]
        result = {}
        for _ in range(size):
            key = read(depth + 1)
            if type(key) is not int or key in result:
                fail()
            result[key] = read(depth + 1)
        return result
    value = read(0)
    if cursor != len(data) or cbor(value) != data:
        fail()
    return value


def uint(value, minimum=1, maximum=MAX_REVISION):
    if type(value) not in (int, float) or not minimum <= value <= maximum or value != int(value):
        fail()
    return int(value)


def hex_bytes(value, size, prefix=''):
    if (type(value) is not str or re.fullmatch('[0-9a-f]{' + str(size * 2) + '}', value) is None or
            not value.startswith(prefix) or value == '0' * (size * 2)):
        fail()
    return bytes.fromhex(value)


def to_wire(value, kind):
    if kind in ('version', 'revision'):
        number = uint(value)
        if kind == 'version' and number != 1:
            fail()
        return number
    if type(value) is not str:
        fail()
    if kind in ('purpose', 'environment', 'role'):
        choices = {'purpose': {'device_identity': 1}, 'environment': {'development': 1, 'production': 2},
                   'role': {'Link': 1, 'Core': 2}}[kind]
        if value not in choices:
            fail()
        return choices[value]
    if kind == 'uuid':
        if re.fullmatch(UUID, value) is None:
            fail()
        return uuid.UUID(value).bytes
    if kind == 'serial':
        if re.fullmatch('[DRO][0-9]{12}', value) is None or value[1:] == '0' * 12:
            fail()
        return value
    return hex_bytes(value, 65, '04') if kind == 'point' else hex_bytes(value, 8)


def fields(value):
    if type(value) is not dict or set(value) != {row[0] for row in LAYOUT} | {'issuer_kid'}:
        fail()
    payload = {label: to_wire(value[name], kind) for name, label, kind in LAYOUT}
    kid = hex_bytes(value['issuer_kid'], 8)
    return payload, kid


def signing_bytes(value, maximum_bytes=MAX_SIGNING):
    payload, kid = fields(value)
    message = cbor(['Signature1', cbor({1: -7, 4: kid}), AAD, cbor(payload)])
    if len(message) > uint(maximum_bytes, 1, MAX_SIGNING):
        fail()
    return message


def assemble(value, signature, maximum_bytes=MAX_OBJECT):
    payload, kid = fields(value)
    if type(signature) is not bytes or len(signature) != 64:
        fail()
    result = b'\xd2' + cbor([cbor({1: -7, 4: kid}), {}, cbor(payload), signature])
    if len(result) > uint(maximum_bytes, 1, MAX_OBJECT):
        fail()
    return result


@dataclass(frozen=True)
class VerifiedDeviceCredential:
    metadata: object = field(repr=False)
    content_id: bytes

    def to_fields(self):
        return dict(self.metadata)


def verify(data, environment, issuers, crypto, expected):
    if type(data) is not bytes or not 0 < len(data) <= MAX_OBJECT or data[:1] != b'\xd2':
        fail()
    if environment not in ('development', 'production'):
        fail()
    if type(expected) is not dict or set(expected) != {'device_uuid', 'role', 'public_key_sha256'}:
        fail()
    to_wire(expected['device_uuid'], 'uuid')
    to_wire(expected['role'], 'role')
    hex_bytes(expected['public_key_sha256'], 32)
    envelope = uncbor(data[1:])
    if (type(envelope) is not list or len(envelope) != 4 or
            type(envelope[0]) is not bytes or envelope[1] != {} or
            type(envelope[2]) is not bytes or type(envelope[3]) is not bytes or len(envelope[3]) != 64):
        fail()
    protected = uncbor(envelope[0])
    if (type(protected) is not dict or set(protected) != {1, 4} or protected[1] != -7 or
            type(protected[4]) is not bytes or len(protected[4]) != 8):
        fail()
    payload = uncbor(envelope[2])
    if type(payload) is not dict or set(payload) != {row[1] for row in LAYOUT}:
        fail()
    decoded = {'issuer_kid': protected[4].hex()}
    for name, label, kind in LAYOUT:
        value = payload[label]
        if kind == 'uuid':
            if type(value) is not bytes or len(value) != 16:
                fail()
            value = str(uuid.UUID(bytes=value))
        elif kind in ('point', 'hardware'):
            if type(value) is not bytes:
                fail()
            value = value.hex()
        elif kind in ('purpose', 'environment', 'role'):
            inverse = {'purpose': {1: 'device_identity'}, 'environment': {1: 'development', 2: 'production'},
                       'role': {1: 'Link', 2: 'Core'}}[kind]
            if type(value) is not int or value not in inverse:
                fail()
            value = inverse[value]
        decoded[name] = value
    fields(decoded)
    public_key = bytes.fromhex(decoded['public_key'])
    if (decoded['environment'] != environment or decoded['device_uuid'] != expected['device_uuid'] or
            decoded['role'] != expected['role'] or hashlib.sha256(public_key).hexdigest() != expected['public_key_sha256']):
        fail()
    if type(issuers) not in (list, tuple) or not 0 < len(issuers) <= 8:
        fail()
    seen, key = set(), None
    for issuer in issuers:
        if (type(issuer) is not dict or set(issuer) != {'environment', 'purpose', 'kid', 'public_key'} or
                issuer['environment'] not in ('development', 'production') or
                issuer['purpose'] not in ('factory_identity', 'ownership_control')):
            fail()
        identity = (issuer['environment'], hex_bytes(issuer['kid'], 8))
        point = hex_bytes(issuer['public_key'], 65, '04')
        if identity in seen:
            fail()
        seen.add(identity)
        if identity == (environment, protected[4]) and issuer['purpose'] == 'factory_identity':
            key = point
    if key is None:
        fail()
    message = signing_bytes(decoded)
    try:
        valid = (crypto.valid_public_key(key) is True and
                 crypto.verify(key, message, envelope[3]) is True and
                 crypto.valid_public_key(public_key) is True)
    except Exception:
        raise ValueError(ERROR) from None
    if not valid:
        fail()
    return VerifiedDeviceCredential(MappingProxyType(decoded), hashlib.sha256(message).digest())


def compare_revision(credential, previous_revision, previous_content_id):
    if not isinstance(credential, VerifiedDeviceCredential):
        fail()
    previous = uint(previous_revision, 0)
    if previous == 0:
        if previous_content_id is not None:
            fail()
    elif type(previous_content_id) is not bytes or len(previous_content_id) != 32:
        fail()
    revision = credential.metadata['credential_revision']
    if revision < previous:
        fail()
    if revision == previous:
        if credential.content_id != previous_content_id:
            fail()
        return 'retry'
    return 'newer'
