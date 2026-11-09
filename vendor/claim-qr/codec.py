"""Bounded v1 claim-QR codec. Parsing supplies no ownership or device authority.

No randomness, storage, networking, CLI or logging. Callers must protect the
returned private material; Python immutable strings/bytes cannot be reliably wiped.
"""
import base64
from dataclasses import dataclass, field
import re
import uuid

PREFIX = 'OCTATRACE-CLAIM-1:'
TEXT_BYTES = 145
CBOR_BYTES = 95
ENVIRONMENTS = {'development': 1, 'production': 2}
ROLES = {'Link': 1, 'Core': 2}
FIELDS = ('v', 'environment', 'role', 'device_uuid', 'public_key_sha256', 'claim_secret')
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
HEX32 = r'[0-9a-f]{64}'
ERROR = 'Invalid claim QR'


@dataclass(frozen=True)
class UntrustedClaim:
    v: int
    environment: str
    role: str
    device_uuid: str
    public_key_sha256: str
    claim_secret: str = field(repr=False)

    def to_fields(self):
        """Explicit private-data export; never pass this dictionary to a logger."""
        return {name: getattr(self, name) for name in FIELDS}


def validate_fields(value):
    """Validate the exact readable JSON representation without echoing input."""
    if type(value) is not dict or set(value) != set(FIELDS):
        raise ValueError(ERROR)
    if type(value['v']) not in (int, float) or value['v'] != 1:
        raise ValueError(ERROR)
    if any(type(value[name]) is not str for name in FIELDS[1:]):
        raise ValueError(ERROR)
    if value['environment'] not in ENVIRONMENTS or value['role'] not in ROLES:
        raise ValueError(ERROR)
    if re.fullmatch(UUID, value['device_uuid']) is None:
        raise ValueError(ERROR)
    for name in ('public_key_sha256', 'claim_secret'):
        if re.fullmatch(HEX32, value[name]) is None or value[name] == '0' * 64:
            raise ValueError(ERROR)
    return UntrustedClaim(**dict(value, v=1))


def encode(value):
    """Encode supplied fields only. C5 must supply independently generated secrets."""
    claim = validate_fields(value)
    raw = (b'\xa6\x01\x01\x02' + bytes([ENVIRONMENTS[claim.environment], 3, ROLES[claim.role]]) +
           b'\x04\x50' + uuid.UUID(claim.device_uuid).bytes +
           b'\x05\x58\x20' + bytes.fromhex(claim.public_key_sha256) +
           b'\x06\x58\x20' + bytes.fromhex(claim.claim_secret))
    return PREFIX + base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


def decode(text, expected_environment):
    """Fail before decoding oversized text; require caller-selected environment."""
    if type(text) is not str or len(text) != TEXT_BYTES:
        raise ValueError(ERROR)
    if expected_environment not in ('development', 'production'):
        raise ValueError(ERROR)
    if not text.startswith(PREFIX):
        raise ValueError(ERROR)
    body = text[len(PREFIX):]
    if re.fullmatch(r'[A-Za-z0-9_-]{127}', body) is None:
        raise ValueError(ERROR)
    raw = base64.urlsafe_b64decode(body + '=')
    if base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=') != body:
        raise ValueError(ERROR)
    # Exact deterministic CBOR skeleton: no general recursion or length-driven allocation.
    if (raw[:4] + raw[5:6] + raw[7:9] + raw[25:28] + raw[60:63] !=
            b'\xa6\x01\x01\x02\x03\x04\x50\x05\x58\x20\x06\x58\x20'):
        raise ValueError(ERROR)
    claim = validate_fields({
        'v': 1, 'environment': {1: 'development', 2: 'production'}.get(raw[4], ''),
        'role': {1: 'Link', 2: 'Core'}.get(raw[6], ''),
        'device_uuid': str(uuid.UUID(bytes=raw[9:25])),
        'public_key_sha256': raw[28:60].hex(), 'claim_secret': raw[63:95].hex()})
    if claim.environment != expected_environment:
        raise ValueError(ERROR)
    return claim
