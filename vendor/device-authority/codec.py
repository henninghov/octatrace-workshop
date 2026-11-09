"""Signed ownership/control metadata. No claiming, command execution or device IO.

Uses the separately pinned factory-contract CBOR primitives. Crypto adapters
return strict bool for valid_public_key(point65) / verify(point65,message,sig64).
Verified metadata and stable context hashes are NOT fresh private-key proofs.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import runpy
from types import MappingProxyType
import uuid

BASE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'device-credential/codec.py'))
ERROR = 'Invalid device authority'
AAD = b'OCTATRACE-DEVICE-AUTHORITY-1'
CONTEXT = b'OCTATRACE-AUTHORITY-CONTEXT-1'
MAX_OBJECT = 270
MAX_SIGNING = 512
PURPOSES = {'ownership_receipt': 1, 'phone_controller': 2, 'core_link': 3}
CAPABILITIES = {'read_state': 1, 'start': 2, 'stop': 4, 'rejoin': 8}
COMMON = (('v', 'version'), ('purpose', 'purpose'), ('environment', 'environment'),
          ('object_uuid', 'uuid'), ('revision', 'revision'), ('resource_uuid', 'uuid'),
          ('resource_role', 'role'), ('resource_key_sha256', 'hash'), ('resource_key_revision', 'revision'),
          ('owner_ref', 'uuid'), ('ownership_epoch', 'revision'))
OWNER = (('claim_operation_uuid', 'uuid'),)
CONTROL = (('state', 'state'), ('capabilities', 'capabilities'))
PHONE = (('phone_installation_uuid', 'uuid'), ('phone_key_sha256', 'hash'))
PEER = (('link_uuid', 'uuid'), ('link_key_sha256', 'hash'), ('link_key_revision', 'revision'),
        ('link_ownership_epoch', 'revision'))
AUDIENCE = ('resource_uuid', 'resource_role', 'resource_key_sha256', 'resource_key_revision')


def fail():
    raise ValueError(ERROR)


def guarded(operation, *args):
    try:
        return operation(*args)
    except (ValueError, TypeError, OverflowError, UnicodeError):
        raise ValueError(ERROR) from None


def layout(value):
    if type(value) is not dict or value.get('purpose') not in tuple(PURPOSES):
        fail()
    if value['purpose'] == 'ownership_receipt':
        return COMMON + OWNER
    if value.get('state') not in ('grant', 'removed'):
        fail()
    return COMMON + CONTROL + (() if value['state'] == 'removed' else
                                PHONE if value['purpose'] == 'phone_controller' else PEER)


def to_wire(value, kind):
    if kind in ('purpose', 'state'):
        choices = PURPOSES if kind == 'purpose' else {'grant': 1, 'removed': 2}
        if type(value) is not str or value not in choices:
            fail()
        return choices[value]
    if kind == 'hash':
        return guarded(BASE['hex_bytes'], value, 32)
    if kind == 'capabilities':
        if (type(value) is not list or any(type(x) is not str or x not in CAPABILITIES for x in value) or
                value != [key for key in CAPABILITIES if key in value]):
            fail()
        return sum(CAPABILITIES[x] for x in value)
    return guarded(BASE['to_wire'], value, kind)


def fields(value):
    rows = layout(value)
    if set(value) != {name for name, _ in rows} | {'issuer_kid'}:
        fail()
    payload = {i + 1: to_wire(value[name], kind) for i, (name, kind) in enumerate(rows)}
    kid = guarded(BASE['hex_bytes'], value['issuer_kid'], 8)
    if value['purpose'] != 'ownership_receipt':
        if (value['resource_role'] != ('Link' if value['purpose'] == 'phone_controller' else 'Core') or
                (value['state'] == 'grant') != bool(value['capabilities'])):
            fail()
        if value['purpose'] == 'core_link' and value['state'] == 'grant' and value['link_uuid'] == value['resource_uuid']:
            fail()
    return payload, kid


def signing_bytes(value, maximum_bytes=MAX_SIGNING):
    payload, kid = fields(value)
    message = BASE['cbor'](['Signature1', BASE['cbor']({1: -7, 4: kid}), AAD, BASE['cbor'](payload)])
    if len(message) > guarded(BASE['uint'], maximum_bytes, 1, MAX_SIGNING):
        fail()
    return message


def assemble(value, signature, maximum_bytes=MAX_OBJECT):
    payload, kid = fields(value)
    if type(signature) is not bytes or len(signature) != 64:
        fail()
    result = b'\xd2' + BASE['cbor']([BASE['cbor']({1: -7, 4: kid}), {}, BASE['cbor'](payload), signature])
    if len(result) > guarded(BASE['uint'], maximum_bytes, 1, MAX_OBJECT):
        fail()
    return result


@dataclass(frozen=True)
class VerifiedAuthority:
    metadata: object = field(repr=False)
    content_id: bytes

    def to_fields(self):
        result = dict(self.metadata)
        if 'capabilities' in result:
            result['capabilities'] = list(result['capabilities'])
        return result


def from_wire(value, kind):
    if kind == 'uuid':
        if type(value) is not bytes or len(value) != 16:
            fail()
        return str(uuid.UUID(bytes=value))
    if kind == 'hash':
        if type(value) is not bytes:
            fail()
        return value.hex()
    maps = {'purpose': PURPOSES, 'state': {'grant': 1, 'removed': 2},
            'environment': {'development': 1, 'production': 2}, 'role': {'Link': 1, 'Core': 2}}
    if kind in maps:
        if type(value) is not int or value not in maps[kind].values():
            fail()
        return next(key for key, number in maps[kind].items() if number == value)
    if kind == 'capabilities':
        if type(value) is not int or not 0 <= value <= 15:
            fail()
        return [key for key, bit in CAPABILITIES.items() if value & bit]
    return value


def verify(data, environment, issuers, crypto, expected):
    if type(data) is not bytes or not 0 < len(data) <= MAX_OBJECT or data[:1] != b'\xd2':
        fail()
    if environment not in ('development', 'production') or type(expected) is not dict or set(expected) != set(AUDIENCE):
        fail()
    for name in AUDIENCE:
        to_wire(expected[name], dict(COMMON)[name])
    envelope = guarded(BASE['uncbor'], data[1:])
    if (type(envelope) is not list or len(envelope) != 4 or type(envelope[0]) is not bytes or
            envelope[1] != {} or type(envelope[2]) is not bytes or type(envelope[3]) is not bytes or len(envelope[3]) != 64):
        fail()
    protected = guarded(BASE['uncbor'], envelope[0])
    if (type(protected) is not dict or set(protected) != {1, 4} or protected[1] != -7 or
            type(protected[4]) is not bytes or len(protected[4]) != 8):
        fail()
    payload = guarded(BASE['uncbor'], envelope[2])
    if type(payload) is not dict or 2 not in payload:
        fail()
    purpose = from_wire(payload[2], 'purpose')
    state = from_wire(payload.get(12), 'state') if purpose != 'ownership_receipt' else None
    rows = layout({'purpose': purpose, 'state': state})
    if set(payload) != set(range(1, len(rows) + 1)):
        fail()
    decoded = {name: from_wire(payload[i + 1], kind) for i, (name, kind) in enumerate(rows)}
    decoded['issuer_kid'] = protected[4].hex()
    fields(decoded)
    if decoded['environment'] != environment or any(decoded[name] != expected[name] for name in AUDIENCE):
        fail()
    if type(issuers) not in (list, tuple) or not 0 < len(issuers) <= 8:
        fail()
    seen, key = set(), None
    for issuer in issuers:
        if (type(issuer) is not dict or set(issuer) != {'environment', 'purpose', 'kid', 'public_key'} or
                issuer['environment'] not in ('development', 'production') or
                issuer['purpose'] not in ('factory_identity', 'ownership_control')):
            fail()
        identity = (issuer['environment'], guarded(BASE['hex_bytes'], issuer['kid'], 8))
        point = guarded(BASE['hex_bytes'], issuer['public_key'], 65, '04')
        if identity in seen:
            fail()
        seen.add(identity)
        if identity == (environment, protected[4]) and issuer['purpose'] == 'ownership_control':
            key = point
    if key is None:
        fail()
    message = signing_bytes(decoded)
    try:
        valid = crypto.valid_public_key(key) is True and crypto.verify(key, message, envelope[3]) is True
    except Exception:
        raise ValueError(ERROR) from None
    if not valid:
        fail()
    if 'capabilities' in decoded:
        decoded['capabilities'] = tuple(decoded['capabilities'])
    return VerifiedAuthority(MappingProxyType(decoded), hashlib.sha256(message).digest())


def checked(value):
    if not isinstance(value, VerifiedAuthority):
        fail()
    return value.metadata


def compare_revision(current, previous=None):
    new = checked(current)
    if previous is None:
        return 'newer'
    old = checked(previous)
    if any(new[name] != old[name] for name in ('purpose', 'environment', 'resource_uuid')) or new['revision'] < old['revision']:
        fail()
    if new['revision'] == old['revision']:
        if current.content_id != previous.content_id:
            fail()
        return 'retry'
    if new['ownership_epoch'] < old['ownership_epoch']:
        fail()
    fixed = ('owner_ref',) + AUDIENCE[1:]
    if new['purpose'] == 'ownership_receipt':
        fixed += ('claim_operation_uuid',)
    if new['ownership_epoch'] == old['ownership_epoch'] and any(new[name] != old[name] for name in fixed):
        fail()
    return 'newer'


def check_owners(policy, resource_owner, link_owner=None):
    value, owner = checked(policy), checked(resource_owner)
    if (value['purpose'] == 'ownership_receipt' or owner['purpose'] != 'ownership_receipt' or
            any(value[name] != owner[name] for name in ('environment', 'owner_ref', 'ownership_epoch') + AUDIENCE)):
        fail()
    peer_required = value['purpose'] == 'core_link' and value['state'] == 'grant'
    if not peer_required:
        if link_owner is not None:
            fail()
        return
    link = checked(link_owner)
    if (link['purpose'] != 'ownership_receipt' or link['resource_role'] != 'Link' or
            link['environment'] != value['environment'] or link['owner_ref'] != value['owner_ref'] or
            any(value['link_' + name] != link['resource_' + name] for name in ('uuid', 'key_sha256', 'key_revision')) or
            value['link_ownership_epoch'] != link['ownership_epoch']):
        fail()


def authority_context(policy, resource_owner, link_owner=None):
    check_owners(policy, resource_owner, link_owner)
    if policy.metadata['state'] != 'grant':
        fail()
    return hashlib.sha256(BASE['cbor']([CONTEXT, policy.content_id, resource_owner.content_id,
                                      b'' if link_owner is None else link_owner.content_id])).digest()


def has_capability(policy, operation):
    value = checked(policy)
    if value['purpose'] == 'ownership_receipt' or type(operation) is not str or operation not in CAPABILITIES:
        fail()
    return value['state'] == 'grant' and operation in value['capabilities']


def check_subject_key(policy, subject_role, subject_uuid, public_key, crypto):
    """Match public identity only. The caller must separately prove possession freshly."""
    value = checked(policy)
    if value['purpose'] == 'ownership_receipt' or value['state'] != 'grant':
        fail()
    phone = value['purpose'] == 'phone_controller'
    prefix = 'phone' if phone else 'link'
    name = 'phone_installation_uuid' if phone else 'link_uuid'
    if (subject_role != ('Phone' if phone else 'Link') or subject_uuid != value[name] or
            type(public_key) is not bytes or len(public_key) != 65 or public_key[:1] != b'\x04' or
            hashlib.sha256(public_key).hexdigest() != value[prefix + '_key_sha256']):
        fail()
    try:
        valid = crypto.valid_public_key(public_key) is True
    except Exception:
        raise ValueError(ERROR) from None
    if not valid:
        fail()
