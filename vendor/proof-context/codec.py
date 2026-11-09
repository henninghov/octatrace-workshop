"""Setup possession-proof / field binding contract; no claims, storage or handshake IO.

The service challenge is authenticated. Proof signatures bind to that challenge.
Field context matching returns untrusted binding data, NEVER authenticated readiness.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import runpy
from types import MappingProxyType
import uuid

AUTH = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'device-authority/codec.py'))
BASE = AUTH['BASE']
ERROR = 'Invalid proof context'
WINDOW = 300
MAX_OBJECT = 512
CHALLENGE_AAD = b'OCTATRACE-SETUP-CHALLENGE-1'
PROOF_AAD = b'OCTATRACE-SETUP-PROOF-1'
FIELD_PREFIX = b'OCTATRACE-FIELD-CONTEXT-1:'
PURPOSES = {'first_claim': 1, 'phone_replace': 2}
CHALLENGE = (('v','version'), ('purpose','purpose'), ('environment','environment'),
 ('challenge_uuid','uuid'), ('operation_uuid','uuid'), ('owner_ref','uuid'),
 ('link_uuid','uuid'), ('link_role','link_role'), ('link_key_sha256','hash'), ('link_key_revision','revision'),
 ('link_boot','boot'), ('link_nonce','hash'), ('phone_installation_uuid','uuid'),
 ('phone_key_sha256','hash'), ('phone_boot','boot'), ('server_nonce','hash'),
 ('issued_at','revision'), ('expires_at','revision'), ('owner_receipt_sha256','optional_hash'),
 ('ownership_epoch','counter'), ('controller_revision','counter'))
PROOF = (('v','version'), ('signer','signer'), ('challenge_content_sha256','hash'),
         ('challenge_uuid','uuid'), ('signer_boot','boot'))
FIELD = (('v','version'), ('kind','kind'), ('environment','environment'),
 ('handshake_profile_sha256','hash'), ('attempt_uuid','uuid'), ('authority_context_sha256','hash'),
 ('initiator_uuid','uuid'), ('initiator_key_sha256','hash'), ('initiator_boot','boot'),
 ('responder_uuid','uuid'), ('responder_key_sha256','hash'), ('responder_boot','boot'),
 ('initiator_nonce','hash'), ('responder_nonce','hash'), ('transcript_sha256','hash'))
EXPECTED = tuple(name for name, _ in CHALLENGE if name not in
                 ('v','challenge_uuid','server_nonce','issued_at','expires_at'))


def fail():
    raise ValueError(ERROR)


def guarded(operation, *args):
    try:
        return operation(*args)
    except (ValueError, TypeError, OverflowError, UnicodeError):
        raise ValueError(ERROR) from None


def to_wire(value, kind):
    choices = {'purpose': PURPOSES, 'signer': {'Link':1,'Phone':2},
               'kind': {'phone_link':1,'link_core':2}, 'link_role': {'Link':1}}
    if kind in choices:
        if type(value) is not str or value not in choices[kind]:
            fail()
        return choices[kind][value]
    if kind in ('hash','boot','optional_hash'):
        if kind == 'optional_hash' and value == '':
            return b''
        return guarded(BASE['hex_bytes'], value, 16 if kind == 'boot' else 32)
    if kind == 'counter':
        return guarded(BASE['uint'], value, 0)
    return guarded(BASE['to_wire'], value, kind)


def fields(kind, value):
    layouts = {'challenge':CHALLENGE, 'proof':PROOF, 'field':FIELD}
    if type(kind) is not str or kind not in layouts or type(value) is not dict:
        fail()
    rows = layouts[kind]
    if set(value) != {name for name, _ in rows} | ({'issuer_kid'} if kind == 'challenge' else set()):
        fail()
    payload = {i+1:to_wire(value[name], encoding) for i,(name,encoding) in enumerate(rows)}
    if kind == 'challenge':
        guarded(BASE['hex_bytes'], value['issuer_kid'], 8)
        if (value['expires_at'] - value['issued_at'] != WINDOW or
                value['link_nonce'] == value['server_nonce'] or value['link_boot'] == value['phone_boot'] or
                value['link_uuid'] == value['phone_installation_uuid'] or value['link_key_sha256'] == value['phone_key_sha256']):
            fail()
        if value['purpose'] == 'first_claim':
            if value['owner_receipt_sha256'] != '' or value['ownership_epoch'] != 0 or value['controller_revision'] != 0:
                fail()
        elif not value['owner_receipt_sha256'] or value['ownership_epoch'] == 0:
            fail()
    if kind == 'field' and any(value['initiator_'+name] == value['responder_'+name]
                               for name in ('uuid','key_sha256','boot','nonce')):
        fail()
    return payload


def protected(kind, value):
    if kind == 'challenge':
        return BASE['cbor']({1:-7,4:bytes.fromhex(value['issuer_kid'])})
    return BASE['cbor']({1:-7})


def signing_bytes(kind, value, maximum_bytes=512):
    if kind not in ('challenge','proof'):
        fail()
    body = fields(kind, value)
    message = BASE['cbor'](['Signature1',protected(kind,value),CHALLENGE_AAD if kind == 'challenge' else PROOF_AAD,BASE['cbor'](body)])
    if len(message) > guarded(BASE['uint'], maximum_bytes, 1, 512):
        fail()
    return message


def assemble(kind, value, signature, maximum_bytes=MAX_OBJECT):
    if kind not in ('challenge','proof'):
        fail()
    body = fields(kind,value)
    if type(signature) is not bytes or len(signature) != 64:
        fail()
    result = b'\xd2' + BASE['cbor']([protected(kind,value),{},BASE['cbor'](body),signature])
    if len(result) > guarded(BASE['uint'], maximum_bytes, 1, MAX_OBJECT):
        fail()
    return result


def decode_payload(kind, payload):
    layouts = {'challenge':CHALLENGE, 'proof':PROOF, 'field':FIELD}
    rows = layouts[kind]
    if type(payload) is not dict or set(payload) != set(range(1,len(rows)+1)):
        fail()
    maps = {'purpose':PURPOSES,'signer':{'Link':1,'Phone':2},'kind':{'phone_link':1,'link_core':2},
            'environment':{'development':1,'production':2},'link_role':{'Link':1}}
    result = {}
    for i,(name,encoding) in enumerate(rows):
        value = payload[i+1]
        if encoding == 'uuid':
            if type(value) is not bytes or len(value) != 16:
                fail()
            value = str(uuid.UUID(bytes=value))
        elif encoding in ('hash','boot','optional_hash'):
            if type(value) is not bytes:
                fail()
            value = value.hex()
        elif encoding in maps:
            if type(value) is not int or value not in maps[encoding].values():
                fail()
            value = next(k for k,v in maps[encoding].items() if value == v)
        result[name] = value
    return result


def envelope(kind, data):
    if type(data) is not bytes or not 0 < len(data) <= MAX_OBJECT or data[:1] != b'\xd2':
        fail()
    value = guarded(BASE['uncbor'], data[1:])
    if (type(value) is not list or len(value) != 4 or type(value[0]) is not bytes or value[1] != {} or
            type(value[2]) is not bytes or type(value[3]) is not bytes or len(value[3]) != 64):
        fail()
    header = guarded(BASE['uncbor'], value[0])
    if type(header) is not dict or set(header) != ({1,4} if kind == 'challenge' else {1}) or header[1] != -7:
        fail()
    decoded = decode_payload(kind, guarded(BASE['uncbor'], value[2]))
    if kind == 'challenge':
        if type(header[4]) is not bytes or len(header[4]) != 8:
            fail()
        decoded['issuer_kid'] = header[4].hex()
    fields(kind,decoded)
    return decoded, value[3]


@dataclass(frozen=True)
class VerifiedChallenge:
    metadata: object = field(repr=False)
    content_id: bytes
    def to_fields(self):
        return dict(self.metadata)


@dataclass(frozen=True)
class VerifiedSetupProof:
    metadata: object = field(repr=False)
    key_sha256: bytes
    def to_fields(self):
        return dict(self.metadata)


@dataclass(frozen=True)
class UntrustedFieldContext:
    metadata: object = field(repr=False)
    context_id: bytes
    def to_fields(self):
        return dict(self.metadata)


def challenge(value):
    if not isinstance(value, VerifiedChallenge):
        fail()
    return value.metadata


def verify_challenge(data, environment, issuers, crypto, expected):
    if environment not in ('development','production') or type(expected) is not dict or set(expected) != set(EXPECTED):
        fail()
    for name in EXPECTED:
        to_wire(expected[name],dict(CHALLENGE)[name])
    decoded, signature = envelope('challenge',data)
    if decoded['environment'] != environment or any(decoded[name] != expected[name] for name in EXPECTED):
        fail()
    if type(issuers) not in (list,tuple) or not 0 < len(issuers) <= 8:
        fail()
    seen,key = set(),None
    for issuer in issuers:
        if (type(issuer) is not dict or set(issuer) != {'environment','purpose','kid','public_key'} or
                issuer['environment'] not in ('development','production') or
                issuer['purpose'] not in ('factory_identity','ownership_control')):
            fail()
        identity = (issuer['environment'],guarded(BASE['hex_bytes'],issuer['kid'],8))
        point = guarded(BASE['hex_bytes'],issuer['public_key'],65,'04')
        if identity in seen:
            fail()
        seen.add(identity)
        if identity == (environment,bytes.fromhex(decoded['issuer_kid'])) and issuer['purpose'] == 'ownership_control':
            key = point
    if key is None:
        fail()
    message = signing_bytes('challenge',decoded)
    try:
        valid = crypto.valid_public_key(key) is True and crypto.verify(key,message,signature) is True
    except Exception:
        raise ValueError(ERROR) from None
    if not valid:
        fail()
    return VerifiedChallenge(MappingProxyType(decoded),hashlib.sha256(message).digest())


def verify_proof(data, current_challenge, public_key, crypto):
    value = challenge(current_challenge)
    proof,signature = envelope('proof',data)
    link = proof['signer'] == 'Link'
    digest = value['link_key_sha256' if link else 'phone_key_sha256']
    if (proof['challenge_content_sha256'] != current_challenge.content_id.hex() or
            proof['challenge_uuid'] != value['challenge_uuid'] or
            proof['signer_boot'] != value['link_boot' if link else 'phone_boot'] or
            type(public_key) is not bytes or len(public_key) != 65 or public_key[:1] != b'\x04' or
            hashlib.sha256(public_key).hexdigest() != digest):
        fail()
    message = signing_bytes('proof',proof)
    try:
        valid = crypto.valid_public_key(public_key) is True and crypto.verify(public_key,message,signature) is True
    except Exception:
        raise ValueError(ERROR) from None
    if not valid:
        fail()
    return VerifiedSetupProof(MappingProxyType(proof),hashlib.sha256(public_key).digest())


def check_local_window(current_challenge, link_boot, link_nonce, elapsed_ms):
    value = challenge(current_challenge)
    elapsed = guarded(BASE['uint'],elapsed_ms,0)
    if value['link_boot'] != link_boot or value['link_nonce'] != link_nonce or elapsed >= WINDOW * 1000:
        fail()


def check_setup_completion(current_challenge, link_proof, phone_proof, now, known_content_id, used):
    value = challenge(current_challenge)
    instant = guarded(BASE['uint'],now,0)
    if (type(known_content_id) is not bytes or len(known_content_id) != 32 or
            known_content_id != current_challenge.content_id or type(used) is not bool or used or
            instant < value['issued_at'] or instant >= value['expires_at']):
        fail()
    for proof,role,prefix in [(link_proof,'Link','link'),(phone_proof,'Phone','phone')]:
        if not isinstance(proof,VerifiedSetupProof):
            fail()
        p = proof.metadata
        if (p['signer'] != role or p['challenge_content_sha256'] != current_challenge.content_id.hex() or
                p['challenge_uuid'] != value['challenge_uuid'] or p['signer_boot'] != value[prefix+'_boot'] or
                proof.key_sha256.hex() != value[prefix+'_key_sha256']):
            fail()


def encode_field(value, maximum_bytes=MAX_OBJECT):
    result = FIELD_PREFIX + BASE['cbor'](fields('field',value))
    if len(result) > guarded(BASE['uint'],maximum_bytes,1,MAX_OBJECT):
        fail()
    return result


def match_field(data, expected):
    fields('field',expected)
    if type(data) is not bytes or not 0 < len(data) <= MAX_OBJECT or not data.startswith(FIELD_PREFIX):
        fail()
    value = decode_payload('field',guarded(BASE['uncbor'],data[len(FIELD_PREFIX):]))
    fields('field',value)
    if value != expected:
        fail()
    return UntrustedFieldContext(MappingProxyType(value),hashlib.sha256(data).digest())


def build_field(policy, resource_owner, link_owner, attempt):
    if type(attempt) is not dict or set(attempt) != {'handshake_profile_sha256','attempt_uuid',
            'initiator_boot','responder_boot','initiator_nonce','responder_nonce','transcript_sha256'}:
        fail()
    context = guarded(AUTH['authority_context'],policy,resource_owner,link_owner)
    p = policy.metadata
    phone = p['purpose'] == 'phone_controller'
    value = {'v':1,'kind':'phone_link' if phone else 'link_core','environment':p['environment'],
             'authority_context_sha256':context.hex(),
             'initiator_uuid':p['phone_installation_uuid' if phone else 'link_uuid'],
             'initiator_key_sha256':p['phone_key_sha256' if phone else 'link_key_sha256'],
             'responder_uuid':p['resource_uuid'],'responder_key_sha256':p['resource_key_sha256'],**attempt}
    return encode_field(value)
