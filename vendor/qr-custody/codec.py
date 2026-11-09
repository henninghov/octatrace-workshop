"""Server-only QR custody contract. No DB/KMS/network or real secret generation.

Trusted crypto, nonce-reservation and final authorise/audit adapters are required.
Python immutable private data cannot be reliably wiped; do not log/export it.
"""
from dataclasses import dataclass, field
import hashlib
import hmac
import json
from pathlib import Path
import re
import runpy
ROOT = next((p for p in Path(__file__).resolve().parents if (p / 'claim-qr.lock.json').is_file() and (p / 'device-credential.lock.json').is_file()))

def dependency(name):
    pin = json.loads((ROOT / (name + '.lock.json')).read_text())
    return runpy.run_path(str(ROOT / pin['path'] / 'codec.py'))
QR = dependency('claim-qr')
BASE = dependency('device-credential')
ERROR = 'Private QR operation denied'
BINDING = ('v', 'environment', 'device_uuid', 'role', 'public_key_sha256', 'claim_revision')
RECORD = BINDING + ('record_uuid', 'record_revision', 'payload_uuid', 'payload_revision', 'algorithm', 'wrapping_key_id', 'wrapped_key', 'nonce', 'ciphertext')
VERIFIER = BINDING + ('verifier_key_id', 'verifier_revision', 'algorithm', 'mac')
REQUEST = ('v', 'action', 'request_uuid', 'environment', 'device_uuid', 'actor_uuid', 'session_uuid')
SNAPSHOT = ('v', 'environment', 'device_uuid', 'role', 'public_key_sha256', 'claim_revision', 'record_uuid', 'record_revision', 'verifier_revision', 'owner_uuid', 'ownership_epoch', 'actor_uuid', 'session_uuid', 'session_revision', 'authenticated_at', 'auth_event', 'logged_in', 'online', 'account_enabled', 'operator_enabled', 'operator_revision')
DOMAIN_PAYLOAD = b'OCTATRACE-QR-PAYLOAD-1'
DOMAIN_WRAP = b'OCTATRACE-QR-WRAP-1'
DOMAIN_MAC = b'OCTATRACE-QR-VERIFIER-1'
DOMAIN_ACCESS = b'OCTATRACE-QR-ACCESS-1'
HEADERS = {'Cache-Control': 'no-store', 'Pragma': 'no-cache'}

def fail():
    raise ValueError(ERROR)

def guarded(operation, *args):
    try:
        return operation(*args)
    except Exception:
        raise ValueError(ERROR) from None

def invoke(adapter, method, *args):
    try:
        return getattr(adapter, method)(*args)
    except Exception:
        raise ValueError(ERROR) from None

def exact(value, names):
    if type(value) is not dict or set(value) != set(names):
        fail()

def number(value, minimum=1):
    return guarded(BASE['uint'], value, minimum)

def uid(value):
    return guarded(BASE['to_wire'], value, 'uuid')

def raw(value, size, nonzero=False):
    if type(value) is not bytes or len(value) != size or (nonzero and (not any(value))):
        fail()
    return value

def unhex(value, size, nonzero=False):
    if type(value) is not str or len(value) != size * 2 or (not re.fullmatch('[0-9a-f]+', value)):
        fail()
    return raw(bytes.fromhex(value), size, nonzero)

def bind(value):
    exact(value, BINDING)
    result = dict(value)
    if number(value['v']) != 1:
        fail()
    guarded(BASE['to_wire'], value['environment'], 'environment')
    uid(value['device_uuid'])
    guarded(BASE['to_wire'], value['role'], 'role')
    unhex(value['public_key_sha256'], 32, True)
    result['v'] = 1
    result['claim_revision'] = number(value['claim_revision'])
    return result

def binding_of(value):
    if type(value) is not dict or any((name not in value for name in BINDING)):
        fail()
    return bind({name: value[name] for name in BINDING})

def record(value):
    exact(value, RECORD)
    result = {**value, **binding_of(value)}
    for name in ('record_uuid', 'payload_uuid', 'wrapping_key_id'):
        uid(value[name])
    for name in ('record_revision', 'payload_revision'):
        result[name] = number(value[name])
    if result['payload_revision'] > result['record_revision'] or value['algorithm'] != 'A256GCM':
        fail()
    wrapped = value['wrapped_key']
    if type(wrapped) is not str or not 2 <= len(wrapped) <= 4096 or len(wrapped) % 2 or (not re.fullmatch('[0-9a-f]+', wrapped)):
        fail()
    unhex(value['nonce'], 12, True)
    unhex(value['ciphertext'], 161)
    return result

def verifier(value):
    exact(value, VERIFIER)
    result = {**value, **binding_of(value)}
    uid(value['verifier_key_id'])
    result['verifier_revision'] = number(value['verifier_revision'])
    if value['algorithm'] != 'HS256':
        fail()
    unhex(value['mac'], 32)
    return result

def pair(value, check, expected):
    (r, v, b) = (record(value), verifier(check), bind(expected))
    if binding_of(r) != b or binding_of(v) != b or r['wrapping_key_id'] == v['verifier_key_id']:
        fail()
    return (r, v, b)

def binding_bytes(value):
    b = bind(value)
    return [1, BASE['to_wire'](b['environment'], 'environment'), uid(b['device_uuid']), BASE['to_wire'](b['role'], 'role'), bytes.fromhex(b['public_key_sha256']), b['claim_revision']]

def payload_aad(value):
    r = record(value)
    return BASE['cbor']([DOMAIN_PAYLOAD, *binding_bytes(binding_of(r)), uid(r['record_uuid']), uid(r['payload_uuid']), r['payload_revision']])

def wrap_aad(value):
    r = record(value)
    return BASE['cbor']([DOMAIN_WRAP, *binding_bytes(binding_of(r)), uid(r['record_uuid']), r['record_revision'], uid(r['payload_uuid']), r['payload_revision'], uid(r['wrapping_key_id'])])

def plaintext(text, expected):
    b = bind(expected)
    claim = guarded(QR['decode'], text, b['environment'])
    if claim.device_uuid != b['device_uuid'] or claim.role != b['role'] or claim.public_key_sha256 != b['public_key_sha256']:
        fail()
    return text.encode('ascii')

def mac_input(value, text):
    v = verifier(value)
    data = plaintext(text, binding_of(v))
    return BASE['cbor']([DOMAIN_MAC, *binding_bytes(binding_of(v)), uid(v['verifier_key_id']), v['verifier_revision'], data])

def matches_claim(text, check, expected, crypto):
    (v, b) = (verifier(check), bind(expected))
    if binding_of(v) != b:
        fail()
    data = mac_input(v, text)
    result = invoke(crypto, 'verify_mac', v['verifier_key_id'], b['environment'], data, bytes.fromhex(v['mac']))
    if type(result) is not bool:
        fail()
    return result

def seal(text, template, check_template, expected, data_key, crypto, reserve_key):
    (r, v, b) = pair(template, check_template, expected)
    data = plaintext(text, b)
    raw(data_key, 32, True)
    # Persistently burn the key reservation before any encryption, including failures.
    if guarded(reserve_key, hashlib.sha256(data_key).digest(), r['record_uuid'], r['payload_uuid']) is not True:
        fail()
    ciphertext = invoke(crypto, 'encrypt', data_key, bytes.fromhex(r['nonce']), payload_aad(r), data)
    raw(ciphertext, 161)
    r['ciphertext'] = ciphertext.hex()
    wrapped = invoke(crypto, 'wrap', r['wrapping_key_id'], b['environment'], data_key, wrap_aad(r))
    if type(wrapped) is not bytes or not 1 <= len(wrapped) <= 2048:
        fail()
    r['wrapped_key'] = wrapped.hex()
    mac = invoke(crypto, 'mac', v['verifier_key_id'], b['environment'], mac_input(v, text))
    raw(mac, 32)
    v['mac'] = mac.hex()
    return (record(r), verifier(v))

def _open_checked(value, check, expected, crypto, before_decrypt=None):
    (r, v, b) = pair(value, check, expected)
    key = invoke(crypto, 'unwrap', r['wrapping_key_id'], b['environment'], bytes.fromhex(r['wrapped_key']), wrap_aad(r))
    raw(key, 32, True)
    if before_decrypt is not None:
        guarded(before_decrypt)
    data = invoke(crypto, 'decrypt', key, bytes.fromhex(r['nonce']), payload_aad(r), bytes.fromhex(r['ciphertext']))
    raw(data, 145)
    text = guarded(bytes.decode, data, 'ascii')
    plaintext(text, b)
    if not matches_claim(text, v, b, crypto):
        fail()
    return (text, key)

def rewrap(value, check, expected, new_key_id, crypto):
    (r, v, b) = pair(value, check, expected)
    uid(new_key_id)
    if new_key_id == v['verifier_key_id']:
        fail()
    (_, key) = _open_checked(r, v, b, crypto)
    if new_key_id == r['wrapping_key_id']:
        return dict(r)
    updated = {**r, 'record_revision': number(r['record_revision'] + 1), 'wrapping_key_id': new_key_id}
    wrapped = invoke(crypto, 'wrap', new_key_id, b['environment'], key, wrap_aad(updated))
    if type(wrapped) is not bytes or not 1 <= len(wrapped) <= 2048:
        fail()
    updated['wrapped_key'] = wrapped.hex()
    return record(updated)

def rotate_verifier(value, check, expected, new_key_id, crypto):
    (r, v, b) = pair(value, check, expected)
    uid(new_key_id)
    if new_key_id == r['wrapping_key_id']:
        fail()
    (text, _) = _open_checked(r, v, b, crypto)
    if new_key_id == v['verifier_key_id']:
        return dict(v)
    updated = {**v, 'verifier_revision': number(v['verifier_revision'] + 1), 'verifier_key_id': new_key_id}
    mac = invoke(crypto, 'mac', new_key_id, b['environment'], mac_input(updated, text))
    raw(mac, 32)
    updated['mac'] = mac.hex()
    return verifier(updated)

def compare_update(current_record, current_verifier, previous_record, previous_verifier):
    (r, v, b) = pair(current_record, current_verifier, binding_of(current_record))
    (old, ov, _) = pair(previous_record, previous_verifier, b)
    if r['record_uuid'] != old['record_uuid'] or r['record_revision'] < old['record_revision'] or r['payload_revision'] < old['payload_revision'] or (v['verifier_revision'] < ov['verifier_revision']):
        fail()
    if r['record_revision'] == old['record_revision'] and r != old:
        fail()
    if v['verifier_revision'] == ov['verifier_revision'] and v != ov:
        fail()
    if r['payload_revision'] == old['payload_revision'] and any((r[n] != old[n] for n in ('payload_uuid', 'nonce', 'ciphertext'))):
        fail()
    return 'retry' if r == old and v == ov else 'newer'

def validate_update(current_record, current_verifier, previous_record, previous_verifier, crypto):
    result = compare_update(current_record, current_verifier, previous_record, previous_verifier)
    expected = binding_of(previous_record)
    (old, _) = _open_checked(previous_record, previous_verifier, expected, crypto)
    (new, _) = _open_checked(current_record, current_verifier, expected, crypto)
    if not hmac.compare_digest(old, new):
        fail()
    return result

def request(value):
    exact(value, REQUEST)
    if number(value['v']) != 1 or value['action'] != 'reveal_private_qr':
        fail()
    guarded(BASE['to_wire'], value['environment'], 'environment')
    for n in ('request_uuid', 'device_uuid', 'actor_uuid', 'session_uuid'):
        uid(value[n])
    return dict(value, v=1)

def snapshot(value):
    exact(value, SNAPSHOT)
    s = dict(value)
    if number(s['v']) != 1:
        fail()
    s['v'] = 1
    binding_of(s)
    for n in ('record_uuid', 'actor_uuid', 'session_uuid'):
        uid(s[n])
    for n in ('claim_revision', 'record_revision', 'verifier_revision', 'session_revision', 'authenticated_at'):
        s[n] = number(s[n])
    for n in ('ownership_epoch', 'operator_revision'):
        s[n] = number(s[n], 0)
    for n in ('logged_in', 'online', 'account_enabled', 'operator_enabled'):
        if type(s[n]) is not bool:
            fail()
    if s['owner_uuid'] is not None:
        uid(s['owner_uuid'])
    if (s['owner_uuid'] is None) != (s['ownership_epoch'] == 0) or s['auth_event'] not in ('sign_in', 'reauthenticated', 'refresh', 'unknown'):
        fail()
    if s['operator_enabled'] and s['operator_revision'] == 0:
        fail()
    return s

def authorise(value, check, expected, query, state, now):
    (r, v, b) = pair(value, check, expected)
    (q, s) = (request(query), snapshot(state))
    instant = number(now, 0)
    if binding_of(s) != b or s['record_uuid'] != r['record_uuid'] or s['record_revision'] != r['record_revision'] or (s['verifier_revision'] != v['verifier_revision']) or (s['environment'] != q['environment']) or (s['device_uuid'] != q['device_uuid']) or (s['actor_uuid'] != q['actor_uuid']) or (s['session_uuid'] != q['session_uuid']) or (not s['logged_in']) or (not s['online']) or (not s['account_enabled']) or (s['auth_event'] not in ('sign_in', 'reauthenticated')) or (not 0 <= instant - s['authenticated_at'] < 900) or (not (s['owner_uuid'] == s['actor_uuid'] or s['operator_enabled'])):
        fail()
    mapped = []
    for name in SNAPSHOT:
        x = s[name]
        if type(x) is bool:
            x = int(x)
        elif x is None:
            x = b''
        mapped.append(x)
    stamp = hashlib.sha256(BASE['cbor']([DOMAIN_ACCESS, uid(q['request_uuid']), mapped])).digest()
    path = 'owner' if s['owner_uuid'] == s['actor_uuid'] else 'operator'
    return (stamp, path)

@dataclass(frozen=True)
class PrivateQr:
    _text: str = field(repr=False)

    def reveal(self):
        """Explicit private output after a trusted gate; never log/cache this value."""
        return self._text

    def headers(self):
        return dict(HEADERS)

def reveal(value, check, expected, query, crypto, get_snapshot, clock, release_gate):
    (r, v, b) = pair(value, check, expected)
    q = request(query)
    before = guarded(get_snapshot, q)
    (stamp, path) = authorise(r, v, b, q, before, guarded(clock))

    def before_decrypt():
        current = guarded(get_snapshot, q)
        (current_stamp, current_path) = authorise(r, v, b, q, current, guarded(clock))
        if current_stamp != stamp or current_path != path:
            fail()
    (text, _) = _open_checked(r, v, b, crypto, before_decrypt)
    after = guarded(get_snapshot, q)
    (fresh, new_path) = authorise(r, v, b, q, after, guarded(clock))
    if fresh != stamp or path != new_path:
        fail()
    event = {'v': 1, 'request_uuid': q['request_uuid'], 'environment': q['environment'], 'actor_uuid': q['actor_uuid'], 'session_uuid': q['session_uuid'], 'device_uuid': q['device_uuid'], 'record_uuid': r['record_uuid'], 'record_revision': r['record_revision'], 'claim_revision': b['claim_revision'], 'purpose': 'private_qr_reveal', 'access_path': path, 'outcome': 'authorised_release'}
    # Trusted server adapter: atomic current-access check plus durable audit before True.
    if guarded(release_gate, q, stamp, event) is not True:
        fail()
    return PrivateQr(text)
