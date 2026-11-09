"""Verify the app/backend-owned QR-custody contract; no DB, KMS or real QR IO."""
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import verify_claim_qr as qr_dependency
import verify_device_credential as cbor_dependency
INVENTORY = {'profile.json', 'custody.schema.json', 'vectors.json', 'codec.py', 'reference.mjs'}
BINDING = ['v', 'environment', 'device_uuid', 'role', 'public_key_sha256', 'claim_revision']
RECORD = BINDING + ['record_uuid', 'record_revision', 'payload_uuid', 'payload_revision', 'algorithm', 'wrapping_key_id', 'wrapped_key', 'nonce', 'ciphertext']
VERIFIER = BINDING + ['verifier_key_id', 'verifier_revision', 'algorithm', 'mac']
REQUEST = ['v', 'action', 'request_uuid', 'environment', 'device_uuid', 'actor_uuid', 'session_uuid']
SNAPSHOT = ['v', 'environment', 'device_uuid', 'role', 'public_key_sha256', 'claim_revision', 'record_uuid', 'record_revision', 'verifier_revision', 'owner_uuid', 'ownership_epoch', 'actor_uuid', 'session_uuid', 'session_revision', 'authenticated_at', 'auth_event', 'logged_in', 'online', 'account_enabled', 'operator_enabled', 'operator_revision']
COUNTS = ('seals', 'rotations', 'access', 'invalid_fields', 'failures', 'reveals', 'primitive_vectors')
PROFILE = {'format': 'octatrace-qr-custody', 'version': 1, 'source_repository': 'octatrace-app', 'payload': {'algorithm': 'AES-256-GCM', 'key_bytes': 32, 'nonce_bytes': 12, 'tag_bytes': 16, 'plaintext_bytes': 145, 'ciphertext_and_tag_bytes': 161, 'aad_domain': 'OCTATRACE-QR-PAYLOAD-1'}, 'wrapping': {'provider': 'protected server adapter, not selected here', 'context_domain': 'OCTATRACE-QR-WRAP-1', 'opaque_ciphertext_bytes_max': 2048, 'key_role': 'qr_wrapping', 'record_revision_authenticated': True}, 'verifier': {'algorithm': 'HMAC-SHA256', 'key_role': 'qr_verifier', 'domain': 'OCTATRACE-QR-VERIFIER-1', 'tag_bytes': 32, 'constant_time_comparison_required': True, 'key_id_and_revision_authenticated': True}, 'fields': {'binding': BINDING, 'record': RECORD, 'verifier': VERIFIER, 'request': REQUEST, 'snapshot': SNAPSHOT}, 'nonce_policy': 'One encryption per independently generated data key; reserve key commitment before encryption and retain it after failure. Real RNG/durable uniqueness is C5.', 'qr_retention': 'Keep exact original canonical QR across owner transfer and encryption/verifier key rotation; current owner/operator access follows authoritative state; used QR cannot grant new first claim', 'access': {'action': 'reveal_private_qr', 'recent_auth_seconds': 900, 'auth_events': ['sign_in', 'reauthenticated'], 'principals': ['current_owner', 'enabled_normal_operator_before_or_after_claim'], 'stamp_domain': 'OCTATRACE-QR-ACCESS-1', 'headers': {'Cache-Control': 'no-store', 'Pragma': 'no-cache'}, 'release': 'Trusted adapter atomically rechecks access/stamp/current time and durably audits before release; not implemented as DB in this checkpoint'}, 'migration_scope': 'No migration or DB write in C4.2c; provisioning/custody migrations C5, claim/recovery C6', 'key_separation': 'Data keys, wrapping keys, verifier keys and factory/authority signing keys have separate roles; server secrets never on Workshop/app/field devices', 'references': ['https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf', 'https://www.rfc-editor.org/rfc/rfc2104.html', 'https://www.rfc-editor.org/rfc/rfc4231.html#section-4.2']}

def schema():
    uid = {'type': 'string', 'minLength': 36, 'maxLength': 36, 'pattern': '^' + cbor_dependency.UUID + '$'}

    def hx(size, nonzero=False):
        value = {'type': 'string', 'minLength': size * 2, 'maxLength': size * 2, 'pattern': '^[0-9a-f]{' + str(size * 2) + '}$'}
        if nonzero:
            value['not'] = {'const': '0' * (size * 2)}
        return value
    rev = {'type': 'integer', 'minimum': 1, 'maximum': 4294967295}
    counter = {'type': 'integer', 'minimum': 0, 'maximum': 4294967295}
    base = {'v': {'type': 'integer', 'const': 1}, 'environment': {'type': 'string', 'enum': ['development', 'production']}, 'device_uuid': uid, 'role': {'type': 'string', 'enum': ['Link', 'Core']}, 'public_key_sha256': hx(32, True), 'claim_revision': rev}
    rec = {**base, 'record_uuid': uid, 'record_revision': rev, 'payload_uuid': uid, 'payload_revision': rev, 'algorithm': {'const': 'A256GCM'}, 'wrapping_key_id': uid, 'wrapped_key': {'type': 'string', 'minLength': 2, 'maxLength': 4096, 'pattern': '^([0-9a-f]{2}){1,2048}$'}, 'nonce': hx(12, True), 'ciphertext': hx(161)}
    ver = {**base, 'verifier_key_id': uid, 'verifier_revision': rev, 'algorithm': {'const': 'HS256'}, 'mac': hx(32)}
    req = {'v': base['v'], 'action': {'const': 'reveal_private_qr'}, 'request_uuid': uid, 'environment': base['environment'], 'device_uuid': uid, 'actor_uuid': uid, 'session_uuid': uid}
    snap = {**base, 'record_uuid': uid, 'record_revision': rev, 'verifier_revision': rev, 'owner_uuid': {'anyOf': [uid, {'type': 'null'}]}, 'ownership_epoch': counter, 'actor_uuid': uid, 'session_uuid': uid, 'session_revision': rev, 'authenticated_at': rev, 'auth_event': {'enum': ['sign_in', 'reauthenticated', 'refresh', 'unknown']}, 'logged_in': {'type': 'boolean'}, 'online': {'type': 'boolean'}, 'account_enabled': {'type': 'boolean'}, 'operator_enabled': {'type': 'boolean'}, 'operator_revision': counter}
    variants = []
    for (kind, props) in [('binding', base), ('record', rec), ('verifier', ver), ('request', req), ('snapshot', snap)]:
        body = {'type': 'object', 'additionalProperties': False, 'required': list(props), 'properties': props}
        if kind == 'snapshot':
            body['allOf'] = [{'if': {'properties': {'owner_uuid': {'type': 'null'}}}, 'then': {'properties': {'ownership_epoch': {'const': 0}}}, 'else': {'properties': {'ownership_epoch': rev}}}, {'if': {'properties': {'operator_enabled': {'const': True}}}, 'then': {'properties': {'operator_revision': rev}}}]
        variants.append({'type': 'object', 'additionalProperties': False, 'required': ['kind', 'value'], 'properties': {'kind': {'const': kind}, 'value': body}})
    return {'$schema': 'https://json-schema.org/draft/2020-12/schema', '$id': 'urn:octatrace:qr-custody:1', 'title': 'QR custody v1 records; auth snapshots must be server trusted', 'oneOf': variants}

def verify(root):
    root = Path(root).resolve()
    lock = json.loads((root / 'qr-custody.lock.json').read_text())
    if lock.get('profile') != 'octatrace-qr-custody' or lock.get('version') != 1 or lock.get('source_repository') != 'octatrace-app' or (lock.get('path') not in ('supabase/contracts/qr-custody', 'vendor/qr-custody')) or (set(lock.get('files', {})) != INVENTORY):
        raise ValueError('Unsupported QR custody pin')
    qr_dependency.verify(root)
    cbor_dependency.verify(root)
    for family in ['claim-qr', 'device-credential']:
        pin = json.loads((root / (family + '.lock.json')).read_text())
        if lock.get('requires_' + family.replace('-', '_') + '_files_sha256') != pin['files']:
            raise ValueError('QR custody dependency mismatch')
    folder = root / lock['path']
    if folder.is_symlink() or not folder.resolve().is_relative_to(root) or {p.name for p in folder.iterdir() if p.is_file()} != INVENTORY:
        raise ValueError('Invalid QR custody inventory')
    for (name, digest) in lock['files'].items():
        path = folder / name
        if path.is_symlink() or not re.fullmatch('[0-9a-f]{64}', digest) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('QR custody checksum mismatch')
    if json.loads((folder / 'profile.json').read_text()) != PROFILE:
        raise ValueError('Unsupported QR custody profile')
    if json.loads((folder / 'custody.schema.json').read_text()) != schema():
        raise ValueError('Unsupported QR custody schema')
    codec = runpy.run_path(str(folder / 'codec.py'))
    v = json.loads((folder / 'vectors.json').read_text())
    if v.get('synthetic') is not True or any((len(v[k]) < n for (k, n) in zip(COUNTS, [4, 2, 26, 180, 17, 15, 3]))):
        raise ValueError('Incomplete QR custody vectors')
    for row in v['seals']:
        if codec['payload_aad'](row['record']).hex() != row['payload_aad'] or codec['wrap_aad'](row['record']).hex() != row['wrap_aad'] or codec['mac_input'](row['verifier'], row['text']).hex() != row['mac_input']:
            raise ValueError('QR custody positive vector mismatch')
    functions = {'binding': codec['bind'], 'record': codec['record'], 'verifier': codec['verifier'], 'request': codec['request'], 'snapshot': codec['snapshot']}
    for row in v['invalid_fields']:
        try:
            functions[row['kind']](row['value'])
        except ValueError as error:
            if str(error) != 'Private QR operation denied':
                raise ValueError('QR custody error may disclose input') from None
        else:
            raise ValueError('QR custody invalid fields accepted')
    result = subprocess.run(['node', str(folder / 'reference.mjs'), str(folder / 'vectors.json')], capture_output=True, text=True)
    expected = {k: len(v[k]) for k in COUNTS}
    if result.returncode or json.loads(result.stdout) != expected:
        raise ValueError('Independent QR custody reference failed')
    return expected
if __name__ == '__main__':
    print(json.dumps(verify(Path(__file__).resolve().parents[1]), sort_keys=True))
