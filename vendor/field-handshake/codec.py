"""Profile/credential/application-export metadata, never authenticated readiness.

Public-key validation is a trusted callback; this module neither verifies device
issuance nor runs EDHOC, derives keys, confirms a peer or sends frames.
"""
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import runpy
from types import MappingProxyType

FOLDER = Path(__file__).resolve().parent
PROOF = runpy.run_path(str(FOLDER.parent/'proof-context/codec.py'))
BASE = PROOF['BASE']
PROFILE_SHA256 = hashlib.sha256((FOLDER/'profile.json').read_bytes()).digest()
ERROR = 'Invalid field handshake metadata'
PURPOSES = {'initiator_confirmation':32768,'responder_confirmation':32769,
            'initiator_traffic':32770,'responder_traffic':32771}
EXPORT_DOMAIN = b'OCTATRACE-FIELD-EXPORT-1'
CONFIRM_DOMAIN = b'OCTATRACE-FIELD-CONFIRM-1'


def fail():
    raise ValueError(ERROR)


def guarded(operation, *args):
    try:
        return operation(*args)
    except Exception:
        raise ValueError(ERROR) from None


@dataclass(frozen=True)
class UntrustedCredentialReference:
    ccs: bytes
    kid: bytes
    key_sha256: bytes
    id_cred: bytes


@dataclass(frozen=True)
class UntrustedPrelude:
    metadata: object = field(repr=False)
    def to_fields(self):
        return dict(self.metadata)


@dataclass(frozen=True)
class UntrustedExportRequest:
    label: int
    context: bytes
    length: int
    field_sha256: bytes


def credential(public_key, crypto):
    if type(public_key) is not bytes or len(public_key)!=65 or public_key[0]!=4:
        fail()
    if guarded(lambda:crypto.valid_public_key(public_key)) is not True:
        fail()
    ccs=BASE['cbor']({8:{1:{1:2,3:-7,-1:1,-2:public_key[1:33],-3:public_key[33:]}}})
    kid=hashlib.sha256(ccs).digest()[:8]
    return UntrustedCredentialReference(ccs,kid,hashlib.sha256(public_key).digest(),BASE['cbor']({4:kid}))


def resolve(kid,public_key,crypto):
    if type(kid) is not bytes or len(kid)!=8:
        fail()
    result=credential(public_key,crypto)
    if kid!=result.kid:
        fail()
    return result


def encode_prelude(value):
    if type(value) is not dict or set(value)!={'attempt_uuid','boot','nonce'}:
        fail()
    return (guarded(BASE['to_wire'],value['attempt_uuid'],'uuid')+
            guarded(BASE['hex_bytes'],value['boot'],16)+guarded(BASE['hex_bytes'],value['nonce'],32))


def decode_prelude(data,expected_attempt_uuid):
    if type(data) is not bytes or len(data)!=64:
        fail()
    expected=guarded(BASE['to_wire'],expected_attempt_uuid,'uuid')
    if data[:16]!=expected:
        fail()
    import uuid
    value={'attempt_uuid':str(uuid.UUID(bytes=data[:16])),'boot':data[16:32].hex(),'nonce':data[32:].hex()}
    encode_prelude(value)
    return UntrustedPrelude(MappingProxyType(value))


def export_request(purpose,data,expected):
    if type(purpose) is not str or purpose not in PURPOSES:
        fail()
    match=guarded(PROOF['match_field'],data,expected)
    if match.metadata['handshake_profile_sha256']!=PROFILE_SHA256.hex():
        fail()
    context=hashlib.sha256(EXPORT_DOMAIN+data).digest()
    return UntrustedExportRequest(PURPOSES[purpose],context,16,match.context_id)


def confirmation_aad(purpose,data,expected):
    if purpose not in ('initiator_confirmation','responder_confirmation'):
        fail()
    request=export_request(purpose,data,expected)
    kind=1 if expected['kind']=='phone_link' else 2
    flight=7 if purpose=='initiator_confirmation' else 8
    return CONFIRM_DOMAIN+bytes([kind,flight])+request.context


def receiver_selector(kind,attempt_uuid,recipient_key_sha256):
    """Public per-attempt receiver filter only; no permission or peer proof."""
    role=guarded(PROOF['to_wire'],kind,'kind')
    attempt=guarded(BASE['to_wire'],attempt_uuid,'uuid')
    recipient=guarded(BASE['hex_bytes'],recipient_key_sha256,32)
    return hashlib.sha256(b'OCTATRACE-FIELD-RECEIVER-1'+bytes([role])+attempt+recipient).digest()[:8]
