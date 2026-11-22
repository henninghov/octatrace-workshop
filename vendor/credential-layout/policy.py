"""Candidate T114 credential reservation; no flash IO or trust activation."""
import re

START = 0xdf000
END = 0xe1000
PAGE = 4096
PROFILE = 't114-nrf52840-s140v6-credential-reservation-v1'
SYMBOLS = {'__octatrace_credential_start': START, '__octatrace_credential_end': END}
ERROR = 'Invalid credential reservation'


def digest(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError(ERROR)
    return value


def capability(layout_lock, linker_guard):
    return {'version': 1, 'profile': PROFILE, 'start': hex(START), 'end_exclusive': hex(END),
            'page_bytes': PAGE, 'pages': 2, 'scope': 'reservation_only',
            'runtime_credential': False, 'maintenance_version': 0,
            'layout_lock_sha256': digest(layout_lock), 'linker_guard_sha256': digest(linker_guard)}


def compatible(manifest, expected):
    if type(manifest) is not dict or type(expected) is not dict:
        return False
    metadata = manifest.get('credential_storage_reservation')
    symbols = manifest.get('credential_storage_symbols')
    existing = manifest.get('phone_storage_reservation')
    if type(metadata) is not dict or metadata != expected or type(symbols) is not dict or type(existing) is not dict:
        return False
    if any(type(metadata.get(key)) is not type(value) for key, value in expected.items()):
        return False
    if set(symbols) != set(SYMBOLS) or any(type(symbols[key]) is not int or symbols[key] != value for key, value in SYMBOLS.items()):
        return False
    image_end = existing.get('__octatrace_image_end')
    return type(image_end) is int and 0x26000 <= image_end <= START
