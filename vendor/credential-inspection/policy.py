"""Owner validation of the read-only credential-inspection status."""
import re

FIELDS = frozenset(('v', 'id', 'ok', 'type', 'role', 'build', 'hardware', 'boot',
                    'state', 'busy', 'failed', 'last_request', 'sha256'))
STATES = frozenset(('unavailable', 'blank', 'unknown', 'recognizable', 'interrupted'))
MAX_ID = 0xffffffff


def _hex(value, length, nonzero=False):
    return (type(value) is str and len(value) == length and
            re.fullmatch('[0-9a-f]+', value) is not None and
            (not nonzero or any(c != '0' for c in value)))


def validate(value, request_id):
    if (type(value) is not dict or set(value) != FIELDS or
            type(request_id) is not int or not 1 <= request_id <= MAX_ID or
            type(value['v']) is not int or value['v'] != 1 or
            type(value['id']) is not int or value['id'] != request_id or
            value['ok'] is not True or type(value['type']) is not str or value['type'] != 'credential_storage' or
            type(value['role']) is not str or value['role'] not in ('Link', 'Core') or
            not _hex(value['build'], 64) or not _hex(value['hardware'], 16, True) or
            not _hex(value['boot'], 32, True) or type(value['state']) is not str or value['state'] not in STATES or
            type(value['busy']) is not bool or type(value['failed']) is not bool or
            type(value['last_request']) is not int or not 0 <= value['last_request'] <= MAX_ID or
            (value['busy'] and value['failed']) or
            ((value['busy'] or value['failed']) and value['last_request'] == 0)):
        raise ValueError('Invalid credential inspection status')
    if value['state'] == 'unavailable':
        if value['sha256'] != '':
            raise ValueError('Invalid credential inspection status')
    elif (value['busy'] or value['failed'] or value['last_request'] == 0 or
          not _hex(value['sha256'], 64)):
        raise ValueError('Invalid credential inspection status')
    return dict(value)
