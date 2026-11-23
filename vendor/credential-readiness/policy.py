"""Strict validation of the read-only startup credential readiness response."""
import re
FIELDS = frozenset(('v','id','ok','type','role','build','hardware','boot','state','revision','content_id'))
STATES = frozenset(('unavailable','empty','ready','pending'))
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
            value['ok'] is not True or type(value['type']) is not str or value['type'] != 'credential_readiness' or
            type(value['role']) is not str or value['role'] not in ('Link','Core') or
            not _hex(value['build'],64) or not _hex(value['hardware'],16,True) or
            not _hex(value['boot'],32,True) or type(value['state']) is not str or value['state'] not in STATES or
            type(value['revision']) is not int or not 0 <= value['revision'] <= MAX_ID):
        raise ValueError('Invalid credential readiness response')
    if value['state'] == 'ready':
        if not value['revision'] or not _hex(value['content_id'],64):
            raise ValueError('Invalid credential readiness response')
    elif value['revision'] != 0 or value['content_id'] != '':
        raise ValueError('Invalid credential readiness response')
    return dict(value)
