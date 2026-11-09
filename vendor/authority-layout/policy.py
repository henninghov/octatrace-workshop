"""Pinned T114 reservation/manifest policy. Not an authority writer or secure boot."""
import re
START = 0xe1000
END = 0xe7000
PAGE = 4096
TOTAL = END-START
PROFILE = 't114-nrf52840-s140v6-authority-v1'
SYMBOLS = {'__octatrace_authority_start':START,'__octatrace_authority_end':END,
 '__octatrace_control_start':0xe7000,'__octatrace_control_end':0xe9000,
 '__octatrace_client_start':0xe9000,'__octatrace_client_end':0xeb000,
 '__octatrace_bond_start':0xeb000,'__octatrace_bond_end':0xed000,
 '__octatrace_identity_start':0xed000,'__octatrace_identity_end':0xef000}
ERROR = 'Invalid authority reservation'


def digest(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}',value):
        raise ValueError(ERROR)
    return value


def capability(layout_lock, journal_lock):
    return {'version':1,'profile':PROFILE,'start':hex(START),'end_exclusive':hex(END),
      'page_bytes':PAGE,'pages':6,'bank_bytes':8192,'banks':3,'journal_version':1,
      'scope':'reservation_only','runtime_authority':False,'maintenance_version':0,
      'layout_lock_sha256':digest(layout_lock),'journal_lock_sha256':digest(journal_lock)}


def compatible(manifest, expected):
    if type(manifest) is not dict:
        return False
    metadata=manifest.get('authority_storage_reservation')
    symbols=manifest.get('phone_storage_reservation')
    if type(metadata) is not dict or metadata!=expected or type(symbols) is not dict:
        return False
    # bool compares equal to integer1 in Python; require exact JSON types too.
    if any(type(metadata.get(k)) is not type(v) for k,v in expected.items()):
        return False
    if any(type(symbols.get(k)) is not int or symbols[k]!=v for k,v in SYMBOLS.items()):
        return False
    end=symbols.get('__octatrace_image_end')
    return type(end) is int and 0x26000<=end<=START


def resource_budget(image_end, static_ram, workspace):
    for value in [image_end,static_ram,workspace]:
        if type(value) is not int or value<0:
            raise ValueError(ERROR)
    if not 0x26000<=image_end<=START or workspace>12288 or static_ram+workspace>237568:
        raise ValueError(ERROR)
    return {'application_capacity':START-0x26000,'image_end':image_end,
      'flash_bytes_before_authority':START-image_end,'static_ram':static_ram,
      'isolated_workspace':workspace,'ram_after_static_and_workspace':237568-static_ram-workspace,
      'boundary':'Static arithmetic only; no live SDK/task/heap/interrupt or physical stack high-water qualification'}
