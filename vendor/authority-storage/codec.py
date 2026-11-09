"""Bounded authority-storage reference; no target registration, trust discovery or RF.

Three relative banks; two matching committed copies are required for Installed.
Configured factory bindings/issuers and a trusted current-operation guard are external.
"""
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import runpy
import struct
import zlib

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'device-authority.lock.json').is_file())
PIN = json.loads((ROOT/'device-authority.lock.json').read_text())
AUTH = runpy.run_path(str(ROOT/PIN['path']/'codec.py'))
BASE = AUTH['BASE']
PAGE = 4096
BANK = 8192
BANKS = 3
SIZE = BANK * BANKS
HEADER = 64
CAPACITY = BANK - HEADER
MAX_RECORDS = 24
MAGIC = b'OCTAAS01'
ERROR = 'Authority storage operation denied'
BINDING = ('environment',) + AUTH['AUDIENCE']
PURPOSES = AUTH['PURPOSES']


def fail():
    raise ValueError(ERROR)


def guarded(operation, *args):
    try:
        return operation(*args)
    except Exception:
        raise ValueError(ERROR) from None


def number(value, minimum=1):
    return guarded(BASE['uint'], value, minimum)


def binding(value):
    if type(value) is not dict or set(value) != set(BINDING):
        fail()
    guarded(AUTH['to_wire'], value['environment'], 'environment')
    for name in AUTH['AUDIENCE']:
        guarded(AUTH['to_wire'], value[name], dict(AUTH['COMMON'])[name])
    return dict(value, resource_key_revision=number(value['resource_key_revision']))


def prefix(value):
    b = binding(value)
    return [1, AUTH['to_wire'](b['environment'], 'environment'), AUTH['to_wire'](b['resource_uuid'], 'uuid'),
            AUTH['to_wire'](b['resource_role'], 'role'), bytes.fromhex(b['resource_key_sha256']), b['resource_key_revision']]


def uncbor(data):
    """Bounded snapshot parser; b1's 512-byte credential parser remains unchanged."""
    if type(data) is not bytes or not 0 < len(data) <= CAPACITY:
        fail()
    cursor = 0
    def read(depth=0):
        nonlocal cursor
        if depth > 3 or cursor >= len(data):
            fail()
        initial = data[cursor]
        cursor += 1
        major, ai = initial >> 5, initial & 31
        n = ai
        if ai >= 24:
            sizes = {24:1, 25:2, 26:4}
            if ai not in sizes or cursor+sizes[ai] > len(data):
                fail()
            n = int.from_bytes(data[cursor:cursor+sizes[ai]], 'big')
            cursor += sizes[ai]
            if n < {24:24, 25:256, 26:65536}[ai]:
                fail()
        if major == 0:
            return n
        if major == 2:
            if cursor+n > len(data):
                fail()
            result = data[cursor:cursor+n]
            cursor += n
            return result
        if major == 4:
            if n > MAX_RECORDS:
                fail()
            return [read(depth+1) for _ in range(n)]
        fail()
    result = read()
    if cursor != len(data) or guarded(BASE['cbor'], result) != data:
        fail()
    return result


@dataclass(frozen=True)
class Entry:
    raw: bytes = field(repr=False)
    authority: object = field(repr=False)

    @property
    def key(self):
        m = self.authority.metadata
        return PURPOSES[m['purpose']], m['resource_uuid']


@dataclass(frozen=True)
class Snapshot:
    payload: bytes = field(repr=False)
    entries: tuple = field(repr=False)

    def find(self, purpose, resource):
        for entry in self.entries:
            m = entry.authority.metadata
            if m['purpose'] == purpose and m['resource_uuid'] == resource:
                return entry.authority
        return None


class Context:
    """Caller supplies trusted factory bindings and configured issuer trust, never a QR flag."""
    def __init__(self, local, registry, issuers, crypto):
        self.local = binding(local)
        if type(registry) is not dict or not 0 < len(registry) <= 64:
            fail()
        self.registry = {}
        for key, value in registry.items():
            b = binding(value)
            if key != b['resource_uuid'] or b['environment'] != self.local['environment']:
                fail()
            self.registry[key] = {n:b[n] for n in AUTH['AUDIENCE']}
        if self.registry.get(self.local['resource_uuid']) != {n:self.local[n] for n in AUTH['AUDIENCE']}:
            fail()
        self.issuers = guarded(json.loads, guarded(json.dumps, issuers))
        self.crypto = crypto

    def entry(self, raw):
        if type(raw) is not bytes or not 0 < len(raw) <= AUTH['MAX_OBJECT']:
            fail()
        # Untrusted extraction only selects an already-configured intended audience.
        envelope = guarded(BASE['uncbor'], raw[1:])
        try:
            payload = BASE['uncbor'](envelope[2])
            resource = AUTH['from_wire'](payload[6], 'uuid')
            expected = self.registry[resource]
        except Exception:
            fail()
        a = guarded(AUTH['verify'], raw, self.local['environment'], self.issuers, self.crypto, expected)
        m = a.metadata
        if m['purpose'] == 'phone_controller' and (self.local['resource_role'] != 'Link' or resource != self.local['resource_uuid']):
            fail()
        if m['purpose'] == 'core_link':
            if self.local['resource_role'] == 'Core' and resource != self.local['resource_uuid']:
                fail()
            if self.local['resource_role'] == 'Link' and m['state'] == 'grant' and m['link_uuid'] != self.local['resource_uuid']:
                fail()
        return Entry(raw, a)

    def encode(self, raws):
        if type(raws) not in (list, tuple) or len(raws) > MAX_RECORDS:
            fail()
        entries = sorted((self.entry(raw) for raw in raws), key=lambda e:e.key)
        if len({e.key for e in entries}) != len(entries):
            fail()
        data = guarded(BASE['cbor'], prefix(self.local) + [[e.raw for e in entries]])
        if len(data) > CAPACITY:
            fail()
        return Snapshot(data, tuple(entries))

    def decode(self, data):
        if type(data) is not bytes or not 0 < len(data) <= CAPACITY:
            fail()
        value = uncbor(data)
        if type(value) is not list or len(value) != 7 or value[:6] != prefix(self.local):
            fail()
        snapshot = self.encode(value[6])
        if data != snapshot.payload:
            fail()
        return snapshot

    def owners(self, snapshot, policy):
        m = policy.metadata
        owner = snapshot.find('ownership_receipt', m['resource_uuid'])
        subject = snapshot.find('ownership_receipt', m['link_uuid']) if m['purpose']=='core_link' and m['state']=='grant' else None
        guarded(AUTH['check_owners'], policy, owner, subject)

    def transition(self, old, new):
        previous = {e.key:e for e in old.entries}
        current = {e.key:e for e in new.entries}
        if not previous.keys() <= current.keys():
            fail()  # No pruning of high-water marks or removals in v1.
        for key, e in current.items():
            prior = previous.get(key)
            result = guarded(AUTH['compare_revision'], e.authority, None if prior is None else prior.authority)
            if result != 'retry' and e.authority.metadata['purpose'] != 'ownership_receipt':
                self.owners(new, e.authority)

    def merge(self, old, raw):
        entry = self.entry(raw)
        previous = next((e for e in old.entries if e.key == entry.key), None)
        if previous is not None and guarded(AUTH['compare_revision'], entry.authority, previous.authority) == 'retry':
            return old
        new = self.encode([e.raw for e in old.entries if e.key != entry.key] + [raw])
        self.transition(old, new)
        return new

    def eligible(self, snapshot, purpose, resource):
        """Current stored policy context only; never fresh peer readiness or command admission."""
        policy = snapshot.find(purpose, resource)
        if policy is None or policy.metadata.get('state') != 'grant':
            return False
        try:
            self.owners(snapshot, policy)
        except ValueError:
            return False
        return True


def bank_bytes(generation, payload):
    generation = number(generation)
    if type(payload) is not bytes or not 0 < len(payload) <= CAPACITY:
        fail()
    first = MAGIC + struct.pack('<III', 1, generation, len(payload)) + hashlib.sha256(payload).digest()
    header = first + struct.pack('<I', zlib.crc32(first)) + b'\0'*4 + b'\xff'*4
    return header + payload + b'\xff'*(CAPACITY-len(payload))


def parse_bank(data, context):
    if type(data) is not bytes or len(data) != BANK:
        fail()
    if data == b'\xff'*BANK:
        return None
    if data[56:60] != b'\0'*4:
        return 'torn'
    version, generation, length = struct.unpack('<III', data[8:20])
    if data[:8] != MAGIC or version != 1 or not generation or not 0 < length <= CAPACITY or data[60:64] != b'\xff'*4:
        fail()
    payload = data[HEADER:HEADER+length]
    if (zlib.crc32(data[:52]) != struct.unpack('<I', data[52:56])[0] or
            hashlib.sha256(payload).digest() != data[20:52] or data[HEADER+length:] != b'\xff'*(CAPACITY-length)):
        fail()
    return generation, context.decode(payload)


@dataclass(frozen=True)
class Loaded:
    status: str
    generation: int = 0
    snapshot: object = field(default=None, repr=False)
    copies: tuple = ()


class Journal:
    def __init__(self, io, context):
        self.io, self.context = io, context

    def read(self):
        try:
            data = [guarded(self.io.read, i*BANK, BANK) for i in range(BANKS)]
        except ValueError:
            return Loaded('Unavailable')
        try:
            rows = [parse_bank(row, self.context) for row in data]
            valid = [(i,row) for i,row in enumerate(rows) if type(row) is tuple]
            if not valid:
                return Loaded('Unprepared' if all(row is None for row in rows) else 'Fault')
            generations = sorted({row[0] for _,row in valid})
            if generations[-1] - generations[0] > 1:
                fail()
            groups = {}
            for i, (generation, snapshot) in valid:
                if generation in groups and groups[generation][0].payload != snapshot.payload:
                    fail()
                if generation not in groups:
                    groups[generation] = (snapshot, [])
                groups[generation][1].append(i)
            if len(generations) == 2:
                self.context.transition(groups[generations[0]][0], groups[generations[1]][0])
            generation = generations[-1]
            snapshot, copies = groups[generation]
            if len(copies) >= 2:
                return Loaded('Ready', generation, snapshot, tuple(copies))
            # A single old copy can never authorise fallback after quorum loss.
            if generation == 1 and not snapshot.entries or len(generations) == 2:
                return Loaded('Pending', generation, snapshot, tuple(copies))
            fail()
        except ValueError:
            return Loaded('Fault')

    def write_copy(self, index, generation, snapshot, guard):
        def allowed():
            if guarded(guard) is not True:
                fail()
        allowed()
        for page in range(BANK//PAGE):
            if guarded(self.io.erase_page, index*(BANK//PAGE)+page) is not True:
                fail()
            allowed()
        raw = bank_bytes(generation, snapshot.payload)
        parts = [(0, raw[:56]), (HEADER, snapshot.payload + b'\xff'*(-len(snapshot.payload)%4))]
        for offset, part in parts:
            for start in range(0, len(part), 128):
                allowed()
                chunk = part[start:start+128]
                address = index*BANK+offset+start
                if guarded(self.io.program, address, chunk) is not True or guarded(self.io.read, address, len(chunk)) != chunk:
                    fail()
        allowed()
        guarded(self.io.program, index*BANK+56, b'\0'*4)
        # The commit callback is not the durability result: always reload exact bytes.
        readback = guarded(self.io.read, index*BANK, BANK)
        if readback != raw:
            fail()

    def publish(self, generation, snapshot, targets, guard):
        try:
            for target in targets:
                self.write_copy(target, generation, snapshot, guard)
        except ValueError:
            pass
        final = self.read()
        if final.status == 'Ready' and final.generation == generation and final.snapshot.payload == snapshot.payload:
            return 'installed'
        fail()

    def prepare(self, authorised):
        if guarded(authorised) is not True:
            fail()
        state = self.read()
        empty = self.context.encode([])
        if state.status == 'Ready' and state.generation == 1 and state.snapshot.payload == empty.payload:
            return 'unchanged'
        if state.status == 'Pending' and state.generation == 1 and state.snapshot.payload == empty.payload:
            return self.recover(authorised, preparation=True)
        if state.status != 'Unprepared':
            fail()
        return self.publish(1, empty, (0, 1), authorised)

    def install(self, raw, guard):
        if guarded(guard) is not True:
            fail()
        state = self.read()
        if state.status != 'Ready':
            fail()
        desired = self.context.merge(state.snapshot, raw)
        if desired.payload == state.snapshot.payload:
            return 'unchanged'
        generation = number(state.generation+1)
        spare = next((i for i in range(BANKS) if i not in state.copies), state.copies[0])
        second = next(i for i in state.copies if i != spare)
        return self.publish(generation, desired, (spare, second), guard)

    def recover(self, guard, preparation=False):
        if guarded(guard) is not True:
            fail()
        state = self.read()
        if state.status == 'Ready':
            return 'unchanged'
        if state.status != 'Pending':
            fail()
        if state.generation == 1:
            # Empty preparation needs the same trusted preparation authority again.
            if preparation is not True:
                fail()
        target = next(i for i in range(BANKS) if i not in state.copies)
        return self.publish(state.generation, state.snapshot, (target,), guard)
