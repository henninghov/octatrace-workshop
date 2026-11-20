"""Host contract for signed setup delivery, with current BLE/transfer and journal owners."""
from dataclasses import dataclass
import hashlib
import json
import sqlite3
from pathlib import Path
import runpy
import struct
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
WIRE = runpy.run_path(str(ROOT / 'setup-transfer/codec.py'))
STORAGE = runpy.run_path(str(ROOT / 'authority-storage/codec.py'))
AUTH = STORAGE['AUTH']
OPEN, ACCEPT, BUSY, REFUSE, CANCEL = range(0xb0, 0xb5)
HEADER = struct.Struct('<BBH16s')
POLICIES = ('ownership_receipt', 'phone_controller', 'core_link')
INPUTS = ('factory_credential', *POLICIES)
STAGED = {'core_credential':(0x11, 'factory_credential'), 'core_owner':(0x12, 'ownership_receipt'),
          'link_credential':(0x21, 'factory_credential'), 'link_owner':(0x22, 'ownership_receipt'),
          'pair_grant':(0x34, 'core_link')}
SELECTORS = {name:number for name,(number, _) in WIRE['KINDS'].items()}
SELECTORS.update({name:code for name,(code, _) in STAGED.items()})
RECORDS = {number:name for name, number in SELECTORS.items()}


def require(condition):
    if not condition:
        raise ValueError('Setup bootstrap denied')


def control(code, kind, transfer, delivery):
    require(code in (OPEN, ACCEPT, BUSY, REFUSE, CANCEL) and kind in RECORDS.values())
    return HEADER.pack(code, SELECTORS[kind], WIRE['number'](transfer, 65535), WIRE['uuid_bytes'](delivery))


def parse(data):
    require(type(data) is bytes and len(data) == HEADER.size)
    code, kind, transfer, raw = HEADER.unpack(data)
    require(kind in RECORDS)
    result = code, RECORDS[kind], transfer, str(UUID(bytes=raw))
    require(control(*result) == data)
    return result


class Budget:
    """One admitted logical attempt owns an absolute monotonic deadline across retries."""
    def __init__(self, clock, deadline):
        self.clock, self.deadline = clock, deadline
        self.last = clock()
        require(type(self.last) is int and type(deadline) is int and 0 <= self.last < deadline)
        self.cancelled = False

    def live(self):
        now = self.clock()
        if type(now) is not int or not self.last <= now < self.deadline:
            self.cancelled = True
        else:
            self.last = now
        return not self.cancelled

    def cancel(self):
        self.cancelled = True


class ReceiveLane:
    """One receiver per connection and direction. Preserve high-water across selections."""
    def __init__(self, connection, upstream):
        self.connection = connection
        self.upstream = upstream  # peripheral to central
        self.last_id = 0
        self.pending = None
        self.assembly = None

    def close(self):
        if self.assembly is not None:
            self.assembly.close()
        self.assembly = self.pending = None

    def offer(self, ticket, data, target, budget):
        code, kind, transfer, correlation = parse(data)
        require(code == OPEN and ticket is not None and self.connection.selected == ticket)
        require((ticket.route, ticket.operation) in ((1, 3), (1, 5), (2, 4)))
        if self.pending and (self.connection.selected != self.pending[0] or not self.pending[3].live()):
            self.close()
        if not budget.live():
            return control(REFUSE, kind, transfer, correlation)
        if self.pending is not None:
            if self.pending == (ticket, data, target, budget):
                return control(ACCEPT, kind, transfer, correlation)
            return control(BUSY, kind, transfer, correlation)
        allowed = ('factory_credential', 'installation_report') if self.upstream else (*INPUTS, *STAGED, 'phone_custody')
        if (transfer <= self.last_id or kind not in allowed or
                (kind == 'phone_controller' and ticket.operation != 5)):
            return control(REFUSE, kind, transfer, correlation)
        self.assembly = WIRE['Reassembly'](ticket.generation, transfer, target, correlation)
        self.pending = (ticket, data, target, budget)
        self.last_id = transfer
        return control(ACCEPT, kind, transfer, correlation)

    def receive(self, ticket, frame):
        require(self.pending is not None and ticket == self.pending[0])
        _, data, _, budget = self.pending
        if self.connection.selected != ticket or not budget.live():
            self.close()
            raise ValueError('Expired setup transfer')
        # Reject foreign frames without displacing a valid pending transfer.
        fragment = WIRE['parse_frame'](frame)
        _, kind, transfer, _ = parse(data)
        require(fragment.transfer == transfer)
        try:
            record = self.assembly.accept(ticket.generation, frame)
            if record is not None:
                require(record.kind == (STAGED[kind][1] if kind in STAGED else kind))
                self.close()
                return Received(kind, record)
            return record
        except ValueError:
            self.close()
            raise

    def cancel(self, ticket, message):
        require(self.pending is not None and self.pending[0] == ticket and self.connection.selected == ticket)
        _, data, _, budget = self.pending
        require(message == bytes([CANCEL]) + data[1:])
        budget.cancel()
        self.close()


@dataclass(frozen=True)
class Received:
    selector: str
    record: object


class StagedContext:
    """Five bounded public slots for a single selected recipient and delivery."""
    def __init__(self, target, delivery, still_current):
        self.target, self.delivery = target, delivery
        self.still_current = still_current
        self.parts = {}

    def active(self):
        if not self.still_current():
            self.parts.clear()
            raise ValueError('Stale setup context')

    def add(self, received):
        self.active()
        slot, rec = received.selector, received.record
        require(slot in STAGED and STAGED[slot][1] == rec.kind
                and (rec.device_uuid, rec.correlation_uuid) == (self.target, self.delivery))
        require(slot not in self.parts or self.parts[slot] == rec.body)
        self.parts[slot] = rec.body

    def resolve(self, expected, environment, issuers, crypto):
        self.active()
        require(set(expected) in ({'Link'}, {'Core', 'Link'}))
        bindings = {}
        for role, hints in expected.items():
            key = role.lower()
            require(hints['resource_role'] == role and key+'_owner' in self.parts
                    and key+'_credential' in self.parts)
            binding = factory_binding(environment, issuers, crypto, hints,
                                      self.parts[key+'_owner'], self.parts[key+'_credential'])
            bindings[binding['resource_uuid']] = binding
        require(len(bindings) == len(expected) and self.target in bindings)
        return bindings


class DriverSlot:
    """One serialized physical TX owner. Retire only on the matching driver callback."""
    def __init__(self):
        self.pending = None

    def submit(self, frame, still_current):
        require(self.pending is None and type(frame) is bytes and len(frame) == 20 and still_current())
        token = object()
        self.pending = (token, frame, still_current)
        return token

    def complete(self, token):
        require(self.pending is not None and token is self.pending[0])
        _, _, still_current = self.pending
        self.pending = None
        return still_current()


def factory_binding(environment, issuers, crypto, expected, owner_envelope, credential):
    """Resolve a candidate public key using both issuer domains before creating a journal audience."""
    audience = {k: expected[k] for k in AUTH['AUDIENCE']}
    owner = AUTH['verify'](owner_envelope, environment, issuers, crypto, audience)
    require(owner.metadata['purpose'] == 'ownership_receipt')
    identity = AUTH['BASE']['verify'](credential, environment, issuers, crypto, {
        'device_uuid': audience['resource_uuid'], 'role': audience['resource_role'],
        'public_key_sha256': audience['resource_key_sha256']})
    require(identity.metadata['key_revision'] == audience['resource_key_revision'])
    return dict(audience, environment=environment)


def owner_binding(owner):
    m = owner.metadata
    require(m['purpose'] == 'ownership_receipt')
    return tuple(m[key] for key in ('environment', 'owner_ref', 'ownership_epoch', *AUTH['AUDIENCE']))


def approved(journal, record, release, *, resource_owner, target_owner, carrier_owner, relationship=None):
    """Bind untrusted input to independent signed release context and local factory audience."""
    ctx = journal.context
    source = ctx.entry(record.body).authority
    owners = [ctx.entry(raw).authority for raw in (resource_owner, target_owner, carrier_owner)]
    resource, target, carrier = owners
    rb, tb, cb = [owner_binding(item) for item in owners]
    m, r, t, c = (a.metadata for a in (source, resource, target, carrier))
    require(rb[:2] == tb[:2] == cb[:2] and c['resource_role'] == 'Link')
    require(all(t[k] == ctx.local[k] for k in STORAGE['BINDING']))
    require(t['resource_role'] != 'Link' or tb == cb)
    require(record.kind == m['purpose'] and record.device_uuid == t['resource_uuid'])
    require(record.correlation_uuid == release['delivery_uuid'])
    expected = {k: m[k] for k in ('v', 'environment', 'purpose', 'resource_uuid', 'object_uuid',
                                    'revision', 'owner_ref', 'ownership_epoch')}
    expected.update(delivery_uuid=record.correlation_uuid, target_uuid=record.device_uuid,
                    target_role=t['resource_role'], target_key_sha256=t['resource_key_sha256'],
                    target_key_revision=t['resource_key_revision'], content_sha256=source.content_id.hex())
    require(expected == release and all(type(release[k]) is type(v) for k, v in expected.items()))
    require(all(m[k] == r[k] for k in ('environment', 'owner_ref', 'ownership_epoch', *AUTH['AUDIENCE'])))
    local = journal.read()
    require(local.status == 'Ready')
    for owner in owners:
        AUTH['compare_revision'](owner, local.snapshot.find('ownership_receipt', owner.metadata['resource_uuid']))
    if m['purpose'] == 'ownership_receipt':
        require(source.content_id == resource.content_id)
    elif m['purpose'] == 'core_link' and m['state'] == 'grant':
        require(relationship is not None)
    else:
        AUTH['check_owners'](source, resource)
        require(rb == tb and relationship is None)
    if relationship is not None:
        grant_raw, core_owner_raw = relationship
        policy = ctx.entry(grant_raw).authority
        p = policy.metadata
        require(p['purpose'] == 'core_link' and p['state'] == 'grant')
        core = ctx.entry(core_owner_raw).authority
        AUTH['compare_revision'](core, local.snapshot.find('ownership_receipt', core.metadata['resource_uuid']))
        for candidate in (resource, target):
            if candidate.metadata['resource_role'] == 'Core':
                require(candidate.content_id == core.content_id)
            else:
                require(owner_binding(candidate) == cb)
        AUTH['check_owners'](policy, core, carrier)
        require({r['resource_uuid'], t['resource_uuid']} <= {p['resource_uuid'], c['resource_uuid']})
        AUTH['compare_revision'](policy, local.snapshot.find('core_link', p['resource_uuid']))
        if m['purpose'] == 'core_link':
            require(source.content_id == policy.content_id)
    else:
        require(rb == tb)
    return cb


def snapshot_hash(state):
    return hashlib.sha256(state.snapshot.payload).hexdigest()


class Leg:
    """Trusted adapter inputs. A proof callback returns the current authenticated courier
    binding for this ticket, or None. At CORE, receipt return also requires a courier
    that obtained this specific phone ACK over an authenticated phone connection.
    """
    def __init__(self, connection, ticket, budget, carrier_proof):
        self.connection, self.ticket, self.budget = connection, ticket, budget
        self.carrier_proof = carrier_proof

    def current(self, role, owner, fixed, *, returning=None):
        if self.ticket is None or self.ticket != self.connection.selected or not self.budget.live():
            return False
        route, op = self.ticket.route, self.ticket.operation
        if (route, op) not in (((1, 5),) if role == 'Link' else ((1, 3), (2, 4))):
            return False
        if route == 2 and returning is None:
            return True  # Signed-only ingress. No proof or permission is inferred.
        binding = self.carrier_proof(self.ticket, returning)
        return (binding is not None and len(binding) == 7 and binding[:2] == owner and binding[4] == 'Link'
                and (fixed is None or binding == fixed))

    def accepted(self, callback_ticket, offer, reply, role, owner, fixed):
        code, _, _, _ = parse(offer)
        return (callback_ticket == self.ticket and code == OPEN and reply == bytes([ACCEPT]) + offer[1:]
                and self.current(role, owner, fixed))


class EvidenceStore:
    """Host-only fixed report slots. One serialized installer owns one target's journal.
    SQLite models durable transitions. Native placement and flash capacity are later gates.
    """
    def __init__(self, path, capacity):
        require(type(capacity) is int and capacity > 0)
        self.capacity = capacity
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('''CREATE TABLE IF NOT EXISTS evidence (
            delivery TEXT PRIMARY KEY, binding TEXT NOT NULL, scope TEXT NOT NULL, source BLOB NOT NULL,
            base_gen INTEGER NOT NULL, base_hash TEXT NOT NULL, generation INTEGER NOT NULL,
            snapshot TEXT NOT NULL, report BLOB NOT NULL, used INTEGER NOT NULL, content BLOB NOT NULL)''')

    def row(self, delivery):
        return self.db.execute('SELECT * FROM evidence WHERE delivery=?', (delivery,)).fetchone()

    def reserve(self, release, fixed, raw, state, desired):
        generation = state.generation + int(desired.payload != state.snapshot.payload)
        require(generation <= 0xffffffff)
        with self.db:
            # Acquire the writer before checking capacity or pending intents.
            self.db.execute('BEGIN IMMEDIATE')
            count, pending = self.db.execute('SELECT count(*), count(*) FILTER (WHERE used=0) FROM evidence').fetchone()
            require(count < self.capacity and pending == 0)
            self.db.execute('INSERT INTO evidence VALUES (?,?,?,?,?,?,?,?,zeroblob(384),0,zeroblob(32))',
                            (release['delivery_uuid'], json.dumps(release, sort_keys=True), json.dumps(fixed),
                             raw, state.generation, snapshot_hash(state), generation,
                             hashlib.sha256(desired.payload).hexdigest()))

    def install(self, journal, record, release, leg, sign, verify, **context):
        # A forwarded phone->LINK operation may stage a CORE object, never install it on LINK.
        role = journal.context.local['resource_role']
        release = dict(release)
        require(leg.ticket is not None and leg.ticket.route == (1 if role == 'Link' else 2))
        require(release['target_uuid'] == journal.context.local['resource_uuid'] == record.device_uuid
                and release['target_role'] == role and release['delivery_uuid'] == record.correlation_uuid)
        carrier = owner_binding(journal.context.entry(context['carrier_owner']).authority)
        fixed = carrier if role == 'Link' or context.get('relationship') is not None else None
        owner = release['environment'], release['owner_ref']
        require(carrier[:2] == owner and carrier[4] == 'Link')
        def guard():
            return leg.current(role, owner, fixed)
        require(guard())
        delivery = record.correlation_uuid
        row = self.row(delivery)
        if row is None:
            approved(journal, record, release, **context)
            state = journal.read()
            require(state.status == 'Ready')
            desired = journal.context.merge(state.snapshot, record.body)
            require(guard())
            self.reserve(release, fixed, record.body, state, desired)
            row = self.row(delivery)
        # Compare stored binding on all retries, including after a later grant/removal.
        require(row['binding'] == json.dumps(release, sort_keys=True) and row['scope'] == json.dumps(fixed)
                and record.kind == release['purpose'])
        if row['source'] != record.body:
            alternate = journal.context.entry(record.body).authority
            require(alternate.content_id.hex() == release['content_sha256'])
        if row['used']:
            saved = self.original(row, verify)
            require(guard())
            return saved
        state = journal.read()
        destination = row['generation'], row['snapshot']
        if state.status == 'Pending':
            require((state.generation, snapshot_hash(state)) == destination and guard())
            journal.recover(guard)
        elif state.status == 'Ready' and (state.generation, snapshot_hash(state)) != destination:
            require((state.generation, snapshot_hash(state)) == (row['base_gen'], row['base_hash']))
            approved(journal, record, release, **context)
            journal.install(row['source'], guard)
        state = journal.read()
        require(state.status == 'Ready' and (state.generation, snapshot_hash(state)) == destination and guard())
        installed = state.snapshot.find(release['purpose'], release['resource_uuid'])
        require(installed is not None and installed.content_id.hex() == release['content_sha256'])
        fields = dict(release, journal_generation=state.generation, snapshot_sha256=destination[1])
        envelope = sign(dict(fields))
        require(type(envelope) is bytes and 0 < len(envelope) <= 384)
        content = verify(envelope, dict(fields))
        require(type(content) is bytes and len(content) == 32 and any(content) and guard())
        with self.db:
            updated = self.db.execute('UPDATE evidence SET report=?, used=?, content=? WHERE delivery=? AND used=0',
                                      (envelope.ljust(384, b'\0'), len(envelope), content, delivery))
            require(updated.rowcount == 1)
        saved = self.original(self.row(delivery), verify)
        require(saved == envelope and guard())
        return saved

    def original(self, row, verify):
        require(0 < row['used'] <= 384 and len(row['report']) == 384)
        fields = dict(json.loads(row['binding']), journal_generation=row['generation'], snapshot_sha256=row['snapshot'])
        envelope = row['report'][:row['used']]
        require(verify(envelope, fields) == row['content'])
        return envelope

    def custody(self, record, leg):
        require(record.kind == 'phone_custody')
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.row(record.correlation_uuid)
            if row is None:
                return False  # A repeated ACK has no effect.
            fields = json.loads(row['binding'])
            fixed = json.loads(row['scope'])
            receipt = (record.device_uuid, record.correlation_uuid, record.body)
            require(row['used'] > 0 and record.body == row['content'] and record.device_uuid == fields['target_uuid'])
            require(leg.ticket is not None and leg.ticket.route == (1 if fields['target_role'] == 'Link' else 2))
            require(leg.current(fields['target_role'], (fields['environment'], fields['owner_ref']),
                                tuple(fixed) if fixed else None, returning=receipt))
            self.db.execute('DELETE FROM evidence WHERE delivery=?', (record.correlation_uuid,))
        return True

    def abandon_unwritten(self, delivery, journal, authorized):
        """Serialized local cancellation can reclaim only an uncommitted, unreported intent."""
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            row = self.row(delivery)
            require(row is not None and row['used'] == 0 and authorized() is True)
            state = journal.read()
            require(state.status == 'Ready' and (state.generation, snapshot_hash(state)) ==
                    (row['base_gen'], row['base_hash']) and row['generation'] != state.generation)
            require(json.loads(row['binding'])['target_uuid'] == journal.context.local['resource_uuid'])
            self.db.execute('DELETE FROM evidence WHERE delivery=?', (delivery,))
