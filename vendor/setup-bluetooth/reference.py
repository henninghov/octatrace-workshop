"""Host reference for the setup BLE contract. No radio, signing or authority writes."""
from dataclasses import dataclass
import struct
from uuid import UUID

CONTROL = struct.Struct('<BBBBHBBHBB')
TARGET = struct.Struct('<BBH16s')
PHONE_LINK, LINK_CORE = 1, 2
HELLO, SELECT, REJECT = 1, 2, 3
FIND, CANDIDATE_MATCHES, SEARCH_ENDED = 16, 17, 18
# Operation -> (GATT route, required v1 capabilities)
OPERATIONS = {1: (PHONE_LINK, 3), 2: (PHONE_LINK, 4), 3: (PHONE_LINK, 9),
              4: (LINK_CORE, 17), 5: (PHONE_LINK, 1)}


def require(condition):
    if not condition:
        raise ValueError('Invalid setup Bluetooth exchange')


def service_usable(profile, route, services):
    """Services are (UUID, [(characteristic UUID, property set), ...]) pairs."""
    spec = profile['routes'][str(route)]
    suffix = profile['uuid_suffix']
    matches = [chars for uuid, chars in services if uuid == spec['service'] + suffix]
    if len(matches) != 1:
        return False
    for field, prop in profile['gatt'].items():
        found = [props for uuid, props in matches[0] if uuid == spec[field] + suffix]
        if found != [{prop}]:
            return False
    return True


def read_offer(data, route):
    require(type(data) is bytes and len(data) == CONTROL.size)
    version, kind, hop, operation, request, low, high, features, reason, reserved = CONTROL.unpack(data)
    require(version == 1 and kind == HELLO and hop == route and hop in (PHONE_LINK, LINK_CORE)
            and request > 0 and 0 < low <= high and reason == reserved == 0)
    return operation, request, low, high, features


def respond(offer, route, local_features, *, supports_v1=True):
    """Pure selection after GATT access/subscription and fresh-request checks."""
    operation, request, low, high, offered = read_offer(offer, route)
    required = OPERATIONS.get(operation)
    if required is None or required[0] != route:
        reason = 1
    elif not supports_v1 or not low <= 1 <= high:
        reason = 2
    elif offered & local_features & required[1] != required[1]:
        reason = 3
    else:
        return CONTROL.pack(1, SELECT, route, operation, request, 1, 1, required[1], 0, 0)
    return CONTROL.pack(1, REJECT, route, operation, request, 0, 0, 0, reason, 0)


@dataclass(frozen=True)
class Selection:
    generation: int
    route: int
    operation: int
    request: int


class Connection:
    """One endpoint on one GATT generation. Closing invalidates all of its tickets."""
    def __init__(self, profile, route, generation, services, subscriptions, *, access_admitted):
        require(route in (PHONE_LINK, LINK_CORE) and type(generation) is int and generation > 0)
        require(access_admitted is True and service_usable(profile, route, services))
        spec = profile['routes'][str(route)]
        require(all(spec[field] + profile['uuid_suffix'] in subscriptions
                    for field in ('control_notify', 'record_notify')))
        self.route = route
        self.generation = generation
        self.last_request = 0
        self.pending = None
        self.selected = None
        self.target_started = False

    def begin(self, generation, offer):
        require(generation == self.generation and self.generation > 0 and self.pending is None)
        _, request, _, _, _ = read_offer(offer, self.route)
        require(request > self.last_request)
        self.cancel()
        self.last_request = request
        self.pending = offer

    def finish(self, generation, reply):
        require(generation == self.generation and self.generation > 0 and self.pending is not None)
        require(type(reply) is bytes and len(reply) == CONTROL.size)
        _, kind, _, _, _, _, _, _, reason, _ = CONTROL.unpack(reply)
        operation, request, _, _, _ = read_offer(self.pending, self.route)
        if kind == REJECT:
            expected = CONTROL.pack(1, REJECT, self.route, operation, request, 0, 0, 0, reason, 0)
            require(reason in (1, 2, 3) and reply == expected)
        else:
            require(kind == SELECT and reply == respond(self.pending, self.route, 0xffff))
            self.selected = Selection(generation, self.route, operation, request)
        self.pending = None
        return self.selected

    def cancel(self):
        self.pending = None
        self.selected = None
        self.target_started = False

    def close(self):
        self.cancel()
        self.generation = 0


def target_message(selection, kind, target):
    require(selection.route == PHONE_LINK and selection.operation == 2
            and kind in (FIND, CANDIDATE_MATCHES, SEARCH_ENDED))
    uid = UUID(target)
    require(uid.version == 4 and str(uid) == target)
    return TARGET.pack(1, kind, selection.request, uid.bytes)


class Search:
    """The protected phone request names one immutable target on this LINK session."""
    def __init__(self, connection, generation, expected, request):
        self.selection = connection.selected
        require(self.selection is not None and self.selection.generation == generation
                and not connection.target_started and expected['role'] == 'Core')
        self.expected = dict(expected)
        self.target = expected['device_uuid']
        require(request == target_message(self.selection, FIND, self.target))
        self.connection = connection
        connection.target_started = True
        self.done = False

    def check_current(self):
        require(not self.done and self.connection.selected == self.selection)

    def match(self, core_connection, ticket, credential, verify_credential):
        self.check_current()
        peer = core_connection.selected
        require(peer is not None and peer == ticket
                and peer.route == LINK_CORE and peer.operation == 4)
        # The pinned verifier raises on any issuer, signature, role or audience mismatch.
        verify_credential(credential, self.expected)
        return self._finish(CANDIDATE_MATCHES)

    def end(self):
        return self._finish(SEARCH_ENDED)

    def _finish(self, kind):
        self.check_current()
        self.done = True
        return target_message(self.selection, kind, self.target)


def target_outcome(connection, ticket, target, data):
    require(ticket is not None and connection.selected == ticket)
    for kind in (CANDIDATE_MATCHES, SEARCH_ENDED):
        if data == target_message(ticket, kind, target):
            return kind
    raise ValueError('Unexpected CORE search result')


def boot_route(journal):
    """Consume a verified Journal.read() for the local CORE, including its history."""
    context = journal.context
    require(context.local['resource_role'] == 'Core')
    local_core = context.local['resource_uuid']
    loaded = journal.read()
    if loaded.status != 'Ready':
        return 'recovery_required'
    if loaded.snapshot.find('core_link', local_core) is None:
        return 'first_setup'
    if context.eligible(loaded.snapshot, 'core_link', local_core):
        return 'configured_link'
    return 'recovery_required'


class DiscoveryWindow:
    """Allocate once per CORE boot. Input times are monotonic milliseconds."""
    def __init__(self):
        self.first_start = None

    def advertising_started(self, now_ms):
        if self.first_start is None:
            self.first_start = now_ms

    def open(self, boot_state, now_ms):
        return (boot_state == 'first_setup' and self.first_start is not None
                and 0 <= now_ms - self.first_start < 300_000)
