"""C8.1.5 host transition model and exact frames; not an EDHOC provider."""
from dataclasses import dataclass
import hashlib
from pathlib import Path

PROFILE_HASH = hashlib.sha256((Path(__file__).parent / 'profile.json').read_bytes()).digest()
SERVICE = 'c10a0300-0595-4016-9495-aeeb59da74f9'
WRITE = 'c10a0301-0595-4016-9495-aeeb59da74f9'
NOTIFY = 'c10a0302-0595-4016-9495-aeeb59da74f9'


def require(value):
    if not value:
        raise ValueError('First-channel contract rejected')


def service_usable(services, subscriptions):
    """The service is a compatibility check, not authenticated identity."""
    matches = [chars for uuid, chars in services if uuid == SERVICE]
    if len(matches) != 1:
        return False
    for uuid, required in ((WRITE, 'write_with_response'), (NOTIFY, 'notify')):
        found = [properties for name, properties in matches[0] if name == uuid]
        if found != [{required}]:
            return False
    return NOTIFY in subscriptions


def valid_size(flight, size):
    return (type(flight) is int and 1 <= flight <= 8 and type(size) is int and 0 < size <= 256
            and ((flight <= 2 and size == 64) or 3 <= flight <= 6 or (flight >= 7 and size == 48)))


def frame(flight, message, index):
    require(type(message) is bytes and valid_size(flight, len(message)) and type(index) is int
            and 0 <= index < (len(message) + 11) // 12)
    payload = message[index * 12:(index + 1) * 12]
    return b'OH\x03\x02' + bytes([flight]) + len(message).to_bytes(2, 'little') + bytes([index]) + payload.ljust(12, b'\0')


def decode(raw):
    require(type(raw) is bytes and len(raw) == 20 and raw[:4] == b'OH\x03\x02')
    flight, total, index = raw[4], int.from_bytes(raw[5:7], 'little'), raw[7]
    require(valid_size(flight, total) and index < (total + 11) // 12)
    used = min(12, total - index * 12)
    require(raw[8 + used:] == bytes(12 - used))
    return flight, total, index, raw[8:8 + used]


@dataclass(frozen=True)
class Context:
    """Values loaded by trusted current-authority/boot and connection adapters."""
    generation: int
    attempt: bytes
    authority: bytes
    link: bytes
    core: bytes
    link_key: bytes
    core_key: bytes
    link_boot: bytes
    core_boot: bytes
    link_nonce: bytes
    core_nonce: bytes
    environment: int
    profile_hash: bytes = PROFILE_HASH

    def valid(self):
        sizes = ((self.attempt, 16), (self.authority, 32), (self.link, 16), (self.core, 16),
                 (self.link_key, 32), (self.core_key, 32), (self.link_boot, 16), (self.core_boot, 16),
                 (self.link_nonce, 32), (self.core_nonce, 32))
        return (type(self.generation) is int and self.generation > 0 and type(self.environment) is int
                and self.environment in (1, 2) and type(self.profile_hash) is bytes and self.profile_hash == PROFILE_HASH
                and all(type(value) is bytes and len(value) == size and any(value) for value, size in sizes)
                and all((self.attempt[6] & 0xf0 == 0x40, self.attempt[8] & 0xc0 == 0x80,
                         self.link[6] & 0xf0 == 0x40, self.link[8] & 0xc0 == 0x80,
                         self.core[6] & 0xf0 == 0x40, self.core[8] & 0xc0 == 0x80))
                and self.link != self.core and self.link_key != self.core_key
                and self.link_boot != self.core_boot and self.link_nonce != self.core_nonce)


class Attempt:
    """Model adapter obligations. confirm is trusted crypto, not packet metadata."""
    def __init__(self, role, context, now, deadline, clock, read_current, confirm, adopt, invalidate, clear):
        require(role in ('Link', 'Core') and isinstance(context, Context) and context.valid())
        require(type(now) is int and type(deadline) is int and 0 <= now < deadline)
        require(all(callable(x) for x in (clock, read_current, confirm, adopt, invalidate, clear)))
        self.role, self.context, self.last, self.deadline = role, context, now, deadline
        self.clock, self.read_current, self.confirm = clock, read_current, confirm
        self.adopt, self.invalidate, self.clear = adopt, invalidate, clear
        self.state = 'pending'

    def _current(self):
        now = self.clock()
        if type(now) is not int or not self.last <= now < self.deadline or self.read_current() != self.context:
            return False
        self.last = now
        return True

    def cancel(self):
        if self.state not in ('retired', 'adopted'):
            handoff = self.state == 'handoff'
            self.state = 'retired'
            try:
                if handoff:
                    try:
                        self.invalidate(self.context)
                    except Exception:
                        # Radio owner must remain disabled if invalidation is uncertain.
                        pass
            finally:
                try:
                    self.clear()
                except Exception:
                    # Caller must halt the owner when cleanup cannot be established.
                    pass

    def finish(self, proof):
        if self.state != 'pending':
            return False
        try:
            if not self._current():
                self.cancel()
                return False
            # Must verify actual EDHOC, transcript, expected role and protected confirmation.
            if (self.confirm(self.role, self.context, proof) is not True or self.state != 'pending'
                    or not self._current()):
                self.cancel()
                return False
            self.state = 'handoff'
            # Owner guards the atomic handoff and invalidates partial/uncertain adoption.
            if self.adopt(self.role, self.context) is not True or self.state != 'handoff' or not self._current():
                self.cancel()
                return False
        except Exception:
            self.cancel()
            return False
        try:
            self.clear()
        except Exception:
            self.cancel()
            return False
        self.state = 'adopted'
        return True
