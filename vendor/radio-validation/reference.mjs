// Host reference only. Real CCM/HKDF with synthetic inputs; not EDHOC or a device adapter.
import { createCipheriv, createDecipheriv, createHash, hkdfSync, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const PROFILE_HASH = createHash('sha256').update(readFileSync(new URL('./profile.json', import.meta.url))).digest();
export const RADIO_HANDSHAKE_HASH = createHash('sha256').update(readFileSync(new URL('../field-handshake/profile.json', import.meta.url))).digest('hex');
const ROLES = { Core: 1, Link: 2 };
const SENDERS = { 1: 2, 2: 1, 3: 2, 4: 1 };
const KEY_DOMAIN = Buffer.from('OCTATRACE-RADIO-VALIDATION-KEY-1');
const AAD_DOMAIN = Buffer.from('OCTATRACE-RADIO-VALIDATION-AAD-1');
const SELECT_DOMAIN = Buffer.from('OCTATRACE-RADIO-VALIDATION-SELECTOR-1');

function requireValue(value) { if (!value) throw new Error('Invalid radio validation'); }
function fixed(value, n) { return Buffer.isBuffer(value) && value.length === n && value.some(x => x !== 0); }
function equal(a, b) { return a.length === b.length && timingSafeEqual(a, b); }

export class RadioOwner {
  // Host object simulates one serialized owner for one current confirmed channel.
  constructor(role, fieldContext, linkKey, coreKey, challengeCapacity) {
    requireValue(Object.hasOwn(ROLES, role) && fixed(fieldContext, 32) && fixed(linkKey, 16) && fixed(coreKey, 16) && !equal(linkKey, coreKey) &&
      Number.isSafeInteger(challengeCapacity) && challengeCapacity > 0);
    this.role = ROLES[role];
    this.context = Buffer.from(fieldContext);
    this.selector = createHash('sha256').update(SELECT_DOMAIN).update(this.context).digest().subarray(0, 8);
    this.keys = {};
    for (const [n, input] of [[1, coreKey], [2, linkKey]]) {
      this.keys[n] = Buffer.from(hkdfSync('sha256', input, this.context, Buffer.concat([KEY_DOMAIN, Buffer.from([n])]), 16));
    }
    this.counter = 0;
    this.highest = 0;
    this.seen = new Map();
    this.challenges = new Set();
    this.challengeCapacity = challengeCapacity;
  }
  nonce(counter) {
    const nonce = Buffer.alloc(13);
    nonce.write('OVP1', 0, 'ascii');
    nonce.writeUInt32LE(counter, 9);
    return nonce;
  }
  aad(header) { return Buffer.concat([AAD_DOMAIN, PROFILE_HASH, this.context, header]); }
  seal(kind, challenge) {
    requireValue(SENDERS[kind] === this.role && fixed(challenge, 16) && this.counter < 0xffffffff);
    this.counter += 1; // Consumed before the primitive; never reset under these keys.
    const header = Buffer.alloc(18);
    header.write('OV', 0, 'ascii'); header[2] = 1; header[3] = kind;
    this.selector.copy(header, 4); header[12] = this.role; header.writeUInt32LE(this.counter, 13); header[17] = 16;
    const cipher = createCipheriv('aes-128-ccm', this.keys[this.role], this.nonce(this.counter), { authTagLength: 16 });
    cipher.setAAD(this.aad(header), { plaintextLength: 16 });
    const encrypted = Buffer.concat([cipher.update(challenge), cipher.final()]);
    return Buffer.concat([header, encrypted, cipher.getAuthTag()]);
  }
  open(packet) {
    if (!Buffer.isBuffer(packet) || packet.length !== 50 || packet.toString('ascii', 0, 2) !== 'OV' || packet[2] !== 1 ||
        !equal(packet.subarray(4, 12), this.selector) || packet[12] === this.role || SENDERS[packet[3]] !== packet[12] ||
        packet[17] !== 16) return null;
    const counter = packet.readUInt32LE(13);
    if (!counter) return null;
    let challenge;
    try {
      const decipher = createDecipheriv('aes-128-ccm', this.keys[packet[12]], this.nonce(counter), { authTagLength: 16 });
      decipher.setAuthTag(packet.subarray(34, 50));
      decipher.setAAD(this.aad(packet.subarray(0, 18)), { plaintextLength: 16 });
      challenge = Buffer.concat([decipher.update(packet.subarray(18, 34)), decipher.final()]);
    } catch { return null; }
    if (!fixed(challenge, 16)) return null;
    if (counter + 64 <= this.highest) return null;
    if (this.seen.has(counter)) {
      if (!equal(this.seen.get(counter), packet)) return null;
      return { kind: packet[3], challenge, duplicate: true };
    }
    this.highest = Math.max(this.highest, counter);
    this.seen.set(counter, Buffer.from(packet));
    for (const n of this.seen.keys()) if (n + 64 <= this.highest) this.seen.delete(n);
    return { kind: packet[3], challenge, duplicate: false };
  }
}

export class Attempt {
  // current() is only a trusted live-authority/context guard; open() performs CCM.
  constructor(owner, now, deadline, maxTransmissions, current, challenge = null) {
    requireValue(owner instanceof RadioOwner && Number.isSafeInteger(now) && Number.isSafeInteger(deadline) &&
      now >= 0 && now < deadline && Number.isSafeInteger(maxTransmissions) && maxTransmissions > 0 && typeof current === 'function');
    this.owner = owner; this.last = now; this.deadline = deadline; this.limit = maxTransmissions; this.current = current;
    this.phase = owner.role === 2 ? 'wait-response' : 'wait-challenge';
    this.challenge = null; this.pending = null; this.replies = new Map(); this.cache = new Map();
    if (owner.role === 2) {
      requireValue(fixed(challenge, 16) && owner.challenges.size < owner.challengeCapacity && !owner.challenges.has(challenge.toString('hex')));
      owner.challenges.add(challenge.toString('hex'));
      this.challenge = Buffer.from(challenge);
      this.queue(1);
    } else requireValue(challenge === null);
  }
  live(now) {
    let current = false;
    try { current = this.current() === true; } catch { current = false; }
    if (!Number.isSafeInteger(now) || now < this.last || !current) {
      this.phase = 'failed'; this.pending = null; this.cache.clear(); this.replies.clear(); return false;
    }
    this.last = now;
    if (now >= this.deadline) {
      if (this.phase !== 'ready') this.phase = 'failed';
      this.pending = null; this.cache.clear(); this.replies.clear(); return false;
    }
    return this.phase !== 'failed';
  }
  queue(kind) {
    let frame;
    try { frame = this.owner.seal(kind, this.challenge); } catch { this.cancel(); return null; }
    const entry = { frame, count: 0 };
    this.cache.set(kind, entry); this.pending = entry;
    return entry;
  }
  afterCrypto(clock) {
    try { return this.live(clock()); } catch { this.cancel(); return false; }
  }
  transmit(now, airtime, clock) {
    if (typeof clock !== 'function') { this.cancel(); return null; }
    if (!this.live(now) || !this.pending || typeof airtime !== 'function') return null;
    if (this.pending.count >= this.limit) { this.phase = 'failed'; this.pending = null; return null; }
    const entry = this.pending;
    let admitted = false, after;
    try { admitted = airtime(entry.frame.length) === true; after = clock(); } catch { this.cancel(); return null; }
    if (!this.live(after) || !admitted || this.pending !== entry) return null;
    this.pending.count += 1;
    // Caller owns this independent immutable copy until its driver completion.
    return Buffer.from(this.pending.frame);
  }
  receive(now, packet, clock) {
    if (typeof clock !== 'function') { this.cancel(); return false; }
    if (!this.live(now)) return false;
    const opened = this.owner.open(packet);
    let after;
    try { after = clock(); } catch { this.cancel(); return false; }
    if (!this.live(after) || !opened) return false;
    const id = packet.toString('hex');
    if (opened.duplicate) {
      const response = this.replies.get(id);
      if (!response) return false;
      this.pending = response;
      return true;
    }
    if (this.owner.role === 1 && this.phase === 'wait-challenge' && opened.kind === 1) {
      const key = opened.challenge.toString('hex');
      if (this.owner.challenges.size >= this.owner.challengeCapacity || this.owner.challenges.has(key)) return false;
      this.owner.challenges.add(key); this.challenge = Buffer.from(opened.challenge);
      const reply = this.queue(2);
      if (!reply || !this.afterCrypto(clock)) return false;
      this.phase = 'wait-ack';
      this.replies.set(id, reply); return true;
    }
    if (!this.challenge || !equal(opened.challenge, this.challenge)) return false;
    if (this.owner.role === 2 && this.phase === 'wait-response' && opened.kind === 2) {
      const reply = this.queue(3);
      if (!reply || !this.afterCrypto(clock)) return false;
      this.phase = 'wait-confirmation';
      this.replies.set(id, reply); return true;
    }
    if (this.owner.role === 1 && this.phase === 'wait-ack' && opened.kind === 3) {
      const reply = this.queue(4);
      if (!reply || !this.afterCrypto(clock)) return false;
      this.phase = 'ready';
      this.replies.set(id, reply); return true;
    }
    if (this.owner.role === 2 && this.phase === 'wait-confirmation' && opened.kind === 4) {
      this.phase = 'ready'; this.pending = null; return true;
    }
    return false;
  }
  ready() {
    try { return this.phase === 'ready' && this.current() === true; } catch { return false; }
  }
  cancel() { this.phase = 'failed'; this.pending = null; this.cache.clear(); this.replies.clear(); }
}

const hex = (value, bytes) => typeof value === 'string' && new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(value) && /[1-9a-f]/.test(value);
const uuid = value => hex(value, 16) && value[12] === '4' && '89ab'.includes(value[16]);
const identityFields = ['authority', 'link', 'core', 'linkBoot', 'coreBoot'];
function validInstalled(value) {
  return value && value.eligible === true && hex(value.authority, 32) && uuid(value.link) && uuid(value.core) &&
    value.link !== value.core && hex(value.linkBoot, 16) && hex(value.coreBoot, 16) && value.linkBoot !== value.coreBoot;
}
function sameInstalled(a, b) { return validInstalled(a) && validInstalled(b) && identityFields.every(k => a[k] === b[k]); }

export class Recovery {
  // Verifier and adopter are trusted integration ports; this model does not execute EDHOC.
  constructor(now, installed, clock, current, verifyHandshake, adopt, invalidate, clear, previous = null) {
    requireValue(Number.isSafeInteger(now) && now >= 0 && now <= Number.MAX_SAFE_INTEGER - 300000 && validInstalled(installed) &&
      [clock, current, verifyHandshake, adopt, invalidate, clear].every(x => typeof x === 'function') &&
      (previous === null || (hex(previous.context, 32) && hex(previous.linkBoot, 16) && hex(previous.coreBoot, 16) &&
        (previous.attempt === undefined || uuid(previous.attempt)) &&
        (previous.linkNonce === undefined || hex(previous.linkNonce, 32)) &&
        (previous.coreNonce === undefined || hex(previous.coreNonce, 32)))));
    this.last = now; this.deadline = now + 300000; this.installed = Object.freeze({ ...installed });
    this.clock = clock; this.current = current; this.verifyHandshake = verifyHandshake; this.adopt = adopt;
    this.invalidate = invalidate; this.clear = clear; this.previous = previous && Object.freeze({ ...previous }); this.state = 'pending';
  }
  live() {
    try {
      const now = this.clock();
      if (!Number.isSafeInteger(now) || now < this.last || now >= this.deadline || !sameInstalled(this.installed, this.current())) return false;
      this.last = now;
    } catch { return false; }
    return true;
  }
  cancel() {
    if (this.state === 'retired' || this.state === 'adopted') return;
    const pending = this.state === 'adopting'; this.state = 'retired';
    try { if (pending) this.invalidate(); } catch { /* The real owner remains disabled on uncertainty. */ }
    try { this.clear(); } catch { /* The real owner halts on uncertain cleanup. */ }
  }
  finish(input) {
    if (this.state !== 'pending') return false;
    try {
      const proof = input && Object.freeze({ ...input, installed: Object.freeze({ ...input.installed }) });
      if (!this.live() || !proof || proof.profile !== RADIO_HANDSHAKE_HASH || !sameInstalled(this.installed, proof.installed) ||
          !uuid(proof.attempt) || !hex(proof.linkNonce, 32) || !hex(proof.coreNonce, 32) || proof.linkNonce === proof.coreNonce ||
          !hex(proof.context, 32) || (this.previous && (proof.context === this.previous.context ||
            proof.attempt === this.previous.attempt || proof.linkNonce === this.previous.linkNonce || proof.coreNonce === this.previous.coreNonce ||
            (this.installed.linkBoot === this.previous.linkBoot && this.installed.coreBoot === this.previous.coreBoot)))) {
        this.cancel(); return false;
      }
      if (this.verifyHandshake(proof) !== true || this.state !== 'pending' || !this.live()) { this.cancel(); return false; }
      this.state = 'adopting';
      if (this.adopt(proof) !== true || this.state !== 'adopting' || !this.live()) { this.cancel(); return false; }
      this.clear();
      if (this.state !== 'adopting' || !this.live()) { this.cancel(); return false; }
      this.state = 'adopted'; return true;
    } catch { this.cancel(); return false; }
  }
}
