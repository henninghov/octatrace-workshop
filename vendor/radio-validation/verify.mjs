// Replays public synthetic vectors with real host AES-CCM; no device claim.
import { readFileSync } from 'node:fs';
import { RadioOwner, PROFILE_HASH } from './reference.mjs';

const v = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
if (v.profile_sha256 !== PROFILE_HASH.toString('hex') || v.frames.length !== 4) throw Error('profile or vector inventory mismatch');
const context = Buffer.from(v.field_context, 'hex'), lk = Buffer.from(v.synthetic_link_key, 'hex');
const ck = Buffer.from(v.synthetic_core_key, 'hex'), challenge = Buffer.from(v.challenge, 'hex');
const link = new RadioOwner('Link', context, lk, ck, 8), core = new RadioOwner('Core', context, lk, ck, 8);
for (let i = 0; i < 4; i++) {
  const sender = i % 2 ? core : link, receiver = i % 2 ? link : core;
  const raw = sender.seal(i + 1, challenge);
  if (raw.toString('hex') !== v.frames[i]) throw Error('vector mismatch');
  const opened = receiver.open(raw);
  if (!opened || opened.kind !== i + 1 || !opened.challenge.equals(challenge)) throw Error('vector authentication mismatch');
  const bad = Buffer.from(raw); bad[49] ^= 1;
  if (receiver.open(bad) !== null) throw Error('tampered tag accepted');
}
console.log(JSON.stringify({ result: 'pass', level: 'synthetic AES-CCM host only', vectors: 4 }));
