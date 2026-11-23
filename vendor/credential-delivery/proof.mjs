import * as crypto from 'node:crypto';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const serial = /^D[0-9]{12}$/;
const hex = (v,n) => typeof v === 'string' && v.length === n*2 && /^[0-9a-f]+$/.test(v);
const nonzero = (v,n) => hex(v,n) && v !== '0'.repeat(n*2);
const uint = v => Number.isInteger(v) && v > 0 && v <= 0xffffffff;
const keys = ['v','id','ok','type','role','build','boot','hardware','device_id','serial',
  'article_id','article_revision_id','transfer_id','challenge','credential_revision',
  'content_id','envelope_sha256','signature'].sort();

// Input values have already passed strict shape validation in verifyResult().
export function proofMessage(frame) {
  return Buffer.from([
    'OCTATRACE-CREDENTIAL-DELIVERY-1', frame.role, frame.build, frame.boot,
    frame.hardware, frame.device_id, frame.serial, frame.article_id, frame.article_revision_id,
    String(frame.transfer_id), frame.challenge, String(frame.credential_revision),
    frame.content_id, frame.envelope_sha256, ''
  ].join('\n'),'ascii');
}

// expected is selected independently, never taken from the returned frame.
export function verifyResult(frame, expected) {
  if (!frame || typeof frame !== 'object' || Array.isArray(frame) ||
      JSON.stringify(Object.keys(frame).sort()) !== JSON.stringify(keys) ||
      !expected || typeof expected !== 'object' || Array.isArray(expected) ||
      frame.v !== 1 || !uint(frame.id) || frame.ok !== true || frame.type !== 'credential_delivery' ||
      !['Link','Core'].includes(frame.role) || !hex(frame.build,32) || !nonzero(frame.boot,16) ||
      !nonzero(frame.hardware,8) || !uuid.test(frame.device_id) || !serial.test(frame.serial) ||
      frame.serial === 'D000000000000' || !uuid.test(frame.article_id) || !uuid.test(frame.article_revision_id) ||
      !uint(frame.transfer_id) || !nonzero(frame.challenge,32) || !uint(frame.credential_revision) ||
      !nonzero(frame.content_id,32) || !nonzero(frame.envelope_sha256,32) || !hex(frame.signature,64) ||
      !hex(expected.public_key,65) || !expected.public_key.startsWith('04') ||
      frame.role !== expected.role || frame.build !== expected.source || frame.boot !== expected.boot ||
      frame.hardware !== expected.hardware || frame.device_id !== expected.device_id || frame.serial !== expected.serial ||
      frame.article_id !== expected.article_id || frame.article_revision_id !== expected.article_revision_id ||
      frame.transfer_id !== expected.transfer_id || frame.challenge !== expected.challenge ||
      frame.credential_revision !== expected.credential_revision || frame.content_id !== expected.content_id ||
      frame.envelope_sha256 !== expected.envelope_sha256) return false;
  try {
    const raw=Buffer.from(expected.public_key,'hex');
    crypto.ECDH.convertKey(raw,'prime256v1');
    const key=crypto.createPublicKey({format:'jwk', key:{kty:'EC',crv:'P-256',
      x:raw.subarray(1,33).toString('base64url'),y:raw.subarray(33).toString('base64url')}});
    return crypto.verify('sha256',proofMessage(frame),{key,dsaEncoding:'ieee-p1363'},Buffer.from(frame.signature,'hex'));
  } catch { return false; }
}
