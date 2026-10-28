// Mirrored into the firmware-owned provisioning contract; pins prevent drift.
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hex = (value, size) => typeof value === 'string'
  && value.length === size * 2 && /^[0-9a-f]+$/.test(value);
const bytes = (value) => Uint8Array.from(value.match(/../g), (byte) => parseInt(byte, 16));
const fields = ['v', 'id', 'ok', 'type', 'role', 'build', 'hardware', 'boot', 'state',
  'busy', 'failed', 'device_id', 'serial', 'article_id', 'article_revision_id',
  'algorithm', 'public_key', 'challenge', 'signature'].sort();

export function proofMessage(frame) {
  return new TextEncoder().encode(`OCTATRACE-USB-PROVISIONING-1\n${frame.challenge}\n${frame.device_id}\n${frame.serial}\n${frame.article_id}\n${frame.article_revision_id}\n${frame.hardware}\n${frame.build}\n${frame.boot}\n`);
}

function validFrame(frame, attempt) {
  return frame && typeof frame === 'object' && !Array.isArray(frame)
    && JSON.stringify(Object.keys(frame).sort()) === JSON.stringify(fields)
    && frame.v === 1 && Number.isInteger(frame.id) && frame.id > 0 && frame.id <= 4294967295
    && frame.ok === true && frame.type === 'identity' && ['Link', 'Core'].includes(frame.role)
    && frame.role === (attempt.role === undefined ? 'Link' : attempt.role)
    && frame.state === 'ready' && frame.busy === false && frame.failed === false
    && frame.algorithm === 'P256-SHA256'
    && uuid.test(frame.device_id) && uuid.test(frame.article_id) && uuid.test(frame.article_revision_id)
    && /^D[0-9]{12}$/.test(frame.serial) && frame.serial !== 'D000000000000'
    && hex(frame.hardware, 8) && frame.hardware !== '0000000000000000'
    && hex(frame.build, 32) && hex(frame.boot, 16) && frame.boot !== '0'.repeat(32)
    && hex(frame.challenge, 32) && frame.challenge !== '0'.repeat(64)
    && hex(frame.public_key, 65) && frame.public_key.startsWith('04') && hex(frame.signature, 64)
    && frame.device_id === attempt.device_id && frame.serial === attempt.serial
    && frame.article_id === attempt.article_id && frame.article_revision_id === attempt.article_revision_id
    && frame.hardware === attempt.hardware && frame.build === attempt.source
    && frame.challenge === attempt.challenge;
}

export async function verifyProofs(report, attempt, subtle) {
  if (!report || typeof report !== 'object' || Array.isArray(report)
    || JSON.stringify(Object.keys(report).sort()) !== '["after","before"]'
    || !validFrame(report.before, attempt) || !validFrame(report.after, attempt)
    || report.before.boot === report.after.boot
    || report.before.public_key !== report.after.public_key
    || (attempt.public_key !== null && attempt.public_key !== report.before.public_key)) return false;
  try {
    const key = await subtle.importKey('raw', bytes(report.before.public_key),
      { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    for (const frame of [report.before, report.after]) {
      if (!await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key,
        bytes(frame.signature), proofMessage(frame))) return false;
    }
    return true;
  } catch {
    return false;
  }
}
