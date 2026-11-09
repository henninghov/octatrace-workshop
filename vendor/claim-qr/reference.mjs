// Independent generic CBOR reference, used only with public synthetic vectors.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';

const prefix = 'OCTATRACE-CLAIM-1:';
const fields = ['v','environment','role','device_uuid','public_key_sha256','claim_secret'];
function fail() { throw Error('Invalid claim QR'); }
function valid(x) {
  if (x === null || typeof x !== 'object' || Array.isArray(x) ||
      Object.keys(x).sort().join() !== [...fields].sort().join() || x.v !== 1) fail();
  if (!['development','production'].includes(x.environment) || !['Link','Core'].includes(x.role)) fail();
  if (typeof x.device_uuid !== 'string' || x.device_uuid.length !== 36 ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(x.device_uuid)) fail();
  for (const key of ['public_key_sha256','claim_secret']) {
    if (typeof x[key] !== 'string' || x[key].length !== 64 || !/^[0-9a-f]{64}$/.test(x[key]) || /^0+$/.test(x[key])) fail();
  }
}
function head(major, n) { return Buffer.from(n < 24 ? [(major << 5) | n] : [(major << 5) | 24, n]); }
function cbor(value) {
  if (typeof value === 'number') return head(0,value);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2,value.length),value]);
  return Buffer.concat([head(5,value.size),...[...value].flatMap(([k,v]) => [cbor(k),cbor(v)])]);
}
export function encode(x) {
  valid(x);
  const map = new Map([[1,1],[2,x.environment === 'development' ? 1 : 2],[3,x.role === 'Link' ? 1 : 2],
    [4,Buffer.from(x.device_uuid.replaceAll('-',''),'hex')],[5,Buffer.from(x.public_key_sha256,'hex')],
    [6,Buffer.from(x.claim_secret,'hex')]]);
  return prefix+cbor(map).toString('base64url');
}
export function decode(text, environment) {
  if (typeof text !== 'string' || text.length !== 145 || !text.startsWith(prefix) ||
      !['development','production'].includes(environment)) fail();
  const body=text.slice(prefix.length);
  if (!/^[A-Za-z0-9_-]{127}$/.test(body)) fail();
  const bytes=Buffer.from(body,'base64url');
  if (bytes.toString('base64url') !== body) fail();
  let cursor=0;
  function take(n) {
    if (cursor+n>bytes.length) fail();
    const result=bytes.subarray(cursor,cursor+n);cursor+=n;return result;
  }
  function read(top=false) {
    const first=take(1)[0], major=first>>5, ai=first&31;
    if (ai>24) fail();
    const n=ai===24 ? take(1)[0] : ai;
    if (major===0) return n;
    if (major===2) return take(n);
    if (major!==5 || !top || n!==6) fail();
    const map=new Map();
    for (let i=0;i<n;i++) {
      const key=read();if (typeof key!=='number' || map.has(key)) fail();map.set(key,read());
    }
    return map;
  }
  const map=read(true);
  if (!(map instanceof Map) || cursor!==bytes.length || [...map.keys()].sort().join()!=='1,2,3,4,5,6') fail();
  for (const [key,size] of [[4,16],[5,32],[6,32]]) if (!Buffer.isBuffer(map.get(key)) || map.get(key).length!==size) fail();
  const id=map.get(4).toString('hex');
  const x={v:map.get(1),environment:({1:'development',2:'production'})[map.get(2)],
    role:({1:'Link',2:'Core'})[map.get(3)],device_uuid:[id.slice(0,8),id.slice(8,12),id.slice(12,16),id.slice(16,20),id.slice(20)].join('-'),
    public_key_sha256:map.get(5).toString('hex'),claim_secret:map.get(6).toString('hex')};
  valid(x);if (x.environment!==environment || encode(x)!==text) fail();return x;
}
if (process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  const vectors=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
  for (const row of vectors.valid) {
    assert.equal(encode(row.fields),row.text,row.name);
    assert.deepEqual(decode(row.text,row.fields.environment),row.fields,row.name);
  }
  for (const row of vectors.invalid_text) assert.throws(()=>decode(row.text,row.environment),/Invalid claim QR/,row.name);
  for (const row of vectors.invalid_fields) assert.throws(()=>encode(row.fields),/Invalid claim QR/,row.name);
  console.log(JSON.stringify({valid:vectors.valid.length,invalid_text:vectors.invalid_text.length,invalid_fields:vectors.invalid_fields.length}));
}
