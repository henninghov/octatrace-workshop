// Independent COSE/CBOR + Node/OpenSSL reference. Public synthetic fixtures only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash, createPublicKey, ECDH, verify as checkSignature} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const aad=Buffer.from('OCTATRACE-DEVICE-CREDENTIAL-1');
const layout=[['v','version'],['purpose','purpose'],['environment','environment'],['credential_uuid','uuid'],
  ['credential_revision','revision'],['device_uuid','uuid'],['role','role'],['key_revision','revision'],
  ['public_key','point'],['serial','serial'],['article_uuid','uuid'],['article_revision_uuid','uuid'],['hardware_uid','hardware']];
const maps={purpose:{device_identity:1},environment:{development:1,production:2},role:{Link:1,Core:2}};
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function fail(){throw Error('Invalid device credential');}
function hex(value,n,prefix=''){
  if(typeof value!=='string'||value.length!==n*2||!new RegExp('^[0-9a-f]{'+n*2+'}$').test(value)||!value.startsWith(prefix)||/^0+$/.test(value))fail();
  return Buffer.from(value,'hex');
}
function convert(value,kind){
  if(kind==='version'||kind==='revision'){
    if(!Number.isInteger(value)||value<1||value>4294967295||(kind==='version'&&value!==1))fail();return value;
  }
  if(typeof value!=='string')fail();
  if(maps[kind]){if(!Object.hasOwn(maps[kind],value))fail();return maps[kind][value];}
  if(kind==='uuid'){if(value.length!==36||!uuid.test(value))fail();return Buffer.from(value.replaceAll('-',''),'hex');}
  if(kind==='serial'){if(value.length!==13||!/^([DRO])[0-9]{12}$/.test(value)||/^0+$/.test(value.slice(1)))fail();return value;}
  return kind==='point'?hex(value,65,'04'):hex(value,8);
}
export function fields(value){
  const names=[...layout.map(x=>x[0]),'issuer_kid'].sort().join();
  if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join()!==names)fail();
  const payload=new Map(layout.map(([name,kind],i)=>[i+1,convert(value[name],kind)]));
  return {payload,kid:hex(value.issuer_kid,8)};
}
function head(major,number){
  const n=BigInt(number);if(n<0n||n>0xffffffffffffffffn)fail();
  if(n<24n)return Buffer.from([(major<<5)|Number(n)]);
  const size=[1,2,4,8].find(s=>n<(1n<<BigInt(s*8))),out=Buffer.alloc(size+1);
  out[0]=(major<<5)|({1:24,2:25,4:26,8:27})[size];let x=n;
  for(let i=size;i>0;i--){out[i]=Number(x&255n);x>>=8n;}return out;
}
export function cbor(value,depth=0){
  if(depth>4)fail();
  if(typeof value==='bigint'||(typeof value==='number'&&Number.isSafeInteger(value))){
    const n=BigInt(value);return n>=0n?head(0,n):head(1,-1n-n);
  }
  if(Buffer.isBuffer(value)||typeof value==='string'){
    const data=Buffer.isBuffer(value)?value:Buffer.from(value,'utf8');if(data.length>512)fail();
    return Buffer.concat([head(Buffer.isBuffer(value)?2:3,data.length),data]);
  }
  if(Array.isArray(value)){if(value.length>32)fail();return Buffer.concat([head(4,value.length),...value.map(x=>cbor(x,depth+1))]);}
  if(!(value instanceof Map)||value.size>32)fail();
  const pairs=[...value].map(([k,v])=>{if(typeof k!=='number'||!Number.isInteger(k))fail();return [cbor(k,depth+1),cbor(v,depth+1)];});
  pairs.sort((a,b)=>Buffer.compare(a[0],b[0]));return Buffer.concat([head(5,pairs.length),...pairs.flat()]);
}
function uncbor(bytes){
  if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>512)fail();let cursor=0;
  function take(n){if(n>bytes.length-cursor)fail();const result=bytes.subarray(cursor,cursor+n);cursor+=n;return result;}
  function read(depth){
    if(depth>4)fail();const first=take(1)[0],major=first>>5,ai=first&31;let n;
    if(ai<24)n=BigInt(ai);else if(ai<=27){n=0n;for(const byte of take(({24:1,25:2,26:4,27:8})[ai]))n=(n<<8n)|BigInt(byte);}else fail();
    if(major<2){const value=major===0?n:-1n-n;return value>=-9007199254740991n&&value<=9007199254740991n?Number(value):value;}
    if(n>BigInt(bytes.length))fail();const size=Number(n);
    if(major===2)return take(size);
    if(major===3){const value=take(size);const text=value.toString('utf8');if(!Buffer.from(text).equals(value))fail();return text;}
    if(![4,5].includes(major)||size>32)fail();
    if(major===4)return Array.from({length:size},()=>read(depth+1));
    const result=new Map();for(let i=0;i<size;i++){const key=read(depth+1);if(typeof key!=='number'||result.has(key))fail();result.set(key,read(depth+1));}return result;
  }
  const value=read(0);if(cursor!==bytes.length||!cbor(value).equals(bytes))fail();return value;
}
export function signingBytes(value){
  const {payload,kid}=fields(value),result=cbor(['Signature1',cbor(new Map([[1,-7],[4,kid]])),aad,cbor(payload)]);
  if(result.length>512)fail();return result;
}
export function assemble(value,signature){
  const {payload,kid}=fields(value);if(!Buffer.isBuffer(signature)||signature.length!==64)fail();
  const result=Buffer.concat([Buffer.from([0xd2]),cbor([cbor(new Map([[1,-7],[4,kid]])),new Map(),cbor(payload),signature])]);
  if(result.length>271)fail();return result;
}
function keyObject(point){
  ECDH.convertKey(point,'prime256v1',undefined,undefined,'uncompressed');
  return createPublicKey({key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')},format:'jwk'});
}
export function verify(data,environment,issuers,expected){
  try{
    if(!Buffer.isBuffer(data)||!data.length||data.length>271||data[0]!==0xd2||!Object.hasOwn(maps.environment,environment))fail();
    if(!expected||Object.keys(expected).sort().join()!=='device_uuid,public_key_sha256,role')fail();
    convert(expected.device_uuid,'uuid');convert(expected.role,'role');hex(expected.public_key_sha256,32);
    const envelope=uncbor(data.subarray(1));
    if(!Array.isArray(envelope)||envelope.length!==4||!Buffer.isBuffer(envelope[0])||!(envelope[1] instanceof Map)||envelope[1].size||!Buffer.isBuffer(envelope[2])||!Buffer.isBuffer(envelope[3])||envelope[3].length!==64)fail();
    const protectedMap=uncbor(envelope[0]);
    if(!(protectedMap instanceof Map)||[...protectedMap.keys()].sort().join()!=='1,4'||protectedMap.get(1)!==-7||!Buffer.isBuffer(protectedMap.get(4))||protectedMap.get(4).length!==8)fail();
    const body=uncbor(envelope[2]);if(!(body instanceof Map)||body.size!==13||[...body.keys()].some(k=>k<1||k>13))fail();
    const value={issuer_kid:protectedMap.get(4).toString('hex')};
    for(const [i,[name,kind]] of layout.entries()){
      let x=body.get(i+1);
      if(kind==='uuid'){if(!Buffer.isBuffer(x)||x.length!==16)fail();const id=x.toString('hex');x=[id.slice(0,8),id.slice(8,12),id.slice(12,16),id.slice(16,20),id.slice(20)].join('-');}
      else if(kind==='point'||kind==='hardware'){if(!Buffer.isBuffer(x))fail();x=x.toString('hex');}
      else if(maps[kind]){if(typeof x!=='number')fail();x=Object.keys(maps[kind]).find(k=>maps[kind][k]===x);}
      value[name]=x;
    }
    fields(value);const point=Buffer.from(value.public_key,'hex');
    if(value.environment!==environment||value.device_uuid!==expected.device_uuid||value.role!==expected.role||createHash('sha256').update(point).digest('hex')!==expected.public_key_sha256)fail();
    if(!Array.isArray(issuers)||!issuers.length||issuers.length>8)fail();const seen=new Set();let key;
    for(const issuer of issuers){
      if(!issuer||Object.keys(issuer).sort().join()!=='environment,kid,public_key,purpose'||!Object.hasOwn(maps.environment,issuer.environment)||!['factory_identity','ownership_control'].includes(issuer.purpose))fail();
      hex(issuer.kid,8);const pub=hex(issuer.public_key,65,'04'),id=issuer.environment+':'+issuer.kid;
      if(seen.has(id))fail();seen.add(id);
      if(issuer.environment===environment&&issuer.kid===value.issuer_kid&&issuer.purpose==='factory_identity')key=pub;
    }
    if(!key)fail();const message=signingBytes(value);
    if(!checkSignature('sha256',message,{key:keyObject(key),dsaEncoding:'ieee-p1363'},envelope[3]))fail();
    keyObject(point);return {fields:value,content_id:createHash('sha256').update(message).digest('hex')};
  }catch{fail();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const v=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
  for(const row of v.valid){assert.equal(signingBytes(row.fields).toString('hex'),row.signing_hex,row.name);assert.equal(assemble(row.fields,Buffer.from(row.signature_hex,'hex')).toString('hex'),row.hex,row.name);assert.deepEqual(verify(Buffer.from(row.hex,'hex'),row.fields.environment,v.issuers,row.expected).fields,row.fields,row.name);}
  for(const row of v.invalid_objects)assert.throws(()=>verify(Buffer.from(row.hex,'hex'),row.environment,row.issuers??v.issuers,row.expected),/Invalid device credential/,row.name);
  for(const row of v.invalid_fields)assert.throws(()=>fields(row.fields),/Invalid device credential/,row.name);
  console.log(JSON.stringify({valid:v.valid.length,invalid_objects:v.invalid_objects.length,invalid_fields:v.invalid_fields.length}));
}
