// Independent authority CBOR/COSE reference. Public fixture crypto only.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,ECDH,verify as signatureValid} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {cbor} from '../device-credential/reference.mjs';
export {cbor};
const aad=Buffer.from('OCTATRACE-DEVICE-AUTHORITY-1');
const context=Buffer.from('OCTATRACE-AUTHORITY-CONTEXT-1');
const purposes={ownership_receipt:1,phone_controller:2,core_link:3};
const capabilities={read_state:1,start:2,stop:4,rejoin:8};
const common=[['v','version'],['purpose','purpose'],['environment','environment'],['object_uuid','uuid'],['revision','revision'],['resource_uuid','uuid'],['resource_role','role'],['resource_key_sha256','hash'],['resource_key_revision','revision'],['owner_ref','uuid'],['ownership_epoch','revision']];
const owner=[['claim_operation_uuid','uuid']],control=[['state','state'],['capabilities','capabilities']];
const phone=[['phone_installation_uuid','uuid'],['phone_key_sha256','hash']];
const peer=[['link_uuid','uuid'],['link_key_sha256','hash'],['link_key_revision','revision'],['link_ownership_epoch','revision']];
const maps={purpose:purposes,state:{grant:1,removed:2},environment:{development:1,production:2},role:{Link:1,Core:2}};
const audience=['resource_uuid','resource_role','resource_key_sha256','resource_key_revision'];
function fail(){throw Error('Invalid device authority');}
function hex(value,n,prefix=''){
 if(typeof value!=='string'||value.length!==n*2||!new RegExp('^[0-9a-f]{'+n*2+'}$').test(value)||!value.startsWith(prefix)||/^0+$/.test(value))fail();return Buffer.from(value,'hex');
}
function layout(value){
 if(!value||typeof value!=='object'||!Object.hasOwn(purposes,value.purpose))fail();
 if(value.purpose==='ownership_receipt')return [...common,...owner];
 if(!['grant','removed'].includes(value.state))fail();
 return [...common,...control,...(value.state==='removed'?[]:value.purpose==='phone_controller'?phone:peer)];
}
function convert(value,kind){
 if(kind==='version'||kind==='revision'){if(!Number.isInteger(value)||value<1||value>4294967295||(kind==='version'&&value!==1))fail();return value;}
 if(kind==='capabilities'){
  if(!Array.isArray(value)||value.some(x=>typeof x!=='string'||!Object.hasOwn(capabilities,x))||JSON.stringify(value)!==JSON.stringify(Object.keys(capabilities).filter(x=>value.includes(x))))fail();return value.reduce((sum,x)=>sum+capabilities[x],0);
 }
 if(typeof value!=='string')fail();
 if(maps[kind]){if(!Object.hasOwn(maps[kind],value))fail();return maps[kind][value];}
 if(kind==='uuid'){
  if(value.length!==36||!(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/).test(value))fail();return Buffer.from(value.replaceAll('-',''),'hex');
 }
 return hex(value,32);
}
export function fields(value){
 const rows=layout(value),names=[...rows.map(x=>x[0]),'issuer_kid'].sort();
 if(Array.isArray(value)||JSON.stringify(Object.keys(value).sort())!==JSON.stringify(names))fail();
 const payload=new Map(rows.map(([name,kind],i)=>[i+1,convert(value[name],kind)])),kid=hex(value.issuer_kid,8);
 if(value.purpose!=='ownership_receipt'){
  if(value.resource_role!==(value.purpose==='phone_controller'?'Link':'Core')||(value.state==='grant')!==!!value.capabilities.length)fail();
  if(value.purpose==='core_link'&&value.state==='grant'&&value.link_uuid===value.resource_uuid)fail();
 }
 return {payload,kid};
}
export function signingBytes(value){const {payload,kid}=fields(value);return cbor(['Signature1',cbor(new Map([[1,-7],[4,kid]])),aad,cbor(payload)]);}
export function assemble(value,signature){const {payload,kid}=fields(value);if(!Buffer.isBuffer(signature)||signature.length!==64)fail();return Buffer.concat([Buffer.from([0xd2]),cbor([cbor(new Map([[1,-7],[4,kid]])),new Map(),cbor(payload),signature])]);}
function parse(data){
 if(!Buffer.isBuffer(data)||!data.length||data.length>512)fail();let cursor=0;
 function take(size){if(size>data.length-cursor)fail();const v=data.subarray(cursor,cursor+size);cursor+=size;return v;}
 function read(depth){
  if(depth>4)fail();const first=take(1)[0],major=first>>5,ai=first&31;let n;
  if(ai<24)n=BigInt(ai);else if(ai<=27){n=0n;for(const x of take(({24:1,25:2,26:4,27:8})[ai]))n=n*256n+BigInt(x);}else fail();
  if(major<2){const v=major===0?n:-1n-n;return v>=-9007199254740991n&&v<=9007199254740991n?Number(v):v;}
  if(n>BigInt(data.length))fail();const size=Number(n);
  if(major===2)return take(size);
  if(major===3){const v=take(size),text=v.toString('utf8');if(!Buffer.from(text).equals(v))fail();return text;}
  if(![4,5].includes(major)||size>32)fail();
  if(major===4)return Array.from({length:size},()=>read(depth+1));
  const out=new Map();for(let i=0;i<size;i++){const k=read(depth+1);if(typeof k!=='number'||out.has(k))fail();out.set(k,read(depth+1));}return out;
 }
 const value=read(0);if(cursor!==data.length||!cbor(value).equals(data))fail();return value;
}
function fromWire(value,kind){
 if(kind==='uuid'){if(!Buffer.isBuffer(value)||value.length!==16)fail();const s=value.toString('hex');return [s.slice(0,8),s.slice(8,12),s.slice(12,16),s.slice(16,20),s.slice(20)].join('-');}
 if(kind==='hash'){if(!Buffer.isBuffer(value))fail();return value.toString('hex');}
 if(maps[kind]){if(typeof value!=='number'||!Object.values(maps[kind]).includes(value))fail();return Object.keys(maps[kind]).find(k=>maps[kind][k]===value);}
 if(kind==='capabilities'){if(!Number.isInteger(value)||value<0||value>15)fail();return Object.keys(capabilities).filter(k=>value&capabilities[k]);}
 return value;
}
function publicKey(point){ECDH.convertKey(point,'prime256v1',undefined,undefined,'uncompressed');return createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')}});}
export function verify(data,environment,issuers,expected){
 try{
  if(!Buffer.isBuffer(data)||!data.length||data.length>270||data[0]!==0xd2||!['development','production'].includes(environment))fail();
  if(!expected||JSON.stringify(Object.keys(expected).sort())!==JSON.stringify([...audience].sort()))fail();
  for(const name of audience)convert(expected[name],common.find(x=>x[0]===name)[1]);
  const env=parse(data.subarray(1));
  if(!Array.isArray(env)||env.length!==4||!Buffer.isBuffer(env[0])||!(env[1] instanceof Map)||env[1].size||!Buffer.isBuffer(env[2])||!Buffer.isBuffer(env[3])||env[3].length!==64)fail();
  const h=parse(env[0]);if(!(h instanceof Map)||h.size!==2||h.get(1)!==-7||!Buffer.isBuffer(h.get(4))||h.get(4).length!==8)fail();
  const body=parse(env[2]);if(!(body instanceof Map)||!body.has(2))fail();
  const purpose=fromWire(body.get(2),'purpose'),state=purpose==='ownership_receipt'?undefined:fromWire(body.get(12),'state');
  const rows=layout({purpose,state});if(body.size!==rows.length||[...body.keys()].some(k=>k<1||k>rows.length))fail();
  const value=Object.fromEntries(rows.map(([name,kind],i)=>[name,fromWire(body.get(i+1),kind)]));value.issuer_kid=h.get(4).toString('hex');fields(value);
  if(value.environment!==environment||audience.some(name=>value[name]!==expected[name]))fail();
  if(!Array.isArray(issuers)||!issuers.length||issuers.length>8)fail();let key;const seen=new Set();
  for(const issuer of issuers){
   if(!issuer||JSON.stringify(Object.keys(issuer).sort())!==JSON.stringify(['environment','kid','public_key','purpose'])||!['development','production'].includes(issuer.environment)||!['factory_identity','ownership_control'].includes(issuer.purpose))fail();
   hex(issuer.kid,8);const point=hex(issuer.public_key,65,'04'),id=issuer.environment+':'+issuer.kid;if(seen.has(id))fail();seen.add(id);
   if(issuer.environment===environment&&issuer.kid===value.issuer_kid&&issuer.purpose==='ownership_control')key=point;
  }
  if(!key)fail();const message=signingBytes(value);
  if(!signatureValid('sha256',message,{key:publicKey(key),dsaEncoding:'ieee-p1363'},env[3]))fail();
  return {fields:value,content_id:createHash('sha256').update(message).digest('hex')};
 }catch{fail();}
}
export function compareRevision(current,previous){
 const a=current.fields;if(!previous)return 'newer';const b=previous.fields;
 if(['purpose','environment','resource_uuid'].some(k=>a[k]!==b[k])||a.revision<b.revision)fail();
 if(a.revision===b.revision){if(current.content_id!==previous.content_id)fail();return 'retry';}
 if(a.ownership_epoch<b.ownership_epoch)fail();
 const fixed=['owner_ref',...audience.slice(1),...(a.purpose==='ownership_receipt'?['claim_operation_uuid']:[])];
 if(a.ownership_epoch===b.ownership_epoch&&fixed.some(k=>a[k]!==b[k]))fail();return 'newer';
}
export function checkOwners(policy,resourceOwner,linkOwner){
 const p=policy.fields,r=resourceOwner.fields;
 if(p.purpose==='ownership_receipt'||r.purpose!=='ownership_receipt'||['environment','owner_ref','ownership_epoch',...audience].some(k=>p[k]!==r[k]))fail();
 if(p.purpose!=='core_link'||p.state!=='grant'){if(linkOwner)fail();return;}
 if(!linkOwner)fail();const l=linkOwner.fields;
 if(l.purpose!=='ownership_receipt'||l.resource_role!=='Link'||l.environment!==p.environment||l.owner_ref!==p.owner_ref||['uuid','key_sha256','key_revision'].some(k=>p['link_'+k]!==l['resource_'+k])||p.link_ownership_epoch!==l.ownership_epoch)fail();
}
export function authorityContext(policy,resourceOwner,linkOwner){checkOwners(policy,resourceOwner,linkOwner);if(policy.fields.state!=='grant')fail();return createHash('sha256').update(cbor([context,Buffer.from(policy.content_id,'hex'),Buffer.from(resourceOwner.content_id,'hex'),linkOwner?Buffer.from(linkOwner.content_id,'hex'):Buffer.alloc(0)])).digest('hex');}
export function checkSubjectKey(policy,role,id,point){
 try{const p=policy.fields;if(p.purpose==='ownership_receipt'||p.state!=='grant')fail();const phone=p.purpose==='phone_controller';
 if(role!==(phone?'Phone':'Link')||id!==p[phone?'phone_installation_uuid':'link_uuid']||!Buffer.isBuffer(point)||point.length!==65||point[0]!==4||createHash('sha256').update(point).digest('hex')!==p[phone?'phone_key_sha256':'link_key_sha256'])fail();publicKey(point);
 }catch{fail();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const v=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),verified=new Map();
 for(const row of v.valid){assert.equal(signingBytes(row.fields).toString('hex'),row.signing_hex,row.name);assert.equal(assemble(row.fields,Buffer.from(row.signature_hex,'hex')).toString('hex'),row.hex,row.name);const result=verify(Buffer.from(row.hex,'hex'),row.fields.environment,v.issuers,row.expected);assert.deepEqual(result.fields,row.fields,row.name);verified.set(row.name,result);}
 for(const row of v.invalid_objects)assert.throws(()=>verify(Buffer.from(row.hex,'hex'),row.environment,row.issuers??v.issuers,row.expected),/Invalid device authority/,row.name);
 for(const row of v.invalid_fields)assert.throws(()=>fields(row.fields),/Invalid device authority/,row.name);
 for(const row of v.revisions){const op=()=>compareRevision(verified.get(row.current),row.previous?verified.get(row.previous):undefined);if(row.result==='deny')assert.throws(op,/Invalid device authority/,row.name);else assert.equal(op(),row.result,row.name);}
 for(const row of v.contexts){const op=()=>authorityContext(verified.get(row.policy),verified.get(row.owner),row.link_owner?verified.get(row.link_owner):undefined);if(row.result==='deny')assert.throws(op,/Invalid device authority/,row.name);else assert.equal(op(),row.result,row.name);}
 for(const row of v.subjects){const op=()=>checkSubjectKey(verified.get(row.policy),row.role,row.uuid,Buffer.from(row.public_key,'hex'));if(row.result==='deny')assert.throws(op,/Invalid device authority/,row.name);else assert.equal(op(),undefined,row.name);}
 console.log(JSON.stringify(Object.fromEntries(['valid','invalid_objects','invalid_fields','revisions','contexts','subjects'].map(k=>[k,v[k].length]))));
}
