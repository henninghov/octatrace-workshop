// Server-custody contract reference. Public fixture material only; no real KMS/DB.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {isDeepStrictEqual} from 'node:util';
import {webcrypto,createHash,createHmac,timingSafeEqual,createCipheriv,createDecipheriv} from 'node:crypto';
let root=path.dirname(fileURLToPath(import.meta.url));while(!fs.existsSync(path.join(root,'claim-qr.lock.json'))){const p=path.dirname(root);if(p===root)throw Error('Missing dependency');root=p;}
const dep=async name=>{const p=JSON.parse(fs.readFileSync(path.join(root,name+'.lock.json'),'utf8'));return import(pathToFileURL(path.join(root,p.path,'reference.mjs')).href);};
const {decode:decodeQr}=await dep('claim-qr'),{cbor}=await dep('device-credential');export {cbor};
const bindingNames=['v','environment','device_uuid','role','public_key_sha256','claim_revision'];
const recordNames=[...bindingNames,'record_uuid','record_revision','payload_uuid','payload_revision','algorithm','wrapping_key_id','wrapped_key','nonce','ciphertext'];
const verifierNames=[...bindingNames,'verifier_key_id','verifier_revision','algorithm','mac'];
const requestNames=['v','action','request_uuid','environment','device_uuid','actor_uuid','session_uuid'];
const snapshotNames=['v','environment','device_uuid','role','public_key_sha256','claim_revision','record_uuid','record_revision','verifier_revision','owner_uuid','ownership_epoch','actor_uuid','session_uuid','session_revision','authenticated_at','auth_event','logged_in','online','account_enabled','operator_enabled','operator_revision'];
const domain=s=>Buffer.from('OCTATRACE-QR-'+s+'-1');
function fail(){throw Error('Private QR operation denied');}
function exact(v,names){if(!v||typeof v!=='object'||Array.isArray(v)||JSON.stringify(Object.keys(v).sort())!==JSON.stringify([...names].sort()))fail();}
function num(v,min=1){if(!Number.isInteger(v)||v<min||v>4294967295)fail();return v;}
function uid(v){if(typeof v!=='string'||v.length!==36||!(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/).test(v))fail();return Buffer.from(v.replaceAll('-',''),'hex');}
function hex(v,n,nonzero=false){if(typeof v!=='string'||v.length!==n*2||!(/^[0-9a-f]+$/).test(v)||(nonzero&&/^0+$/.test(v)))fail();return Buffer.from(v,'hex');}
function same(a,b){return isDeepStrictEqual(a,b);}
function sha(v){return createHash('sha256').update(v).digest('hex');}
export function bind(v){exact(v,bindingNames);if(num(v.v)!==1||!['development','production'].includes(v.environment)||!['Link','Core'].includes(v.role))fail();uid(v.device_uuid);hex(v.public_key_sha256,32,true);num(v.claim_revision);return Object.fromEntries(bindingNames.map(n=>[n,v[n]]));}
export function bindingOf(v){return bind(Object.fromEntries(bindingNames.map(n=>[n,v[n]])));}
export function record(v){exact(v,recordNames);bindingOf(v);for(const n of ['record_uuid','payload_uuid','wrapping_key_id'])uid(v[n]);for(const n of ['record_revision','payload_revision'])num(v[n]);if(v.payload_revision>v.record_revision||v.algorithm!=='A256GCM'||typeof v.wrapped_key!=='string'||v.wrapped_key.length<2||v.wrapped_key.length>4096||v.wrapped_key.length%2||!(/^[0-9a-f]+$/).test(v.wrapped_key))fail();hex(v.nonce,12,true);hex(v.ciphertext,161);return {...v};}
export function verifier(v){exact(v,verifierNames);bindingOf(v);uid(v.verifier_key_id);num(v.verifier_revision);if(v.algorithm!=='HS256')fail();hex(v.mac,32);return {...v};}
function pair(value,check,expected){const r=record(value),v=verifier(check),b=bind(expected);if(!same(bindingOf(r),b)||!same(bindingOf(v),b)||r.wrapping_key_id===v.verifier_key_id)fail();return [r,v,b];}
function bindingBytes(b){b=bind(b);return [1,b.environment==='development'?1:2,uid(b.device_uuid),b.role==='Link'?1:2,hex(b.public_key_sha256,32),b.claim_revision];}
export function payloadAad(v){const r=record(v);return cbor([domain('PAYLOAD'),...bindingBytes(bindingOf(r)),uid(r.record_uuid),uid(r.payload_uuid),r.payload_revision]);}
export function wrapAad(v){const r=record(v);return cbor([domain('WRAP'),...bindingBytes(bindingOf(r)),uid(r.record_uuid),r.record_revision,uid(r.payload_uuid),r.payload_revision,uid(r.wrapping_key_id)]);}
export function plaintext(text,expected){try{const b=bind(expected),q=decodeQr(text,b.environment);if(q.device_uuid!==b.device_uuid||q.role!==b.role||q.public_key_sha256!==b.public_key_sha256)fail();return Buffer.from(text,'ascii');}catch{fail();}}
export function macInput(value,text){const v=verifier(value);return cbor([domain('VERIFIER'),...bindingBytes(bindingOf(v)),uid(v.verifier_key_id),v.verifier_revision,plaintext(text,bindingOf(v))]);}
export async function matchesClaim(text,check,expected,crypto){const v=verifier(check),b=bind(expected);if(!same(bindingOf(v),b))fail();const result=await crypto.verifyMac(v.verifier_key_id,b.environment,macInput(v,text),hex(v.mac,32));if(typeof result!=='boolean')fail();return result;}
export async function seal(text,template,checkTemplate,expected,key,crypto,reserve){try{
 const [r,v,b]=pair(template,checkTemplate,expected);const p=plaintext(text,b);if(!Buffer.isBuffer(key)||key.length!==32||!key.some(x=>x))fail();if(await reserve(sha(key),r.record_uuid,r.payload_uuid)!==true)fail();
 const ciphertext=await crypto.encrypt(key,hex(r.nonce,12),payloadAad(r),p);if(!Buffer.isBuffer(ciphertext)||ciphertext.length!==161)fail();r.ciphertext=ciphertext.toString('hex');
 const wrapped=await crypto.wrap(r.wrapping_key_id,b.environment,key,wrapAad(r));if(!Buffer.isBuffer(wrapped)||!wrapped.length||wrapped.length>2048)fail();r.wrapped_key=wrapped.toString('hex');
 const mac=await crypto.mac(v.verifier_key_id,b.environment,macInput(v,text));if(!Buffer.isBuffer(mac)||mac.length!==32)fail();v.mac=mac.toString('hex');return {record:record(r),verifier:verifier(v)};
}catch{fail();}}
export async function openInternal(value,check,expected,crypto,beforeDecrypt){try{
 const [r,v,b]=pair(value,check,expected),key=await crypto.unwrap(r.wrapping_key_id,b.environment,Buffer.from(r.wrapped_key,'hex'),wrapAad(r));if(!Buffer.isBuffer(key)||key.length!==32||!key.some(x=>x))fail();if(beforeDecrypt)await beforeDecrypt();
 const p=await crypto.decrypt(key,hex(r.nonce,12),payloadAad(r),hex(r.ciphertext,161));if(!Buffer.isBuffer(p)||p.length!==145)fail();const text=p.toString('ascii');if(!Buffer.from(text,'ascii').equals(p))fail();plaintext(text,b);if(!await matchesClaim(text,v,b,crypto))fail();return {text,key};
}catch{fail();}}
export async function rewrap(value,check,expected,kid,crypto){const [r,v,b]=pair(value,check,expected);uid(kid);if(kid===v.verifier_key_id)fail();const {key}=await openInternal(r,v,b,crypto);if(kid===r.wrapping_key_id)return r;const out={...r,record_revision:num(r.record_revision+1),wrapping_key_id:kid},wrapped=await crypto.wrap(kid,b.environment,key,wrapAad(out));if(!Buffer.isBuffer(wrapped)||!wrapped.length||wrapped.length>2048)fail();out.wrapped_key=wrapped.toString('hex');return record(out);}
export async function rotateVerifier(value,check,expected,kid,crypto){const [r,v,b]=pair(value,check,expected);uid(kid);if(kid===r.wrapping_key_id)fail();const {text}=await openInternal(r,v,b,crypto);if(kid===v.verifier_key_id)return v;const out={...v,verifier_revision:num(v.verifier_revision+1),verifier_key_id:kid},mac=await crypto.mac(kid,b.environment,macInput(out,text));if(!Buffer.isBuffer(mac)||mac.length!==32)fail();out.mac=mac.toString('hex');return verifier(out);}
export function compareUpdate(current,check,previous,oldCheck){const [r,v,b]=pair(current,check,bindingOf(current)),[o,ov]=pair(previous,oldCheck,b);if(r.record_uuid!==o.record_uuid||r.record_revision<o.record_revision||r.payload_revision<o.payload_revision||v.verifier_revision<ov.verifier_revision)fail();if(r.record_revision===o.record_revision&&!same(r,o))fail();if(v.verifier_revision===ov.verifier_revision&&!same(v,ov))fail();if(r.payload_revision===o.payload_revision&&['payload_uuid','nonce','ciphertext'].some(n=>r[n]!==o[n]))fail();return same(r,o)&&same(v,ov)?'retry':'newer';}
export async function validateUpdate(r,v,old,ov,crypto){const result=compareUpdate(r,v,old,ov),b=bindingOf(old);const a=await openInternal(old,ov,b,crypto),n=await openInternal(r,v,b,crypto);if(!timingSafeEqual(Buffer.from(a.text,'ascii'),Buffer.from(n.text,'ascii')))fail();return result;}
export function request(v){exact(v,requestNames);if(num(v.v)!==1||v.action!=='reveal_private_qr'||!['development','production'].includes(v.environment))fail();for(const n of ['request_uuid','device_uuid','actor_uuid','session_uuid'])uid(v[n]);return {...v};}
export function snapshot(v){exact(v,snapshotNames);if(num(v.v)!==1)fail();bindingOf(v);for(const n of ['record_uuid','actor_uuid','session_uuid'])uid(v[n]);for(const n of ['claim_revision','record_revision','verifier_revision','session_revision','authenticated_at'])num(v[n]);for(const n of ['ownership_epoch','operator_revision'])num(v[n],0);for(const n of ['logged_in','online','account_enabled','operator_enabled'])if(typeof v[n]!=='boolean')fail();if(v.owner_uuid!==null)uid(v.owner_uuid);if((v.owner_uuid===null)!==(v.ownership_epoch===0)||!['sign_in','reauthenticated','refresh','unknown'].includes(v.auth_event)||(v.operator_enabled&&!v.operator_revision))fail();return {...v};}
export function authorise(value,check,expected,query,state,now){const [r,v,b]=pair(value,check,expected),q=request(query),s=snapshot(state);num(now,0);
 if(!same(bindingOf(s),b)||s.record_uuid!==r.record_uuid||s.record_revision!==r.record_revision||s.verifier_revision!==v.verifier_revision||s.environment!==q.environment||s.device_uuid!==q.device_uuid||s.actor_uuid!==q.actor_uuid||s.session_uuid!==q.session_uuid||!s.logged_in||!s.online||!s.account_enabled||!['sign_in','reauthenticated'].includes(s.auth_event)||now-s.authenticated_at<0||now-s.authenticated_at>=900||!(s.owner_uuid===s.actor_uuid||s.operator_enabled))fail();
 const mapped=snapshotNames.map(n=>typeof s[n]==='boolean'?Number(s[n]):s[n]===null?Buffer.alloc(0):s[n]);return {stamp:sha(cbor([domain('ACCESS'),uid(q.request_uuid),mapped])),path:s.owner_uuid===s.actor_uuid?'owner':'operator'};
}
export async function reveal(value,check,expected,query,crypto,getSnapshot,clock,releaseGate){try{
 const [r,v,b]=pair(value,check,expected),q=request(query),before=await getSnapshot(q),first=authorise(r,v,b,q,before,await clock());
 const current=async()=>{const a=authorise(r,v,b,q,await getSnapshot(q),await clock());if(a.stamp!==first.stamp||a.path!==first.path)fail();};
 const {text}=await openInternal(r,v,b,crypto,current);await current();
 const event={v:1,request_uuid:q.request_uuid,environment:q.environment,actor_uuid:q.actor_uuid,session_uuid:q.session_uuid,device_uuid:q.device_uuid,record_uuid:r.record_uuid,record_revision:r.record_revision,claim_revision:b.claim_revision,purpose:'private_qr_reveal',access_path:first.path,outcome:'authorised_release'};
 if(await releaseGate(q,first.stamp,event)!==true)fail();return {text,headers:{'Cache-Control':'no-store','Pragma':'no-cache'}};
}catch{fail();}}

export class FixtureCrypto {
 constructor(keys,wrapNonce){this.keys=keys;this.wrapNonce=wrapNonce;this.hook=()=>{};}
 get(id,env,purpose,write=false){const rows=this.keys.filter(x=>x.key_id===id&&x.environment===env&&x.purpose===purpose);if(rows.length!==1||!['active','read_only'].includes(rows[0].mode)||(write&&rows[0].mode!=='active'))fail();return hex(rows[0].key_hex,32,true);}
 async encrypt(key,nonce,aad,plain){const k=await webcrypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt']);return Buffer.from(await webcrypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},k,plain));}
 async decrypt(key,nonce,aad,data){const k=await webcrypto.subtle.importKey('raw',key,'AES-GCM',false,['decrypt']);const out=Buffer.from(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},k,data));this.hook('decrypt');return out;}
 async wrap(id,env,key,aad){const out=await this.encrypt(this.get(id,env,'qr_wrapping',true),this.wrapNonce,aad,key);return Buffer.concat([this.wrapNonce,out]);}
 async unwrap(id,env,data,aad){if(data.length!==60)fail();const k=await webcrypto.subtle.importKey('raw',this.get(id,env,'qr_wrapping'),'AES-GCM',false,['decrypt']);const out=Buffer.from(await webcrypto.subtle.decrypt({name:'AES-GCM',iv:data.subarray(0,12),additionalData:aad,tagLength:128},k,data.subarray(12)));this.hook('unwrap');return out;}
 async mac(id,env,data){const k=await webcrypto.subtle.importKey('raw',this.get(id,env,'qr_verifier',true),{name:'HMAC',hash:'SHA-256'},false,['sign']);return Buffer.from(await webcrypto.subtle.sign('HMAC',k,data));}
 async verifyMac(id,env,data,mac){const k=await webcrypto.subtle.importKey('raw',this.get(id,env,'qr_verifier'),{name:'HMAC',hash:'SHA-256'},false,['verify']);return webcrypto.subtle.verify('HMAC',k,mac,data);}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 if(process.argv[2]==='--crypto'){
  // Classic Node crypto is the Python unit-test adapter; keys/plaintext are PUBLIC fixtures.
  try{const q=JSON.parse(fs.readFileSync(0,'utf8'));let out;const key=Buffer.from(q.key,'hex'),aad=Buffer.from(q.aad??'','hex');
   if(q.op==='encrypt'){const nonce=Buffer.from(q.nonce,'hex'),cipher=createCipheriv('aes-256-gcm',key,nonce);cipher.setAAD(aad);const data=Buffer.concat([cipher.update(Buffer.from(q.data,'hex')),cipher.final()]);out=Buffer.concat([data,cipher.getAuthTag()]);}
   else if(q.op==='decrypt'){const nonce=Buffer.from(q.nonce,'hex'),data=Buffer.from(q.data,'hex'),ciphertext=data.subarray(0,-16),tag=data.subarray(-16),decipher=createDecipheriv('aes-256-gcm',key,nonce);decipher.setAAD(aad);decipher.setAuthTag(tag);out=Buffer.concat([decipher.update(ciphertext),decipher.final()]);}
   else if(q.op==='hmac')out=createHmac('sha256',key).update(Buffer.from(q.data,'hex')).digest();else fail();
   console.log(JSON.stringify({hex:out.toString('hex')}));
  }catch{console.log(JSON.stringify({error:'crypto failed'}));process.exitCode=1;}
 }else{
  const v=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),records=new Map(),verifiers=new Map();
  for(const row of v.primitive_vectors){
   const key=Buffer.from(row.key,'hex'),data=Buffer.from(row.data,'hex');let out;
   if(row.op==='encrypt'){const crypto=new FixtureCrypto([],Buffer.alloc(12));out=await crypto.encrypt(key,Buffer.from(row.nonce,'hex'),Buffer.from(row.aad,'hex'),data);assert.equal((await crypto.decrypt(key,Buffer.from(row.nonce,'hex'),Buffer.from(row.aad,'hex'),out)).toString('hex'),row.data,row.name);}
   else{const k=await webcrypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-256'},false,['sign']);out=Buffer.from(await webcrypto.subtle.sign('HMAC',k,data));}
   assert.equal(out.toString('hex'),row.result,row.name);
  }
  for(const row of v.seals){
   const crypto=new FixtureCrypto(v.keys,Buffer.from(row.wrap_nonce,'hex')),seen=new Set(),reserve=async key=>{if(seen.has(key))return false;seen.add(key);return true;};
   const result=await seal(row.text,row.template,row.verifier_template,row.binding,Buffer.from(row.data_key,'hex'),crypto,reserve);
   assert.deepEqual(result.record,row.record,row.name);assert.deepEqual(result.verifier,row.verifier,row.name);
   assert.equal(payloadAad(result.record).toString('hex'),row.payload_aad,row.name);assert.equal(wrapAad(result.record).toString('hex'),row.wrap_aad,row.name);assert.equal(macInput(result.verifier,row.text).toString('hex'),row.mac_input,row.name);
   assert.equal((await openInternal(result.record,result.verifier,row.binding,crypto)).text,row.text,row.name);assert.equal(compareUpdate(Object.fromEntries(Object.entries(result.record).reverse()),result.verifier,result.record,result.verifier),'retry');records.set(row.name,result.record);verifiers.set(row.name,result.verifier);
  }
  for(const row of v.rotations){const source=v.seals.find(x=>x.name===row.source),crypto=new FixtureCrypto(v.keys,Buffer.from(row.wrap_nonce,'hex')),r=records.get(row.source),check=verifiers.get(row.source);
   const result=row.kind==='wrap'?await rewrap(r,check,source.binding,row.new_key_id,crypto):await rotateVerifier(r,check,source.binding,row.new_key_id,crypto);
   assert.deepEqual(result,row.result,row.name);const nr=row.kind==='wrap'?result:r,nv=row.kind==='verifier'?result:check;
   assert.equal(await validateUpdate(nr,nv,r,check,crypto),'newer',row.name);assert.equal((await openInternal(nr,nv,source.binding,crypto)).text,source.text,row.name);
  }
  for(const row of v.access){const source=v.seals.find(x=>x.name===row.source),op=()=>authorise(source.record,source.verifier,source.binding,row.request,row.snapshot,row.now);
   if(row.result==='deny')assert.throws(op,/Private QR operation denied/,row.name);else assert.equal(op().path,row.result,row.name);
  }
  for(const row of v.invalid_fields){const op=()=>row.kind==='binding'?bind(row.value):row.kind==='record'?record(row.value):row.kind==='verifier'?verifier(row.value):row.kind==='request'?request(row.value):snapshot(row.value);assert.throws(op,/Private QR operation denied/,row.name);}
  for(const row of v.failures){const source=v.seals.find(x=>x.name===row.source),crypto=new FixtureCrypto(v.keys,Buffer.from(source.wrap_nonce,'hex'));await assert.rejects(()=>openInternal(row.record??source.record,row.verifier??source.verifier,row.binding??source.binding,crypto),/Private QR operation denied/,row.name);}
  for(const row of v.reveals){const source=v.seals.find(x=>x.name===row.source),a=v.access.find(x=>x.name===row.access);let state=structuredClone(a.snapshot),now=a.now,audits=[];const crypto=new FixtureCrypto(v.keys,Buffer.from(source.wrap_nonce,'hex'));
   crypto.hook=stage=>{if(row.mutate_stage===stage)Object.assign(state,row.changes);};
   const getSnapshot=async()=>structuredClone(state),clock=async()=>now,gate=async(q,stamp,event)=>{if(row.mutate_stage==='gate')Object.assign(state,row.changes);try{const fresh=authorise(source.record,source.verifier,source.binding,q,state,now);if(fresh.stamp!==stamp||row.audit_failure)return false;audits.push(event);return true;}catch{return false;}};
   const op=()=>reveal(source.record,source.verifier,source.binding,a.request,crypto,getSnapshot,clock,gate);
   if(row.result==='deny')await assert.rejects(op,/Private QR operation denied/,row.name);else{const result=await op();assert.equal(result.text,source.text,row.name);assert.equal(result.headers['Cache-Control'],'no-store');assert.equal(audits.length,1);assert.ok(!JSON.stringify(audits).includes(source.text));}
  }
  console.log(JSON.stringify(Object.fromEntries(['seals','rotations','access','invalid_fields','failures','reveals','primitive_vectors'].map(n=>[n,v[n].length]))));
 }
}
