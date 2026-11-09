// Independent proof/context reference. No IO other than public fixture files.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {createHash,createPublicKey,ECDH,verify as checkSignature} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {cbor} from '../device-credential/reference.mjs';
import {verify as verifyAuthority,authorityContext} from '../device-authority/reference.mjs';
export {cbor};
const windowSeconds=300,prefix=Buffer.from('OCTATRACE-FIELD-CONTEXT-1:');
const challengeAAD=Buffer.from('OCTATRACE-SETUP-CHALLENGE-1'),proofAAD=Buffer.from('OCTATRACE-SETUP-PROOF-1');
const layouts={challenge:[['v','version'],['purpose','purpose'],['environment','environment'],['challenge_uuid','uuid'],['operation_uuid','uuid'],['owner_ref','uuid'],['link_uuid','uuid'],['link_role','link_role'],['link_key_sha256','hash'],['link_key_revision','revision'],['link_boot','boot'],['link_nonce','hash'],['phone_installation_uuid','uuid'],['phone_key_sha256','hash'],['phone_boot','boot'],['server_nonce','hash'],['issued_at','revision'],['expires_at','revision'],['owner_receipt_sha256','optional_hash'],['ownership_epoch','counter'],['controller_revision','counter']],
 proof:[['v','version'],['signer','signer'],['challenge_content_sha256','hash'],['challenge_uuid','uuid'],['signer_boot','boot']],
 field:[['v','version'],['kind','kind'],['environment','environment'],['handshake_profile_sha256','hash'],['attempt_uuid','uuid'],['authority_context_sha256','hash'],['initiator_uuid','uuid'],['initiator_key_sha256','hash'],['initiator_boot','boot'],['responder_uuid','uuid'],['responder_key_sha256','hash'],['responder_boot','boot'],['initiator_nonce','hash'],['responder_nonce','hash'],['transcript_sha256','hash']]};
const maps={purpose:{first_claim:1,phone_replace:2},signer:{Link:1,Phone:2},kind:{phone_link:1,link_core:2},environment:{development:1,production:2},link_role:{Link:1}};
const expectedNames=layouts.challenge.map(x=>x[0]).filter(x=>!['v','challenge_uuid','server_nonce','issued_at','expires_at'].includes(x));
function fail(){throw Error('Invalid proof context');}
function digest(data){return createHash('sha256').update(data).digest('hex');}
function hex(value,n,p='') {if(typeof value!=='string'||value.length!==n*2||!new RegExp('^[0-9a-f]{'+n*2+'}$').test(value)||!value.startsWith(p)||/^0+$/.test(value))fail();return Buffer.from(value,'hex');}
function convert(value,kind){
 if(['version','revision','counter'].includes(kind)){if(!Number.isInteger(value)||value<(kind==='counter'?0:1)||value>4294967295||(kind==='version'&&value!==1))fail();return value;}
 if(kind==='optional_hash'&&value==='')return Buffer.alloc(0);
 if(typeof value!=='string')fail();
 if(maps[kind]){if(!Object.hasOwn(maps[kind],value))fail();return maps[kind][value];}
 if(kind==='uuid'){if(value.length!==36||!(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/).test(value))fail();return Buffer.from(value.replaceAll('-',''),'hex');}
 return hex(value,kind==='boot'?16:32);
}
export function fields(kind,value){
 if(typeof kind!=='string'||!Object.hasOwn(layouts,kind)||!value||typeof value!=='object'||Array.isArray(value))fail();
 const rows=layouts[kind],names=[...rows.map(x=>x[0]),...(kind==='challenge'?['issuer_kid']:[])];
 if(JSON.stringify(Object.keys(value).sort())!==JSON.stringify(names.sort()))fail();
 const payload=new Map(rows.map(([name,encoding],i)=>[i+1,convert(value[name],encoding)]));
 if(kind==='challenge'){
  hex(value.issuer_kid,8);
  if(value.expires_at-value.issued_at!==windowSeconds||value.link_nonce===value.server_nonce||value.link_boot===value.phone_boot||value.link_uuid===value.phone_installation_uuid||value.link_key_sha256===value.phone_key_sha256)fail();
  if(value.purpose==='first_claim'){if(value.owner_receipt_sha256!==''||value.ownership_epoch!==0||value.controller_revision!==0)fail();}
  else if(!value.owner_receipt_sha256||!value.ownership_epoch)fail();
 }
 if(kind==='field'&&['uuid','key_sha256','boot','nonce'].some(k=>value['initiator_'+k]===value['responder_'+k]))fail();
 return payload;
}
function protectedBytes(kind,value){return cbor(kind==='challenge'?new Map([[1,-7],[4,Buffer.from(value.issuer_kid,'hex')]]):new Map([[1,-7]]));}
export function signingBytes(kind,value){if(!['challenge','proof'].includes(kind))fail();const p=fields(kind,value);return cbor(['Signature1',protectedBytes(kind,value),kind==='challenge'?challengeAAD:proofAAD,cbor(p)]);}
export function assemble(kind,value,signature){if(!['challenge','proof'].includes(kind)||!Buffer.isBuffer(signature)||signature.length!==64)fail();return Buffer.concat([Buffer.from([0xd2]),cbor([protectedBytes(kind,value),new Map(),cbor(fields(kind,value)),signature])]);}

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
function decode(kind,body){
 const rows=layouts[kind];if(!(body instanceof Map)||body.size!==rows.length||[...body.keys()].some(k=>k<1||k>rows.length))fail();
 return Object.fromEntries(rows.map(([name,encoding],i)=>{let v=body.get(i+1);
  if(encoding==='uuid'){if(!Buffer.isBuffer(v)||v.length!==16)fail();const s=v.toString('hex');v=[s.slice(0,8),s.slice(8,12),s.slice(12,16),s.slice(16,20),s.slice(20)].join('-');}
  else if(['hash','boot','optional_hash'].includes(encoding)){if(!Buffer.isBuffer(v))fail();v=v.toString('hex');}
  else if(maps[encoding]){if(typeof v!=='number'||!Object.values(maps[encoding]).includes(v))fail();v=Object.keys(maps[encoding]).find(x=>maps[encoding][x]===v);}
  return [name,v];}));
}
function envelope(kind,data){
 if(!Buffer.isBuffer(data)||!data.length||data.length>512||data[0]!==0xd2)fail();const v=parse(data.subarray(1));
 if(!Array.isArray(v)||v.length!==4||!Buffer.isBuffer(v[0])||!(v[1] instanceof Map)||v[1].size||!Buffer.isBuffer(v[2])||!Buffer.isBuffer(v[3])||v[3].length!==64)fail();
 const h=parse(v[0]);if(!(h instanceof Map)||h.size!==(kind==='challenge'?2:1)||h.get(1)!==-7||(kind==='challenge'?!h.has(4):h.has(4)))fail();
 const value=decode(kind,parse(v[2]));if(kind==='challenge'){if(!Buffer.isBuffer(h.get(4))||h.get(4).length!==8)fail();value.issuer_kid=h.get(4).toString('hex');}fields(kind,value);return {fields:value,signature:v[3]};
}
function publicKey(point){ECDH.convertKey(point,'prime256v1',undefined,undefined,'uncompressed');return createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:point.subarray(1,33).toString('base64url'),y:point.subarray(33).toString('base64url')}});}
export function verifyChallenge(data,environment,issuers,expected){try{
 if(!['development','production'].includes(environment)||!expected||JSON.stringify(Object.keys(expected).sort())!==JSON.stringify([...expectedNames].sort()))fail();
 for(const name of expectedNames)convert(expected[name],layouts.challenge.find(x=>x[0]===name)[1]);
 const {fields:value,signature}=envelope('challenge',data);if(value.environment!==environment||expectedNames.some(k=>value[k]!==expected[k]))fail();
 if(!Array.isArray(issuers)||!issuers.length||issuers.length>8)fail();let key;const seen=new Set();
 for(const issuer of issuers){
  if(!issuer||JSON.stringify(Object.keys(issuer).sort())!==JSON.stringify(['environment','kid','public_key','purpose'])||!['development','production'].includes(issuer.environment)||!['factory_identity','ownership_control'].includes(issuer.purpose))fail();
  hex(issuer.kid,8);const point=hex(issuer.public_key,65,'04'),id=issuer.environment+':'+issuer.kid;if(seen.has(id))fail();seen.add(id);
  if(issuer.environment===environment&&issuer.kid===value.issuer_kid&&issuer.purpose==='ownership_control')key=point;
 }
 if(!key)fail();const message=signingBytes('challenge',value);if(!checkSignature('sha256',message,{key:publicKey(key),dsaEncoding:'ieee-p1363'},signature))fail();
 return {fields:value,content_id:digest(message)};
}catch{fail();}}
export function verifyProof(data,ch,key){try{
 const {fields:value,signature}=envelope('proof',data),c=ch.fields,link=value.signer==='Link';
 if(value.challenge_content_sha256!==ch.content_id||value.challenge_uuid!==c.challenge_uuid||value.signer_boot!==c[link?'link_boot':'phone_boot']||!Buffer.isBuffer(key)||key.length!==65||key[0]!==4||digest(key)!==c[link?'link_key_sha256':'phone_key_sha256'])fail();
 if(!checkSignature('sha256',signingBytes('proof',value),{key:publicKey(key),dsaEncoding:'ieee-p1363'},signature))fail();return {fields:value,key_sha256:digest(key)};
}catch{fail();}}
export function checkLocal(ch,boot,nonce,elapsed){convert(elapsed,'counter');if(ch.fields.link_boot!==boot||ch.fields.link_nonce!==nonce||elapsed>=300000)fail();}
export function checkCompletion(ch,lp,pp,now,known,used){
 convert(now,'counter');if(known!==ch.content_id||typeof used!=='boolean'||used||now<ch.fields.issued_at||now>=ch.fields.expires_at)fail();
 for(const [p,role,prefix] of [[lp,'Link','link'],[pp,'Phone','phone']])if(!p||p.fields.signer!==role||p.fields.challenge_content_sha256!==ch.content_id||p.fields.challenge_uuid!==ch.fields.challenge_uuid||p.fields.signer_boot!==ch.fields[prefix+'_boot']||p.key_sha256!==ch.fields[prefix+'_key_sha256'])fail();
}
export function encodeField(value){return Buffer.concat([prefix,cbor(fields('field',value))]);}
export function matchField(data,expected){fields('field',expected);if(!Buffer.isBuffer(data)||!data.length||data.length>512||!data.subarray(0,prefix.length).equals(prefix))fail();const v=decode('field',parse(data.subarray(prefix.length)));fields('field',v);if(layouts.field.some(([name])=>v[name]!==expected[name]))fail();return {fields:v,context_id:digest(data),trust:'untrusted'};}
export function buildField(policy,owner,linkOwner,attempt){
 const names=['handshake_profile_sha256','attempt_uuid','initiator_boot','responder_boot','initiator_nonce','responder_nonce','transcript_sha256'];if(!attempt||JSON.stringify(Object.keys(attempt).sort())!==JSON.stringify(names.sort()))fail();
 let bound;try{bound=authorityContext(policy,owner,linkOwner);}catch{fail();}const p=policy.fields,phone=p.purpose==='phone_controller';
 return encodeField({v:1,kind:phone?'phone_link':'link_core',environment:p.environment,authority_context_sha256:bound,initiator_uuid:p[phone?'phone_installation_uuid':'link_uuid'],initiator_key_sha256:p[phone?'phone_key_sha256':'link_key_sha256'],responder_uuid:p.resource_uuid,responder_key_sha256:p.resource_key_sha256,...attempt});
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const v=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),challenges=new Map(),proofs=new Map();
 for(const row of v.challenges){assert.equal(signingBytes('challenge',row.fields).toString('hex'),row.signing_hex,row.name);assert.equal(assemble('challenge',row.fields,Buffer.from(row.signature_hex,'hex')).toString('hex'),row.hex,row.name);const c=verifyChallenge(Buffer.from(row.hex,'hex'),row.fields.environment,v.issuers,row.expected);assert.deepEqual(c.fields,row.fields,row.name);challenges.set(row.name,c);}
 for(const row of v.proofs){assert.equal(signingBytes('proof',row.fields).toString('hex'),row.signing_hex,row.name);assert.equal(assemble('proof',row.fields,Buffer.from(row.signature_hex,'hex')).toString('hex'),row.hex,row.name);const p=verifyProof(Buffer.from(row.hex,'hex'),challenges.get(row.challenge),Buffer.from(row.public_key,'hex'));assert.deepEqual(p.fields,row.fields,row.name);proofs.set(row.name,p);}
 for(const row of v.fields){assert.equal(encodeField(row.fields).toString('hex'),row.hex,row.name);assert.deepEqual(matchField(Buffer.from(row.hex,'hex'),row.fields).fields,row.fields,row.name);}
 for(const row of v.invalid_objects)assert.throws(()=>row.kind==='challenge'?verifyChallenge(Buffer.from(row.hex,'hex'),row.environment,row.issuers??v.issuers,row.expected):row.kind==='proof'?verifyProof(Buffer.from(row.hex,'hex'),challenges.get(row.challenge),Buffer.from(row.public_key,'hex')):matchField(Buffer.from(row.hex,'hex'),row.expected),/Invalid proof context/,row.name);
 for(const row of [...v.invalid_fields,...v.invalid_relations])assert.throws(()=>fields(row.kind,row.fields),/Invalid proof context/,row.name);
 for(const row of v.completions){const op=()=>checkCompletion(challenges.get(row.challenge),proofs.get(row.link_proof),proofs.get(row.phone_proof),row.now,row.known,row.used);if(row.result==='deny')assert.throws(op,/Invalid proof context/,row.name);else assert.equal(op(),undefined,row.name);}
 for(const row of v.local_windows){const op=()=>checkLocal(challenges.get(row.challenge),row.boot,row.nonce,row.elapsed);if(row.result==='deny')assert.throws(op,/Invalid proof context/,row.name);else assert.equal(op(),undefined,row.name);}
 const av=JSON.parse(fs.readFileSync(new URL('../device-authority/vectors.json',import.meta.url),'utf8')),get=name=>{const r=av.valid.find(x=>x.name===name);return verifyAuthority(Buffer.from(r.hex,'hex'),r.fields.environment,av.issuers,r.expected);};
 for(const row of v.bindings){const op=()=>buildField(get(row.policy),get(row.owner),row.link_owner?get(row.link_owner):undefined,row.attempt);if(row.result==='deny')assert.throws(op,/Invalid proof context/,row.name);else assert.equal(op().toString('hex'),row.hex,row.name);}
 console.log(JSON.stringify(Object.fromEntries(['challenges','proofs','fields','invalid_objects','invalid_fields','invalid_relations','completions','local_windows','bindings'].map(k=>[k,v[k].length]))));
}
