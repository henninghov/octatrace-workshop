import * as crypto from 'node:crypto';
import {proofMessage as deliveryMessage} from '../credential-delivery/proof.mjs';
const extra=['result','journal_state','slots_used','journal_revision','journal_content_id','fault'];
const base=['v','id','ok','type','role','build','boot','hardware','device_id','serial','article_id','article_revision_id','transfer_id','challenge','credential_revision','content_id','envelope_sha256','signature'];
const keys=[...base,...extra].sort();
const hex=(v,n)=>typeof v==='string' && v.length===n*2 && /^[0-9a-f]+$/.test(v);
const nonzero=(v,n)=>hex(v,n)&&v!=='0'.repeat(n*2);
const uint=(v,min=0)=>Number.isInteger(v)&&v>=min&&v<=0xffffffff;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function proofMessage(frame){
  const old=deliveryMessage(frame).toString('ascii');
  return Buffer.from('OCTATRACE-CREDENTIAL-INSTALLATION-1\n'+old.slice(old.indexOf('\n')+1)+extra.map(k=>String(frame[k])).join('\n')+'\n','ascii');
}
export function verifyResult(f,e){
  if(!f||typeof f!=='object'||Array.isArray(f)||JSON.stringify(Object.keys(f).sort())!==JSON.stringify(keys)||!e||typeof e!=='object'||Array.isArray(e)||
     f.v!==1||!uint(f.id,1)||f.ok!==true||f.type!=='credential_installation'||!['Link','Core'].includes(f.role)||!hex(f.build,32)||!nonzero(f.boot,16)||!nonzero(f.hardware,8)||
     !['device_id','article_id','article_revision_id'].every(k=>typeof f[k]==='string'&&uuid.test(f[k]))||!/^D[0-9]{12}$/.test(f.serial)||f.serial==='D000000000000'||
     !uint(f.transfer_id,1)||!uint(f.credential_revision,1)||!nonzero(f.challenge,32)||!nonzero(f.content_id,32)||!nonzero(f.envelope_sha256,32)||!nonzero(f.signature,64)||
     !['review','installed','retry','full','rejected','interrupted'].includes(f.result)||!['unavailable','empty','ready','pending'].includes(f.journal_state)||
     !uint(f.slots_used)||f.slots_used>9||!uint(f.journal_revision)||!hex(f.journal_content_id,32)||!Number.isInteger(f.fault)||![0,1].includes(f.fault)||
     (f.journal_state==='ready')!==(f.journal_revision!==0)||(f.journal_state==='ready')!==(f.journal_content_id!=='0'.repeat(64))||
     (['unavailable','empty'].includes(f.journal_state)&&f.slots_used!==0)||(['ready','pending'].includes(f.journal_state)&&f.slots_used===0)||
     (f.result==='review'&&f.journal_state==='unavailable')||(['installed','retry'].includes(f.result)&&(f.journal_state!=='ready'||f.journal_revision!==f.credential_revision||f.journal_content_id!==f.content_id))||
     (f.result==='full'&&(f.journal_state!=='ready'||f.slots_used!==9))||(f.fault===1&&!['review','interrupted'].includes(f.result))||
     !hex(e.public_key,65)||!e.public_key.startsWith('04')||f.build!==e.source||('result' in e&&f.result!==e.result)||
     !['role','boot','hardware','device_id','serial','article_id','article_revision_id','transfer_id','challenge','credential_revision','content_id','envelope_sha256','fault'].every(k=>f[k]===e[k]))return false;
  try{
    const raw=Buffer.from(e.public_key,'hex');crypto.ECDH.convertKey(raw,'prime256v1');
    const key=crypto.createPublicKey({format:'jwk',key:{kty:'EC',crv:'P-256',x:raw.subarray(1,33).toString('base64url'),y:raw.subarray(33).toString('base64url')}});
    return crypto.verify('sha256',proofMessage(f),{key,dsaEncoding:'ieee-p1363'},Buffer.from(f.signature,'hex'));
  }catch{return false;}
}
