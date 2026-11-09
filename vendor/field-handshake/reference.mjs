// Independent metadata bytes only, not an EDHOC or authority implementation.
import {createHash,ECDH} from 'node:crypto';
import {readFileSync} from 'node:fs';
const sha=b=>createHash('sha256').update(b).digest();
function cbor(v){
 const head=(m,n)=>n<24?Buffer.from([(m<<5)|n]):Buffer.from([(m<<5)|24,n]);
 if(Buffer.isBuffer(v))return Buffer.concat([head(2,v.length),v]);
 if(typeof v==='number')return head(v<0?1:0,v<0?-1-v:v);
 if(v instanceof Map){const pairs=[...v].map(([k,x])=>[cbor(k),cbor(x)]).sort((a,b)=>Buffer.compare(a[0],b[0]));return Buffer.concat([head(5,pairs.length),...pairs.flat()]);}
 throw Error('Unsupported fixture');
}
const hex=x=>Buffer.from(x,'hex');
export function credential(key){
 const p=hex(key);if(p.length!==65||p[0]!==4)throw Error('Invalid public key');
 const canonical=ECDH.convertKey(p,'prime256v1',undefined,undefined,'uncompressed');
 if(!canonical.equals(p))throw Error('Invalid public key');
 const ccs=cbor(new Map([[8,new Map([[1,new Map([[1,2],[3,-7],[-1,1],[-2,p.subarray(1,33)],[-3,p.subarray(33)]])]])]]));
 const kid=sha(ccs).subarray(0,8);return {ccs:ccs.toString('hex'),kid:kid.toString('hex'),key_sha256:sha(p).toString('hex'),id_cred:cbor(new Map([[4,kid]])).toString('hex')};
}
const file=process.argv[2];
if(file){
 const v=JSON.parse(readFileSync(file));let count=0;
 for(const row of v.credentials){if(JSON.stringify(credential(row.public_key))!==JSON.stringify(row.expected))throw Error('Credential bytes disagree');count++;}
 for(const row of v.preludes){const got=Buffer.concat([hex(row.fields.attempt_uuid.replaceAll('-','')),hex(row.fields.boot),hex(row.fields.nonce)]);if(got.toString('hex')!==row.hex)throw Error('Prelude bytes disagree');count++;}
 for(const row of v.fields){const field=hex(row.hex),context=sha(Buffer.concat([Buffer.from('OCTATRACE-FIELD-EXPORT-1'),field]));if(context.toString('hex')!==row.context||sha(field).toString('hex')!==row.field_sha256)throw Error('Export context disagrees');count++;}
 for(const row of v.receiver_selectors){const k=row.fields.kind==='phone_link'?1:2,got=sha(Buffer.concat([Buffer.from('OCTATRACE-FIELD-RECEIVER-1'),Buffer.from([k]),hex(row.fields.attempt_uuid.replaceAll('-','')),hex(row.fields.recipient_key_sha256)])).subarray(0,8);if(got.toString('hex')!==row.hex)throw Error('Receiver selector disagrees');count++;}
 for(const key of v.invalid_public_keys){let rejected=false;try{credential(key);}catch{rejected=true;}if(!rejected)throw Error('Invalid point accepted');count++;}
 console.log(JSON.stringify({result:'pass',checks:count,scope:'independent metadata bytes/real public-point validation; no authenticated readiness'}));
}
