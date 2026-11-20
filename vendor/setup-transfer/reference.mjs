// Independent candidate carrier codec. No signing, trust, device or readiness.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const kinds={factory_credential:[1,271],ownership_receipt:[2,270],phone_controller:[3,270],
 core_link:[4,270],setup_challenge:[5,426],setup_proof:[6,151],installation_report:[7,384],phone_custody:[8,32]};
const fail=()=>{throw Error('Invalid setup transfer');};
function uuid(value){
 if(typeof value!=='string'||!(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/).test(value))fail();
 return Buffer.from(value.replaceAll('-',''),'hex');
}
function uuidText(bytes){const h=bytes.toString('hex');return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}`;}
export function encode(f){
 if(!f||typeof f!=='object'||Object.keys(f).sort().join()!=='body_hex,correlation_uuid,device_uuid,kind'||typeof f.kind!=='string'||!Object.hasOwn(kinds,f.kind))fail();
 const [code,max]=kinds[f.kind];
 if(typeof f.body_hex!=='string'||!(/^(?:[0-9a-f]{2})+$/).test(f.body_hex)||f.body_hex.length>max*2)fail();
 const body=Buffer.from(f.body_hex,'hex');
 if(f.kind==='phone_custody'&&(body.length!==32||body.every(n=>n===0)))fail();
 const header=Buffer.alloc(68);header[0]=1;header[1]=code;uuid(f.device_uuid).copy(header,2);uuid(f.correlation_uuid).copy(header,18);
 header.writeUInt16LE(body.length,34);createHash('sha256').update(body).digest().copy(header,36);
 return Buffer.concat([header,body]);
}
export function decode(data){
 if(!Buffer.isBuffer(data)||data.length<=68||data.length>494||data[0]!==1||data.readUInt16LE(34)!==data.length-68)fail();
 const kind=Object.keys(kinds).find(k=>kinds[k][0]===data[1]);
 const fields={kind,device_uuid:uuidText(data.subarray(2,18)),correlation_uuid:uuidText(data.subarray(18,34)),body_hex:data.subarray(68).toString('hex')};
 if(!encode(fields).equals(data))fail();return fields;
}
export function frames(data,transfer){
 decode(data);if(!Number.isInteger(transfer)||transfer<1||transfer>65535)fail();
 const result=[];
 for(let offset=0;offset<data.length;offset+=12){
  const f=Buffer.alloc(20);f.write('OS',0,'ascii');f[2]=1;f.writeUInt16LE(transfer,3);f.writeUInt16LE(data.length,5);f[7]=offset/12;
  data.copy(f,8,offset,Math.min(data.length,offset+12));result.push(f);
 }return result;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const v=JSON.parse(readFileSync(process.argv[2],'utf8'));let valid=0,invalid=0;
 for(const row of v.valid){const data=Buffer.from(row.hex,'hex');if(!encode(row.fields).equals(data)||JSON.stringify(decode(data))!==JSON.stringify(row.fields)||JSON.stringify(frames(data,row.transfer).map(x=>x.toString('hex')))!==JSON.stringify(row.frames))throw Error('Candidate vector mismatch');valid++;}
 for(const row of v.invalid_records){let denied=false;try{decode(Buffer.from(row.hex,'hex'));}catch{denied=true;}if(!denied)throw Error('Candidate invalid record accepted');invalid++;}
 console.log(JSON.stringify({valid,invalid,result:'pass',scope:'untrusted record carrier only'}));
}
