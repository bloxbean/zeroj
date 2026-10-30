// Explicit research only: generate separate dev keys, never overwrite the default fixture manifest.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url)),source=path.join(root,'build/circuit'),out=path.join(root,'build/circuit-large');
if(process.argv[2]!=='--research-only')throw Error('Pass --research-only; disposable local setup, not a production ceremony');
const original=JSON.parse(await fs.readFile(path.join(source,'manifest.json'),'utf8'));
const manifest=original.filter(f=>['merkle_d8','merkle_d16','merkle_d32'].includes(f.name)).map(f=>({...f,proofSupported:false,experiment:'large-merkle-v1'}));
if(manifest.length!==3||manifest.some(f=>!f.developmentOnly))throw Error('Generate the three development R1CS/witness fixtures first');
await fs.mkdir(out,{recursive:true});
const cli=path.join(root,'node_modules/snarkjs/build/cli.cjs');
const log=await fs.open(path.join(out,'setup.log'),'w');
function run(...args){const t=performance.now();const r=spawnSync(process.execPath,[cli,...args],{cwd:out,stdio:['ignore',log.fd,log.fd],timeout:600000});if(r.status!==0)throw Error('snarkjs failed: '+args.slice(0,2).join(' '));return performance.now()-t;}
try{
 for(const f of manifest){await fs.mkdir(path.join(out,f.name),{recursive:true});for(const file of ['graph.json','inputs.json','circuit.r1cs','witness.wtns'])await fs.copyFile(path.join(source,f.name,file),path.join(out,f.name,file));}
 run('powersoftau','new','bls12-381','13','pot0.ptau');
 run('powersoftau','contribute','pot0.ptau','pot1.ptau','--name=research-only','-e='+randomBytes(64).toString('hex'));
 run('powersoftau','prepare','phase2','pot1.ptau','pot_final.ptau');
 for(const f of manifest){
  console.log('Generating',f.name,'(development ceremony)');
  run('wtns','check',f.name+'/circuit.r1cs',f.name+'/witness.wtns');
  f.setupMs=run('groth16','setup',f.name+'/circuit.r1cs','pot_final.ptau',f.name+'/key0.zkey');
  run('zkey','contribute',f.name+'/key0.zkey',f.name+'/key.zkey','--name=research-only','-e='+randomBytes(64).toString('hex'));
  run('zkey','verify',f.name+'/circuit.r1cs','pot_final.ptau',f.name+'/key.zkey');
  run('zkey','export','verificationkey',f.name+'/key.zkey',f.name+'/vk.json');
  f.snarkjsProveMs=run('groth16','prove',f.name+'/key.zkey',f.name+'/witness.wtns',f.name+'/snarkjs-proof.json',f.name+'/snarkjs-public.json');
  run('groth16','verify',f.name+'/vk.json',f.name+'/snarkjs-public.json',f.name+'/snarkjs-proof.json');
  const key=await fs.readFile(path.join(out,f.name,'key.zkey'));f.keyBytes=key.length;f.keySha256=createHash('sha256').update(key).digest('hex');
  // Public size census of this locally generated zkey, not a cryptographic admission parser.
  const sections={};let offset=12;for(let i=0;i<key.readUInt32LE(8);i++){const id=key.readUInt32LE(offset),bytes=Number(key.readBigUInt64LE(offset+4));offset+=12;sections[id]={offset,bytes};offset+=bytes;}
  if(offset!==key.length)throw Error('Unexpected local zkey structure');
  f.coefficients=key.readUInt32LE(sections[4].offset);f.domainSize=key.readUInt32LE(sections[2].offset+96);f.sectionBytes=Object.fromEntries(Object.entries(sections).map(([id,s])=>[id,s.bytes]));
  f.proofSupported=key.length<=32*1024*1024&&f.wires<=65536&&f.domainSize<=8192&&f.coefficients<=262144;
  f.independentProofVerified=true;delete f.proofLimit;
  await fs.unlink(path.join(out,f.name,'key0.zkey'));
  await fs.writeFile(path.join(out,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');console.log(f.name,JSON.stringify({bytes:f.keyBytes,coefficients:f.coefficients,domain:f.domainSize,admitted:f.proofSupported}));
 }
}finally{
 await log.close();for(const name of ['pot0.ptau','pot1.ptau','pot_final.ptau'])await fs.rm(path.join(out,name),{force:true});
}
