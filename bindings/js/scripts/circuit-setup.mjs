// Disposable local fixtures only. Uses snarkjs' existing writer, ceremony and prover.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
const root=fileURLToPath(new URL('../',import.meta.url));
const require=createRequire(path.join(root,'package.json'));
const snarkjs=require('snarkjs'), bin=require('@iden3/binfileutils');
const {write}=await import(pathToFileURL(path.join(root,'node_modules/snarkjs/src/wtns_utils.js')));
const out=path.join(root,'build/circuit'),cli=path.join(root,'node_modules/snarkjs/build/cli.cjs');
const manifest=JSON.parse(await fs.readFile(path.join(out,'manifest.json'),'utf8'));
const log=await fs.open(path.join(out,'setup.log'),'w');
function run(...args){const r=spawnSync(process.execPath,[cli,...args],{cwd:out,stdio:['ignore',log.fd,log.fd]});if(r.status!==0)throw Error('snarkjs failed: '+args.slice(0,2).join(' '));}
run('powersoftau','new','bls12-381','9','pot0.ptau');
run('powersoftau','contribute','pot0.ptau','pot1.ptau','--name=research-only','-e='+randomBytes(64).toString('hex'));
run('powersoftau','prepare','phase2','pot1.ptau','pot_final.ptau');
for(const item of manifest){
  const dir=path.join(out,item.name),witness=JSON.parse(await fs.readFile(path.join(dir,'witness.json'),'utf8')).map(BigInt);
  const fd=await bin.createBinFile(path.join(dir,'witness.wtns'),'wtns',2,2);
  await write(fd,witness,BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001'));await fd.close();
  if(!await snarkjs.wtns.check(path.join(dir,'circuit.r1cs'),path.join(dir,'witness.wtns')))throw Error('Independent R1CS check failed');
  if(item.wires>4096||item.constraints+item.publicInputs+1>4096){item.proofSupported=false;item.proofLimit='Exceeds compiler profile 4096-wire / domain limits';continue;}
  run('groth16','setup',item.name+'/circuit.r1cs','pot_final.ptau',item.name+'/key0.zkey');
  run('zkey','contribute',item.name+'/key0.zkey',item.name+'/key.zkey','--name=research-only','-e='+randomBytes(64).toString('hex'));
  run('zkey','verify',item.name+'/circuit.r1cs','pot_final.ptau',item.name+'/key.zkey');
  run('zkey','export','verificationkey',item.name+'/key.zkey',item.name+'/vk.json');
  run('groth16','prove',item.name+'/key.zkey',item.name+'/witness.wtns',item.name+'/snarkjs-proof.json',item.name+'/snarkjs-public.json');
  run('groth16','verify',item.name+'/vk.json',item.name+'/snarkjs-public.json',item.name+'/snarkjs-proof.json');
  const key=await fs.readFile(path.join(dir,'key.zkey'));item.keySha256=createHash('sha256').update(key).digest('hex');item.keyBytes=key.length;
  item.independentProofVerified=true;
  item.proofSupported=key.length<=2*1024*1024&&item.wires<=4096;
  if(!item.proofSupported)item.proofLimit=`Measured ${key.length}-byte key exceeds circuit-key-v1 2 MiB import cap; snarkjs proof verified separately`;
  await fs.unlink(path.join(dir,'key0.zkey'));
}
await log.close();
for(const name of ['pot0.ptau','pot1.ptau','pot_final.ptau'])await fs.unlink(path.join(out,name));
await fs.writeFile(path.join(out,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
console.log(`${manifest.length} independently checked R1CS/witness pairs; ${manifest.filter(x=>x.independentProofVerified).length} development keys and snarkjs proofs; ${manifest.filter(x=>x.proofSupported).length} fit Wasm import caps.`);
// snarkjs curve workers are not consistently released by its programmatic wtns check.
process.exit(0);
