// Build local tarballs, install outside the workspace, and exercise real packaged assets and types.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('../',import.meta.url)),out=path.join(root,'build/npm');fs.mkdirSync(out,{recursive:true});
const names=['runtime','hash','pedersen','bbs','groth16-verifier','groth16-prover','elgamal','threshold','confidential-notes',
 'bundle-hash','bundle-crypto','bundle-verifier','bundle-prover','bundle-confidential','bundle-all'];
function run(cmd,args,cwd){const result=spawnSync(cmd,args,{cwd,encoding:'utf8',timeout:180_000,maxBuffer:4*1024*1024});if(result.status!==0)throw Error(result.stderr+result.stdout);return result.stdout;}
const tarballs=[];
for(const name of names){
 const [packed]=JSON.parse(run('npm',['pack','--json','--ignore-scripts','--pack-destination',out],path.join(root,'packages',name)));
 if(!packed.files.some(f=>f.path==='dist/index.d.ts'))throw Error('Types missing: '+name);
 if(name.startsWith('bundle-')&&!packed.files.some(f=>f.path==='assets/engine.wasm'))throw Error('Image missing: '+name);
 if(packed.files.some(f=>/\.log$|\.zkey$|\.wat$/.test(f.path)))throw Error('Unexpected evidence/key in '+name);
 tarballs.push(path.join(out,packed.filename));
}
const consumer=fs.mkdtempSync(path.join(os.tmpdir(),'zeroj-npm-consumer-'));
try {
 fs.writeFileSync(path.join(consumer,'package.json'),JSON.stringify({private:true,type:'module'}));
 run('npm',['install','--ignore-scripts','--offline','--no-audit','--no-fund',...tarballs],consumer);
 const source=`import {createRuntime} from '@zeroj/runtime';
import {createHash} from '@zeroj/hash';
import {createPedersen} from '@zeroj/pedersen';
import {createBbs} from '@zeroj/bbs';
import {createElGamal} from '@zeroj/elgamal';
import {createConfidentialNotes} from '@zeroj/confidential-notes';
import {createThreshold} from '@zeroj/threshold';
import {createGroth16Prover} from '@zeroj/groth16-prover';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {bundle} from '@zeroj/bundle-all';
const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
try {
 const digest=await createHash(runtime,{shaBackend:'wasm'}).sha256(new TextEncoder().encode('abc'));
 if(Array.from(digest,b=>b.toString(16).padStart(2,'0')).join('')!=='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')throw Error('hash');
 const p=createPedersen(runtime).jubjub,c=await p.commitScalar({value:42n,blinding:12n});
 if(!await p.verifyOpening({commitment:c,value:42n,blinding:12n}))throw Error('commitment');
 const bbs=createBbs(runtime),key=await bbs.generateKey(),messages=[new Uint8Array([1])],header=new Uint8Array();
 const signature=await bbs.sign({secret:key.secret,messages,header});
 if(!await bbs.verify({publicKey:key.publicKey,signature,messages,header}))throw Error('signature');
 const notes=createConfidentialNotes(runtime),reader=await notes.generateViewingKey(),opening=await notes.createOpening(9n);
 const [delivery]=await notes.seal(opening.handle,[reader.readerKey]);
 if(!await notes.open({key:reader.handle,delivery:delivery!,u:opening.u,v:opening.v}))throw Error('note');
 const elgamal=createElGamal(runtime),secret=await elgamal.generateKey(),context=await elgamal.aggregate([secret.share]);
 const cipher=await elgamal.encrypt(context.handle,1n,1),share=await elgamal.decryptionShare(secret.secret,cipher.handle);
 if(await elgamal.decrypt(cipher.handle,[share.handle],1)!==1n)throw Error('decryption');
 const description=await createGroth16Prover(runtime).describe('tutorial-cubic-bls12381-v1');
 if(description.constraints!==3)throw Error('circuit');
 createGroth16Verifier(runtime);createThreshold(runtime);
 console.log('Packed consumer: hash, commitments, BBS, notes, ElGamal, circuit metadata and all package types PASS');
}finally{await runtime.dispose();}`;
 fs.writeFileSync(path.join(consumer,'main.ts'),source);
 fs.writeFileSync(path.join(consumer,'tsconfig.json'),JSON.stringify({compilerOptions:{target:'ES2022',module:'NodeNext',moduleResolution:'NodeNext',strict:true,lib:['ES2022','DOM'],outDir:'dist'},include:['main.ts']}));
 run(process.execPath,[path.join(root,'node_modules/typescript/bin/tsc'),'-p',consumer],consumer);
 console.log(run(process.execPath,['--experimental-wasm-exnref','dist/main.js'],consumer).trim());
 console.log('Offline local tarball install:',names.length,'packages');
}finally{fs.rmSync(consumer,{recursive:true,force:true});}
