// Install only the compiler's packages outside the workspace; run real packaged proving.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=fileURLToPath(new URL('../',import.meta.url)),out=path.join(root,'build/circuit-npm');fs.mkdirSync(out,{recursive:true});
function run(cmd,args,cwd){const r=spawnSync(cmd,args,{cwd,encoding:'utf8',timeout:180000,maxBuffer:4*1024*1024});if(r.status!==0)throw Error(r.stderr+r.stdout);return r.stdout;}
const names=['runtime','groth16-verifier','circuit','circuit-lint','bundle-circuit'],tarballs=[];
for(const name of names){
 const [packed]=JSON.parse(run('npm',['pack','--json','--ignore-scripts','--pack-destination',out],path.join(root,'packages',name)));
 if(name!=='circuit-lint'&&!packed.files.some(f=>f.path==='dist/index.d.ts'))throw Error('Missing types');
 if(packed.files.some(f=>/\.log$|\.zkey$|\.wat$/.test(f.path)))throw Error('Raw artifacts in package');
 tarballs.push(path.join(out,packed.filename));
}
const consumer=fs.mkdtempSync(path.join(os.tmpdir(),'zeroj-circuit-consumer-'));
try{
 fs.writeFileSync(path.join(consumer,'package.json'),'{"private":true,"type":"module"}');
 run('npm',['install','--ignore-scripts','--offline','--no-audit','--no-fund',...tarballs,'typescript@5.9.3'],consumer);
 const dir=path.join(root,'build/circuit/cubic'),f=JSON.parse(fs.readFileSync(path.join(root,'build/circuit/manifest.json'))).find(x=>x.name==='cubic');
 const vk=JSON.parse(fs.readFileSync(path.join(dir,'vk.json'))),key=Array.from(fs.readFileSync(path.join(dir,'key.zkey')));
 const arrayIdentity=JSON.parse(fs.readFileSync(path.join(root,'../wasm/adapter-circuit/build/symbolic-test-vectors/arrays-identity.json')));
 const source=`import {createRuntime} from '@zeroj/runtime';
import {createCircuitCompiler,defineCircuit,field,bool,uint,array} from '@zeroj/circuit';
import {createGroth16Verifier,type Groth16VerificationKey} from '@zeroj/groth16-verifier';
import {bundle} from '@zeroj/bundle-circuit';
const d=defineCircuit({name:'cubic',public:{y:field()},secret:{x:field()}},({public:p,secret:s,zk})=>{s.x.mul(s.x).mul(s.x).add(s.x).add(zk.constant(5n)).assertEqual(p.y);});
const r=createRuntime({bundles:[bundle],experimentalSecrets:true});
try{
 const c=await createCircuitCompiler(r).compile(d,${JSON.stringify({expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint})});
 const vk=${JSON.stringify(vk)} as Groth16VerificationKey;
 const key=await c.loadKey({zkey:new Uint8Array(${JSON.stringify(key)}),expectedSha256:new Uint8Array(${JSON.stringify(Array.from(Buffer.from(f.keySha256,'hex')))}),verificationKey:vk});
 const proof=await c.prove(key,{public:{y:35n},secret:{x:3n}});
 if(!await createGroth16Verifier(r).verify({...proof,verificationKey:vk}))throw Error('proof');
 if(await createGroth16Verifier(r).verify({...proof,publicInputs:[36n],verificationKey:vk}))throw Error('tamper');
 await c.dispose();console.log('Packed circuit SDK: author, compile, prove, verify, reject tamper PASS');
}finally{await r.dispose();}
const arrays=defineCircuit({name:'arrays',public:{out:array(field(),2)},secret:{flags:array(bool(),2),values:array(uint(8),2)}},({public:p,secret:s})=>{
 for(let i=0;i<s.flags.length;i++)s.flags.get(i).assertTrue();
 for(let i=0;i<p.out.length;i++)s.values.get(i).asField().assertEqual(p.out.get(i));
});
const ar=createRuntime({bundles:[bundle],experimentalSecrets:true});
try{
 const c=await createCircuitCompiler(ar).compile(arrays,${JSON.stringify(arrayIdentity)});
 if(!(await c.checkWitness({public:{out:[5n,7n]},secret:{flags:[true,true],values:[5n,7n]}})).valid)throw Error('array witness');
 await c.dispose();console.log('Packed SDK fixed arrays: typed recipe v2 and Wasm witness PASS');
}finally{await ar.dispose();}`;
 fs.writeFileSync(path.join(consumer,'main.ts'),source);
 fs.writeFileSync(path.join(consumer,'tsconfig.json'),JSON.stringify({compilerOptions:{target:'ES2022',module:'NodeNext',moduleResolution:'NodeNext',strict:true,lib:['ES2022','DOM'],outDir:'dist'},include:['main.ts']}));
 run(process.execPath,[path.join(root,'node_modules/typescript/bin/tsc'),'-p',consumer],consumer);
 run(process.execPath,[path.join(consumer,'node_modules/@zeroj/circuit-lint/src/index.mjs'),'main.ts'],consumer);
 console.log(run(process.execPath,['--experimental-wasm-exnref','dist/main.js'],consumer).trim());
 console.log('Offline install:',names.length,'local SDK tarballs; no publication.');
}finally{fs.rmSync(consumer,{recursive:true,force:true});}
