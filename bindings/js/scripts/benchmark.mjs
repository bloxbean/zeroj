// Reproducible illustrative latency samples. Run without concurrent benchmarks/builds.
import fs from 'node:fs';
import os from 'node:os';
import {runScenario} from '../examples/shared/scenarios.js';
const build=new URL('../build/',import.meta.url);
const bytes=async name=>new Uint8Array(fs.readFileSync(new URL(name,build)));
const json=async name=>JSON.parse(new TextDecoder().decode(await bytes(name)));
const results={environment:{node:process.version,platform:process.platform,arch:process.arch,cpu:os.cpus()[0]?.model},samples:{}};
for(const name of ['pedersen','bbs','groth16','elgamal','threshold','notes']){
 const samples=[];
 for(let i=0;i<3;i++)samples.push(await runScenario(name,json,bytes));
 results.samples[name]=samples;
}
fs.mkdirSync(build,{recursive:true});fs.writeFileSync(new URL('benchmark.json',build),JSON.stringify(results,null,2)+'\n');
for(const [name,samples] of Object.entries(results.samples)){
 const median=field=>samples.map(s=>s[field]).sort((a,b)=>a-b)[1];
 console.log(name,JSON.stringify({totalMs:median('totalMs'),...(name==='groth16'?{proofMs:median('proofMs'),verifyMs:median('verifyMs')}:{})}));
}
