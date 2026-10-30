import fs from 'node:fs/promises';
import os from 'node:os';
import {createRequire} from 'node:module';
import {largeResearch} from '../examples/circuit/large-research.mjs';
const name=process.argv[2];if(!['merkle_d8','merkle_d16','merkle_d32'].includes(name))throw Error('Select an admitted research fixture');
const dir=new URL('../build/circuit-large/',import.meta.url),load=(n,k)=>fs.readFile(new URL(n,dir),k==='text'?'utf8':undefined);
for(const suffix of ['-proof.json','-result.json'])await fs.rm(new URL(name+'/node'+suffix,dir),{force:true});
const baseline=process.memoryUsage.rss(),peak={};let current='baseline';
const sample=()=>{peak[current]=Math.max(peak[current]??0,process.memoryUsage.rss());};const timer=setInterval(sample,10);sample();
try{
 const result=await largeResearch(name,load,{onPhase:p=>{sample();current=p;sample();console.log(name,p);}});sample();
 const {proof,...report}=result;
 report.environment={node:process.version,cpu:os.cpus()[0]?.model,platform:process.platform,arch:process.arch};
 report.memory={baselineRss:baseline,peakRssByPhase:{...peak},maxRssKiB:process.resourceUsage().maxRSS,scope:'Whole Node process including workers; 10 ms RSS sampling, not Java/Wasm heap'};
 clearInterval(timer);
 const require=createRequire(import.meta.url);try{
  const vk=JSON.parse(await load(name+'/vk.json','text'));
  if(!await require('snarkjs').groth16.verify(vk,proof.publicInputs,proof.proof))throw Error('Independent snarkjs verification failed');
 }finally{const curve=await require('ffjavascript').getCurveFromName('bls12381');await curve.terminate();}
 report.independentSnarkjsVerified=true;
 await fs.writeFile(new URL(name+'/node-proof.json',dir),JSON.stringify(proof));
 await fs.writeFile(new URL(name+'/node-result.json',dir),JSON.stringify(report,null,2));
 console.log(JSON.stringify({name,timingsMs:report.timingsMs,warmProofMs:report.warmProofMs,memory:report.memory},null,2));
}finally{clearInterval(timer);}
