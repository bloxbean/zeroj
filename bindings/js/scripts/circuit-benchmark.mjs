// RSS includes the whole Node process and workers; sampled peaks are lower bounds.
import fs from 'node:fs/promises';
import os from 'node:os';
import {benchmark} from '../examples/circuit/benchmark.mjs';
const name=process.argv[2]??'poseidon_opening';
if(!['poseidon_opening','allowlist_d1','merkle_d2'].includes(name))throw Error('Unknown benchmark');
const dir=new URL('../build/circuit/',import.meta.url),out=new URL('../build/circuit-results/',import.meta.url);
const load=(name,kind)=>fs.readFile(new URL(name,dir),kind==='text'?'utf8':undefined);
let phase='baseline';const memory={},baseline=process.memoryUsage();
function sample(){const rss=process.memoryUsage.rss();memory[phase]=Math.max(memory[phase]??0,rss);}
const timer=setInterval(sample,10);sample();
try{
 const result=await benchmark(load,{name,onPhase:p=>{sample();phase=p;sample();}});sample();
 Object.assign(result,{environment:{node:process.version,platform:process.platform,arch:process.arch,cpu:os.cpus()[0]?.model},
  memory:{scope:'entire Node process, including workers; 10 ms RSS sampling, not Wasm/JVM heap or retained key size',baselineRss:baseline.rss,peakRssByPhase:memory,maxRssKiB:process.resourceUsage().maxRSS}});
 await fs.mkdir(out,{recursive:true});await fs.writeFile(new URL((name==='poseidon_opening'?'poseidon':name)+'-benchmark-node.json',out),JSON.stringify(result,null,2)+'\n');
 console.log(JSON.stringify({summary:result.summary,warm:result.warm,memory:result.memory},null,2));
}finally{clearInterval(timer);}
