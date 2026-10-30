import {chromium,firefox} from '@playwright/test';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
const fixture=process.argv[2]??'poseidon_opening';
if(!['poseidon_opening','allowlist_d1','merkle_d2'].includes(fixture))throw Error('Unknown benchmark');
const port='8795',base='http://127.0.0.1:'+port;
const server=spawn('python3',['scripts/serve.py','--port',port],{stdio:['ignore','pipe','inherit']});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',code=>reject(Error('Server exited '+code)));});
try{
 for(const [name,type]of [['chromium',chromium],['firefox',firefox]]){
  const browser=await type.launch({headless:true});
  try{
   const page=await browser.newPage();await page.goto(base+'/examples/circuit/');
   const result=await page.evaluate(async name=>{
    const {benchmark}=await import('/examples/circuit/benchmark.mjs');
    const load=async(n,k)=>{const r=await fetch('/build/circuit/'+n);if(!r.ok)throw Error('fixture');return k==='text'?r.text():r.arrayBuffer();};
    return benchmark(load,{name});
   },fixture);
   result.environment={browser:name,version:browser.version(),headless:true};
   await fs.writeFile(new URL('../build/circuit-results/'+(fixture==='poseidon_opening'?'poseidon':fixture)+'-benchmark-'+name+'.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
   console.log(name,JSON.stringify({summary:result.summary,warm:result.warm}));
  }finally{await browser.close();}
 }
}finally{server.kill();}
