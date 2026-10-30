import {chromium,firefox} from '@playwright/test';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const port='8793',base='http://127.0.0.1:'+port;
const server=spawn('python3',['scripts/serve.py','--port',port],{stdio:['ignore','pipe','inherit']});
const out=new URL('../build/circuit-results/',import.meta.url);await fs.mkdir(out,{recursive:true});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',code=>reject(Error('Server exited '+code)));});
const all=[];
try{
 for(const [name,type] of [['chromium',chromium],['firefox',firefox]]){
  const browser=await type.launch({headless:true});
  try{
   const page=await browser.newPage({viewport:{width:1280,height:900}}),errors=[],external=[],assets=[];
   page.on('pageerror',e=>errors.push(e.message));
   page.on('request',r=>{if(new URL(r.url()).origin!==base)external.push(r.url());if(r.url().includes('/assets/'))assets.push(r.url());});
   await page.goto(base+'/examples/circuit/');
   await page.waitForFunction(()=>!!document.querySelector('button[data-name]'));
   assert.equal(assets.length,0,'imports must not eagerly fetch Wasm');
   await page.screenshot({path:new URL(name+'-initial.png',out).pathname,fullPage:true});
   const results=[];
   for(const id of ['multiplier','cubic','age_check','symbolic_select','poseidon_opening','sha256_abc']){
    await page.locator('button[data-name="'+id+'"]').click();
    await page.waitForFunction(id=>!!document.getElementById(id).dataset.status,id,{timeout:120000});
    const box=page.locator('#'+id);assert.equal(await box.getAttribute('data-status'),'passed',await box.textContent());
    const result=JSON.parse(await box.textContent());assert.equal(result.valid,true);
    if(['poseidon_opening','sha256_abc'].includes(id))assert.equal(result.proofGenerated,false);
    else {assert.equal(result.proofGenerated,true);assert.equal(result.tamperedAccepted,false);assert.equal(result.snarkjsAccepted,true);}
    if(id==='sha256_abc')assert.equal(result.hostDigestMatches,true);
    results.push(result);
   }
   assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
   await page.screenshot({path:new URL(name+'-results.png',out).pathname,fullPage:true});
   await page.setViewportSize({width:390,height:844});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   await page.screenshot({path:new URL(name+'-mobile.png',out).pathname,fullPage:true});
   all.push({browser:name,version:browser.version(),results});
   console.log(name,browser.version(),'all six compiler scenarios passed');
  }finally{await browser.close();}
 }
 await fs.writeFile(new URL('browser.json',out),JSON.stringify(all,null,2)+'\n');
}finally{server.kill();}
