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
    if(id==='sha256_abc')assert.equal(result.proofGenerated,false);
    else {assert.equal(result.proofGenerated,true);assert.equal(result.tamperedAccepted,false);assert.equal(result.snarkjsAccepted,true);}
    if(id==='sha256_abc')assert.equal(result.hostDigestMatches,true);
    if(id==='poseidon_opening'){
      const proof=await page.evaluate(async()=>{const {scenario}=await import('/examples/circuit/scenarios.mjs');const load=async(n,k)=>{const r=await fetch('/build/circuit/'+n);return k==='text'?r.text():r.arrayBuffer();};const r=await scenario('poseidon_opening',load);return {proof:r.proof.proof,publicInputs:r.proof.publicInputs.map(String)};});
      await fs.writeFile(new URL('../circuit/poseidon_opening/'+name+'-proof.json',out),JSON.stringify(proof));
    }
    results.push(result);
   }
   const cancelled=await page.evaluate(async()=>{
    const {createCircuitCompiler}=await import('@zeroj/circuit');
    const {circuitRuntime,symbolicExamples}=await import('/examples/circuit/scenarios.mjs');
    const f=(await(await fetch('/build/circuit/manifest.json')).json()).find(x=>x.name==='poseidon_opening');
    const r=circuitRuntime(),controller=new AbortController();
    try{
     const c=await createCircuitCompiler(r).compile(symbolicExamples.find(x=>x.name===f.name),{expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint});
     const a={zkey:new Uint8Array(await(await fetch('/build/circuit/poseidon_opening/key.zkey')).arrayBuffer()),expectedSha256:Uint8Array.from(f.keySha256.match(/../g),h=>parseInt(h,16)),verificationKey:await(await fetch('/build/circuit/poseidon_opening/vk.json')).json()};
     const call=r.call.bind(r);r.call=(cap,op,args)=>{const promise=call(cap,op,args);if(op==='finishKey')setTimeout(()=>controller.abort(),25);return promise;};
     try{await c.loadKey(a,{signal:controller.signal});return false;}catch(e){return e.code==='ABORTED';}
    }finally{await r.dispose();}
   });
   assert.equal(cancelled,true,'browser abort during import');
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
