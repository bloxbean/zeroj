import {chromium,firefox} from '@playwright/test';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const engine=process.argv[2],name=process.argv[3];
if(!['chromium','firefox'].includes(engine)||!['merkle_d8','merkle_d16','merkle_d32'].includes(name))throw Error('Select browser and depth');
const out=new URL('../build/circuit-large/'+name+'/',import.meta.url);
for(const suffix of ['-proof.json','-result.json'])await fs.rm(new URL(engine+suffix,out),{force:true});
let phase='startup';const started=Date.now();
const port=engine==='chromium'?'8796':'8797',base='http://127.0.0.1:'+port;
const server=spawn('python3',['scripts/serve.py','--port',port],{stdio:['ignore','pipe','inherit']});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',c=>reject(Error('Server exited '+c)));});
try{
 const browser=await({chromium,firefox}[engine]).launch({headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1100,height:900}}),external=[],errors=[],assets=[];
  page.on('request',r=>{if(new URL(r.url()).origin!==base)external.push(r.url());if(r.url().includes('/assets/'))assets.push(r.url());});page.on('pageerror',e=>errors.push(e.message));
  await page.goto(base+'/examples/circuit-large/');await page.waitForFunction(()=>!!document.querySelector('[data-depth]'));
  assert.deepEqual(assets,[],'module import must remain inert');
  await page.exposeFunction('researchPhase',p=>{if(p!=='dispose')phase=p;console.log(engine,name,p);});
  const result=await page.evaluate(async name=>{
   const {largeResearch}=await import('/examples/circuit/large-research.mjs');
   const load=async(n,k)=>{const r=await fetch('/build/circuit-large/'+n);if(!r.ok)throw Error('fixture');return k==='text'?r.text():r.arrayBuffer();};
   return largeResearch(name,load,{onPhase:p=>{document.getElementById('result').textContent=p+'…';void window.researchPhase(p);}});
  },name);
  const {proof,...report}=result;report.environment={browser:engine,version:browser.version(),headless:true};
  await page.evaluate(r=>{document.getElementById('result').textContent=JSON.stringify({name:r.name,timingsMs:r.timingsMs,warmProofMs:r.warmProofMs,keyBytes:r.keyBytes,invalidPathRejected:r.invalidPathRejected,changedRootRejected:r.changedRootRejected},null,2);},report);
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);assert(assets.length>0);
  assert(assets.every(u=>u.includes('/build/circuit-large/bundle/assets/')),'only selected research image may download');
  await fs.writeFile(new URL(engine+'-proof.json',out),JSON.stringify(proof));await fs.writeFile(new URL(engine+'-result.json',out),JSON.stringify(report,null,2));
  await page.screenshot({path:new URL(engine+'.png',out).pathname,fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  console.log(JSON.stringify({engine,name,timingsMs:report.timingsMs,warmProofMs:report.warmProofMs}));
 }finally{await browser.close();}
}catch(error){
 await fs.rm(new URL(engine+'-proof.json',out),{force:true});
 await fs.writeFile(new URL(engine+'-result.json',out),JSON.stringify({status:'failed',engine,name,phase,elapsedMs:Date.now()-started,errorCode:error.code??error.message},null,2));
 throw error;
}finally{server.kill();}
