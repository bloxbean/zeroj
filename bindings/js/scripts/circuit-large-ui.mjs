// Exercise the actual demo controls, including recovery after cancelling an import.
import {chromium} from '@playwright/test';
import {spawn} from 'node:child_process';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const base='http://127.0.0.1:8798';
const server=spawn('python3',['scripts/serve.py','--port','8798'],{stdio:['ignore','pipe','inherit']});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',c=>reject(Error('Server exited '+c)));});
try{
 const browser=await chromium.launch({headless:true});
 try{
  const page=await browser.newPage({viewport:{width:1100,height:900}}),errors=[],external=[],assets=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('request',r=>{if(new URL(r.url()).origin!==base)external.push(r.url());if(r.url().includes('/assets/'))assets.push(r.url());});
  await page.goto(base+'/examples/circuit-large/');
  await page.waitForFunction(()=>!!document.querySelector('button[data-depth]'));assert.deepEqual(assets,[]);
  await page.click('[data-depth="8"]');
  await page.waitForFunction(()=>document.getElementById('result').textContent.startsWith('keyLoad'),null,{timeout:30000});
  await page.click('#cancel');
  await page.waitForFunction(()=>document.getElementById('result').dataset.status==='stopped');
  assert.equal(await page.locator('[data-depth="8"]').isEnabled(),true);
  assert.equal(await page.locator('#cancel').isEnabled(),false);
  console.log('UI cancellation and controls recovered');
  await page.click('[data-depth="8"]');
  await page.waitForFunction(()=>!!document.getElementById('result').dataset.status,null,{timeout:660000});
  assert.equal(await page.locator('#result').getAttribute('data-status'),'passed',await page.locator('#result').textContent());
  const result=JSON.parse(await page.locator('#full-result').textContent());
  assert.equal(result.invalidPathRejected,true);assert.equal(result.changedRootRejected,true);assert.equal(result.snarkjsAccepted,true);
  assert.equal(await page.locator('[data-depth="8"]').isEnabled(),true);
  assert.equal(await page.locator('#cancel').isEnabled(),false);
  assert.deepEqual(errors,[]);assert.deepEqual(external,[]);
  assert(assets.length>0&&assets.every(u=>u.includes('/build/circuit-large/bundle/assets/')));
  const out=new URL('../build/circuit-large/',import.meta.url);
  await fs.writeFile(new URL('ui-result.json',out),JSON.stringify({status:'passed',cancellation:true,browser:browser.version(),...result},null,2));
  await page.screenshot({path:new URL('ui-desktop.png',out).pathname,fullPage:true});
  await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.screenshot({path:new URL('ui-mobile-width.png',out).pathname,fullPage:true});
  console.log('UI final-image depth-8 proof and responsive layout passed',result.image);
 }finally{await browser.close();}
}finally{server.kill();}
