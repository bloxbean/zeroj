import {chromium,firefox} from '@playwright/test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
const server=spawn('python3',['scripts/serve.py','--port','8792'],{stdio:['ignore','pipe','inherit']});
await new Promise((resolve,reject)=>{server.stdout.once('data',resolve);server.once('error',reject);server.once('exit',code=>reject(Error('Server exited '+code)));});
try {
 for(const [name,type] of Object.entries({chromium,firefox})) {
  const browser=await type.launch({headless:true});
  try {
   const page=await browser.newPage();
   const assets=[],errors=[];
   page.on('request',r=>{if(r.url().includes('/assets/')) assets.push(r.url());});
   page.on('pageerror',e=>errors.push(e.message));
   await page.goto('http://127.0.0.1:8792/examples/browser/');
   await page.waitForFunction(()=>!!document.querySelector('#hash'));
   assert.equal(assets.length,0,'no eager Wasm download');
   await page.locator('#hash').click();
   await page.waitForFunction(()=>document.querySelector('#result').textContent.includes('agree'),{},{timeout:30_000});
   assert.equal(assets.filter(p=>p.endsWith('.wasm')).length,1);
   await page.locator('#hash').click();
   await page.waitForFunction(()=>!document.querySelector('#hash').disabled);
   assert.equal(assets.filter(p=>p.endsWith('.wasm')).length,1,'one shared image load');
   assert.deepEqual(errors,[]);
   await page.setViewportSize({width:390,height:844});
   assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
   console.log(name, 'PASS',await browser.version());
  } finally {await browser.close();}
 }
} finally {server.kill('SIGTERM');}
