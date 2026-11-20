import {createRuntime,bytesToHex} from '@zeroj/runtime';
import {createHash} from '@zeroj/hash';
import {bundle} from '../../packages/bundle-hash/dist/index.js';
const runtime=createRuntime({bundles:[bundle]});
const wasm=createHash(runtime,{shaBackend:'wasm'}),host=createHash();
const button=document.querySelector('#hash'),result=document.querySelector('#result');
button.addEventListener('click',async()=>{
  button.disabled=true;result.textContent='Loading the hash bundle and computing locally…';
  try {
    const bytes=new TextEncoder().encode(document.querySelector('#message').value);
    const start=performance.now();
    const native=await host.sha256(bytes),java=await wasm.sha256(bytes),blake=await wasm.blake2b(bytes);
    if(bytesToHex(native)!==bytesToHex(java)) throw Error('HASH_MISMATCH');
    result.textContent='SHA-256: WebCrypto and ZeroJ agree\n'+bytesToHex(java)
      +'\n\nBLAKE2b-256:\n'+bytesToHex(blake)+'\n\nElapsed for this call (first call loads image): '+(performance.now()-start).toFixed(1)+' ms';
  } catch(error) { result.textContent='Operation failed: '+(error.code ?? 'UNAVAILABLE'); }
  finally {button.disabled=false;}
});
window.addEventListener('pagehide',()=>void runtime.dispose());

// Every scenario has an explicit runtime lifetime; workers are terminated after completion.
import {runScenario} from '../shared/scenarios.js';
const loadBytes=async name=>{
 const response=await fetch('/build/'+name);if(!response.ok)throw Error('Build the development fixtures first.');
 return new Uint8Array(await response.arrayBuffer());
};
const loadJson=async name=>JSON.parse(new TextDecoder().decode(await loadBytes(name)));
for(const button of document.querySelectorAll('[data-scenario]')) {
 button.addEventListener('click',async()=>{
  const name=button.dataset.scenario,output=document.querySelector('#result-'+name);button.disabled=true;
  output.textContent='Loading the selected image and running locally…';
  try {output.textContent=JSON.stringify(await runScenario(name,loadJson,loadBytes),null,2);output.dataset.status='pass';}
  catch(error){output.textContent=error.code??error.message;output.dataset.status='fail';}
  finally{button.disabled=false;}
 });
}
