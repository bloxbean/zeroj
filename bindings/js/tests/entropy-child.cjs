/* Test process only. Intentionally replaces host entropy to test failure and routing. */
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),crypto=require('node:crypto');
const [folder,mode]=process.argv.slice(2);
const requests=JSON.parse(fs.readFileSync(0,'utf8'));
const manifest=JSON.parse(fs.readFileSync(path.join(folder,'assets/manifest.json')));
const rawJs=fs.readFileSync(path.join(folder,'assets/engine.js'));
const rawWasm=fs.readFileSync(path.join(folder,'assets/engine.wasm'));
for(const [entry,data] of [[manifest.launcher,rawJs],[manifest.wasm,rawWasm]]) {
 if(data.length!==entry.bytes||crypto.createHash('sha256').update(data).digest('hex')!==entry.sha256)throw Error('Test artifact mismatch');
}
let weakCalls=0,drawLengths=[];
Math.random=()=>{weakCalls++;throw Error('Weak RNG called');};
const host=crypto.webcrypto;
let random;
if(mode!=='absent') random=bytes=>{
 drawLengths.push(bytes.length);
 if(mode==='throw'||(mode==='late'&&drawLengths.length>2))throw Error('Entropy unavailable');
 if(mode==='constant')return bytes.fill(1);
 return host.getRandomValues(bytes);
};
Object.defineProperty(globalThis,'crypto',{value:{subtle:host.subtle,getRandomValues:random},configurable:true});
globalThis.ZEROJ_EXPERIMENTAL_SECRETS=true;
globalThis.ZEROJ_WASM_BYTES=new Uint8Array(rawWasm);
globalThis.require=require;
globalThis.__filename=path.resolve(folder,'assets/engine.js');
globalThis.__dirname=path.dirname(globalThis.__filename);
globalThis.zerojReady=()=>{
 const results=requests.map(request=>{
  try {return JSON.parse(String(globalThis.zerojCall(JSON.stringify(request))));}
  catch {return {ok:false,error:{code:'UNCAUGHT_RUNTIME_ERROR'}};}
 });
 process.stdout.write(JSON.stringify({results,weakCalls,drawLengths}));
};
vm.runInThisContext(rawJs.toString('utf8'),{filename:globalThis.__filename});
