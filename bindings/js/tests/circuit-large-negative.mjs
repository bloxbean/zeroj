// Explicit opt-in test: requires separate large fixtures/research assets and the default image.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRuntime} from '@zeroj/runtime';
import {createCircuitCompiler} from '@zeroj/circuit';
import {bundle as standardBundle} from '@zeroj/bundle-circuit';
import {bundle as researchBundle} from '../build/circuit-large/bundle/dist/index.js';
import {merkleMembership} from '../build/circuit-examples/symbolic-examples.js';
const dir=new URL('../build/circuit-large/',import.meta.url),f=JSON.parse(await fs.readFile(new URL('manifest.json',dir),'utf8')).find(x=>x.name==='merkle_d8');
if(!f?.developmentOnly||!f.proofSupported)throw Error('Generate research fixtures');
const key=new Uint8Array(await fs.readFile(new URL('merkle_d8/key.zkey',dir))),vk=JSON.parse(await fs.readFile(new URL('merkle_d8/vk.json',dir),'utf8'));
const identity={expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint},hash=b=>new Uint8Array(createHash('sha256').update(b).digest());
const r=createRuntime({bundles:[standardBundle],experimentalSecrets:true});
try{
 const c=await createCircuitCompiler(r).compile(merkleMembership(8),identity);
 assert.equal(c.description.keyProfile,'circuit-key-v1');assert.equal(c.description.withinProverDimensions,false);
 await assert.rejects(c.loadKey({zkey:key,expectedSha256:hash(key),verificationKey:vk}),e=>e.code==='INVALID_BYTES');
 await assert.rejects(r.call('circuit','beginKey',{circuit:'h1',fingerprint:f.fingerprint,length:1,expectedSha256:f.keySha256,verificationKey:vk}),e=>e.code==='CIRCUIT_LIMIT');
 assert.equal((await c.keyResources()).peakStagingBytes,0);
}finally{await r.dispose();}
const s=createRuntime({bundles:[researchBundle],experimentalSecrets:true,timeoutMs:600000});
try{
 const c=await createCircuitCompiler(s).compile(merkleMembership(8),identity);
 const meta={circuit:'h1',fingerprint:f.fingerprint,expectedSha256:f.keySha256,verificationKey:vk};
 for(const length of [0,33554433,2147483647])await assert.rejects(s.call('circuit','beginKey',{...meta,length}));
 await assert.rejects(s.call('circuit','beginKey',{...meta,length:1,profile:'unbounded'}));
 const upload=await s.call('circuit','beginKey',{...meta,length:2});
 await s.call('circuit','appendKey',{circuit:'h1',upload:upload.upload,offset:0,chunk:'00'});
 await assert.rejects(s.call('circuit','finishKey',{circuit:'h1',upload:upload.upload}),e=>e.code==='INCOMPLETE_KEY');
 assert.equal((await c.keyResources()).reservedBytes,0);
 await assert.rejects(c.loadKey({zkey:key,expectedSha256:new Uint8Array(32),verificationKey:vk}),e=>e.code==='INVALID_PROVING_KEY');
 // Oversized wire/domain header with recomputed integrity hash must reach parser validation.
 let offset=12,header;const data=Buffer.from(key);
 for(let i=0;i<data.readUInt32LE(8);i++){const id=data.readUInt32LE(offset),bytes=Number(data.readBigUInt64LE(offset+4));offset+=12;if(id===2)header=offset;offset+=bytes;}
 assert.equal(typeof header,'number');
 for(const [position,value]of [[88,65537],[96,16384]]){
  const bad=Buffer.from(key);bad.writeUInt32LE(value,header+position);
  await assert.rejects(c.loadKey({zkey:bad,expectedSha256:hash(bad),verificationKey:vk}),e=>e.code==='INVALID_PROVING_KEY');
  assert.equal((await c.keyResources()).reservedBytes,0);
 }
 // Cancellation during actual subgroup import, after the last key chunk.
 const controller=new AbortController(),call=s.call.bind(s);let entered=false;
 s.call=(cap,op,args)=>{const promise=call(cap,op,args);if(op==='finishKey'){entered=true;setTimeout(()=>controller.abort(),100);}return promise;};
 await assert.rejects(c.loadKey({zkey:key,expectedSha256:hash(key),verificationKey:vk},{signal:controller.signal}),e=>e.code==='ABORTED');
 assert.equal(entered,true);await assert.rejects(c.keyResources(),e=>e.code==='INVALID_HANDLE');
}finally{await s.dispose();}
console.log('Default admission, research ceilings, incomplete/digest/malformed-header rejection, cleanup and actual import cancellation PASS');
