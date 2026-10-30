import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createCircuitCompiler} from '@zeroj/circuit';
import {circuitRuntime,symbolicExamples} from '../examples/circuit/scenarios.mjs';
const root=new URL('../build/circuit/',import.meta.url);
const manifest=JSON.parse(await fs.readFile(new URL('manifest.json',root),'utf8'));
const fixture=n=>manifest.find(x=>x.name===n);
const definition=n=>symbolicExamples.find(x=>x.name===n);
const expected=f=>({expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint});
const artifact=async n=>({zkey:new Uint8Array(await fs.readFile(new URL(n+'/key.zkey',root))),
 expectedSha256:Buffer.from(fixture(n).keySha256,'hex'),verificationKey:JSON.parse(await fs.readFile(new URL(n+'/vk.json',root),'utf8'))});
const digest=b=>createHash('sha256').update(b).digest();
const sections=b=>{const v=new DataView(b.buffer,b.byteOffset,b.byteLength),m={};let o=12;for(let i=0;i<v.getUint32(8,true);i++){const id=v.getUint32(o,true),len=Number(v.getBigUint64(o+4,true));m[id]=o+12;o+=12+len;}return m;};
const clean=async c=>{const stats=await c.keyResources();assert.equal(stats.reservedBytes,0);assert.equal(stats.importedKeys,0);};
test('chunk import enforces digest, parser validation and unchanged dimensions before retaining a key',async()=>{
 const r=circuitRuntime();try{
  const c=await createCircuitCompiler(r).compile(definition('poseidon_opening'),expected(fixture('poseidon_opening'))),a=await artifact('poseidon_opening');
  await assert.rejects(c.loadKey({...a,expectedSha256:new Uint8Array(32)}),e=>e.code==='INVALID_PROVING_KEY');await clean(c);
  for(const mutate of [
    b=>b[0]=0,
    b=>b.fill(255,sections(b)[2]+100,sections(b)[2]+148), // noncanonical base field
    b=>b.fill(0,sections(b)[2]+100,sections(b)[2]+196), // forbidden alpha infinity
    b=>{ // (0,2) is on y²=x³+4 but has order 3, outside the prime-order G1 subgroup.
      const h=sections(b)[2],q=BigInt('0x'+Buffer.from(b.subarray(h+4,h+52)).reverse().toString('hex'));
      let y=(2n*(1n<<384n))%q;b.fill(0,h+100,h+196);
      for(let i=0;i<48;i++){b[h+148+i]=Number(y&255n);y>>=8n;}
    },
    b=>new DataView(b.buffer).setUint32(sections(b)[2]+88,4097,true), // max wires + 1
    b=>new DataView(b.buffer).setUint32(sections(b)[2]+96,8192,true), // above domain cap
    b=>new DataView(b.buffer).setUint32(sections(b)[4],16385,true),
  ]){
    const bad=a.zkey.slice();mutate(bad);
    await assert.rejects(c.loadKey({...a,zkey:bad,expectedSha256:digest(bad)}),e=>e.code==='INVALID_PROVING_KEY');await clean(c);
  }
  await assert.rejects(c.loadKey({...a,zkey:new Uint8Array(2*1024*1024+1)}),e=>e.code==='INVALID_BYTES');await clean(c);
  const key=await c.loadKey(a),stats=await c.keyResources();
  assert.equal(stats.reservedBytes,0);assert.equal(stats.peakStagingBytes,a.zkey.length);assert.equal(stats.importedKeys,1);assert.equal(stats.lastKeyBytes,a.zkey.length);
  await assert.rejects(c.loadKey(a),e=>e.code==='KEY_LIMIT');
  await r.release(key);await assert.rejects(c.loadKey(a),e=>e.code==='KEY_LIMIT');
 }finally{await r.dispose();}
});
test('invalid Poseidon witness/public commitment rejects after a valid key load',async()=>{
 const r=circuitRuntime();try{
  const f=fixture('poseidon_opening'),c=await createCircuitCompiler(r).compile(definition(f.name),expected(f));
  const key=await c.loadKey(await artifact(f.name));
  const flat=JSON.parse(await fs.readFile(new URL(f.name+'/inputs.json',root),'utf8'));
  const input={public:{commitment:BigInt(flat.commitment)},secret:{value:BigInt(flat.value),salt:BigInt(flat.salt)}};
  input.secret.value+=1n;await assert.rejects(c.prove(key,input),e=>['INVALID_WITNESS','INVALID_REQUEST'].includes(e.code));
  input.secret.value-=1n;input.public.commitment+=1n;await assert.rejects(c.prove(key,input),e=>['INVALID_WITNESS','INVALID_REQUEST'].includes(e.code));
 }finally{await r.dispose();}
});
test('pre-abort leaves runtime usable; abort during transfer/import terminates all handles',async()=>{
 for(const stage of ['before','appendKey','finishKey']){
  const r=circuitRuntime();try{
   const f=fixture('poseidon_opening'),c=await createCircuitCompiler(r).compile(definition(f.name),expected(f)),a=await artifact(f.name),controller=new AbortController();
   if(stage==='before')controller.abort();
   else{
    const call=r.call.bind(r);r.call=(cap,op,args)=>{const promise=call(cap,op,args);if(op===stage)setTimeout(()=>controller.abort(),stage==='finishKey'?25:0);return promise;};
   }
   await assert.rejects(c.loadKey(a,{signal:controller.signal}),e=>e.code==='ABORTED');
   if(stage==='before')await clean(c);else await assert.rejects(c.keyResources(),e=>['INVALID_HANDLE','DISPOSED'].includes(e.code));
  }finally{await r.dispose();}
 }
});
test('circuit disposal during transfer drops the upload and rejects its load promise',async()=>{
 const r=circuitRuntime();try{
  const f=fixture('poseidon_opening'),c=await createCircuitCompiler(r).compile(definition(f.name),expected(f)),a=await artifact(f.name);
  const call=r.call.bind(r);let closing;r.call=(cap,op,args)=>{const promise=call(cap,op,args);if(op==='appendKey'&&!closing)closing=c.dispose();return promise;};
  await assert.rejects(c.loadKey(a),e=>e.code==='INVALID_HANDLE');await closing;
 }finally{await r.dispose();}
});

test('small direct-request compatibility shares the key slot and reports import accounting',async()=>{
 const r=circuitRuntime();try{
  const f=fixture('cubic'),a=await artifact('cubic');
  const c=await r.call('circuit','compileRecipe',{recipe:definition('cubic').recipe,...expected(f)});
  const loaded=await r.call('circuit','loadKey',{circuit:c.handle,fingerprint:f.fingerprint,
    zkey:Buffer.from(a.zkey).toString('hex'),expectedSha256:Buffer.from(a.expectedSha256).toString('hex'),verificationKey:a.verificationKey});
  const stats=await r.call('circuit','keyResources',{circuit:c.handle});
  assert.equal(stats.lastKeyBytes,a.zkey.length);assert.ok(stats.lastImportMs>0);assert.equal(stats.importedKeys,1);
  await assert.rejects(r.call('circuit','beginKey',{circuit:c.handle,fingerprint:f.fingerprint,length:a.zkey.length,
    expectedSha256:Buffer.from(a.expectedSha256).toString('hex'),verificationKey:a.verificationKey}),e=>e.code==='KEY_LIMIT');
  assert.ok(loaded.handle);
 }finally{await r.dispose();}
});

test('import deadline terminates the worker and invalidates its compiled handle',async()=>{
 const r=circuitRuntime({timeoutMs:1000});try{
  const f=fixture('poseidon_opening'),c=await createCircuitCompiler(r).compile(definition(f.name),expected(f));
  await assert.rejects(c.loadKey(await artifact(f.name)),e=>e.code==='CALL_TIMEOUT');
  await assert.rejects(c.keyResources(),e=>e.code==='INVALID_HANDLE');
 }finally{await r.dispose();}
});
