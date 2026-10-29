import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from '@zeroj/hash';
import { createRuntime, bytesToHex } from '@zeroj/runtime';
import { bundle } from '../packages/bundle-hash/dist/index.js';
test('Java/Wasm hashes match Node WebCrypto and published BLAKE2 vectors',async()=>{
  const runtime=createRuntime({bundles:[bundle]});
  try {
    const wasm=createHash(runtime,{shaBackend:'wasm'}),host=createHash();
    for(const data of [new Uint8Array(),new TextEncoder().encode('abc'),Uint8Array.from({length:129},(_,i)=>i)]) {
      assert.deepEqual(await wasm.sha256(data),await host.sha256(data));
      assert.deepEqual(await wasm.sha512(data),await host.sha512(data));
    }
    assert.equal(bytesToHex(await wasm.blake2b(new TextEncoder().encode('abc'),32)),
      'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319');
    await assert.rejects(runtime.call('hash','sha256',{data:'FF'}),{code:'INVALID_REQUEST'});
    await assert.rejects(runtime.call('hash','sha256',{data:'00',extra:true}),{code:'INVALID_REQUEST'});
    await assert.rejects(runtime.call('hash','unknown',{data:'00'}),{code:'UNSUPPORTED_OPERATION'});
    await Promise.all(Array.from({length:8},()=>wasm.sha256(new Uint8Array([1]))));
  } finally { await runtime.dispose(); }
  await assert.rejects(runtime.call('hash','sha256',{data:''}),{code:'DISPOSED'});
});
test('unsupported capability and duplicate providers fail explicitly',async()=>{
  assert.throws(()=>createRuntime({bundles:[bundle,bundle]}),{code:'INVALID_DESCRIPTOR'});
  const runtime=createRuntime({bundles:[]});
  await assert.rejects(runtime.call('missing','run',{}),{code:'UNSUPPORTED_CAPABILITY'});
  await runtime.dispose();
});
test('tampered artifacts fail closed and no call remains pending',async()=>{
  const bad={...bundle,id:'tampered-test',wasm:{...bundle.wasm,sha256:'0'.repeat(64)}};
  const runtime=createRuntime({bundles:[bad],timeoutMs:10_000});
  const calls=Array.from({length:3},()=>runtime.call('hash','sha256',{data:''}));
  await Promise.all(calls.map(call=>assert.rejects(call,{code:'BUNDLE_LOAD_FAILED'})));
  await assert.rejects(runtime.call('hash','sha256',{data:''}),{code:'BUNDLE_LOAD_FAILED'});
  await runtime.dispose();
});
test('startup queue is bounded and disposal settles every queued request',async()=>{
  const runtime=createRuntime({bundles:[bundle]});
  const calls=Array.from({length:65},()=>runtime.call('hash','sha256',{data:''}));
  const settled=Promise.allSettled(calls);
  await runtime.dispose();
  const results=await settled;
  assert.equal(results.length,65);
  for(const result of results.slice(0,64)) {
    assert.equal(result.status,'rejected');assert.equal(result.reason.code,'DISPOSED');
  }
  assert.equal(results[64].status,'rejected');assert.equal(results[64].reason.code,'QUEUE_LIMIT');
});
test('explicit BLS12-381 Poseidon profile matches independent Sage vectors and rejects aliases',async()=>{
 const {readFileSync}=await import('node:fs');
 const source=readFileSync(new URL('../../../zeroj-circuit-lib/src/test/resources/poseidon-sage/sage-reference-output.txt',import.meta.url),'utf8');
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 try {
  const api=createHash(runtime);let count=0;
  for(const match of source.matchAll(/Poseidon\((\d+),\s*(\d+)\)\s*=\s*(0x[0-9a-f]+)/g)){
   assert.equal(await api.poseidonBls12381T3(BigInt(match[1]),BigInt(match[2])),BigInt(match[3]));count++;
  }
  assert.equal(count,3);
  await assert.rejects(api.poseidonBls12381T3(-1n,0n));
  await assert.rejects(api.poseidonBls12381T3(52435875175126190479447740508185965837690552500527637822603658699938581184513n,0n));
 } finally {await runtime.dispose();}
});
