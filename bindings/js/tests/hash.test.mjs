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
