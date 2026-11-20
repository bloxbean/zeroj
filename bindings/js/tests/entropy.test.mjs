import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const request=(capability,operation,args={})=>({apiVersion:1,capability,operation,arguments:args});
function run(image,mode,requests) {
 const proc=spawnSync(process.execPath,['--experimental-wasm-exnref','tests/entropy-child.cjs',
   path.resolve('packages/bundle-'+image),mode],{input:JSON.stringify(requests),encoding:'utf8',timeout:20_000,maxBuffer:2*1024*1024});
 assert.equal(proc.status,0,proc.stderr);const result=JSON.parse(proc.stdout);
 assert.equal(result.weakCalls,0);return result;
}
test('actual Web Image core guard rejects unprotected RNG, key generation and commitment generation',()=>{
 for(const operation of ['random','bbs','pedersen']) {
  const result=run('unprotected','real',[request('unprotected',operation)]);
  assert.deepEqual(result.results[0],{ok:false,error:{code:'RANDOMNESS_UNAVAILABLE'}},operation);
 }
});
test('missing/throwing entropy rejects secrets and public Pedersen verification remains available',()=>{
 const point='80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e';
 for(const mode of ['absent','throw']) {
  const result=run('crypto',mode,[
   request('pedersen','commitScalar',{curve:'bls12381',value:'1',blinding:'0'}),
   request('pedersen','verifyScalar',{curve:'bls12381',value:'1',blinding:'0',commitment:point}),
   request('bbs','generateKey',{suite:'BLS12381_SHA256',keyInfo:''})
  ]);
  assert.equal(result.results[0].error.code,'RANDOMNESS_UNAVAILABLE');
  assert.deepEqual(result.results[1],{ok:true,value:{valid:true}});
  assert.equal(result.results[2].error.code,'RANDOMNESS_UNAVAILABLE');
 }
});
test('entropy chunking, complete host routing and late failure',()=>{
 const input=request('probe','entropy',{length:131073});
 const result=run('probe','constant',[input]);
 assert.equal(result.results[0].value.bytes,'01'.repeat(131073));
 assert.deepEqual(result.drawLengths,[16,65536,65536,1]);
 const failure=run('probe','late',[input]);
 assert.equal(failure.results[0].error.code,'RANDOMNESS_UNAVAILABLE');
 assert.equal('value' in failure.results[0],false);
});
test('new prover and confidential secret APIs fail closed before exposing results',()=>{
 for(const mode of ['absent','throw']) {
  const requests=[request('elgamal','generateKey'),request('confidential-notes','generateViewingKey'),
    request('confidential-notes','createOpening',{value:'42'})];
  for(const result of run('confidential',mode,requests).results)assert.equal(result.error.code,'RANDOMNESS_UNAVAILABLE');
  const proof=run('prover',mode,[request('groth16-prover','prove',{key:'h1',input:{x:'3'}})]);
  assert.equal(proof.results[0].error.code,'RANDOMNESS_UNAVAILABLE');
 }
});
