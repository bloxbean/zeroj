import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {createRequire} from 'node:module';
import {createCircuitCompiler} from '@zeroj/circuit';
import {cubic} from '@zeroj/circuit/graph';
import {scenario,circuitRuntime,symbolicExamples,typedFixtureInputs} from '../examples/circuit/scenarios.mjs';
import {operations,widthOverflow,underflow} from '../build/circuit-examples/operation-examples.js';
const load=(name,kind)=>fs.readFile(new URL('../build/circuit/'+name,import.meta.url),kind==='text'?'utf8':undefined);
const require=createRequire(import.meta.url),snarkjs=require('snarkjs');
const manifest=JSON.parse(await load('manifest.json','text'));
const expected=f=>({expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint});
const fixture=name=>manifest.find(x=>x.name===name);
const definition=name=>symbolicExamples.find(x=>x.name===name);
const hash=text=>createHash('sha256').update(text).digest('hex');
for(const name of ['multiplier',...symbolicExamples.map(x=>x.name)])test('packaged compiler '+name+' compiles/checks and small proofs interoperate',async()=>{
  const result=await scenario(name,load);
  assert.equal(result.valid,true);
  if(result.proofGenerated)assert.equal(await snarkjs.groth16.verify(result.verificationKey,result.proof.publicInputs.map(String),result.proof.proof),true);
  else assert.ok(['poseidon_opening','sha256_abc'].includes(name));
  const {proof,verificationKey,...summary}=result;
  await fs.mkdir(new URL('../build/circuit-results/',import.meta.url),{recursive:true});
  await fs.writeFile(new URL('../build/circuit-results/'+name+'.json',import.meta.url),JSON.stringify(summary,null,2));
});
test('portable TS graph matches Java and uses the same SDK lifecycle',async()=>{
  assert.equal(cubic(),await load('cubic/graph.json','text'));
  assert.equal((await scenario('cubic',load,{graph:true})).proofGenerated,true);
});
test('graph and constraint identities are both enforced; a failed attempt cannot compile again',async()=>{
  for(const wrong of [{...expected(fixture('cubic')),expectedGraphSha256:'0'.repeat(64)},{...expected(fixture('cubic')),fingerprint:'wrong'}]){
    const r=circuitRuntime();try{
      const c=createCircuitCompiler(r);
      await assert.rejects(c.compile(definition('cubic'),wrong),e=>e.code==='CIRCUIT_MISMATCH');
      await assert.rejects(c.compile(definition('cubic'),expected(fixture('cubic'))));
    }finally{await r.dispose();}
  }
});
test('canonical encoding, compiler policy and closed operation vocabulary reject',async()=>{
  const source=await load('cubic/graph.json','text');
  for(const bad of [' '+source,source+' {}',source.replace('zeroj-graph','zeroj-graph-research'),source.replace('zeroj-r1cs-bls12381-v1','different-policy'),source.replace('"format":"zeroj-graph","version":1','"version":1,"format":"zeroj-graph"')]){
    const r=circuitRuntime();try{await assert.rejects(createCircuitCompiler(r).compileGraph(bad,{expectedGraphSha256:hash(bad),fingerprint:fixture('cubic').fingerprint}));}finally{await r.dispose();}
  }
  const raw=JSON.parse(definition('age_check').recipe);raw.commands[0][1]=999;
  const r=circuitRuntime();try{await assert.rejects(r.call('circuit','compileRecipe',{recipe:JSON.stringify(raw),...expected(fixture('age_check'))}));}finally{await r.dispose();}
});
test('witness opt-in, byte/range constraints and disposal reject invalid use',async()=>{
  const r=circuitRuntime({experimentalSecrets:false});try{
    const c=await createCircuitCompiler(r).compile(definition('age_check'),expected(fixture('age_check')));
    await assert.rejects(c.checkWitness({public:{threshold:18n},secret:{age:21n}}),e=>e.code==='EXPERIMENTAL_SECRETS_DISABLED');
  }finally{await r.dispose();}
  const s=circuitRuntime();try{
    const c=await createCircuitCompiler(s).compile(definition('age_check'),expected(fixture('age_check')));
    await assert.rejects(c.checkWitness({public:{threshold:18n},secret:{age:17n}}));
    await assert.rejects(c.checkWitness({public:{threshold:18n},secret:{age:256n}}));
    await c.dispose();await assert.rejects(c.checkWitness({public:{threshold:18n},secret:{age:21n}}),e=>e.code==='INVALID_HANDLE');
  }finally{await s.dispose();}
  const t=circuitRuntime();try{
    const c=await createCircuitCompiler(t).compile(definition('sha256_abc'),expected(fixture('sha256_abc')));
    const input=typedFixtureInputs(definition('sha256_abc'),JSON.parse(await load('sha256_abc/inputs.json','text')));
    input.secret.message[0]=98;await assert.rejects(c.checkWitness(input));
  }finally{await t.dispose();}
});
test('keys retain circuit/runtime ownership and are released with their circuit',async()=>{
  const a=circuitRuntime(),b=circuitRuntime();try{
    const f=fixture('cubic'),d=definition('cubic'),ca=await createCircuitCompiler(a).compile(d,expected(f)),cb=await createCircuitCompiler(b).compile(d,expected(f));
    const key=await ca.loadKey({zkey:new Uint8Array(await load('cubic/key.zkey','bytes')),expectedSha256:Buffer.from(f.keySha256,'hex'),verificationKey:JSON.parse(await load('cubic/vk.json','text'))});
    const input={public:{y:35n},secret:{x:3n}};
    await assert.rejects(cb.prove(key,input),e=>e.code==='INVALID_HANDLE');
    const keyId=a.handleId(key,'circuit-proving-key','circuit');
    await ca.dispose();
    await assert.rejects(ca.prove(key,input),e=>e.code==='INVALID_HANDLE');
    assert.equal((await a.call('circuit','compileRecipe',{recipe:d.recipe,...expected(f)}).catch(e=>({code:e.code}))).code,'INVALID_REQUEST');
    await a.release(key); // Java already removed the owned key; TS drops its stale wrapper.
    await assert.rejects(a.call('circuit','prove',{circuit:'h1',key:keyId,input:{x:'3',y:'35'}}));
  }finally{await a.dispose();await b.dispose();}
});
test('wrong key/VK and measured oversized Poseidon key reject without widening limits',async()=>{
  const r=circuitRuntime();try{
    const f=fixture('cubic'),c=await createCircuitCompiler(r).compile(definition('cubic'),expected(f));
    const other=fixture('multiplier');
    await assert.rejects(c.loadKey({zkey:new Uint8Array(await load('multiplier/key.zkey','bytes')),expectedSha256:Buffer.from(other.keySha256,'hex'),verificationKey:JSON.parse(await load('multiplier/vk.json','text'))}));
    const wrongVkKey=await c.loadKey({zkey:new Uint8Array(await load('cubic/key.zkey','bytes')),expectedSha256:Buffer.from(f.keySha256,'hex'),verificationKey:JSON.parse(await load('multiplier/vk.json','text'))});
    await assert.rejects(c.prove(wrongVkKey,{public:{y:35n},secret:{x:3n}}),e=>e.code==='KEY_PROOF_MISMATCH');
    const poseidon=fixture('poseidon_opening');assert.ok(poseidon.keyBytes>262144);assert.equal(poseidon.independentProofVerified,true);
    await assert.rejects(c.loadKey({zkey:new Uint8Array(await load('poseidon_opening/key.zkey','bytes')),expectedSha256:Buffer.from(poseidon.keySha256,'hex'),verificationKey:JSON.parse(await load('poseidon_opening/vk.json','text'))}));
  }finally{await r.dispose();}
});
test('every exposed primitive executes in Wasm; zero divisor, integer underflow and width overflow reject',async()=>{
  const vectors=new URL('../../wasm/adapter-circuit/build/symbolic-test-vectors/',import.meta.url);
  const id=JSON.parse(await fs.readFile(new URL('operations-identity.json',vectors),'utf8'));
  const flat=JSON.parse(await fs.readFile(new URL('operations-input.json',vectors),'utf8'));
  const r=circuitRuntime();try{
    const c=await createCircuitCompiler(r).compile(operations,id),input=typedFixtureInputs(operations,flat);
    assert.equal((await c.checkWitness(input)).valid,true);input.secret.y=0n;await assert.rejects(c.checkWitness(input));
  }finally{await r.dispose();}
  const s=circuitRuntime();try{
    // Expansion rejects width overflow before circuit-identity admission.
    await assert.rejects(createCircuitCompiler(s).compile(widthOverflow,id));
  }finally{await s.dispose();}
  const t=circuitRuntime();try{
    const underflowId=JSON.parse(await fs.readFile(new URL('underflow-identity.json',vectors),'utf8'));
    const c=await createCircuitCompiler(t).compile(underflow,underflowId);
    await assert.rejects(c.checkWitness({public:{},secret:{u:1n,v:2n}}));
  }finally{await t.dispose();}
});
test.after(async()=>{const curve=await require('ffjavascript').getCurveFromName('bls12381');await curve.terminate();});
