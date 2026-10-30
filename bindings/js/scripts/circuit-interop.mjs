// JVM and browser proof JSON is generated, ignored development evidence.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {circuitRuntime} from '../examples/circuit/scenarios.mjs';
const require=createRequire(import.meta.url),snarkjs=require('snarkjs');
const dir=new URL('../build/circuit/poseidon_opening/',import.meta.url),r=circuitRuntime();
try{
 const vk=JSON.parse(await fs.readFile(new URL('vk.json',dir),'utf8'));
 for(const engine of ['node','chromium','firefox','jvm']){
  const {proof,publicInputs}=JSON.parse(await fs.readFile(new URL(engine+'-proof.json',dir),'utf8'));
  assert.equal(await snarkjs.groth16.verify(vk,publicInputs,proof),true);
  const bad=publicInputs.map(BigInt);bad[0]+=1n;
  assert.equal(await snarkjs.groth16.verify(vk,bad.map(String),proof),false);
  assert.equal(await createGroth16Verifier(r).verify({proof,publicInputs:publicInputs.map(BigInt),verificationKey:vk}),true);
  console.log('snarkjs and Wasm verified '+engine+' Poseidon proof; snarkjs rejected changed commitment');
 }
}finally{await r.dispose();const curve=await require('ffjavascript').getCurveFromName('bls12381');await curve.terminate();}
