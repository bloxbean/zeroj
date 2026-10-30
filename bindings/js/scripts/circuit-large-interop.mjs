import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const require=createRequire(import.meta.url),snarkjs=require('snarkjs'),root=new URL('../build/circuit-large/',import.meta.url);
try{
 for(const depth of [8,16,32]){
  const dir=new URL('merkle_d'+depth+'/',root),vk=JSON.parse(await fs.readFile(new URL('vk.json',dir),'utf8'));
  for(const engine of ['node','chromium','firefox','jvm-6g','jvm-8g']){
   const {proof,publicInputs}=JSON.parse(await fs.readFile(new URL(engine+'-proof.json',dir),'utf8'));
   assert.equal(await snarkjs.groth16.verify(vk,publicInputs,proof),true);
   assert.equal(await snarkjs.groth16.verify(vk,[String(BigInt(publicInputs[0])+1n)],proof),false);
   console.log('snarkjs verified depth',depth,engine,'and rejected changed root');
  }
 }
}finally{const curve=await require('ffjavascript').getCurveFromName('bls12381');await curve.terminate();}
