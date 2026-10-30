import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createRuntime,hexToBytes} from '@zeroj/runtime';
import {createGroth16Prover} from '@zeroj/groth16-prover';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {bundle as prover} from '../packages/bundle-prover/dist/index.js';
import {bundle as verifier} from '../packages/bundle-verifier/dist/index.js';
const dir=new URL('../build/tutorial/',import.meta.url);
const read=name=>JSON.parse(fs.readFileSync(new URL(name,dir),'utf8'));
const cli=fileURLToPath(new URL('../node_modules/snarkjs/build/cli.cjs',import.meta.url));
function snark(...args){const r=spawnSync(process.execPath,[cli,...args],{cwd:fileURLToPath(dir),encoding:'utf8',timeout:60_000});assert.equal(r.status,0,r.stderr+r.stdout);return r.stdout;}
function witnessFile(values) {
 const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
 const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b;};
 const scalar=n=>{const b=Buffer.alloc(32);for(let i=0;i<32;i++){b[i]=Number(n&255n);n>>=8n;}return b;};
 const section=(id,body)=>Buffer.concat([u32(id),u64(body.length),body]);
 const fr=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
 return Buffer.concat([Buffer.from('wtns'),u32(2),u32(2),section(1,Buffer.concat([u32(32),scalar(fr),u32(values.length)])),section(2,Buffer.concat(values.map(scalar)))]);
}
test('supplied-key Wasm proofs verify independently in snarkjs and vice versa',async()=>{
 const runtime=createRuntime({bundles:[prover,verifier],experimentalSecrets:true});
 const publicOnly=createRuntime({bundles:[prover,verifier]});
 try {
  const p=createGroth16Prover(runtime),v=createGroth16Verifier(runtime);
  const meta=read('manifest.json'),verificationKey=read('vk.json');
  const input={circuit:meta.circuit,fingerprint:meta.fingerprint,verificationKey,
   zkey:new Uint8Array(fs.readFileSync(new URL('key.zkey',dir))),expectedSha256:hexToBytes(meta.sha256)};
  const description=await p.describe(meta.circuit);assert.equal(description.fingerprint,meta.fingerprint);
  await assert.rejects(p.loadKey({...input,expectedSha256:new Uint8Array(32)}),{code:'INVALID_PROVING_KEY'});
  await assert.rejects(p.loadKey({...input,fingerprint:'untrusted'}),{code:'CIRCUIT_MISMATCH'});
  // The compiler's chunk profile must not widen the standalone prover or JSON byte cap.
  await assert.rejects(p.loadKey({...input,zkey:new Uint8Array(262145)}),{code:'INVALID_BYTES'});
  await assert.rejects(runtime.call('groth16-prover','loadKey',{
    ...input,zkey:'00'.repeat(262145),expectedSha256:meta.sha256}),{code:'INVALID_REQUEST'});
  const key=await p.loadKey(input);
  const start=performance.now(),result=await p.proveCubic(key,3n),elapsed=performance.now()-start;
  assert.deepEqual(result.publicInputs,[35n]);
  assert.equal(await v.verify({...result,verificationKey}),true);
  assert.equal(await v.verify({...result,verificationKey,publicInputs:[36n]}),false);
  const second=await p.proveCubic(key,3n);assert.notDeepEqual(second.proof,result.proof);
  fs.writeFileSync(new URL('zeroj-proof.json',dir),JSON.stringify(result.proof));
  fs.writeFileSync(new URL('zeroj-public.json',dir),JSON.stringify(result.publicInputs.map(String)));
  assert.match(snark('groth16','verify','vk.json','zeroj-public.json','zeroj-proof.json'),/OK/);
  fs.writeFileSync(new URL('witness.wtns',dir),witnessFile([1n,35n,3n,9n,27n]));
  snark('groth16','prove','key.zkey','witness.wtns','snarkjs-proof.json','snarkjs-public.json');
  assert.equal(await v.verify({proof:read('snarkjs-proof.json'),verificationKey,publicInputs:read('snarkjs-public.json').map(BigInt)}),true);
  await assert.rejects(v.verify({...result,verificationKey,publicInputs:[-1n]}));
  const malformed=structuredClone(result.proof);malformed.pi_a[2]='2';assert.equal(await v.verify({...result,proof:malformed,verificationKey}),false);
  const wrongProfile={...result.proof,curve:'bn128'};await assert.rejects(v.verify({...result,proof:wrongProfile,verificationKey}),{code:'UNSUPPORTED_PROFILE'});
  const publicProver=createGroth16Prover(publicOnly),publicKey=await publicProver.loadKey(input);
  await assert.rejects(publicProver.proveCubic(publicKey,3n),{code:'EXPERIMENTAL_SECRETS_DISABLED'});
  await runtime.release(key);await assert.rejects(p.proveCubic(key,3n),{code:'INVALID_HANDLE'});
  console.log('Node supplied-key cubic proof + self-check ms:',Math.round(elapsed));
 } finally {await runtime.dispose();await publicOnly.dispose();}
});
