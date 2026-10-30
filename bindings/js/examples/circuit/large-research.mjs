// Opt-in resource experiment. Never imported by the default example page or normal SDK bundle.
import {createRuntime} from '@zeroj/runtime';
import {createCircuitCompiler} from '@zeroj/circuit';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {bundle} from '../../build/circuit-large/bundle/dist/index.js';
import {merkleMembership} from '../../build/circuit-examples/symbolic-examples.js';
import {typedFixtureInputs} from './scenarios.mjs';
export const largeRuntime=()=>createRuntime({bundles:[bundle],experimentalSecrets:true,timeoutMs:600_000});
export async function largeResearch(name,load,{onPhase=()=>{},warmRuns=3,signal}={}){
 if(!['merkle_d8','merkle_d16','merkle_d32'].includes(name)||!Number.isInteger(warmRuns)||warmRuns<1||warmRuns>5)throw Error('RESEARCH_CASE_LIMIT');
 const f=JSON.parse(await load('manifest.json','text')).find(x=>x.name===name);
 if(!f?.developmentOnly||!f.proofSupported||f.experiment!=='large-merkle-v1')throw Error('DEVELOPMENT_FIXTURE_REQUIRED');
 if(signal?.aborted)throw Error('ABORTED');
 const r=largeRuntime(),timingsMs={};let c,failed=false;
 const abort=()=>{void r.dispose();};signal?.addEventListener('abort',abort,{once:true});
 const phase=async(label,action)=>{onPhase(label);const t=performance.now();const v=await action();timingsMs[label]=performance.now()-t;return v;};
 try{
  await phase('startup',()=>r.preload('circuit'));
  const definition=merkleMembership(Number(name.slice(8)));
  c=await phase('compile',()=>createCircuitCompiler(r).compile(definition,{expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint}));
  if(c.description.keyProfile!=='circuit-key-research-merkle-v1'||c.description.maxKeyBytes!==33554432)throw Error('RESEARCH_PROFILE_MISMATCH');
  const input=typedFixtureInputs(definition,JSON.parse(await load(name+'/inputs.json','text')));
  await phase('witnessAndCheck',()=>c.checkWitness(input));
  const bytes=await phase('readKey',async()=>new Uint8Array(await load(name+'/key.zkey','bytes')));
  const vk=JSON.parse(await load(name+'/vk.json','text'));
  const key=await phase('keyLoad',()=>c.loadKey({zkey:bytes,expectedSha256:Uint8Array.from(f.keySha256.match(/../g),h=>parseInt(h,16)),verificationKey:vk}));
  const resources=await c.keyResources();timingsMs.keyImport=resources.lastImportMs;
  const bad=structuredClone(input);bad.secret.pathBits[0]=!bad.secret.pathBits[0];let rejected=false;
  try{await c.prove(key,bad);}catch(e){if(e.code!=='INVALID_REQUEST')throw e;rejected=true;}
  if(!rejected)throw Error('INVALID_PATH_ACCEPTED');
  const proof=await phase('firstProofAndSelfVerify',()=>c.prove(key,input));
  const verifier=createGroth16Verifier(r);
  if(!await phase('verify',()=>verifier.verify({...proof,verificationKey:vk})))throw Error('PROOF_REJECTED');
  if(await verifier.verify({...proof,publicInputs:[proof.publicInputs[0]+1n],verificationKey:vk}))throw Error('CHANGED_ROOT_ACCEPTED');
  const foreign=JSON.parse(await load(name+'/snarkjs-proof.json','text'));
  const foreignInputs=JSON.parse(await load(name+'/snarkjs-public.json','text')).map(BigInt);
  if(!await verifier.verify({proof:foreign,publicInputs:foreignInputs,verificationKey:vk}))throw Error('SNARKJS_REJECTED');
  const warm=[];for(let i=0;i<warmRuns;i++){
   onPhase('reusedProofAndSelfVerify');const t=performance.now();const p=await c.prove(key,input);warm.push(performance.now()-t);
   if(!await verifier.verify({...p,verificationKey:vk}))throw Error('REUSED_PROOF_REJECTED');
  }
  return {name,developmentOnly:true,experimentalProfile:true,image:bundle.id,description:c.description,keyBytes:f.keyBytes,keySha256:f.keySha256,
   timingsMs,warmProofMs:warm,resources,invalidPathRejected:true,changedRootRejected:true,snarkjsAccepted:true,
   proof:{proof:proof.proof,publicInputs:proof.publicInputs.map(String)}};
 }catch(error){failed=true;throw error;}finally{
  signal?.removeEventListener('abort',abort);onPhase('dispose');
  try{if(c&&!signal?.aborted)await c.dispose();}catch(error){if(!failed)throw error;}finally{await r.dispose();}
 }
}
