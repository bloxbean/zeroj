import {createRuntime} from '@zeroj/runtime';
import {createCircuitCompiler} from '@zeroj/circuit';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {bundle} from '@zeroj/bundle-circuit';
import {symbolicExamples} from '../../build/circuit-examples/symbolic-examples.js';
export {symbolicExamples};
export const circuitRuntime=(options={})=>createRuntime({bundles:[bundle],experimentalSecrets:true,...options});
export function typedFixtureInputs(definition,flat){
  const input={public:{},secret:{}};
  for(const d of JSON.parse(definition.recipe).inputs){
    input[d.visibility][d.name]=d.type==='bytes'?Uint8Array.from({length:d.length},(_,i)=>Number(flat[d.name+'_'+i])):
      d.type==='bool'?flat[d.name]==='1':BigInt(flat[d.name]);
  }
  return input;
}
export async function scenario(name,load,{graph=false}={}){
  const fixture=JSON.parse(await load('manifest.json','text')).find(x=>x.name===name);
  if(!fixture?.developmentOnly)throw Error('UNKNOWN_DEVELOPMENT_FIXTURE');
  const r=circuitRuntime(),verifier=createGroth16Verifier(r),start=performance.now();let circuit;
  try{
    const definition=symbolicExamples.find(x=>x.name===name),compiler=createCircuitCompiler(r);
    const identity={expectedGraphSha256:fixture.graphSha256,fingerprint:fixture.fingerprint};
    const flat=JSON.parse(await load(name+'/inputs.json','text'));
    const useGraph=graph||!definition;
    circuit=useGraph?await compiler.compileGraph(await load(name+'/graph.json','text'),identity):await compiler.compile(definition,identity);
    const input=useGraph?Object.fromEntries(Object.entries(flat).map(([k,v])=>[k,BigInt(v)])):typedFixtureInputs(definition,flat);
    const result={...circuit.description,authoring:useGraph?'portable-graph':'symbolic-recipe',...await circuit.checkWitness(input),proofGenerated:false};
    if(fixture.proofSupported){
      let t=performance.now();
      const verificationKey=JSON.parse(await load(name+'/vk.json','text'));
      const key=await circuit.loadKey({zkey:new Uint8Array(await load(name+'/key.zkey','bytes')),
        expectedSha256:Uint8Array.from(fixture.keySha256.match(/../g),x=>parseInt(x,16)),verificationKey});
      result.keyLoadMs=performance.now()-t;result.keyResources=await circuit.keyResources();t=performance.now();
      const proof=await circuit.prove(key,input);result.proveAndSelfVerifyMs=performance.now()-t;
      if(!await verifier.verify({...proof,verificationKey}))throw Error('PROOF_REJECTED');
      const bad=[...proof.publicInputs];bad[0]+=1n;
      if(await verifier.verify({...proof,publicInputs:bad,verificationKey}))throw Error('TAMPER_ACCEPTED');
      const foreignProof=JSON.parse(await load(name+'/snarkjs-proof.json','text'));
      const foreignInputs=JSON.parse(await load(name+'/snarkjs-public.json','text')).map(BigInt);
      if(!await verifier.verify({proof:foreignProof,publicInputs:foreignInputs,verificationKey}))throw Error('SNARKJS_PROOF_REJECTED');
      Object.assign(result,{proofGenerated:true,tamperedAccepted:false,snarkjsAccepted:true,proof,verificationKey});
    }else result.proofLimit=fixture.proofLimit;
    if(name==='sha256_abc'){
      const digest=new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array([97,98,99])));
      if(!digest.every((v,i)=>String(v)===flat['digest_'+i]))throw Error('HOST_DIGEST_MISMATCH');
      result.hostDigestMatches=true;
    }
    result.totalMs=performance.now()-start;return result;
  }finally{if(circuit)await circuit.dispose();await r.dispose();}
}
