// Public development fixture only. Cold = fresh worker, not cold filesystem/browser cache.
import {bundle} from '@zeroj/bundle-circuit';
import {createCircuitCompiler} from '@zeroj/circuit';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {circuitRuntime,allDefinitions,typedFixtureInputs} from './scenarios.mjs';
const percentile=(values,q)=>[...values].sort((a,b)=>a-b)[Math.ceil(q*values.length)-1];
export async function benchmark(load,{name="poseidon_opening",runs=5,warmRuns=5,onPhase=()=>{}}={}){
 if(!Number.isInteger(runs)||runs<1||runs>20||!Number.isInteger(warmRuns)||warmRuns<1||warmRuns>20)throw Error('BENCHMARK_LIMIT');
 const f=JSON.parse(await load('manifest.json','text')).find(x=>x.name===name);
 if(!f?.developmentOnly)throw Error('DEVELOPMENT_FIXTURE_REQUIRED');
 const definition=allDefinitions.find(x=>x.name===name),input=typedFixtureInputs(definition,JSON.parse(await load(name+'/inputs.json','text')));
 const artifact={zkey:new Uint8Array(await load(name+'/key.zkey','bytes')),verificationKey:JSON.parse(await load(name+'/vk.json','text')),
  expectedSha256:Uint8Array.from(f.keySha256.match(/../g),v=>parseInt(v,16))};
 const cold=[],warm=[];let resources;
 for(let i=0;i<runs;i++){
  const r=circuitRuntime();let c;
  const row={};const phase=async(label,fn)=>{onPhase(label);const start=performance.now();const result=await fn();row[label+'Ms']=performance.now()-start;return result;};
  try{
   await phase('startup',()=>r.preload('circuit'));
   c=await phase('compile',()=>createCircuitCompiler(r).compile(definition,{expectedGraphSha256:f.graphSha256,fingerprint:f.fingerprint}));
   await phase('witness',()=>c.checkWitness(input));
   const key=await phase('keyLoad',()=>c.loadKey(artifact));resources=await c.keyResources();
   row.importMs=resources.lastImportMs;
   const verifier=createGroth16Verifier(r);
   const proof=await phase('proveAndSelfVerify',()=>c.prove(key,input));
   if(!await phase('verify',()=>verifier.verify({...proof,verificationKey:artifact.verificationKey})))throw Error('VERIFY_FAILED');
   cold.push(row);
   if(i===runs-1)for(let j=0;j<warmRuns;j++){
    onPhase('warmProveAndSelfVerify');const start=performance.now();const p=await c.prove(key,input);warm.push(performance.now()-start);
    if(!await verifier.verify({...p,verificationKey:artifact.verificationKey}))throw Error('VERIFY_FAILED');
   }
  }finally{onPhase('dispose');if(c)await c.dispose();await r.dispose();}
 }
 const summary=Object.fromEntries(Object.keys(cold[0]).map(k=>[k,{p50:percentile(cold.map(r=>r[k]),.5),p95:percentile(cold.map(r=>r[k]),.95)}]));
 return {fixture:name,developmentOnly:true,image:bundle.id,graphSha256:f.graphSha256,fingerprint:f.fingerprint,keySha256:f.keySha256,keyBytes:artifact.zkey.length,coldDefinition:'fresh worker; host code/file caches may be warm',
  runs,warmRuns,cold,warmProveAndSelfVerifyMs:warm,summary,warm:{p50:percentile(warm,.5),p95:percentile(warm,.95)},resources};
}
