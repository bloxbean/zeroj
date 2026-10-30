/** Experimental circuit authoring/compiler lifecycle. Java owns every constraint and gadget. */
export * from './symbolic.js';
import {type ZeroJRuntime,type Handle,bytesToHex,scalarToString,ZeroJError} from '@zeroj/runtime';
import type {Groth16Proof,Groth16VerificationKey} from '@zeroj/groth16-verifier';
import type {CircuitDefinition,CircuitInputs,Schema} from './symbolic.js';

export const compilerPolicy = 'zeroj-r1cs-bls12381-v1' as const;
const CAPABILITY='circuit';
const FR=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
/** These identities must come from the application's trusted circuit manifest. */
export type CircuitIdentity=Readonly<{expectedGraphSha256:string;fingerprint:string}>;
export type CircuitDescription=Readonly<{
  name:string;compiler:string;graphSha256:string;fingerprint:string;
  wires:number;constraints:number;publicInputs:number;publicNames:readonly string[];secretNames:readonly string[];
  maxKeyBytes:number;withinProverDimensions:boolean;compileMs:number;
  recipeSha256?:string;expandMs?:number;graphValidationMs:number;
}>;
export type CircuitProvingKey=Handle<'circuit-proving-key'>;
export type CircuitProof=Readonly<{proof:Groth16Proof;publicInputs:readonly bigint[]}>;
export interface CompiledCircuit<I> {
  readonly description:CircuitDescription;
  /** Checks constraints locally; never returns witnesses or their hashes. */
  checkWitness(input:I):Promise<{valid:boolean;witnessMs:number;constraintCheckMs:number}>;
  /** Supplied ceremony artifacts only; the hash and VK must be application-trusted. */
  loadKey(artifact:{zkey:Uint8Array;expectedSha256:Uint8Array;verificationKey:Groth16VerificationKey}):Promise<CircuitProvingKey>;
  prove(key:CircuitProvingKey,input:I):Promise<CircuitProof>;
  /** Releases the compiled circuit and all its keys. A new compilation needs a new runtime. */
  dispose():Promise<void>;
}
function identity(value:CircuitIdentity):CircuitIdentity {
  if(!value||!/^[a-f0-9]{64}$/.test(value.expectedGraphSha256)||typeof value.fingerprint!=='string'
    ||value.fingerprint.length<1||value.fingerprint.length>160)throw new ZeroJError('INVALID_CIRCUIT_IDENTITY');
  return {expectedGraphSha256:value.expectedGraphSha256,fingerprint:value.fingerprint};
}
type CompiledResponse=CircuitDescription&{handle:string};
function lifecycle<I>(runtime:ZeroJRuntime,response:CompiledResponse,encode:(input:I)=>Readonly<Record<string,string>>):CompiledCircuit<I>{
  const handle=runtime.retainHandle('compiled-circuit',CAPABILITY,response.handle),keys=new WeakSet<object>();
  const {handle:ignored,...data}=response;
  const description=Object.freeze({...data,publicNames:Object.freeze([...data.publicNames]),secretNames:Object.freeze([...data.secretNames])});
  let closed=false;
  const id=()=>{if(closed)throw new ZeroJError('INVALID_HANDLE');return runtime.handleId(handle,'compiled-circuit',CAPABILITY);};
  return Object.freeze({description,
    async checkWitness(input:I){return runtime.call<{valid:boolean;witnessMs:number;constraintCheckMs:number}>(CAPABILITY,'checkWitness',{circuit:id(),input:encode(input)});},
    async loadKey(artifact:{zkey:Uint8Array;expectedSha256:Uint8Array;verificationKey:Groth16VerificationKey}){
      const circuit=id();
      if(!(artifact.expectedSha256 instanceof Uint8Array)||artifact.expectedSha256.length!==32)throw new ZeroJError('INVALID_BYTES');
      const result=await runtime.call<{handle:string}>(CAPABILITY,'loadKey',{circuit,fingerprint:description.fingerprint,
        zkey:bytesToHex(artifact.zkey,description.maxKeyBytes),expectedSha256:bytesToHex(artifact.expectedSha256,32),verificationKey:artifact.verificationKey});
      // dispose() may have been called while loadKey was pending. Never return a stale key.
      if(closed){await runtime.release(runtime.retainHandle('circuit-proving-key',CAPABILITY,result.handle));throw new ZeroJError('INVALID_HANDLE');}
      const key=runtime.retainHandle('circuit-proving-key',CAPABILITY,result.handle);keys.add(key);return key;
    },
    async prove(key:CircuitProvingKey,input:I){
      const circuit=id();if(!keys.has(key))throw new ZeroJError('INVALID_HANDLE');
      const result=await runtime.call<{proof:Groth16Proof;publicInputs:string[]}>(CAPABILITY,'prove',{
        circuit,key:runtime.handleId(key,'circuit-proving-key',CAPABILITY),input:encode(input)});
      return {proof:result.proof,publicInputs:result.publicInputs.map(BigInt)};
    },
    async dispose(){if(closed)return;closed=true;await runtime.release(handle);}
  });
}
export function createCircuitCompiler(runtime:ZeroJRuntime){
  return Object.freeze({
    async compile<P extends Schema,S extends Schema>(definition:CircuitDefinition<P,S>,expected:CircuitIdentity):Promise<CompiledCircuit<CircuitInputs<P,S>>>{
      const trusted=identity(expected);
      const result=await runtime.call<CompiledResponse>(CAPABILITY,'compileRecipe',{recipe:definition.recipe,...trusted});
      return lifecycle(runtime,result,input=>definition.encodeInputs(input));
    },
    /** Graph inputs are flattened names -> canonical Fr bigint, without a higher-level type schema. */
    async compileGraph(graph:string,expected:CircuitIdentity):Promise<CompiledCircuit<Readonly<Record<string,bigint>>>>{
      const trusted=identity(expected);
      if(typeof graph!=='string'||graph.length<1||graph.length>16*1024*1024)throw new ZeroJError('INVALID_GRAPH');
      await runtime.call(CAPABILITY,'beginGraph',{length:graph.length,...trusted});
      for(let offset=0;offset<graph.length;offset+=200000)
        await runtime.call(CAPABILITY,'appendGraph',{offset,text:graph.slice(offset,offset+200000)});
      const result=await runtime.call<CompiledResponse>(CAPABILITY,'compileGraph',{});
      return lifecycle(runtime,result,input=>{
        if(!input||typeof input!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(input)))throw new ZeroJError('INVALID_INPUT');
        return Object.fromEntries(Object.entries(input).map(([k,v])=>[k,scalarToString(v,FR)]));
      });
    }
  });
}
