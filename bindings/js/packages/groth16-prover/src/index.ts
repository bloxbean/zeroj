import {type ZeroJRuntime,type Handle,bytesToHex,scalarToString} from '@zeroj/runtime';
import type {Groth16Proof,Groth16VerificationKey} from '@zeroj/groth16-verifier';
export type ProvingKey=Handle<'groth16-proving-key'>;
export type CircuitDescription = {circuit:string;fingerprint:string;numPublic:number;numWires:number;constraints:number;}
const FR=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
export function createGroth16Prover(runtime:ZeroJRuntime) {
  return Object.freeze({
    describe:(circuit:string)=>runtime.call<CircuitDescription>('groth16-prover','describe',{circuit}),
    /** expectedSha256 and fingerprint come from the trusted application/ceremony manifest. */
    async loadKey(input:{circuit:string;fingerprint:string;zkey:Uint8Array;expectedSha256:Uint8Array;verificationKey:Groth16VerificationKey}):Promise<ProvingKey> {
      const value=await runtime.call<{handle:string}>('groth16-prover','loadKey',{
        ...input,zkey:bytesToHex(input.zkey),expectedSha256:bytesToHex(input.expectedSha256,32)});
      return runtime.retainHandle('groth16-proving-key','groth16-prover',value.handle);
    },
    /** Named tutorial circuit, y = x^3 + x + 5 in Fr. Other circuits require a compiled Java adapter. */
    async proveCubic(key:ProvingKey,x:bigint):Promise<{proof:Groth16Proof;publicInputs:readonly bigint[]}> {
      const value=await runtime.call<{proof:Groth16Proof;publicInputs:string[]}>('groth16-prover','prove',{
        key:runtime.handleId(key,'groth16-proving-key','groth16-prover'),input:{x:scalarToString(x,FR)}});
      return {proof:value.proof,publicInputs:value.publicInputs.map(BigInt)};
    }
  });
}
