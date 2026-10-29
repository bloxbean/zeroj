import {type ZeroJRuntime,scalarToString} from '@zeroj/runtime';
/** Canonical snarkjs BLS12-381 JSON. Validated in Java before pairing verification. */
export type Groth16Proof = {
  readonly protocol:'groth16';readonly curve:'bls12381';
  readonly pi_a:readonly string[];readonly pi_b:readonly (readonly string[])[];readonly pi_c:readonly string[];
}
export type Groth16VerificationKey = {
  readonly protocol:'groth16';readonly curve:'bls12381';readonly nPublic:number;
  readonly vk_alpha_1:readonly string[];readonly vk_beta_2:readonly (readonly string[])[];
  readonly vk_gamma_2:readonly (readonly string[])[];readonly vk_delta_2:readonly (readonly string[])[];
  readonly vk_alphabeta_12:readonly (readonly (readonly string[])[])[];readonly IC:readonly (readonly string[])[];
}
const FR=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
export function createGroth16Verifier(runtime:ZeroJRuntime) {
  return Object.freeze({
    /** Verify against the application's trusted VK and expected public values, never sender-selected policy. */
    async verify(input:{proof:Groth16Proof;verificationKey:Groth16VerificationKey;publicInputs:readonly bigint[]}):Promise<boolean> {
      const value=await runtime.call<{valid:boolean}>('groth16-verifier','verify',{
        proof:input.proof,verificationKey:input.verificationKey,publicInputs:input.publicInputs.map(x=>scalarToString(x,FR))});
      return value.valid;
    }
  });
}
