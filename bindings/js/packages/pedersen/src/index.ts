import {type ZeroJRuntime,bytesToHex,hexToBytes,scalarToString} from '@zeroj/runtime';
const BLS=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const JUBJUB=0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7n;
export interface ScalarOpening {value:bigint;blinding:bigint;}
export interface BytesOpening {data:Uint8Array;blinding:bigint;}
export function createPedersen(runtime:ZeroJRuntime) {
  const curveApi=(curve:'bls12381'|'jubjub',modulus:bigint)=>Object.freeze({
    async randomBlinding():Promise<bigint> {
      const result=await runtime.call<{blinding:string}>('pedersen','randomBlinding',{curve});
      return BigInt(result.blinding);
    },
    async commitScalar({value,blinding}:ScalarOpening):Promise<Uint8Array> {
      const result=await runtime.call<{commitment:string}>('pedersen','commitScalar',{
        curve,value:scalarToString(value,modulus),blinding:scalarToString(blinding,modulus)});
      return hexToBytes(result.commitment);
    },
    /** Disclosed opening verification (class V1). Use only when the opening is already public. */
    async verifyOpening({commitment,value,blinding}:ScalarOpening & {commitment:Uint8Array}):Promise<boolean> {
      const result=await runtime.call<{valid:boolean}>('pedersen','verifyScalar',{
        curve,commitment:bytesToHex(commitment,48),value:scalarToString(value,modulus),blinding:scalarToString(blinding,modulus)});
      return result.valid;
    },
    async commitBytes({data,blinding}:BytesOpening):Promise<Uint8Array> {
      const result=await runtime.call<{commitment:string}>('pedersen','commitBytes',{
        curve,data:bytesToHex(data),blinding:scalarToString(blinding,modulus)});
      return hexToBytes(result.commitment);
    },
    /** Disclosed byte-opening verification (class V1). */
    async verifyBytes({commitment,data,blinding}:BytesOpening & {commitment:Uint8Array}):Promise<boolean> {
      const result=await runtime.call<{valid:boolean}>('pedersen','verifyBytes',{
        curve,commitment:bytesToHex(commitment,48),data:bytesToHex(data),blinding:scalarToString(blinding,modulus)});
      return result.valid;
    }
  });
  return Object.freeze({bls12381:curveApi('bls12381',BLS),jubjub:curveApi('jubjub',JUBJUB)});
}
