import {type ZeroJRuntime,type Handle,ZeroJError,bytesToHex,hexToBytes,scalarToString} from '@zeroj/runtime';
export type BbsSuite='BLS12381_SHA256'|'BLS12381_SHAKE256';
export interface BbsKey {readonly secret:Handle<'bbs-key'>;readonly publicKey:Uint8Array;}
export interface SignatureInput {publicKey:Uint8Array;signature:Uint8Array;messages:readonly Uint8Array[];header:Uint8Array;}
export interface PresentationInput extends SignatureInput {presentationHeader:Uint8Array;disclosedIndexes:readonly number[];}
const MODULUS=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
const messages=(values:readonly Uint8Array[])=>{
  if(!Array.isArray(values)||values.length>64)throw new ZeroJError('INVALID_MESSAGES');
  return values.map(value=>bytesToHex(value,4096));
};
const indexes=(values:readonly number[])=>{
  if(!Array.isArray(values)||values.length>64 || values.some((n,i)=>!Number.isInteger(n)||n<0||n>63||(i>0&&n<=values[i-1]!)))
    throw new ZeroJError('INVALID_DISCLOSURE_INDEXES');
  return [...values];
};
export function createBbs(runtime:ZeroJRuntime,suite:BbsSuite='BLS12381_SHA256') {
  if(!['BLS12381_SHA256','BLS12381_SHAKE256'].includes(suite))throw new ZeroJError('INVALID_SUITE');
  const key=(value:{handle:string;publicKey:string}):BbsKey=>Object.freeze({
    secret:runtime.retainHandle('bbs-key','bbs',value.handle),publicKey:hexToBytes(value.publicKey)});
  return Object.freeze({
    async generateKey(keyInfo=new Uint8Array()):Promise<BbsKey>{
      return key(await runtime.call<{handle:string;publicKey:string}>('bbs','generateKey',{suite,keyInfo:bytesToHex(keyInfo,4096)}));
    },
    async importKey(secret:bigint):Promise<BbsKey>{
      return key(await runtime.call<{handle:string;publicKey:string}>('bbs','importKey',{suite,secret:scalarToString(secret,MODULUS)}));
    },
    /** Explicit sensitive export for caller-owned storage. Prefer keeping the key in its worker. */
    async exportKey(secret:Handle<'bbs-key'>):Promise<bigint>{
      const value=await runtime.call<{secret:string}>('bbs','exportKey',{suite,handle:runtime.handleId(secret,'bbs-key','bbs')});
      return BigInt(value.secret);
    },
    async sign(input:{secret:Handle<'bbs-key'>;messages:readonly Uint8Array[];header:Uint8Array}):Promise<Uint8Array>{
      const value=await runtime.call<{signature:string}>('bbs','sign',{
        suite,handle:runtime.handleId(input.secret,'bbs-key','bbs'),messages:messages(input.messages),header:bytesToHex(input.header,4096)});
      return hexToBytes(value.signature);
    },
    async verify(input:SignatureInput):Promise<boolean>{
      const value=await runtime.call<{valid:boolean}>('bbs','verify',{suite,
        publicKey:bytesToHex(input.publicKey,96),signature:bytesToHex(input.signature,80),
        messages:messages(input.messages),header:bytesToHex(input.header,4096)});
      return value.valid;
    },
    async deriveProof(input:PresentationInput):Promise<Uint8Array>{
      const value=await runtime.call<{proof:string}>('bbs','deriveProof',{suite,
        publicKey:bytesToHex(input.publicKey,96),signature:bytesToHex(input.signature,80),
        messages:messages(input.messages),header:bytesToHex(input.header,4096),
        presentationHeader:bytesToHex(input.presentationHeader,4096),disclosedIndexes:indexes(input.disclosedIndexes)});
      return hexToBytes(value.proof);
    },
    async verifyProof(input:{publicKey:Uint8Array;proof:Uint8Array;disclosedMessages:readonly Uint8Array[];
        header:Uint8Array;presentationHeader:Uint8Array;disclosedIndexes:readonly number[]}):Promise<boolean>{
      const value=await runtime.call<{valid:boolean}>('bbs','verifyProof',{suite,
        publicKey:bytesToHex(input.publicKey,96),proof:bytesToHex(input.proof,8192),
        messages:messages(input.disclosedMessages),header:bytesToHex(input.header,4096),
        presentationHeader:bytesToHex(input.presentationHeader,4096),disclosedIndexes:indexes(input.disclosedIndexes)});
      return value.valid;
    }
  });
}
