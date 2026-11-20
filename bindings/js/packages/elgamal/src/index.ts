import {type ZeroJRuntime,type Handle,bytesToHex,hexToBytes,scalarToString} from '@zeroj/runtime';
import type {Groth16Proof,Groth16VerificationKey} from '@zeroj/groth16-verifier';
export type ElGamalSecret=Handle<'elgamal-secret'>;
export type VerifiedKeyShare=Handle<'elgamal-key-share'>;
export type KeyContext=Handle<'elgamal-context'>;
export type AdmittedCiphertext=Handle<'elgamal-ciphertext'>;
export type VerifiedDecryptionShare=Handle<'elgamal-decryption-share'>;
export type RelationKey=Handle<'elgamal-relation-key'>;
export interface ElGamalKey {secret:ElGamalSecret;share:VerifiedKeyShare;publicKey:Uint8Array;}
export interface Ciphertext {handle:AdmittedCiphertext;bytes:Uint8Array;bound:bigint;}
export interface DecryptionShare {handle:VerifiedDecryptionShare;bytes:Uint8Array;publicInputs:readonly bigint[];}
const L=6554484396890773809930967563523245729705921265872317281365359162392183254199n;
export function createElGamal(runtime:ZeroJRuntime) {
 const id=<K extends string>(h:Handle<K>,kind:K)=>runtime.handleId(h,kind,'elgamal');
 const retain=<K extends string>(kind:K,h:string)=>runtime.retainHandle(kind,'elgamal',h);
 const key=(v:{secret:string;share:string;publicKey:string}):ElGamalKey=>({secret:retain('elgamal-secret',v.secret),share:retain('elgamal-key-share',v.share),publicKey:hexToBytes(v.publicKey)});
 const cipher=(v:{handle:string;bytes:string;bound:string}):Ciphertext=>({handle:retain('elgamal-ciphertext',v.handle),bytes:hexToBytes(v.bytes),bound:BigInt(v.bound)});
 const share=(v:{handle:string;bytes:string;publicInputs:string[]}):DecryptionShare=>({handle:retain('elgamal-decryption-share',v.handle),bytes:hexToBytes(v.bytes),publicInputs:v.publicInputs.map(BigInt)});
 return Object.freeze({
  generateKey:async()=>key(await runtime.call<{secret:string;share:string;publicKey:string}>('elgamal','generateKey',{})),
  importKey:async(secret:bigint)=>key(await runtime.call<{secret:string;share:string;publicKey:string}>('elgamal','importKey',{secret:scalarToString(secret,L)})),
  async exportKey(secret:ElGamalSecret):Promise<bigint>{return BigInt((await runtime.call<{secret:string}>('elgamal','exportKey',{secret:id(secret,'elgamal-secret')})).secret);},
  async aggregate(shares:readonly VerifiedKeyShare[]):Promise<{handle:KeyContext;publicKey:Uint8Array}>{
   const v=await runtime.call<{handle:string;publicKey:string}>('elgamal','aggregate',{shares:shares.map(h=>id(h,'elgamal-key-share'))});
   return {handle:retain('elgamal-context',v.handle),publicKey:hexToBytes(v.publicKey)};
  },
  async encrypt(context:KeyContext,message:bigint,width:number):Promise<Ciphertext>{
   return cipher(await runtime.call('elgamal','encrypt',{context:id(context,'elgamal-context'),message:scalarToString(message,1n<<64n),width}));
  },
  async add(ciphertexts:readonly AdmittedCiphertext[]):Promise<Ciphertext>{return cipher(await runtime.call('elgamal','add',{ciphertexts:ciphertexts.map(h=>id(h,'elgamal-ciphertext'))}));},
  async scale(ciphertext:AdmittedCiphertext,factor:bigint):Promise<Ciphertext>{return cipher(await runtime.call('elgamal','scale',{ciphertext:id(ciphertext,'elgamal-ciphertext'),factor:scalarToString(factor,L)}));},
  async decryptionShare(secret:ElGamalSecret,ciphertext:AdmittedCiphertext):Promise<DecryptionShare>{return share(await runtime.call('elgamal','decryptionShare',{secret:id(secret,'elgamal-secret'),ciphertext:id(ciphertext,'elgamal-ciphertext')}));},
  /** Search is bounded to 1,000,000 and must cover the established ciphertext bound. */
  async decrypt(ciphertext:AdmittedCiphertext,shares:readonly VerifiedDecryptionShare[],maxPlaintext:number):Promise<bigint>{
   const v=await runtime.call<{message:string}>('elgamal','decrypt',{ciphertext:id(ciphertext,'elgamal-ciphertext'),shares:shares.map(h=>id(h,'elgamal-decryption-share')),maxPlaintext});return BigInt(v.message);
  },
  /** The application must authenticate this VK as the exact six-input relation and fixed width. */
  async registerRelationKey(input:{relation:'dleq'|'encryption';width:number;verificationKey:Groth16VerificationKey}):Promise<RelationKey>{
   const v=await runtime.call<{handle:string}>('elgamal','registerRelationKey',{...input});return retain('elgamal-relation-key',v.handle);
  },
  async importKeyShare(input:{relationKey:RelationKey;proof:Groth16Proof;publicKey:Uint8Array}):Promise<VerifiedKeyShare>{
   const v=await runtime.call<{handle:string;publicKey:string}>('elgamal','importKeyShare',{
    relationKey:id(input.relationKey,'elgamal-relation-key'),proof:input.proof,publicKey:bytesToHex(input.publicKey,32)});return retain('elgamal-key-share',v.handle);
  },
  async admitCiphertext(input:{relationKey:RelationKey;proof:Groth16Proof;context:KeyContext;bytes:Uint8Array;width:number}):Promise<Ciphertext>{
   return cipher(await runtime.call('elgamal','admitCiphertext',{relationKey:id(input.relationKey,'elgamal-relation-key'),proof:input.proof,
    context:id(input.context,'elgamal-context'),bytes:bytesToHex(input.bytes,64),width:input.width}));
  },
  async importDecryptionShare(input:{relationKey:RelationKey;proof:Groth16Proof;ciphertext:AdmittedCiphertext;trustee:VerifiedKeyShare;bytes:Uint8Array}):Promise<DecryptionShare>{
   return share(await runtime.call('elgamal','importDecryptionShare',{relationKey:id(input.relationKey,'elgamal-relation-key'),proof:input.proof,
    ciphertext:id(input.ciphertext,'elgamal-ciphertext'),trustee:id(input.trustee,'elgamal-key-share'),bytes:bytesToHex(input.bytes,32)}));
  },
  async importThresholdDecryptionShare(input:{relationKey:RelationKey;proof:Groth16Proof;ciphertext:AdmittedCiphertext;participantId:number;bytes:Uint8Array}):Promise<DecryptionShare>{
   return share(await runtime.call('elgamal','importThresholdDecryptionShare',{relationKey:id(input.relationKey,'elgamal-relation-key'),proof:input.proof,
    ciphertext:id(input.ciphertext,'elgamal-ciphertext'),participantId:input.participantId,bytes:bytesToHex(input.bytes,32)}));
  }
 });
}
