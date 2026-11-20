import {type ZeroJRuntime,type Handle,bytesToHex,hexToBytes,scalarToString} from '@zeroj/runtime';
export type ViewingSecret=Handle<'note-viewing-key'>;
export type PrivateOpening=Handle<'note-opening'>;
export interface NoteOpening {handle:PrivateOpening;commitment:Uint8Array;u:bigint;v:bigint;}
const L=6554484396890773809930967563523245729705921265872317281365359162392183254199n;
const P=52435875175126190479447740508185965837690552500527637822603658699938581184513n;
export function createConfidentialNotes(runtime:ZeroJRuntime) {
 const id=<K extends string>(h:Handle<K>,kind:K)=>runtime.handleId(h,kind,'confidential-notes');
 const retain=<K extends string>(kind:K,h:string)=>runtime.retainHandle(kind,'confidential-notes',h);
 const key=(v:{handle:string;readerKey:string})=>({handle:retain('note-viewing-key',v.handle),readerKey:hexToBytes(v.readerKey)});
 const opening=(v:{handle:string;commitment:string;u:string;v:string}):NoteOpening=>({handle:retain('note-opening',v.handle),commitment:hexToBytes(v.commitment),u:BigInt(v.u),v:BigInt(v.v)});
 return Object.freeze({
  async generateViewingKey(){return key(await runtime.call('confidential-notes','generateViewingKey',{}));},
  async restoreViewingKey(secret:Uint8Array){return key(await runtime.call('confidential-notes','restoreViewingKey',{secret:bytesToHex(secret,32)}));},
  /** Explicit sensitive export. Prefer keeping the secret in its worker. */
  async exportViewingKey(secret:ViewingSecret):Promise<Uint8Array>{const v=await runtime.call<{secret:string}>('confidential-notes','exportViewingKey',{key:id(secret,'note-viewing-key')});return hexToBytes(v.secret);},
  async createOpening(value:bigint):Promise<NoteOpening>{return opening(await runtime.call('confidential-notes','createOpening',{value:scalarToString(value,1n<<64n)}));},
  async restoreOpening(value:bigint,blinding:bigint):Promise<NoteOpening>{return opening(await runtime.call('confidential-notes','restoreOpening',{value:scalarToString(value,1n<<64n),blinding:scalarToString(blinding,L)}));},
  async exportOpening(secret:PrivateOpening):Promise<{value:bigint;blinding:bigint}>{
   const v=await runtime.call<{value:string;blinding:string}>('confidential-notes','exportOpening',{opening:id(secret,'note-opening')});return {value:BigInt(v.value),blinding:BigInt(v.blinding)};
  },
  /** Readers must belong to the application's authenticated registry; encoding validity is not authorization. */
  async seal(secret:PrivateOpening,readers:readonly Uint8Array[]):Promise<Uint8Array[]>{
   const v=await runtime.call<{deliveries:string[]}>('confidential-notes','seal',{opening:id(secret,'note-opening'),readers:readers.map(r=>bytesToHex(r,32))});return v.deliveries.map(hexToBytes);
  },
  /** A rejected delivery is null. Platform faults reject the promise; never suppress them as "not mine". */
  async open(input:{key:ViewingSecret;delivery:Uint8Array;u:bigint;v:bigint}):Promise<PrivateOpening|null>{
   const v=await runtime.call<{opened:boolean;opening?:string}>('confidential-notes','open',{key:id(input.key,'note-viewing-key'),
    delivery:bytesToHex(input.delivery,4096),u:scalarToString(input.u,P),v:scalarToString(input.v,P)});
   return v.opened?retain('note-opening',v.opening!):null;
  }
 });
}
