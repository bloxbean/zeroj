import {type ZeroJRuntime,type Handle,bytesToHex,hexToBytes,scalarToString} from '@zeroj/runtime';
import type {KeyContext,AdmittedCiphertext,DecryptionShare} from '@zeroj/elgamal';
export type DkgConfiguration=Handle<'dkg-config'>;
export type DkgParticipant=Handle<'dkg-participant'>;
export type ThresholdSecret=Handle<'threshold-secret'>;
export interface DkgMessage {bytes:Uint8Array;channel:'private'|'broadcast';sender:number;recipient:number;kind:string;}
type WireRound={round:number;messages:{bytes:string;channel:string;sender:number;recipient:number;kind:string}[]};
export interface ThresholdResult {key:ThresholdSecret;context:KeyContext;participantId:number;publicKey:Uint8Array;
 transcriptDigest:Uint8Array;requiredShares:number;qualified:readonly number[];}
export function createThreshold(runtime:ZeroJRuntime) {
 const id=<K extends string>(h:Handle<K>,kind:K)=>runtime.handleId(h,kind,'threshold');
 const retain=<K extends string>(kind:K,h:string)=>runtime.retainHandle(kind,'threshold',h);
 const round=(v:WireRound):{round:number;messages:DkgMessage[]}=>({round:v.round,messages:v.messages.map(m=>({...m,bytes:hexToBytes(m.bytes),channel:m.channel as 'private'|'broadcast'}))});
 return Object.freeze({
  /** Supports 3..16 participants; faults=t means t+1 required shares and 2t+1 <= n. */
  async configure(input:{faults:number;roster:readonly Uint8Array[];applicationContext:Uint8Array;attempt:bigint}):Promise<{handle:DkgConfiguration;session:Uint8Array}>{
   const v=await runtime.call<{handle:string;session:string}>('threshold','configure',{faults:input.faults,
    roster:input.roster.map(k=>bytesToHex(k,4096)),applicationContext:bytesToHex(input.applicationContext,4096),attempt:scalarToString(input.attempt,1n<<64n)});
   return {handle:retain('dkg-config',v.handle),session:hexToBytes(v.session)};
  },
  async createParticipant(config:DkgConfiguration,participantId:number):Promise<DkgParticipant>{
   const v=await runtime.call<{handle:string}>('threshold','createParticipant',{config:id(config,'dkg-config'),participantId});return retain('dkg-participant',v.handle);
  },
  async start(participant:DkgParticipant){return round(await runtime.call<WireRound>('threshold','start',{participant:id(participant,'dkg-participant')}));},
  /** Host must establish broadcast agreement, delivery deadlines and authenticated round closure before calling. */
  async closeRound(participant:DkgParticipant){return round(await runtime.call<WireRound>('threshold','closeRound',{participant:id(participant,'dkg-participant')}));},
  /** authenticatedSender must come from the authenticated channel, not the message header. */
  async receiveBroadcast(participant:DkgParticipant,authenticatedSender:number,message:Uint8Array):Promise<void>{
   await runtime.call('threshold','receiveBroadcast',{participant:id(participant,'dkg-participant'),authenticatedSender,message:bytesToHex(message,4096)});
  },
  /** Private SHARE messages must only be delivered over the authenticated confidential recipient channel. */
  async receivePrivate(participant:DkgParticipant,authenticatedSender:number,message:Uint8Array):Promise<void>{
   await runtime.call('threshold','receivePrivate',{participant:id(participant,'dkg-participant'),authenticatedSender,message:bytesToHex(message,4096)});
  },
  async result(participant:DkgParticipant):Promise<ThresholdResult>{
   const v=await runtime.call<{key:string;context:string;participantId:number;publicKey:string;transcriptDigest:string;requiredShares:number;qualified:number[]}>('threshold','result',{participant:id(participant,'dkg-participant')});
   return {...v,key:retain('threshold-secret',v.key),context:retain('elgamal-context',v.context),publicKey:hexToBytes(v.publicKey),transcriptDigest:hexToBytes(v.transcriptDigest)};
  },
  async decryptionShare(key:ThresholdSecret,ciphertext:AdmittedCiphertext):Promise<DecryptionShare>{
   const v=await runtime.call<{handle:string;bytes:string;publicInputs:string[]}>('threshold','decryptionShare',{key:id(key,'threshold-secret'),ciphertext:id(ciphertext,'elgamal-ciphertext')});
   return {handle:retain('elgamal-decryption-share',v.handle),bytes:hexToBytes(v.bytes),publicInputs:v.publicInputs.map(BigInt)};
  }
 });
}
