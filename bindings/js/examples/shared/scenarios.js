// Disposable local examples. These use the public SDK exactly as an application would.
import {createRuntime,hexToBytes} from '@zeroj/runtime';
import {createPedersen} from '@zeroj/pedersen';
import {createBbs} from '@zeroj/bbs';
import {createGroth16Prover} from '@zeroj/groth16-prover';
import {createGroth16Verifier} from '@zeroj/groth16-verifier';
import {createElGamal} from '@zeroj/elgamal';
import {createThreshold} from '@zeroj/threshold';
import {createConfidentialNotes} from '@zeroj/confidential-notes';
import {bundle as cryptoBundle} from '../../packages/bundle-crypto/dist/index.js';
import {bundle as proverBundle} from '../../packages/bundle-prover/dist/index.js';
import {bundle as verifierBundle} from '../../packages/bundle-verifier/dist/index.js';
import {bundle as confidentialBundle} from '../../packages/bundle-confidential/dist/index.js';
const encode=s=>new TextEncoder().encode(s);
const bundles={pedersen:[cryptoBundle],bbs:[cryptoBundle],groth16:[proverBundle,verifierBundle],elgamal:[confidentialBundle],threshold:[confidentialBundle],notes:[confidentialBundle]};
const check=(condition)=>{if(!condition)throw Error('Example verification failed');};
export async function runScenario(name,loadJson,loadBytes,options={}) {
 const runtime=createRuntime({bundles:options.bundles??bundles[name],experimentalSecrets:true});
 const start=performance.now();
 try {
  let result;
  if(name==='pedersen') {
   const api=createPedersen(runtime).jubjub,blinding=await api.randomBlinding();
   const commitment=await api.commitScalar({value:42n,blinding});
   const valid=await api.verifyOpening({commitment,value:42n,blinding});check(valid);
   result={valid,commitmentBytes:commitment.length,message:'Commit 42, then disclose the opening and check it.'};
  } else if(name==='bbs') {
   const api=createBbs(runtime),key=await api.generateKey();
   const messages=['Member #42','over-18'].map(encode),header=encode('zeroj-disposable-demo-v1');
   const signature=await api.sign({secret:key.secret,messages,header});
   const challenge=crypto.getRandomValues(new Uint8Array(32));
   const proof=await api.deriveProof({publicKey:key.publicKey,signature,messages,header,presentationHeader:challenge,disclosedIndexes:[1]});
   const valid=await api.verifyProof({publicKey:key.publicKey,proof,disclosedMessages:[messages[1]],header,presentationHeader:challenge,disclosedIndexes:[1]});check(valid);
   result={valid,proofBytes:proof.length,disclosed:'over-18',hidden:'Member identifier',message:'The presentation is bound to a fresh verifier challenge.'};
  } else if(name==='groth16') {
   const manifest=await loadJson('tutorial/manifest.json'),verificationKey=await loadJson('tutorial/vk.json');
   check(manifest.developmentOnly===true);
   const prover=createGroth16Prover(runtime),verifier=createGroth16Verifier(runtime);
   const key=await prover.loadKey({circuit:manifest.circuit,fingerprint:manifest.fingerprint,verificationKey,
    expectedSha256:hexToBytes(manifest.sha256),zkey:await loadBytes('tutorial/key.zkey')});
   const proofStart=performance.now(),proof=await prover.proveCubic(key,3n),proofMs=performance.now()-proofStart;
   const verifyStart=performance.now(),valid=await verifier.verify({...proof,verificationKey}),verifyMs=performance.now()-verifyStart;check(valid);
   const changedAccepted=await verifier.verify({...proof,verificationKey,publicInputs:[36n]});check(!changedAccepted);
   result={valid,proofMs:Math.round(proofMs),verifyMs:Math.round(verifyMs),publicY:String(proof.publicInputs[0]),changedAccepted,
    message:'Private x = 3; public y = x³ + x + 5 = 35. DEVELOPMENT KEY ONLY.'};
  } else if(name==='elgamal') {
   const api=createElGamal(runtime),keys=[await api.generateKey(),await api.generateKey()];
   const context=await api.aggregate(keys.map(k=>k.share));
   const votes=[];for(const value of [1n,0n,1n])votes.push(await api.encrypt(context.handle,value,1));
   const tally=await api.add(votes.map(v=>v.handle)),shares=[];
   for(const key of keys)shares.push(await api.decryptionShare(key.secret,tally.handle));
   const value=await api.decrypt(tally.handle,shares.map(s=>s.handle),3);check(value===2n);
   result={tally:String(value),bound:String(tally.bound),trustees:2,message:'All 2 trustees are required. Local simulation only; decrypt totals only after closure.'};
  } else if(name==='threshold') {
   const api=createThreshold(runtime),elgamal=createElGamal(runtime);
   const config=await api.configure({faults:1,roster:[1,2,3].map(i=>new Uint8Array(32).fill(i)),
    applicationContext:encode('zeroj-local-example-only'),attempt:1n});
   const participants=[];for(let id=1;id<=3;id++)participants.push(await api.createParticipant(config.handle,id));
   let outgoing=[];for(const p of participants)outgoing.push(...(await api.start(p)).messages);
   // This in-process delivery loop simulates authenticated channels and common round closure.
   // It is deliberately NOT exported as a production distributed transport.
   for(let round=1;round<=7;round++){
    for(const message of outgoing){
     if(message.channel==='private')await api.receivePrivate(participants[message.recipient-1],message.sender,message.bytes);
     else for(const p of participants)await api.receiveBroadcast(p,message.sender,message.bytes);
    }
    outgoing=[];for(const p of participants)outgoing.push(...(await api.closeRound(p)).messages);
   }
   const trustees=[];for(const p of participants)trustees.push(await api.result(p));
   const ct=await elgamal.encrypt(trustees[0].context,7n,3),shares=[];
   for(const i of [0,2])shares.push(await api.decryptionShare(trustees[i].key,ct.handle));
   const value=await elgamal.decrypt(ct.handle,shares.map(s=>s.handle),7);check(value===7n);
   result={plaintext:String(value),requiredShares:2,participants:3,rounds:7,message:'Local protocol simulation. A real deployment supplies authenticated private channels, broadcast agreement and deadlines.'};
  } else if(name==='notes') {
   const api=createConfidentialNotes(runtime),owner=await api.generateViewingKey(),auditor=await api.generateViewingKey();
   const opening=await api.createOpening(42n),deliveries=await api.seal(opening.handle,[owner.readerKey,auditor.readerKey]);
   const values=[];
   for(const [key,index] of [[owner,0],[auditor,1]]){
    const opened=await api.open({key:key.handle,delivery:deliveries[index],u:opening.u,v:opening.v});check(opened!==null);
    values.push(String((await api.exportOpening(opened)).value));
   }
   const altered=deliveries[0].slice();altered[88]^=1;
   const changedAccepted=(await api.open({key:owner.handle,delivery:altered,u:opening.u,v:opening.v}))!==null;check(!changedAccepted);
   result={ownerValue:values[0],auditorValue:values[1],deliveryBytes:deliveries[0].length,changedAccepted,
    message:'Commitment-checked delivery to owner and auditor. Spending, nullifiers and ledger ownership checks are separate.'};
  } else throw Error('Unknown scenario');
  return {...result,totalMs:Math.round(performance.now()-start)};
 } finally {await runtime.dispose();}
}
