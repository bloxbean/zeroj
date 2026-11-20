import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRuntime,bytesToHex,hexToBytes} from '@zeroj/runtime';
import {createElGamal} from '@zeroj/elgamal';
import {createThreshold} from '@zeroj/threshold';
import {createConfidentialNotes} from '@zeroj/confidential-notes';
import {bundle} from '../packages/bundle-confidential/dist/index.js';
const root=new URL('../../../',import.meta.url);
function vectors(folder){return Object.fromEntries(fs.readFileSync(new URL('zeroj-circuit-lib/src/test/resources/'+folder+'/reference-output.txt',root),'utf8').split('\n').filter(l=>l&&!l.startsWith('#')).map(l=>{const i=l.indexOf('=');return[l.slice(0,i),l.slice(i+1)];}));}
const scalarBytes=n=>hexToBytes(n.toString(16).padStart(64,'0'));
test('ElGamal n-of-n tally preserves context, bounds and verified share provenance',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 try {
  const e=createElGamal(runtime),ref=vectors('elgamal-reference');
  const known=await e.importKey(BigInt('0x0281799c40fb5bca4f8cc6af4812fae96cdf7113e1ab203ea4d73fb7027e8343'));
  assert.equal(bytesToHex(known.publicKey),'36d7d5a69ac65a6761ac10fd3338bd4692939aefc4f5d5a1eb37477b29423e68');
  const keys=[await e.generateKey(),await e.generateKey(),await e.generateKey()];
  const context=await e.aggregate(keys.map(k=>k.share));
  const encrypted=[];for(const vote of [1n,0n,1n,1n,0n])encrypted.push(await e.encrypt(context.handle,vote,1));
  const tally=await e.add(encrypted.map(c=>c.handle));assert.equal(tally.bound,5n);
  const shares=[];for(const key of keys)shares.push(await e.decryptionShare(key.secret,tally.handle));
  assert.equal(await e.decrypt(tally.handle,shares.map(s=>s.handle),5),3n);
  await assert.rejects(e.decrypt(tally.handle,[shares[0].handle,shares[0].handle,shares[2].handle],5));
  await assert.rejects(e.decrypt(tally.handle,[shares[0].handle,shares[1].handle],5));
  await assert.rejects(e.decrypt(tally.handle,shares.map(s=>s.handle),4));
  await assert.rejects(e.decrypt(encrypted[0].handle,shares.map(s=>s.handle),5));
  const another=await e.aggregate([known.share]),foreign=await e.encrypt(another.handle,1n,1);
  await assert.rejects(e.add([tally.handle,foreign.handle]));
  await assert.rejects(e.aggregate([keys[0].share,keys[0].share]));
  await assert.rejects(e.encrypt(context.handle,2n,1));
  await assert.rejects(e.scale(tally.handle,0n));
  await assert.rejects(runtime.call('elgamal','admitCiphertext',{verified:true,bytes:bytesToHex(tally.bytes)}));
 } finally {await runtime.dispose();}
});
export async function localDkg(runtime,{negativeChecks=false}={}) {
 const d=createThreshold(runtime),e=createElGamal(runtime);
 const config=await d.configure({faults:1,roster:[1,2,3].map(i=>new Uint8Array(32).fill(i)),applicationContext:new TextEncoder().encode('zeroj-local-simulation-only'),attempt:1n});
 const participants=[];for(let i=1;i<=3;i++)participants.push(await d.createParticipant(config.handle,i));
 let outgoing=[];for(const p of participants)outgoing.push(...(await d.start(p)).messages);
 if(negativeChecks){
  const privateMessage=outgoing.find(m=>m.channel==='private');
  await assert.rejects(d.receiveBroadcast(participants[0],privateMessage.sender,privateMessage.bytes));
  const broadcast=outgoing.find(m=>m.channel==='broadcast');
  await assert.rejects(d.receiveBroadcast(participants[0],broadcast.sender===1?2:1,broadcast.bytes));
  const changed=broadcast.bytes.slice();changed[0]^=1;
  await assert.rejects(d.receiveBroadcast(participants[0],broadcast.sender,changed));
  await assert.rejects(d.result(participants[0]));
 }
 for(let round=1;round<=7;round++){
  for(const message of outgoing){
   if(message.channel==='private')await d.receivePrivate(participants[message.recipient-1],message.sender,message.bytes);
   else for(const p of participants)await d.receiveBroadcast(p,message.sender,message.bytes);
  }
  outgoing=[];for(const p of participants)outgoing.push(...(await d.closeRound(p)).messages);
 }
 const results=[];for(const p of participants)results.push(await d.result(p));
 for(const result of results){assert.deepEqual(result.publicKey,results[0].publicKey);assert.deepEqual(result.transcriptDigest,results[0].transcriptDigest);assert.equal(result.requiredShares,2);}
 const a=await e.encrypt(results[0].context,1n,1),b=await e.encrypt(results[1].context,1n,1),sum=await e.add([a.handle,b.handle]);
 const shares=[];for(const result of results)shares.push(await d.decryptionShare(result.key,sum.handle));
 const value=await e.decrypt(sum.handle,[shares[0].handle,shares[2].handle],2);assert.equal(value,2n);
 if(negativeChecks){await assert.rejects(e.decrypt(sum.handle,[shares[0].handle],2));await assert.rejects(e.decrypt(sum.handle,[shares[0].handle,shares[0].handle],2));}
 return {value,requiredShares:2};
}
test('seven-round local DKG simulation and 2-of-3 decryption, with channel/session/state negatives',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 const start=performance.now();try {await localDkg(runtime,{negativeChecks:true});console.log('Node local 2-of-3 DKG + tally ms:',Math.round(performance.now()-start));} finally{await runtime.dispose();}
});
test('confidential notes open independent reference deliveries and reject all malformed profile cases',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 try {
  const api=createConfidentialNotes(runtime),ref=vectors('confidential-note-reference'),keys=new Map();
  for(const [name,value] of Object.entries(ref).filter(([k])=>k.startsWith('key.')&&k.endsWith('.sk'))){
   const reader=name.slice(4,-3),key=await api.restoreViewingKey(scalarBytes(BigInt(value)));keys.set(reader,key);
   assert.equal(bytesToHex(key.readerKey),ref['key.'+reader+'.pk']);
  }
  let count=0;
  for(const name of Object.keys(ref).filter(k=>k.startsWith('case.open.')&&k.endsWith('.config'))){
   const p=name.slice(0,-6),valid=ref[p+'expect']==='accept';let opened=null;
   try {opened=await api.open({key:keys.get(ref[p+'reader']).handle,delivery:hexToBytes(ref[p+'delivery']),u:BigInt(ref[p+'commitment_u']),v:BigInt(ref[p+'commitment_v'])});}
   catch(e){if(valid || !['INVALID_SCALAR','INVALID_REQUEST'].includes(e.code))throw e;}
   assert.equal(opened!==null,valid,name);
   if(opened){const value=await api.exportOpening(opened);assert.equal(value.value,BigInt(ref[p+'value']));assert.equal(value.blinding,BigInt(ref[p+'blinding']));await runtime.release(opened);}
   count++;
  }
  const owner=await api.generateViewingKey(),auditor=await api.generateViewingKey(),opening=await api.createOpening(42n);
  const deliveries=await api.seal(opening.handle,[owner.readerKey,auditor.readerKey]);assert.notDeepEqual(deliveries[0].slice(0,32),deliveries[1].slice(0,32));
  const opened=await api.open({...opening,key:owner.handle,delivery:deliveries[0]});assert.equal((await api.exportOpening(opened)).value,42n);
  assert.equal(await api.open({...opening,key:owner.handle,delivery:deliveries[1]}),null);
  const bad=deliveries[0].slice();bad[88]^=1;assert.equal(await api.open({...opening,key:owner.handle,delivery:bad}),null);
  await assert.rejects(api.seal(opening.handle,[owner.readerKey,owner.readerKey]));
  await runtime.release(owner.handle);await assert.rejects(api.exportViewingKey(owner.handle),{code:'INVALID_HANDLE'});
  console.log('Independent confidential-note opening vectors:',count);
 } finally {await runtime.dispose();}
});
test('Groth16 admission verifies exact key, width, ciphertext and DLEQ share statements',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 const dir=new URL('../build/confidential/',import.meta.url);
 const read=name=>JSON.parse(fs.readFileSync(new URL(name,dir),'utf8'));
 try {
  const e=createElGamal(runtime),manifest=read('manifest.json');
  const dleq=await e.registerRelationKey({relation:'dleq',width:0,verificationKey:read('dleq-vk.json')});
  const enc=await e.registerRelationKey({relation:'encryption',width:1,verificationKey:read('encryption-vk.json')});
  const trustee=await e.importKeyShare({relationKey:dleq,proof:read('possession-proof.json'),publicKey:hexToBytes(manifest.publicKey)});
  const context=await e.aggregate([trustee]);
  const input={relationKey:enc,proof:read('encryption-proof.json'),context:context.handle,bytes:hexToBytes(manifest.ciphertext),width:1};
  const ct=await e.admitCiphertext(input);
  const share=await e.importDecryptionShare({relationKey:dleq,proof:read('share-proof.json'),ciphertext:ct.handle,trustee,bytes:hexToBytes(manifest.decryptionShare)});
  assert.equal(await e.decrypt(ct.handle,[share.handle],1),1n);
  await assert.rejects(e.admitCiphertext({...input,width:2}),{code:'RELATION_MISMATCH'});
  const other=await e.generateKey(),otherContext=await e.aggregate([other.share]);
  await assert.rejects(e.importKeyShare({relationKey:dleq,proof:read('possession-proof.json'),publicKey:other.publicKey}));
  await assert.rejects(e.admitCiphertext({...input,context:otherContext.handle}));
  await assert.rejects(e.admitCiphertext({...input,proof:read('possession-proof.json')}));
  const different=await e.encrypt(context.handle,0n,1);
  await assert.rejects(e.importDecryptionShare({relationKey:dleq,proof:read('share-proof.json'),ciphertext:different.handle,trustee,bytes:hexToBytes(manifest.decryptionShare)}));
  // A sender cannot provide their own public-input list or bypass the Java-derived statement.
  await assert.rejects(runtime.call('elgamal','importKeyShare',{relationKey:'h1',proof:read('possession-proof.json'),publicKey:manifest.publicKey,publicInputs:read('possession-public.json')}));
  const {spawnSync}=await import('node:child_process'),{fileURLToPath}=await import('node:url');
  for(const name of ['possession','share','encryption']) {
   const key=name==='encryption'?'encryption':'dleq';
   const result=spawnSync(process.execPath,[fileURLToPath(new URL('../node_modules/snarkjs/build/cli.cjs',import.meta.url)),
    'groth16','verify',key+'-vk.json',name+'-public.json',name+'-proof.json'],{cwd:fileURLToPath(dir),encoding:'utf8',timeout:60_000});
   assert.equal(result.status,0,result.stderr+result.stdout);assert.match(result.stdout,/OK/);
  }
 } finally {await runtime.dispose();}
});
test('DKG duplicate delivery is bounded and excess distinct messages abort the participant',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 try {
  const api=createThreshold(runtime),config=await api.configure({faults:1,roster:[1,2,3].map(i=>new Uint8Array([i])),applicationContext:new Uint8Array([3]),attempt:2n});
  const first=await api.createParticipant(config.handle,1),second=await api.createParticipant(config.handle,2);
  const outgoing=await api.start(first);await api.start(second);
  const message=outgoing.messages.find(m=>m.channel==='private'&&m.recipient===2);
  for(let i=0;i<1030;i++)await api.receivePrivate(second,1,message.bytes); // One retained unique message.
  // Canonical but conflicting private scalar pairs are adversarial protocol messages.
  let rejected=false;
  for(let i=0;i<1025;i++){
   const bytes=message.bytes.slice();bytes.fill(0,36,68);bytes[66]=i>>>8;bytes[67]=i&255;
   try {await api.receivePrivate(second,1,bytes);}catch(error){assert.equal(error.code,'PROTOCOL_RESOURCE_LIMIT');rejected=true;break;}
  }
  assert.equal(rejected,true);
  await assert.rejects(api.closeRound(second),{code:'PROTOCOL_RESOURCE_LIMIT'});
  await assert.rejects(api.result(second),{code:'PROTOCOL_RESOURCE_LIMIT'});
 }finally{await runtime.dispose();}
});
