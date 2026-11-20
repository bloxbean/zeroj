import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createRuntime,bytesToHex,hexToBytes} from '@zeroj/runtime';
import {createPedersen} from '@zeroj/pedersen';
import {createBbs} from '@zeroj/bbs';
import {bundle} from '../packages/bundle-crypto/dist/index.js';
const root=new URL('../../../',import.meta.url);
const read=path=>JSON.parse(fs.readFileSync(new URL(path,root),'utf8'));
test('Pedersen scalar/byte commitments match independent reference vectors on both curves',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 const verifier=createRuntime({bundles:[bundle]});
 let count=0;
 try {
  const api=createPedersen(runtime),check=createPedersen(verifier);
  for(const [curve,profile] of [['bls12381','pedersen-bls12-381-g1'],['jubjub','pedersen-jubjub']]) {
   for(const bytes of [false,true]) {
    const vectors=read('zeroj-test-vectors/src/main/resources/test-vectors/commitment-profiles-v1/'+profile+(bytes?'-bytes':'')+'-v1.json');
    for(const v of vectors.positive.filter(v=>v.operation==='commit'&&(!bytes||typeof v.input.payload.hex==='string'))) {
     const opening=bytes?{data:hexToBytes(v.input.payload.hex),blinding:BigInt(v.input.blinding)}
       :{value:BigInt(v.input.value),blinding:BigInt(v.input.blinding)};
     const commitment=await api[curve][bytes?'commitBytes':'commitScalar'](opening);
     assert.equal(bytesToHex(commitment),v.expected.pointHex,v.name);
     assert.equal(await check[curve][bytes?'verifyBytes':'verifyOpening']({...opening,commitment}),true,v.name);
     count++;
    }
   }
   await assert.rejects(check[curve].commitScalar({value:1n,blinding:2n}),{code:'EXPERIMENTAL_SECRETS_DISABLED'});
   await assert.rejects(api[curve].verifyOpening({commitment:new Uint8Array(curve==='bls12381'?48:32),value:1n,blinding:2n}),{code:'INVALID_REQUEST'});
  }
  console.log('Pedersen independent commitment vectors:',count);
 } finally {await runtime.dispose();await verifier.dispose();}
});
test('BBS official signature and presentation vectors across both suites',async()=>{
 const runtime=createRuntime({bundles:[bundle]});
 let count=0;
 try {
  for(const [suite,folder] of [['BLS12381_SHA256','bls12-381-sha-256'],['BLS12381_SHAKE256','bls12-381-shake-256']]) {
   const bbs=createBbs(runtime,suite);
   for(const type of ['signature','proof']) {
    const dir='zeroj-bbs/src/test/resources/cfrg-bbs/draft10/official/'+folder+'/'+type+'/';
    for(const file of fs.readdirSync(new URL(dir,root)).sort()) {
     const v=read(dir+file);
     const header=hexToBytes(v.header),messages=v.messages.map(hexToBytes);
     let accepted=false;
     try {
      accepted=type==='signature'?await bbs.verify({
       publicKey:hexToBytes(v.signerKeyPair.publicKey),signature:hexToBytes(v.signature),messages,header
      }):await bbs.verifyProof({
       publicKey:hexToBytes(v.signerPublicKey),proof:hexToBytes(v.proof),header,
       presentationHeader:hexToBytes(v.presentationHeader),disclosedIndexes:v.disclosedIndexes,
       disclosedMessages:v.disclosedIndexes.map(i=>messages[i])
      });
     } catch(e) {if(v.result.valid || !['INVALID_REQUEST','INVALID_DISCLOSURE_INDEXES'].includes(e.code))throw e;}
     assert.equal(accepted,v.result.valid,file);count++;
    }
   }
  }
  console.log('BBS official fixtures:',count);
 } finally {await runtime.dispose();}
});
test('BBS full typed lifecycle, challenge binding and foreign/released handle rejection',async()=>{
 const runtime=createRuntime({bundles:[bundle],experimentalSecrets:true});
 const other=createRuntime({bundles:[bundle],experimentalSecrets:true});
 try {
  const bbs=createBbs(runtime),foreign=createBbs(other);
  const key=await bbs.generateKey();
  const messages=['member','over-18'].map(s=>new TextEncoder().encode(s));
  const header=new TextEncoder().encode('zeroj-sdk-example-v1');
  const signature=await bbs.sign({secret:key.secret,messages,header});
  assert.equal(await bbs.verify({publicKey:key.publicKey,signature,messages,header}),true);
  const presentationHeader=new Uint8Array([1,2,3]);
  const input={publicKey:key.publicKey,signature,messages,header,presentationHeader,disclosedIndexes:[1]};
  const proof=await bbs.deriveProof(input),second=await bbs.deriveProof(input);
  assert.notDeepEqual(proof,second,'fresh proof blinding');
  assert.equal(await bbs.verifyProof({...input,proof,disclosedMessages:[messages[1]]}),true);
  assert.equal(await bbs.verifyProof({...input,proof,disclosedMessages:[messages[1]],presentationHeader:new Uint8Array([4])}),false);
  await assert.rejects(foreign.sign({secret:key.secret,messages,header}),{code:'INVALID_HANDLE'});
  await runtime.release(key.secret);
  await assert.rejects(bbs.sign({secret:key.secret,messages,header}),{code:'INVALID_HANDLE'});
 } finally {await runtime.dispose();await other.dispose();}
});
