import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {defineCircuit,field,uint,bool,bytes} from '@zeroj/circuit';
import {ageCheck,sha256Preimage} from '../build/circuit-examples/symbolic-examples.js';
import {lintSymbolic} from '@zeroj/circuit-lint';
const spec=()=>({name:'test',public:{out:field()},secret:{x:field()}});
test('typed inputs encode exactly and never enter authoring recipe',()=>{
  assert.deepEqual({...ageCheck.encodeInputs({public:{threshold:18n},secret:{age:21n}})},{threshold:'18',age:'21'});
  for(const age of [-1n,256n,21,'21'])assert.throws(()=>ageCheck.encodeInputs({public:{threshold:18n},secret:{age}}));
  assert.throws(()=>ageCheck.encodeInputs({public:{threshold:18n},secret:{age:21n,extra:1n}}));
  const data=sha256Preimage.encodeInputs({public:{digest:new Uint8Array(32)},secret:{message:new Uint8Array([97,98,99])}});
  assert.equal(data.message_2,'99');assert.equal(Object.keys(data).length,35);
  assert.throws(()=>sha256Preimage.encodeInputs({public:{digest:new Uint8Array(32)},secret:{message:[97,98,99]}}));
  assert.throws(()=>sha256Preimage.encodeInputs({public:{digest:new Uint8Array(32)},secret:{message:new Uint8Array(4)}}));
  assert.equal(ageCheck.recipe.includes('21'),false);
});
test('ownership, fake symbols, closed definitions and caught authoring errors reject',()=>{
  let escaped;defineCircuit(spec(),({secret:s})=>{escaped=s.x;});
  assert.throws(()=>escaped.add(escaped));
  assert.throws(()=>defineCircuit(spec(),({secret:s})=>{s.x.add(escaped);}));
  assert.throws(()=>defineCircuit(spec(),({secret:s})=>{s.x.add({__zerojSymbolic:'field'});}));
  assert.throws(()=>defineCircuit(spec(),({secret:s})=>{try{s.x.assertEqual(undefined);}catch{}}));
  assert.throws(()=>defineCircuit(spec(),({zk})=>{try{zk.constant(-1n);}catch{}}));
  assert.throws(()=>defineCircuit(spec(),({secret:s})=>{try{String(s.x);}catch{}}));
  assert.throws(()=>defineCircuit(spec(),async()=>{}));
  assert.throws(()=>defineCircuit(spec(),({secret:s})=>s.x));
  assert.throws(()=>defineCircuit(spec(),({secret:s})=>{for(let i=0;i<129;i++)s.x.assertEqual(s.x);}));
});
test('shape validation and byte/profile limits reject before compilation',()=>{
  for(const n of [0,254,1.5,NaN])assert.throws(()=>uint(n));
  for(const n of [0,65,-1])assert.throws(()=>bytes(n));
  assert.throws(()=>defineCircuit({name:'bad',public:{x:field()},secret:{x:field()}},()=>{}));
  assert.throws(()=>defineCircuit({name:'bad',public:{x:bytes(2)},secret:{x_0:field()}},()=>{}));
  assert.throws(()=>defineCircuit({name:'bad',public:{},secret:{x:bytes(56)}},({zk,secret:s})=>{zk.gadgets.sha256(s.x);}));
  assert.throws(()=>defineCircuit({name:'bad',public:{a:bytes(2)},secret:{b:bytes(3)}},({public:p,secret:s})=>{try{p.a.assertEqual(s.b);}catch{}}));
  assert.throws(()=>defineCircuit({name:'bad',public:{},secret:{flag:bool()}},({secret:s})=>{s.flag.select(s.flag,{});}));
});
test('type-aware lint catches symbolic JS truthiness and operators; symbolic select is allowed',async()=>{
  // TypeScript itself allows if(object); runtime coercion hooks cannot intercept it.
  const file='build/lint-negative.ts';
  await fs.writeFile(file,`import {defineCircuit,field,bool} from '@zeroj/circuit';
    defineCircuit({name:'bad',public:{y:field()},secret:{x:field(),b:bool()}},({public:p,secret:s})=>{
      if(s.b) s.x.assertEqual(p.y);
      const wrong=s.x===p.y;
      const ignored=s.b&&s.x;
      const cast=Boolean(s.b);
      const negated=!s.b;
      const selected=s.b?s.x:p.y;
      s.b.select(s.x,p.y).assertEqual(p.y);
    });`);
  assert.equal(lintSymbolic([file]).length,6);
  assert.deepEqual(lintSymbolic(['examples/circuit/symbolic-examples.ts']),[]);
});
