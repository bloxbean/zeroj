import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {defineCircuit,field,uint,bool,bytes,array} from '@zeroj/circuit';
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

test('fixed arrays have immutable schemas, typed values and bounded static indices',()=>{
 const element={type:'uint',bits:8},spec=array(element,2);element.bits=16;
 const c=defineCircuit({name:'arrays_test',public:{out:array(field(),2)},secret:{values:spec,flags:array(bool(),2)}},({public:p,secret:s})=>{
   for(let i=0;i<p.out.length;i++)s.flags.get(i).select(s.values.get(i).asField(),p.out.get(i)).assertEqual(p.out.get(i));
 });
 assert.equal(JSON.parse(c.recipe).version,2);
 const input={public:{out:[1n,2n]},secret:{values:[1n,2n],flags:[true,false]}};
 assert.deepEqual({...c.encodeInputs(input)},{out_0:'1',out_1:'2',values_0:'1',values_1:'2',flags_0:'1',flags_1:'0'});
 for(const values of [[1n], [1n,256n], [1,2], new Array(2)])assert.throws(()=>c.encodeInputs({...input,secret:{...input.secret,values}}));
 assert.throws(()=>c.encodeInputs({...input,secret:{...input.secret,flags:[1,0]}}));
 for(const n of [0,65,-1,1.5,NaN])assert.throws(()=>array(field(),n));
 assert.throws(()=>array(bytes(2),1));assert.throws(()=>array(array(field(),2),2));
 assert.throws(()=>defineCircuit({name:'collision',public:{x:array(field(),1)},secret:{x_0:field()}},()=>{}));
 assert.throws(()=>defineCircuit({name:'bounds',public:{},secret:{a:array(field(),2)}},({secret:s})=>{try{s.a.get(2);}catch{}}));
 assert.throws(()=>defineCircuit({name:'bounds',public:{},secret:{a:array(field(),2)}},({secret:s})=>{s.a.get(s.a.get(0));}));
});
test('Merkle array ownership, element type and lengths cannot be forged',()=>{
 const spec={name:'merkle_test',public:{root:field()},secret:{leaf:field(),siblings:array(field(),1),bits:array(bool(),1)}};
 let foreign;defineCircuit(spec,({secret:s})=>{foreign=s.siblings;});
 for(const change of [(s)=>foreign,(s)=>({__zerojSymbolic:'array',length:1}),(s)=>s.bits])
  assert.throws(()=>defineCircuit(spec,({secret:s,zk})=>{try{zk.gadgets.merkleRootBls12381T3(s.leaf,change(s),s.bits);}catch{}}));
 assert.throws(()=>defineCircuit({...spec,secret:{...spec.secret,bits:array(bool(),2)}},({secret:s,zk})=>{zk.gadgets.merkleRootBls12381T3(s.leaf,s.siblings,s.bits);}));
 assert.throws(()=>defineCircuit({...spec,secret:{leaf:field(),siblings:array(field(),33),bits:array(bool(),33)}},({secret:s,zk})=>{zk.gadgets.merkleRootBls12381T3(s.leaf,s.siblings,s.bits);}));
 assert.equal(JSON.parse(ageCheck.recipe).version,1,'existing recipes keep v1');
});
