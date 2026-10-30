import {defineCircuit,field,bool,uint,bytes,array} from '@zeroj/circuit';
const circuit=defineCircuit({name:'typing',public:{out:field()},secret:{x:field(),flag:bool(),count:uint(8),data:bytes(3)}},({public:p,secret:s,zk})=>{
  s.flag.select(s.x,p.out).assertEqual(p.out);
  zk.gadgets.sha256(s.data).get(0).asField();
  // @ts-expect-error a boolean is not a field
  s.x.mul(s.flag);
  // @ts-expect-error selection branches must have the same symbolic type
  s.flag.select(s.x,s.count);
  // @ts-expect-error SHA input must be bytes
  zk.gadgets.sha256(s.x);
  // @ts-expect-error a host bigint is not a symbolic value
  s.x.add(1n);
});
circuit.encodeInputs({public:{out:1n},secret:{x:1n,flag:true,count:2n,data:new Uint8Array(3)}});
// @ts-expect-error use bigint, not a lossy number
circuit.encodeInputs({public:{out:1},secret:{x:1n,flag:true,count:2n,data:new Uint8Array(3)}});
// @ts-expect-error missing private data
circuit.encodeInputs({public:{out:1n},secret:{x:1n,flag:true,count:2n}});

import type {CompiledCircuit,CircuitKeyArtifact} from '@zeroj/circuit';
declare const compiled:CompiledCircuit<{public:{y:bigint};secret:{x:bigint}}>;
declare const artifact:CircuitKeyArtifact;
compiled.loadKey(artifact,{signal:new AbortController().signal});
compiled.keyResources().then(r=>r.reservedBytes+r.lastImportMs);
// @ts-expect-error cancellation requires an AbortSignal
compiled.loadKey(artifact,{signal:true});
// @ts-expect-error an arbitrary key cannot bypass local ownership
compiled.prove('key',{public:{y:35n},secret:{x:3n}});

const membership=defineCircuit({name:'membership',public:{root:field()},secret:{leaf:field(),siblings:array(field(),1),path:array(bool(),1)}},({public:p,secret:s,zk})=>{
 zk.gadgets.merkleRootBls12381T3(s.leaf,s.siblings,s.path).assertEqual(p.root);
 // @ts-expect-error path directions must be symbolic booleans
 zk.gadgets.merkleRootBls12381T3(s.leaf,s.siblings,s.siblings);
 // @ts-expect-error indexing is a host integer, not a field witness
 s.siblings.get(s.leaf);
});
membership.encodeInputs({public:{root:1n},secret:{leaf:2n,siblings:[3n],path:[true]}});
// @ts-expect-error field arrays take bigint values
membership.encodeInputs({public:{root:1n},secret:{leaf:2n,siblings:[3],path:[true]}});
// @ts-expect-error nested arrays are not admitted in recipe v2
array(array(field(),2),2);
