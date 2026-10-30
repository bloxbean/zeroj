import {defineCircuit,field,bool,uint,bytes} from '@zeroj/circuit';
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
