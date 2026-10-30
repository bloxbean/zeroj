import {defineCircuit,field,uint,bool,bytes} from '@zeroj/circuit';

export const symbolicCubic=defineCircuit({name:'cubic',public:{y:field()},secret:{x:field()}},({public:p,secret:s,zk})=>{
  s.x.mul(s.x).mul(s.x).add(s.x).add(zk.constant(5n)).assertEqual(p.y);
});
export const ageCheck=defineCircuit({name:'age_check',public:{threshold:uint(8)},secret:{age:uint(8)}},({public:p,secret:s})=>{
  s.age.gte(p.threshold).assertTrue();
});
export const typedSelection=defineCircuit({name:'symbolic_select',public:{selected:field()},
  secret:{chooseLeft:bool(),left:field(),right:field()}},({public:p,secret:s})=>{
  s.chooseLeft.select(s.left,s.right).assertEqual(p.selected);
});
export const poseidonOpening=defineCircuit({name:'poseidon_opening',public:{commitment:field()},secret:{value:field(),salt:field()}},({public:p,secret:s,zk})=>{
  zk.gadgets.poseidonBls12381T3(s.value,s.salt).assertEqual(p.commitment);
});
export const sha256Preimage=defineCircuit({name:'sha256_abc',public:{digest:bytes(32)},secret:{message:bytes(3)}},({public:p,secret:s,zk})=>{
  zk.gadgets.sha256(s.message).assertEqual(p.digest);
});
export const symbolicExamples=[symbolicCubic,ageCheck,typedSelection,poseidonOpening,sha256Preimage] as const;
