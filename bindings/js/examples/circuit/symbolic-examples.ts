import {defineCircuit,field,uint,bool,bytes,array} from '@zeroj/circuit';

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

/** An input leaf is a field value; this profile does not implicitly hash/encode a document. */
export const merkleMembership=(depth:number)=>defineCircuit({name:'merkle_d'+depth,
  public:{root:field()},secret:{leaf:field(),siblings:array(field(),depth),pathBits:array(bool(),depth)}},
  ({public:p,secret:s,zk})=>{zk.gadgets.merkleRootBls12381T3(s.leaf,s.siblings,s.pathBits).assertEqual(p.root);});
export const merkleExamples=[1,2,8,16,32].map(merkleMembership);
export const allowlist=defineCircuit({name:'allowlist_d1',public:{root:field()},
  secret:{leaf:field(),siblings:array(field(),1),pathBits:array(bool(),1)}},
  ({public:p,secret:s,zk})=>{
    zk.gadgets.merkleRootBls12381T3(s.leaf,s.siblings,s.pathBits).assertEqual(p.root);
  });
export const arrayExample=defineCircuit({name:'arrays',public:{out:array(field(),2)},
  secret:{flags:array(bool(),2),values:array(uint(8),2)}},({public:p,secret:s})=>{
    for(let i=0;i<s.flags.length;i++)s.flags.get(i).assertTrue();
    for(let i=0;i<p.out.length;i++)s.values.get(i).asField().assertEqual(p.out.get(i));
  });
