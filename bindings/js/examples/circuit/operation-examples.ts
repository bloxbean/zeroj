/** Test-only algebra exercises; no cryptographic implementation. */
import {defineCircuit,field,uint,bool,bytes} from '@zeroj/circuit';
export const operations=defineCircuit({name:'operations',public:{sum:field()},secret:{x:field(),y:field(),u:uint(8),v:uint(8),yes:bool(),no:bool(),a:bytes(1),b:bytes(1)}},({public:p,secret:s,zk})=>{
  s.x.add(s.y).assertEqual(p.sum);
  s.x.sub(s.y).assertEqual(zk.constant(1n));
  s.x.mul(s.y).assertEqual(zk.constant(6n));
  s.x.div(s.y).mul(s.y).assertEqual(s.x);
  s.x.isEqual(s.y).assertFalse();
  s.u.add(s.v).asField().assertEqual(zk.constant(7n));
  s.u.sub(s.v).asField().assertEqual(zk.constant(3n));
  s.u.mul(s.v).asField().assertEqual(zk.constant(10n));
  s.u.lt(s.v).assertFalse();s.u.lte(s.u).assertTrue();s.u.gt(s.v).assertTrue();s.u.gte(s.u).assertTrue();
  s.u.isEqual(s.v).assertFalse();s.u.inRange(s.v,s.u).assertTrue();s.u.assertEqual(s.u);
  s.yes.and(s.no).assertFalse();s.yes.or(s.no).assertTrue();s.yes.xor(s.no).assertTrue();s.yes.not().assertFalse();
  s.yes.isEqual(s.no).assertFalse();s.no.assertEqual(s.no);s.yes.asField().assertEqual(zk.constant(1n));
  s.yes.select(s.x,s.y).assertEqual(s.x);s.no.select(s.u,s.v).assertEqual(s.v);s.yes.select(s.no,s.yes).assertFalse();
  s.a.get(0).asField().assertEqual(zk.constant(42n));s.a.isEqual(s.b).assertTrue();s.a.assertEqual(s.b);
});
export const underflow=defineCircuit({name:'underflow',public:{},secret:{u:uint(8),v:uint(8)}},({secret:s})=>{s.u.sub(s.v);});
export const widthOverflow=defineCircuit({name:'widthOverflow',public:{},secret:{u:uint(200),v:uint(100)}},({secret:s})=>{s.u.mul(s.v);});
