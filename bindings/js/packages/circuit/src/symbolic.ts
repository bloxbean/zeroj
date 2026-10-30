/** Experimental symbolic frontend (ADR-0064). Every operation is expanded by the existing Java symbolic API. */
const FR = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
type Kind = 'field' | 'uint' | 'bool' | 'bytes' | 'array';
export type ScalarInputSpec = Readonly<{type:'field'} | {type:'bool'} | {type:'uint';bits:number}>;
export type InputSpec = ScalarInputSpec | Readonly<{type:'bytes';length:number} | {type:'array';element:ScalarInputSpec;length:number}>;
export type Schema = Readonly<Record<string,InputSpec>>;
export const field = ():Readonly<{type:'field'}> => Object.freeze({type:'field'});
export const bool = ():Readonly<{type:'bool'}> => Object.freeze({type:'bool'});
export function uint(bits:number):Readonly<{type:'uint';bits:number}> { size(bits,1,253);return Object.freeze({type:'uint',bits}); }
export function bytes(length:number):Readonly<{type:'bytes';length:number}> { size(length,1,64);return Object.freeze({type:'bytes',length}); }
export function array<T extends ScalarInputSpec>(element:T,length:number):Readonly<{type:'array';element:T;length:number}> {
  size(length,1,64);scalarSpec(element);
  const copy=Object.freeze(element.type==='uint'?{type:'uint',bits:element.bits}:{type:element.type}) as T;
  return Object.freeze({type:'array',element:copy,length});
}
function scalarSpec(value:unknown):asserts value is ScalarInputSpec {
  object(value);
  if(value.type==='field'||value.type==='bool')exact(value,['type']);
  else if(value.type==='uint'){exact(value,['type','bits']);size(value.bits as number,1,253);}
  else fail('INVALID_ARRAY_ELEMENT');
}
interface Symbolic<K extends Kind> { readonly __zerojSymbolic:K; }
export interface ZkField extends Symbolic<'field'> {
  add(value:ZkField):ZkField; sub(value:ZkField):ZkField; mul(value:ZkField):ZkField; div(value:ZkField):ZkField;
  isEqual(value:ZkField):ZkBool; assertEqual(value:ZkField):void;
}
export interface ZkUInt extends Symbolic<'uint'> {
  add(value:ZkUInt):ZkUInt; sub(value:ZkUInt):ZkUInt; mul(value:ZkUInt):ZkUInt;
  lt(value:ZkUInt):ZkBool; lte(value:ZkUInt):ZkBool; gt(value:ZkUInt):ZkBool; gte(value:ZkUInt):ZkBool;
  isEqual(value:ZkUInt):ZkBool; inRange(lo:ZkUInt,hi:ZkUInt):ZkBool;
  assertEqual(value:ZkUInt):void; asField():ZkField;
}
export interface ZkBool extends Symbolic<'bool'> {
  and(value:ZkBool):ZkBool; or(value:ZkBool):ZkBool; xor(value:ZkBool):ZkBool; not():ZkBool;
  isEqual(value:ZkBool):ZkBool; assertEqual(value:ZkBool):void; assertTrue():void; assertFalse():void; asField():ZkField;
  select(ifTrue:ZkField,ifFalse:ZkField):ZkField;
  select(ifTrue:ZkUInt,ifFalse:ZkUInt):ZkUInt;
  select(ifTrue:ZkBool,ifFalse:ZkBool):ZkBool;
}
export interface ZkBytes extends Symbolic<'bytes'> {
  get(index:number):ZkUInt; isEqual(value:ZkBytes):ZkBool; assertEqual(value:ZkBytes):void;
}
export interface ZkArray<T extends ZkField|ZkBool|ZkUInt> extends Symbolic<'array'> {
  readonly length:number;
  get(index:number):T;
}
export interface ZkContext {
  constant(value:bigint):ZkField;
  readonly gadgets:{
    poseidonBls12381T3(left:ZkField,right:ZkField):ZkField;
    sha256(message:ZkBytes):ZkBytes;
    merkleRootBls12381T3(leaf:ZkField,siblings:ZkArray<ZkField>,pathBits:ZkArray<ZkBool>):ZkField;
  };
}
type Values = {field:ZkField;uint:ZkUInt;bool:ZkBool;bytes:ZkBytes;array:ZkArray<ZkField|ZkBool|ZkUInt>};
type SymbolFor<T extends InputSpec> = T extends {type:'array';element:infer E extends ScalarInputSpec} ? ZkArray<Values[E['type']]> : Values[T['type']];
type Symbols<S extends Schema> = {readonly [K in keyof S]: SymbolFor<S[K]>};
type InputValue<T extends InputSpec> = T extends {type:'array';element:infer E extends ScalarInputSpec} ? readonly InputValue<E>[] : T extends {type:'bool'} ? boolean : T extends {type:'bytes'} ? Uint8Array : bigint;
export type Inputs<S extends Schema> = {readonly [K in keyof S]:InputValue<S[K]>};
export interface CircuitDefinition<P extends Schema,S extends Schema> {
  readonly name:string;
  /** Public declarations/commands/constants; encodeInputs values never enter this recipe. */
  readonly recipe:string;
  encodeInputs(values:{public:Inputs<P>;secret:Inputs<S>}):Readonly<Record<string,string>>;
}
export type CircuitInputs<P extends Schema,S extends Schema> = {public:Inputs<P>;secret:Inputs<S>};
type Declaration = {name:string;visibility:'public'|'secret'} & InputSpec;
type Reference = {owner:Recorder;id:number;kind:Kind;length?:number|undefined;element?:ScalarInputSpec['type']|undefined};
const references=new WeakMap<object,Reference>();
function fail(code:string):never{throw new Error(code);}
function size(n:number,min:number,max:number):void{if(!Number.isSafeInteger(n)||n<min||n>max)fail('INVALID_SHAPE');}
function identifier(n:string):void{if(typeof n!=='string'||!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(n)||['constructor','prototype'].includes(n))fail('INVALID_NAME');}
function scalar(value:bigint):string{if(typeof value!=='bigint'||value<0n||value>=FR)fail('NONCANONICAL_SCALAR');return value.toString();}
function object(value:unknown):asserts value is Record<string,unknown>{
  if(!value||typeof value!=='object'||![null,Object.prototype].includes(Object.getPrototypeOf(value)))fail('EXPECTED_RECORD');
}
function exact(value:unknown,keys:readonly string[]):asserts value is Record<string,unknown>{
  object(value);const found=Object.keys(value);if(found.length!==keys.length||found.some(k=>!keys.includes(k)))fail('INPUT_SHAPE_MISMATCH');
}
class Recorder {
  active=true;
  extended=false;
  next=0;
  readonly commands:(string|number)[][]=[];
  check():void{if(!this.active)fail('DEFINITION_CLOSED');}
  guard<T>(action:()=>T):T{this.check();try{return action();}catch(error){this.active=false;throw error;}}
  ref(value:unknown,kind?:Kind):Reference{
    this.check();const r=value&&typeof value==='object'?references.get(value):undefined;
    if(!r||r.owner!==this||(kind!==undefined&&r.kind!==kind)){this.active=false;fail('FOREIGN_OR_WRONG_SYMBOL');}return r;
  }
  emit(op:string,args:(string|number)[]):void{this.check();if(this.commands.length>=128){this.active=false;fail('COMMAND_LIMIT');}this.commands.push([op,...args]);}
  result<K extends Kind>(op:string,args:(string|number)[],kind:K,length?:number):Values[K]{this.emit(op,args);return this.value(kind,length);}
  value<K extends Kind>(kind:K,length?:number,element?:ScalarInputSpec['type']):Values[K]{
    this.check();const id=this.next++,owner=this;
    const value:Record<string|symbol,unknown>={__zerojSymbolic:kind,
      [Symbol.toPrimitive](){return fail('SYMBOLIC_VALUE_IS_NOT_A_JS_VALUE');}};
    references.set(value,{owner,id,kind,length,element});
    const own=()=>this.ref(value,kind).id;
    const binary=<R extends Kind>(op:string,other:unknown,result:R)=>this.result(op,[own(),this.ref(other,kind).id],result);
    const assertion=(op:string,...other:unknown[])=>this.emit(op,other.length===0?[own()]:[own(),this.ref(other[0],kind).id]);
    if(kind==='field'){
      for(const op of ['add','sub','mul','div'])value[op]=(other:ZkField)=>binary('f.'+op,other,'field');
      value.isEqual=(other:ZkField)=>binary('f.isEqual',other,'bool');value.assertEqual=(other:ZkField)=>assertion('f.assertEqual',other);
    }else if(kind==='uint'){
      for(const op of ['add','sub','mul'])value[op]=(other:ZkUInt)=>binary('u.'+op,other,'uint');
      for(const op of ['lt','lte','gt','gte','isEqual'])value[op]=(other:ZkUInt)=>binary('u.'+op,other,'bool');
      value.inRange=(lo:ZkUInt,hi:ZkUInt)=>this.result('u.inRange',[own(),this.ref(lo,'uint').id,this.ref(hi,'uint').id],'bool');
      value.asField=()=>this.result('u.asField',[own()],'field');value.assertEqual=(other:ZkUInt)=>assertion('u.assertEqual',other);
    }else if(kind==='bool'){
      for(const op of ['and','or','xor','isEqual'])value[op]=(other:ZkBool)=>binary('b.'+op,other,'bool');
      value.not=()=>this.result('b.not',[own()],'bool');value.asField=()=>this.result('b.asField',[own()],'field');
      value.assertTrue=()=>assertion('b.assertTrue');value.assertFalse=()=>assertion('b.assertFalse');
      value.assertEqual=(other:ZkBool)=>assertion('b.assertEqual',other);
      value.select=(a:ZkField|ZkUInt|ZkBool,b:ZkField|ZkUInt|ZkBool)=>{
        own();const left=this.ref(a),right=this.ref(b);if(left.kind!==right.kind||(left.kind==='bytes'||left.kind==='array')){this.active=false;fail('SELECT_TYPE_MISMATCH');}
        const suffix={field:'Field',uint:'UInt',bool:'Bool'}[left.kind];
        return this.result('b.select'+suffix,[id,left.id,right.id],left.kind);
      };
    }else if(kind==='array'){
      this.extended=true;value.length=length;
      value.get=(index:number)=>{own();size(index,0,length!-1);return this.result('a.get',[id,index],element!);};
    }else{
      value.get=(index:number)=>{own();size(index,0,length!-1);return this.result('bytes.get',[id,index],'uint');};
      value.isEqual=(other:ZkBytes)=>{own();const r=this.ref(other,'bytes');if(r.length!==length)fail('BYTE_LENGTH_MISMATCH');return this.result('bytes.isEqual',[id,r.id],'bool');};
      value.assertEqual=(other:ZkBytes)=>{own();const r=this.ref(other,'bytes');if(r.length!==length)fail('BYTE_LENGTH_MISMATCH');this.emit('bytes.assertEqual',[id,r.id]);};
    }
    // A caught authoring error must not leave a partially recorded definition usable.
    for(const key of Reflect.ownKeys(value))if(typeof value[key]==='function'){
      const fn=value[key] as (...args:unknown[])=>unknown;
      value[key]=(...args:unknown[])=>this.guard(()=>fn(...args));
    }
    return Object.freeze(value) as unknown as Values[K];
  }
  context():ZkContext{return Object.freeze({
    constant:(v:bigint)=>this.guard(()=>this.result('f.constant',[scalar(v)],'field')),
    gadgets:Object.freeze({
      poseidonBls12381T3:(a:ZkField,b:ZkField)=>this.result('g.poseidonBls12381T3',[this.ref(a,'field').id,this.ref(b,'field').id],'field'),
      merkleRootBls12381T3:(leaf:ZkField,siblings:ZkArray<ZkField>,pathBits:ZkArray<ZkBool>)=>this.guard(()=>{
        const l=this.ref(leaf,'field'),s=this.ref(siblings,'array'),p=this.ref(pathBits,'array');
        if(s.element!=='field'||p.element!=='bool'||s.length!==p.length)fail('MERKLE_SHAPE_MISMATCH');
        size(s.length!,1,32);this.extended=true;
        return this.result('g.merkleRootBls12381T3',[l.id,s.id,p.id,s.length!],'field');
      }),
      sha256:(message:ZkBytes)=>this.guard(()=>{const r=this.ref(message,'bytes');if(r.length! > 55)fail('SHA256_PROTOTYPE_ONE_BLOCK_LIMIT');return this.result('g.sha256',[r.id],'bytes',32);})
    })
  });}
}
export function defineCircuit<P extends Schema,S extends Schema>(
  spec:{name:string;public:P;secret:S},
  body:(values:{public:Symbols<P>;secret:Symbols<S>;zk:ZkContext})=>void,
):CircuitDefinition<P,S>{
  exact(spec,['name','public','secret']);identifier(spec.name);object(spec.public);object(spec.secret);
  const recorder=new Recorder(),declarations:Declaration[]=[],flat=new Set<string>(),logical=new Set<string>();
  const pub:Record<string,unknown>=Object.create(null),sec:Record<string,unknown>=Object.create(null);
  let expanded=0;
  try{
    for(const visibility of ['public','secret'] as const)for(const [name,input] of Object.entries(spec[visibility])){
      identifier(name);if(logical.has(name))fail('DUPLICATE_INPUT');logical.add(name);
      if(logical.size>64)fail('INPUT_LIMIT');object(input);
      switch(input.type){
        case 'field':case 'bool':exact(input,['type']);break;
        case 'uint':exact(input,['type','bits']);size(input.bits as number,1,253);break;
        case 'array':exact(input,['type','element','length']);scalarSpec(input.element);size(input.length as number,1,64);break;
        case 'bytes':exact(input,['type','length']);size(input.length as number,1,64);break;
        default:fail('INVALID_TYPE');
      }
      const typed=(input.type==='array'?array(input.element as ScalarInputSpec,input.length as number):input) as InputSpec,width=(typed.type==='bytes'||typed.type==='array')?typed.length:1;
      expanded+=width;if(expanded>256)fail('INPUT_LIMIT');
      for(let i=0;i<width;i++){const key=(typed.type==='bytes'||typed.type==='array')?name+'_'+i:name;if(flat.has(key))fail('FLATTENED_INPUT_COLLISION');flat.add(key);}
      declarations.push(Object.freeze({name,visibility,...typed}));
      (visibility==='public'?pub:sec)[name]=recorder.value(typed.type,(typed.type==='bytes'||typed.type==='array')?typed.length:undefined,typed.type==='array'?typed.element.type:undefined);
    }
    const result:unknown=body({public:Object.freeze(pub) as Symbols<P>,secret:Object.freeze(sec) as Symbols<S>,zk:recorder.context()});
    if(result!==undefined){if(result instanceof Promise)void result.catch(()=>{});fail('DEFINITION_MUST_BE_SYNCHRONOUS_AND_VOID');}
    recorder.check();
  }finally{recorder.active=false;}
  const recipe=JSON.stringify({format:'zeroj-symbolic',version:recorder.extended?2:1,compiler:'zeroj-r1cs-bls12381-v1',field:'bls12-381-fr',name:spec.name,inputs:declarations,commands:recorder.commands});
  return Object.freeze({name:spec.name,recipe,
    encodeInputs(values:{public:Inputs<P>;secret:Inputs<S>}):Readonly<Record<string,string>>{
      exact(values,['public','secret']);
      for(const visibility of ['public','secret'] as const)exact(values[visibility],declarations.filter(d=>d.visibility===visibility).map(d=>d.name));
      const result:Record<string,string>=Object.create(null);
      for(const d of declarations){
        const v=(values[d.visibility] as Record<string,unknown>)[d.name];
        if(d.type==='array'){
          if(!Array.isArray(v)||v.length!==d.length)fail('ARRAY_LENGTH_MISMATCH');
          for(let i=0;i<d.length;i++)result[d.name+'_'+i]=encodeScalar(d.element,v[i]);
        }else if(d.type==='bytes'){
          if(!(v instanceof Uint8Array)||v.length!==d.length)fail('BYTE_LENGTH_MISMATCH');
          for(let i=0;i<v.length;i++)result[d.name+'_'+i]=String(v[i]);
        }else result[d.name]=encodeScalar(d,v);
      }
      return Object.freeze(result);
    }
  });
}

function encodeScalar(spec:ScalarInputSpec,value:unknown):string {
  if(spec.type==='bool'){if(typeof value!=='boolean')fail('EXPECTED_BOOLEAN');return value?'1':'0';}
  if(typeof value!=='bigint')fail('EXPECTED_BIGINT');const encoded=scalar(value);
  if(spec.type==='uint'&&value>=(1n<<BigInt(spec.bits)))fail('UINT_OUT_OF_RANGE');return encoded;
}
