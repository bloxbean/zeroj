/** Experimental field-arithmetic builder. Java is the validating/compiler authority. */
type Gate = [string, ...(number|string)[]];
export interface Wire {readonly id:number;}
const FR=BigInt('0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001');
export class CircuitBuilder {
  private readonly owners=new WeakSet<object>();
  private readonly names=new Map<string,Wire>();
  private readonly gates:Gate[]=[['c',0,'1']];
  private count=1;
  private frozen=false;
  constructor(private readonly name:string,private readonly publicNames:readonly string[],private readonly secretNames:readonly string[]){
    this.publicNames=[...publicNames];this.secretNames=[...secretNames];
    if(!/^[A-Za-z_][A-Za-z0-9_-]{0,95}$/.test(name)||publicNames.length+secretNames.length>4096)throw Error('INVALID_CIRCUIT');
    for(const n of [...publicNames,...secretNames]){
      if(!/^[A-Za-z_][A-Za-z0-9_-]{0,95}$/.test(n)||this.names.has(n))throw Error('INVALID_INPUT_NAME');
      this.names.set(n,this.next());
    }
  }
  private next():Wire{if(this.frozen||this.count>=200000)throw Error('BUILDER_CLOSED_OR_LIMIT');const w=Object.freeze({id:this.count++});this.owners.add(w);return w;}
  private check(w:Wire):number{if(!w||!this.owners.has(w)||this.frozen)throw Error('FOREIGN_WIRE_OR_CLOSED');return w.id;}
  private emit(gate:Gate):void{if(this.gates.length>=200000){this.frozen=true;throw Error('GATE_LIMIT');}this.gates.push(gate);}
  input(name:string):Wire{const w=this.names.get(name);if(!w)throw Error('UNKNOWN_INPUT');return w;}
  constant(value:bigint):Wire{if(typeof value!=='bigint'||value<0n||value>=FR)throw Error('NONCANONICAL_SCALAR');const w=this.next();this.emit(['c',w.id,value.toString()]);return w;}
  add(a:Wire,b:Wire):Wire{const x=this.check(a),y=this.check(b),w=this.next();this.emit(['a',w.id,x,y]);return w;}
  mul(a:Wire,b:Wire):Wire{const x=this.check(a),y=this.check(b),w=this.next();this.emit(['m',w.id,x,y]);return w;}
  assertEqual(a:Wire,b:Wire):void{this.emit(['e',this.check(a),this.check(b)]);}
  serialize():string{if(this.frozen)throw Error('BUILDER_CLOSED');this.frozen=true;
    return JSON.stringify({format:'zeroj-graph',version:1,compiler:'zeroj-r1cs-bls12381-v1',field:'bls12-381-fr',name:this.name,
      public:this.publicNames,secret:this.secretNames,wires:this.count,gates:this.gates});}
}
export function multiplier():string{const c=new CircuitBuilder('multiplier',['product'],['x','y']);c.assertEqual(c.mul(c.input('x'),c.input('y')),c.input('product'));return c.serialize();}
export function cubic():string{const c=new CircuitBuilder('cubic',['y'],['x']),x=c.input('x');
  const x2=c.mul(x,x),x3=c.mul(x2,x),sum=c.add(x3,x),five=c.constant(5n);
  c.assertEqual(c.add(sum,five),c.input('y'));return c.serialize();}
