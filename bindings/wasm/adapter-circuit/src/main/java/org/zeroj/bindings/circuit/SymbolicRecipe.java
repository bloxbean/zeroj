package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.ConstraintGraph;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkValue;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkBytes;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkMerkle;
import org.zeroj.circuit.lib.zk.ZkPoseidon;
import org.zeroj.circuit.lib.zk.ZkSha256;

/** Typed authoring commands delegate to Java symbolic APIs. This class contains no gadget equations. */
public final class SymbolicRecipe {
    private record Input(String name, boolean visible, String type, int size, String element, int bits) {}
    private SymbolicRecipe() {}
    public static ConstraintGraph expand(String text) {
        JsonNode recipe=Boundary.parse(text);
        Boundary.fields(recipe,"format","version","compiler","field","name","inputs","commands");
        int version=Boundary.integer(recipe,"version",1,2);
        if (!Boundary.text(recipe,"format").equals("zeroj-symbolic")
                || !Boundary.text(recipe,"compiler").equals(GraphCodec.COMPILER)
                || !Boundary.text(recipe,"field").equals("bls12-381-fr")
                || !recipe.toString().equals(text)) throw Boundary.invalid();
        String name=identifier(recipe.get("name"));
        JsonNode inputs=recipe.get("inputs"),commands=recipe.get("commands");
        if(!inputs.isArray() || inputs.size()>64 || !commands.isArray() || commands.size()>128) throw Boundary.invalid();
        var canonical=Boundary.object().put("format","zeroj-symbolic").put("version",version)
                .put("compiler",GraphCodec.COMPILER).put("field","bls12-381-fr").put("name",name);
        var canonicalInputs=canonical.putArray("inputs");
        var declarations=new ArrayList<Input>();var names=new HashSet<String>();var logicalNames=new HashSet<String>();
        int expanded=0,budget=0;boolean secretSeen=false;
        for(JsonNode n:inputs) {
            String type=Boundary.text(n,"type");
            int size,bits=0;String element=null;
            switch(type) {
                case "field","bool" -> {Boundary.fields(n,"name","visibility","type");size=1;}
                case "uint" -> {Boundary.fields(n,"name","visibility","type","bits");size=Boundary.integer(n,"bits",1,253);}
                case "array" -> {
                    if(version!=2)throw Boundary.invalid();
                    Boundary.fields(n,"name","visibility","type","element","length");
                    size=Boundary.integer(n,"length",1,64);
                    JsonNode e=n.get("element");element=Boundary.text(e,"type");
                    if(element.equals("uint")){Boundary.fields(e,"type","bits");bits=Boundary.integer(e,"bits",1,253);}
                    else if(element.equals("field")||element.equals("bool"))Boundary.fields(e,"type");
                    else throw Boundary.invalid();
                }
                case "bytes" -> {Boundary.fields(n,"name","visibility","type","length");size=Boundary.integer(n,"length",1,64);}
                default -> throw Boundary.invalid();
            }
            String id=identifier(n.get("name")),visibility=Boundary.text(n,"visibility");
            if(!visibility.equals("public")&&!visibility.equals("secret"))throw Boundary.invalid();
            boolean visible=visibility.equals("public");
            if(visible&&secretSeen)throw Boundary.invalid();if(!visible)secretSeen=true;
            if(!logicalNames.add(id))throw Boundary.invalid();
            int width=(type.equals("bytes")||type.equals("array"))?size:1;
            expanded+=width;if(expanded>256)throw Boundary.invalid();
            for(int i=0;i<width;i++)if(!names.add((type.equals("bytes")||type.equals("array"))?id+"_"+i:id))throw Boundary.invalid();
            budget+=switch(type){case "uint"->4*size+16;case "bytes"->40*size;case "array"->size*(element.equals("uint")?4*bits+16:16);default->16;};
            if(budget>180000)throw Boundary.invalid();
            declarations.add(new Input(id,visible,type,size,element,bits));
            var encoded=canonicalInputs.addObject().put("name",id).put("visibility",visibility).put("type",type);
            if(type.equals("uint"))encoded.put("bits",size);
            if(type.equals("bytes"))encoded.put("length",size);
            if(type.equals("array")){
                var e=encoded.putObject("element").put("type",element);
                if(element.equals("uint"))e.put("bits",bits);
                encoded.put("length",size);
            }
        }
        int sha=0,poseidon=0,merkle=0;
        for(JsonNode command:commands) {
            if(!command.isArray() || command.isEmpty() || !command.get(0).isTextual())throw Boundary.invalid();
            String op=command.get(0).textValue();int cost;
            if(op.equals("g.merkleRootBls12381T3")){
                if(version!=2||++merkle>1)throw Boundary.invalid();arity(command,5);
                int depth=integer(command.get(4),32);if(depth<1)throw Boundary.invalid();cost=5000*depth;
            }
            else if(op.equals("a.get")){if(version!=2)throw Boundary.invalid();cost=512;}
            else if(op.equals("g.sha256")){if(++sha>1)throw Boundary.invalid();cost=150000;}
            else if(op.equals("g.poseidonBls12381T3")){if(++poseidon>4)throw Boundary.invalid();cost=5000;}
            else if(op.startsWith("u.")||op.startsWith("bytes."))cost=4096;
            else if(op.startsWith("f."))cost=512;
            else if(op.startsWith("b."))cost=256;
            else throw Boundary.invalid();
            budget+=cost;if(budget>180000)throw Boundary.invalid();
        }
        canonical.set("commands",commands);
        if(!canonical.toString().equals(text))throw Boundary.invalid();
        var builder=CircuitBuilder.create(name);
        for(Input in:declarations)for(int i=0;i<((in.type.equals("bytes")||in.type.equals("array"))?in.size:1);i++) {
            String id=(in.type.equals("bytes")||in.type.equals("array"))?in.name+"_"+i:in.name;
            if(in.visible)builder.publicVar(id);else builder.secretVar(id);
        }
        return builder.defineSignals(signals->{
            var zk=new ZkContext(signals);var values=new ArrayList<Object>();
            for(Input in:declarations)values.add(bind(signals,in));
            for(JsonNode command:commands) {
                Object result=execute(command,values,zk);
                if(result!=null)values.add(result);
            }
        }).constraintGraph();
    }
    private static String identifier(JsonNode n) {
        if(n==null||!n.isTextual()||!n.textValue().matches("[A-Za-z][A-Za-z0-9_]{0,63}")
                || List.of("constructor","prototype").contains(n.textValue()))throw Boundary.invalid();
        return n.textValue();
    }
    private static Object bind(SignalBuilder b,Input i) {
        return switch(i.type) {
            case "field" -> i.visible?ZkField.publicInput(b,i.name):ZkField.secret(b,i.name);
            case "uint" -> i.visible?ZkUInt.publicInput(b,i.name,i.size):ZkUInt.secret(b,i.name,i.size);
            case "bool" -> i.visible?ZkBool.publicInput(b,i.name):ZkBool.secret(b,i.name);
            case "array" -> switch(i.element) {
                case "field" -> i.visible?ZkArray.publicFields(b,i.name,i.size):ZkArray.secretFields(b,i.name,i.size);
                case "bool" -> i.visible?ZkArray.publicBools(b,i.name,i.size):ZkArray.secretBools(b,i.name,i.size);
                case "uint" -> i.visible?ZkArray.publicUInts(b,i.name,i.size,i.bits):ZkArray.secretUInts(b,i.name,i.size,i.bits);
                default -> throw Boundary.invalid();
            };
            case "bytes" -> i.visible?ZkBytes.publicInput(b,i.name,i.size):ZkBytes.secret(b,i.name,i.size);
            default -> throw Boundary.invalid();
        };
    }
    private static void arity(JsonNode c,int n){if(c.size()!=n)throw Boundary.invalid();}
    private static int integer(JsonNode n,int max) {
        if(n==null||!n.isIntegralNumber()||!n.canConvertToInt()||n.intValue()<0||n.intValue()>max)throw Boundary.invalid();
        return n.intValue();
    }
    private static <T> T value(JsonNode c,int index,List<Object> values,Class<T> type) {
        int id=integer(c.get(index),values.size()-1);Object v=values.get(id);
        if(!type.isInstance(v))throw Boundary.invalid();return type.cast(v);
    }
    private static ZkField f(JsonNode c,int i,List<Object> v){return value(c,i,v,ZkField.class);}
    private static ZkUInt u(JsonNode c,int i,List<Object> v){return value(c,i,v,ZkUInt.class);}
    private static ZkBool b(JsonNode c,int i,List<Object> v){return value(c,i,v,ZkBool.class);}
    private static ZkBytes bytes(JsonNode c,int i,List<Object> v){return value(c,i,v,ZkBytes.class);}
    private static <T extends ZkValue> ZkArray<T> array(JsonNode c,int index,List<Object> values,Class<T> element) {
        var array=value(c,index,values,ZkArray.class);
        var checked=new ArrayList<T>(array.size());
        for(Object item:array.values()){
            if(!element.isInstance(item))throw Boundary.invalid();checked.add(element.cast(item));
        }
        return new ZkArray<>(checked);
    }
    private static Object execute(JsonNode c,List<Object> v,ZkContext zk) {
        String op=c.get(0).textValue();
        return switch(op) {
            case "f.constant" -> {arity(c,2);if(!c.get(1).isTextual())throw Boundary.invalid();yield zk.constant(GraphCodec.scalar(c.get(1).textValue()));}
            case "f.add" -> {arity(c,3);yield f(c,1,v).add(f(c,2,v));}
            case "f.sub" -> {arity(c,3);yield f(c,1,v).sub(f(c,2,v));}
            case "f.mul" -> {arity(c,3);yield f(c,1,v).mul(f(c,2,v));}
            case "f.div" -> {arity(c,3);yield f(c,1,v).div(f(c,2,v));}
            case "f.isEqual" -> {arity(c,3);yield f(c,1,v).isEqual(f(c,2,v));}
            case "f.assertEqual" -> {arity(c,3);f(c,1,v).assertEqual(f(c,2,v));yield null;}
            case "u.add" -> {arity(c,3);yield u(c,1,v).add(u(c,2,v));}
            case "u.sub" -> {arity(c,3);yield u(c,1,v).sub(u(c,2,v));}
            case "u.mul" -> {arity(c,3);yield u(c,1,v).mul(u(c,2,v));}
            case "u.lt" -> {arity(c,3);yield u(c,1,v).lt(u(c,2,v));}
            case "u.lte" -> {arity(c,3);yield u(c,1,v).lte(u(c,2,v));}
            case "u.gt" -> {arity(c,3);yield u(c,1,v).gt(u(c,2,v));}
            case "u.gte" -> {arity(c,3);yield u(c,1,v).gte(u(c,2,v));}
            case "u.isEqual" -> {arity(c,3);yield u(c,1,v).isEqual(u(c,2,v));}
            case "u.inRange" -> {arity(c,4);yield u(c,1,v).inRange(u(c,2,v),u(c,3,v));}
            case "u.asField" -> {arity(c,2);yield u(c,1,v).asField();}
            case "u.assertEqual" -> {arity(c,3);u(c,1,v).assertEqual(u(c,2,v));yield null;}
            case "b.and" -> {arity(c,3);yield b(c,1,v).and(b(c,2,v));}
            case "b.or" -> {arity(c,3);yield b(c,1,v).or(b(c,2,v));}
            case "b.xor" -> {arity(c,3);yield b(c,1,v).xor(b(c,2,v));}
            case "b.not" -> {arity(c,2);yield b(c,1,v).not();}
            case "b.isEqual" -> {arity(c,3);yield b(c,1,v).isEqual(b(c,2,v));}
            case "b.asField" -> {arity(c,2);yield b(c,1,v).asField();}
            case "b.assertTrue" -> {arity(c,2);b(c,1,v).assertTrue();yield null;}
            case "b.assertFalse" -> {arity(c,2);b(c,1,v).assertFalse();yield null;}
            case "b.assertEqual" -> {arity(c,3);b(c,1,v).assertEqual(b(c,2,v));yield null;}
            case "b.selectField" -> {arity(c,4);yield b(c,1,v).select(f(c,2,v),f(c,3,v));}
            case "b.selectUInt" -> {arity(c,4);yield b(c,1,v).select(u(c,2,v),u(c,3,v));}
            case "b.selectBool" -> {arity(c,4);yield b(c,1,v).select(b(c,2,v),b(c,3,v));}
            case "bytes.get" -> {arity(c,3);var x=bytes(c,1,v);yield x.get(integer(c.get(2),x.size()-1));}
            case "bytes.isEqual" -> {arity(c,3);yield bytes(c,1,v).isEqual(bytes(c,2,v));}
            case "bytes.assertEqual" -> {arity(c,3);bytes(c,1,v).assertEqual(bytes(c,2,v));yield null;}
            case "g.poseidonBls12381T3" -> {arity(c,3);yield ZkPoseidon.hash(zk,PoseidonParamsBLS12_381T3.INSTANCE,f(c,1,v),f(c,2,v));}
            case "a.get" -> {arity(c,3);var array=value(c,1,v,ZkArray.class);yield array.get(integer(c.get(2),array.size()-1));}
            case "g.merkleRootBls12381T3" -> {
                arity(c,5);int depth=integer(c.get(4),32);
                var siblings=array(c,2,v,ZkField.class);var directions=array(c,3,v,ZkBool.class);
                if(depth<1||siblings.size()!=depth||directions.size()!=depth)throw Boundary.invalid();
                yield ZkMerkle.computeRootPoseidon(zk,PoseidonParamsBLS12_381T3.INSTANCE,f(c,1,v),siblings,directions);
            }
            case "g.sha256" -> {arity(c,2);var message=bytes(c,1,v);if(message.size()>55)throw Boundary.invalid();yield ZkSha256.hash(zk,message);}
            default -> throw Boundary.invalid();
        };
    }
}
