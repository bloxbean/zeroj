package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Gate;
import static org.junit.jupiter.api.Assertions.*;

class GraphCodecTest {
    private String source() { return GraphCodec.encode(MultiplierCircuit.build().constraintGraph()); }
    private ObjectNode tree() throws Exception { return (ObjectNode)GraphCodec.JSON.readTree(source()); }
    private void reject(Consumer<ObjectNode> mutate) throws Exception {
        var node=tree(); mutate.accept(node); assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(node.toString()));
    }
    @Test void annotationGraphsRoundTripWithSameConstraintsAndWitnesses() throws Exception {
        for(String name:List.of("multiplier","cubic","age_check","sha256_abc")) {
            var original=Fixtures.circuit(name).constraintGraph();
            String encoded=GraphCodec.encode(original);
            var decoded=GraphCodec.decode(encoded);
            assertEquals(encoded,GraphCodec.encode(decoded));
            var a=new CompiledGraph(original); var b=new CompiledGraph(decoded);
            assertEquals(a.fingerprint(),b.fingerprint());
            var wa=a.witness(Fixtures.inputs(name)); var wb=b.witness(Fixtures.inputs(name));
            assertArrayEquals(wa,wb); b.check(wb);
        }
    }
    @Test void rejectsShapeEncodingFieldAndResourceViolations() throws Exception {
        reject(n->n.put("version",2)); reject(n->n.put("version",1.0));
        reject(n->n.put("field","bn254")); reject(n->n.put("extra",true));
        reject(n->n.put("wires",Integer.MAX_VALUE)); reject(n->n.put("wires",0));
        reject(n->n.put("name","a\nb")); reject(n->((ArrayNode)n.get("secret")).set(0,GraphCodec.JSON.getNodeFactory().textNode("product")));
        reject(n->((ArrayNode)n.get("gates")).addArray().add("unsupported"));
        assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(source()+" {}"));
        assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(" "+source()));
        assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(source().replace("\"version\":1","\"version\":1,\"version\":1")));
        assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(" ".repeat(GraphCodec.MAX_CHARS+1)));
    }
    @Test void rejectsWritesToInputsMissingOrForwardWiresAndNoncanonicalScalars() throws Exception {
        reject(n->((ArrayNode)n.path("gates").get(1)).set(1,GraphCodec.JSON.getNodeFactory().numberNode(1)));
        reject(n->((ArrayNode)n.path("gates").get(1)).set(2,GraphCodec.JSON.getNodeFactory().numberNode(n.get("wires").intValue()-1)));
        reject(n->((ArrayNode)n.get("gates")).remove(1));
        reject(n->((ArrayNode)n.get("gates")).add(n.path("gates").get(1).deepCopy()));
        reject(n->((ArrayNode)n.path("gates").get(0)).set(2,GraphCodec.JSON.getNodeFactory().textNode("0")));
        for(String s:List.of("01","-1","+1",GraphCodec.FR.toString(),"1.0","1e2"))
            assertThrows(IllegalArgumentException.class,()->GraphCodec.scalar(s));
    }
    @Test void rangeConstraintsRejectInvalidAndOutOfRangeWitnesses() throws Exception {
        var c=new CompiledGraph(GraphCodec.decode(GraphCodec.encode(AgeCheckCircuit.build().constraintGraph())));
        for(String bad:List.of("17","256","511")) {
            var n=Fixtures.inputs("age_check"); n.put("age",bad);
            assertThrows(RuntimeException.class,()->{var w=c.witness(n);c.check(w);});
        }
        var w=c.witness(Fixtures.inputs("age_check")); w[1]=BigInteger.valueOf(22);
        assertThrows(IllegalArgumentException.class,()->c.check(w));
    }
    @Test void rejectsMalformedDecompositionAndLinearTerms() throws Exception {
        String encoded=GraphCodec.encode(AgeCheckCircuit.build().constraintGraph());
        for(int mode=0;mode<4;mode++) {
            var root=(ObjectNode)GraphCodec.JSON.readTree(encoded);
            for(var g:root.path("gates")) if(g.get(0).asText().equals("d")) {
                var gate=(ArrayNode)g;
                if(mode==0)((ArrayNode)gate.get(1)).set(1,gate.get(1).get(0));
                if(mode==1)gate.set(3,GraphCodec.JSON.getNodeFactory().numberNode(254));
                if(mode==2)gate.set(3,GraphCodec.JSON.getNodeFactory().numberNode(0));
                if(mode==3)((ArrayNode)gate.get(1)).remove(0);
                break;
            }
            assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(root.toString()));
        }
        var root=(ObjectNode)GraphCodec.JSON.readTree(encoded);
        for(var g:root.path("gates")) if(g.get(0).asText().equals("l")) {
            ((ArrayNode)g.get(2).get(0)).set(1,GraphCodec.JSON.getNodeFactory().textNode("-1")); break;
        }
        assertThrows(IllegalArgumentException.class,()->GraphCodec.decode(root.toString()));
    }
    @Test void sha256MatchesJdkAndRejectsWrongMessageOrDigest() throws Exception {
        var c=new CompiledGraph(GraphCodec.decode(GraphCodec.encode(Sha256PreimageCircuit.build().constraintGraph())));
        var n=Fixtures.inputs("sha256_abc"); c.check(c.witness(n));
        n.put("message_0","98"); assertThrows(RuntimeException.class,()->c.check(c.witness(n)));
        var bad=Fixtures.inputs("sha256_abc"); bad.put("digest_0","0");
        assertThrows(RuntimeException.class,()->c.check(c.witness(bad)));
    }
    @Test void hintsDoNotReplaceConstraints() {
        var original=CircuitBuilder.create("inverse").publicVar("y").secretVar("x").define(api->{
            var inverse=api.div(api.constant(1),api.var("x")); api.assertEqual(inverse,api.var("y"));
        }).constraintGraph();
        var graph=GraphCodec.decode(GraphCodec.encode(original)); var c=new CompiledGraph(graph);
        var n=GraphCodec.JSON.createObjectNode().put("x","2").put("y",BigInteger.TWO.modInverse(GraphCodec.FR).toString());
        var w=c.witness(n); c.check(w);
        for(var gate:graph.gates()) if(gate instanceof Gate.Hint h) {
            var changed=w.clone(); changed[h.output().id()]=changed[h.output().id()].add(BigInteger.ONE).mod(GraphCodec.FR);
            assertThrows(IllegalArgumentException.class,()->c.check(changed));
        }
    }
    @Test void randomArithmeticGraphsMatchIndependentIntegerEvaluation() {
        var random=new Random(0x5a65726fL); // deterministic, public test generation only
        for(int sample=0;sample<100;sample++) {
            var n=GraphCodec.JSON.createObjectNode().put("format","zeroj-graph").put("version",1).put("compiler",GraphCodec.COMPILER)
                    .put("field","bls12-381-fr").put("name","random");
            n.putArray("public").add("result"); n.putArray("secret").add("x"); n.put("wires",23);
            var gates=n.putArray("gates"); gates.addArray().add("c").add(0).add("1");
            var values=new BigInteger[23]; values[0]=BigInteger.ONE; values[2]=BigInteger.valueOf(random.nextInt(1000));
            for(int out=3;out<23;out++) {
                int left=out==3?2:2+random.nextInt(out-2),right=2+random.nextInt(out-2);
                boolean mul=random.nextBoolean(); gates.addArray().add(mul?"m":"a").add(out).add(left).add(right);
                values[out]=(mul?values[left].multiply(values[right]):values[left].add(values[right])).mod(GraphCodec.FR);
            }
            gates.addArray().add("e").add(22).add(1); values[1]=values[22];
            var c=new CompiledGraph(GraphCodec.decode(n.toString()));
            var input=GraphCodec.JSON.createObjectNode().put("result",values[1].toString()).put("x",values[2].toString());
            var actual=c.witness(input); assertArrayEquals(values,actual); c.check(actual);
        }
    }
}
