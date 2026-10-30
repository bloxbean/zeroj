package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class MerkleRecipeTest {
    private String recipe(String name) throws Exception{return Files.readString(Path.of("build/recipes/"+name+".json"));}
    private CompiledGraph compile(String recipe){return new CompiledGraph(GraphCodec.decode(GraphCodec.encode(SymbolicRecipe.expand(recipe))));}
    @Test void depthsMatchJavaGraphWitnessAndHostRootsForAllPathPatterns() throws Exception {
        for(int depth:new int[]{1,2,8,16,32}) {
            var c=compile(recipe("merkle_d"+depth));var java=new CompiledGraph(MerkleFixtures.circuit(depth).constraintGraph());
            assertEquals(GraphCodec.hash(GraphCodec.encode(java.graph)),GraphCodec.hash(GraphCodec.encode(c.graph)));assertEquals(java.fingerprint(),c.fingerprint());
            for(int pattern:new int[]{0,1,2}) {
                var input=MerkleFixtures.input(depth,pattern);var w=c.witness(input);c.check(w);
                assertArrayEquals(java.witness(input),w);
                var broken=w.clone();broken[1]=broken[1].add(BigInteger.ONE);
                assertThrows(RuntimeException.class,()->c.check(broken));
            }
        }
    }
    @Test void annotationAllowlistMatchesRecipeAndBindsRoot() throws Exception {
        var c=compile(recipe("allowlist_d1"));var java=new CompiledGraph(AllowlistCircuit.build().constraintGraph());
        assertEquals(GraphCodec.hash(GraphCodec.encode(java.graph)),GraphCodec.hash(GraphCodec.encode(c.graph)));
        var input=Fixtures.inputs("allowlist_d1");c.check(c.witness(input));assertArrayEquals(java.witness(input),c.witness(input));
        for(String k:List.of("root","leaf","siblings_0","pathBits_0")){
            var changed=input.deepCopy();changed.put(k,k.equals("pathBits_0")?"0":"123");
            assertThrows(RuntimeException.class,()->c.check(c.witness(changed)),k);
        }
        input.put("pathBits_0","2");assertThrows(RuntimeException.class,()->c.check(c.witness(input)));
    }
    @Test void arrayElementsAreConstrainedAndIndexedInDeclaredOrder() throws Exception {
        var c=compile(recipe("arrays"));var input=GraphCodec.JSON.createObjectNode().put("out_0","5").put("out_1","7")
                .put("flags_0","1").put("flags_1","1").put("values_0","5").put("values_1","7");
        c.check(c.witness(input));
        Files.createDirectories(Path.of("build/symbolic-test-vectors"));
        Files.writeString(Path.of("build/symbolic-test-vectors/arrays-identity.json"),GraphCodec.JSON.createObjectNode()
                .put("expectedGraphSha256",GraphCodec.hash(GraphCodec.encode(c.graph))).put("fingerprint",c.fingerprint()).toString());
        assertEquals(List.of("out_0","out_1"),c.graph.publicInputs().stream().map(v->v.name()).toList());
        for(String[] change:new String[][]{{"flags_0","2"},{"flags_1","0"},{"values_0","256"},{"out_1","5"}}){
            var bad=input.deepCopy();bad.put(change[0],change[1]);assertThrows(RuntimeException.class,()->c.check(c.witness(bad)));
        }
    }
    @Test void v1DoesNotAcceptExtensionsAndShapesCannotLieAboutWork() throws Exception {
        String text=recipe("merkle_d1");
        assertThrows(RuntimeException.class,()->compile(text.replace("\"version\":2","\"version\":1")));
        for(int depth:new int[]{0,2,33,Integer.MAX_VALUE}){
            var n=(ObjectNode)GraphCodec.JSON.readTree(text);((ArrayNode)n.get("commands").get(0)).set(4,GraphCodec.JSON.getNodeFactory().numberNode(depth));
            assertThrows(RuntimeException.class,()->compile(n.toString()));
        }
        for(String replacement:List.of("\"element\":{\"type\":\"bool\"}","\"element\":{\"type\":\"bytes\",\"length\":1}"))
            assertThrows(RuntimeException.class,()->compile(text.replace("\"element\":{\"type\":\"field\"}",replacement)));
        assertThrows(RuntimeException.class,()->compile(text.replace("\"length\":1","\"length\":0")));
        assertThrows(RuntimeException.class,()->compile(text.replace("\"length\":1","\"length\":65")));
        assertThrows(RuntimeException.class,()->compile(text.replace("\"element\":{\"type\":\"field\"},\"length\":1","\"length\":1,\"element\":{\"type\":\"field\"}")));
        var n=(ObjectNode)GraphCodec.JSON.readTree(text);var commands=(ArrayNode)n.get("commands");commands.insert(1,commands.get(0).deepCopy());
        assertThrows(RuntimeException.class,()->compile(n.toString()));
    }
    @Test void arrayIndexAndFlattenedCollisionsReject() throws Exception {
        String text=recipe("arrays");
        assertThrows(RuntimeException.class,()->compile(text.replace("[\"a.get\",1,0]","[\"a.get\",1,2]")));
        var n=(ObjectNode)GraphCodec.JSON.readTree(text);
        ((ObjectNode)n.get("inputs").get(1)).put("name","out_0").put("type","bool").remove(List.of("element","length"));
        assertThrows(RuntimeException.class,()->compile(n.toString()));
    }
}
