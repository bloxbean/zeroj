package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SymbolicRecipeTest {
    private String recipe(String name) throws Exception {return Files.readString(Path.of("build/recipes/"+name+".json"));}
    private CompiledGraph compile(String text) {return new CompiledGraph(GraphCodec.decode(GraphCodec.encode(SymbolicRecipe.expand(text))));}
    @Test void typescriptRecipesExactlyMatchJavaAnnotations() throws Exception {
        for(String name:List.of("cubic","age_check","symbolic_select","poseidon_opening","sha256_abc")) {
            var graph=SymbolicRecipe.expand(recipe(name));
            assertEquals(GraphCodec.encode(Fixtures.circuit(name).constraintGraph()),GraphCodec.encode(graph),name);
            var actual=compile(recipe(name));var expected=new CompiledGraph(Fixtures.circuit(name).constraintGraph());
            assertEquals(expected.fingerprint(),actual.fingerprint(),name);
            var witness=actual.witness(Fixtures.inputs(name));actual.check(witness);
            assertArrayEquals(expected.witness(Fixtures.inputs(name)),witness,name);
        }
    }
    @Test void typedWitnessesRejectWrongCommitmentNonBooleanAndOutOfRange() throws Exception {
        for(String[] test:new String[][]{{"poseidon_opening","value","43"},{"symbolic_select","chooseLeft","2"},
                {"symbolic_select","selected","7"},{"age_check","age","17"},{"age_check","age","256"},
                {"sha256_abc","message_0","98"},{"sha256_abc","digest_0","256"}}) {
            var c=compile(recipe(test[0]));var n=Fixtures.inputs(test[0]);n.put(test[1],test[2]);
            assertThrows(RuntimeException.class,()->c.check(c.witness(n)),String.join("/",test));
        }
    }
    @Test void rejectsInvalidRecipeReferencesTypesAndLimits() throws Exception {
        String valid=recipe("symbolic_select");
        for(String text:List.of(" "+valid,valid+" {}",valid.replace("\"version\":1","\"version\":1,\"version\":1"),
                valid.replace("bls12-381-fr","bn254"),valid.replace("b.selectField","g.unknown"),
                valid.replace("[\"b.selectField\",1,2,3]","[\"b.selectField\",0,2,3]"),
                valid.replace("[\"b.selectField\",1,2,3]","[\"b.selectField\",1,2,99]"),
                valid.replace("[\"b.selectField\",1,2,3]","[\"b.selectField\",1,2]")))
            assertThrows(RuntimeException.class,()->SymbolicRecipe.expand(text),text);
        var n=(ObjectNode)GraphCodec.JSON.readTree(recipe("poseidon_opening"));
        var commands=n.putArray("commands");for(int i=0;i<5;i++)commands.addArray().add("g.poseidonBls12381T3").add(1).add(2);
        assertThrows(RuntimeException.class,()->SymbolicRecipe.expand(n.toString()));
        commands.removeAll();for(int i=0;i<129;i++)commands.addArray().add("f.constant").add("1");
        assertThrows(RuntimeException.class,()->SymbolicRecipe.expand(n.toString()));
        var sha=(ObjectNode)GraphCodec.JSON.readTree(recipe("sha256_abc"));
        ((ObjectNode)sha.get("inputs").get(1)).put("length",56);
        assertThrows(RuntimeException.class,()->SymbolicRecipe.expand(sha.toString()));
    }
    @Test void allExposedOperationsHaveConstrainedSemantics() throws Exception {
        var c=compile(recipe("operations"));
        var input=GraphCodec.JSON.createObjectNode().put("sum","5").put("x","3").put("y","2").put("u","5").put("v","2")
                .put("yes","1").put("no","0").put("a_0","42").put("b_0","42");
        c.check(c.witness(input));
        Files.createDirectories(Path.of("build/symbolic-test-vectors"));
        Files.writeString(Path.of("build/symbolic-test-vectors/operations-input.json"),input.toString());
        Files.writeString(Path.of("build/symbolic-test-vectors/operations-witness.sha256"),TestWitness.digest(c.witness(input)));
        Files.writeString(Path.of("build/symbolic-test-vectors/operations-identity.json"),GraphCodec.JSON.createObjectNode()
                .put("expectedGraphSha256",GraphCodec.hash(GraphCodec.encode(c.graph))).put("fingerprint",c.fingerprint()).toString());
        for(String key:List.of("sum","x","y","u","v","yes","no","a_0","b_0")) {
            var changed=input.deepCopy();changed.put(key,"43");
            assertThrows(RuntimeException.class,()->c.check(c.witness(changed)),key);
        }
        input.put("y","0");assertThrows(RuntimeException.class,()->c.check(c.witness(input)));
        var subtract=compile(recipe("underflow"));
        Files.writeString(Path.of("build/symbolic-test-vectors/underflow-identity.json"),GraphCodec.JSON.createObjectNode()
                .put("expectedGraphSha256",GraphCodec.hash(GraphCodec.encode(subtract.graph))).put("fingerprint",subtract.fingerprint()).toString());
        var bad=GraphCodec.JSON.createObjectNode().put("u","1").put("v","2");
        assertThrows(RuntimeException.class,()->subtract.check(subtract.witness(bad)));
        bad.put("u","255");subtract.check(subtract.witness(bad));
        assertThrows(RuntimeException.class,()->SymbolicRecipe.expand(recipe("widthOverflow")));
    }
}
