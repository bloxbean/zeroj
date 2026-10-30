package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import static org.junit.jupiter.api.Assertions.*;

class CircuitAdapterTest {
    @TempDir Path temporary;
    private BindingSession session(boolean secrets) { return new BindingSession(Map.of("circuit",new CircuitAdapter()),secrets); }
    private JsonNode request(BindingSession s,String capability,String op,JsonNode args) {
        var request=Boundary.object().put("apiVersion",1).put("capability",capability).put("operation",op);
        request.set("arguments",args);return Boundary.parse(s.call(request.toString()));
    }
    private JsonNode call(BindingSession s,String op,JsonNode args) {return request(s,"circuit",op,args);}
    private JsonNode compile(BindingSession s) throws Exception {
        var graph=AgeCheckCircuit.build().constraintGraph();
        var args=Boundary.object().put("recipe",Files.readString(Path.of("build/recipes/age_check.json")))
                .put("expectedGraphSha256",GraphCodec.hash(GraphCodec.encode(graph)))
                .put("fingerprint",new CompiledGraph(graph).fingerprint());
        return call(s,"compileRecipe",args);
    }
    @Test void compileIdentityWitnessOptInAndReleaseAreEnforced() throws Exception {
        var s=session(true);var result=compile(s);assertTrue(result.path("ok").asBoolean(),result.toString());
        String handle=result.path("value").path("handle").asText();
        var args=Boundary.object().put("circuit",handle);args.set("input",Fixtures.inputs("age_check"));
        var checked=call(s,"checkWitness",args);assertTrue(checked.path("value").path("valid").asBoolean());
        assertEquals(3,checked.path("value").size()); // no witness or digest in the consumer API
        ((ObjectNode)args.get("input")).put("age","17");
        assertFalse(call(s,"checkWitness",args).path("ok").asBoolean());
        assertFalse(compile(s).path("ok").asBoolean());
        assertTrue(request(s,"runtime","release",Boundary.object().put("handle",handle)).path("ok").asBoolean());
        assertEquals("INVALID_HANDLE",call(s,"checkWitness",args).path("error").path("code").asText());
        var publicSession=session(false);var c=compile(publicSession);args.put("circuit",c.path("value").path("handle").asText());
        assertEquals("EXPERIMENTAL_SECRETS_DISABLED",call(publicSession,"checkWitness",args).path("error").path("code").asText());
    }
    @Test void badIdentityAndUploadFailureCannotLeaveAUsableCircuit() {
        var s=session(false);String graph=GraphCodec.encode(MultiplierCircuit.build().constraintGraph());
        var begin=Boundary.object().put("length",graph.length()).put("expectedGraphSha256","0".repeat(64)).put("fingerprint","wrong");
        assertTrue(call(s,"beginGraph",begin).path("ok").asBoolean());
        assertFalse(call(s,"appendGraph",Boundary.object().put("offset",1).put("text",graph)).path("ok").asBoolean());
        assertTrue(call(s,"appendGraph",Boundary.object().put("offset",0).put("text",graph)).path("ok").asBoolean());
        assertEquals("CIRCUIT_MISMATCH",call(s,"compileGraph",Boundary.object()).path("error").path("code").asText());
        assertFalse(call(s,"beginGraph",begin).path("ok").asBoolean());
    }
    @Test void canonicalRecipeOrderAndCompilerPolicyAreNotOptional() throws Exception {
        String recipe=Files.readString(Path.of("build/recipes/age_check.json"));
        for(String bad:new String[]{recipe.replace("zeroj-symbolic","zeroj-symbolic-research"),
                recipe.replace(GraphCodec.COMPILER,"other-policy"),
                recipe.replace("\"format\":\"zeroj-symbolic\",\"version\":1","\"version\":1,\"format\":\"zeroj-symbolic\""),
                recipe.replace("\"name\":\"threshold\",\"visibility\":\"public\"","\"visibility\":\"public\",\"name\":\"threshold\"")})
            assertThrows(RuntimeException.class,()->SymbolicRecipe.expand(bad));
    }
    @Test void typescriptRecipeExportsPublicCeremonyArtifactsWithoutJavaCircuitAuthoring() throws Exception {
        ExportCircuit.main(new String[]{"build/recipes/age_check.json",temporary.toString()});
        var manifest=Boundary.parse(Files.readString(temporary.resolve("manifest.json")));
        String graph=Files.readString(temporary.resolve("graph.json"));
        assertEquals(GraphCodec.hash(graph),manifest.path("graphSha256").asText());
        assertEquals(new CompiledGraph(AgeCheckCircuit.build().constraintGraph()).fingerprint(),manifest.path("fingerprint").asText());
        assertEquals("uint",manifest.path("inputs").get(0).path("type").asText());
        assertTrue(Files.size(temporary.resolve("circuit.r1cs"))>0);
        try(var files=Files.list(temporary)){assertEquals(4,files.count());}
    }
}
