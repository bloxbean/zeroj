package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.BindingException;
import org.zeroj.bindings.common.Boundary;
import static org.junit.jupiter.api.Assertions.*;

class CircuitKeyProfileTest {
    private static JsonNode call(BindingSession s,String op,ObjectNode args) {
        var request=Boundary.object().put("apiVersion",1).put("capability","circuit").put("operation",op);
        request.set("arguments",args);return Boundary.parse(s.call(request.toString()));
    }
    private static JsonNode ok(BindingSession s,String op,ObjectNode args) {
        var r=call(s,op,args);assertTrue(r.path("ok").asBoolean(),r.toString());return r.path("value");
    }
    private static JsonNode compile(BindingSession session,int depth) {
        var g=MerkleFixtures.circuit(depth).constraintGraph();String graph=GraphCodec.encode(g);
        ok(session,"beginGraph",Boundary.object().put("length",graph.length()).put("expectedGraphSha256",GraphCodec.hash(graph)).put("fingerprint",new CompiledGraph(g).fingerprint()));
        for(int i=0;i<graph.length();i+=200000)ok(session,"appendGraph",Boundary.object().put("offset",i).put("text",graph.substring(i,Math.min(i+200000,graph.length()))));
        return ok(session,"compileGraph",Boundary.object());
    }
    private static ObjectNode metadata(JsonNode c,int length) {
        var vk=Boundary.object().put("protocol","groth16").put("curve","bls12381").put("nPublic",1);
        for(String k:new String[]{"vk_alpha_1","vk_beta_2","vk_gamma_2","vk_delta_2","vk_alphabeta_12","IC"})vk.putArray(k).add("0");
        var n=Boundary.object().put("circuit",c.path("handle").asText()).put("fingerprint",c.path("fingerprint").asText()).put("length",length).put("expectedSha256","0".repeat(64));n.set("verificationKey",vk);return n;
    }
    @Test void normalConstructorKeepsDefaultPolicyAndRejectsDeepCircuitBeforeReservation() {
        var s=new BindingSession(Map.of("circuit",new CircuitAdapter()),false);var c=compile(s,8);
        assertEquals("circuit-key-v1",c.path("keyProfile").asText());assertEquals(2097152,c.path("maxKeyBytes").asInt());
        assertEquals(4096,c.path("maxWires").asInt());assertEquals(16384,c.path("maxCoefficients").asInt());
        assertFalse(c.path("withinProverDimensions").asBoolean());
        assertEquals("CIRCUIT_LIMIT",call(s,"beginKey",metadata(c,1)).path("error").path("code").asText());
        var r=ok(s,"keyResources",Boundary.object().put("circuit",c.path("handle").asText()));
        assertEquals(0,r.path("peakStagingBytes").asInt());assertEquals(0,r.path("reservedBytes").asInt());
    }
    @Test void researchPolicyIsBoundedAndCannotBeReconfiguredByRpc() {
        var s=new BindingSession(Map.of("circuit",new CircuitAdapter(CircuitKeyProfile.RESEARCH_MERKLE)),false);var c=compile(s,8);
        assertEquals("circuit-key-research-merkle-v1",c.path("keyProfile").asText());assertTrue(c.path("withinProverDimensions").asBoolean());
        int cap=32*1024*1024;assertEquals(cap,c.path("maxKeyBytes").asInt());
        for(int size:new int[]{0,cap+1,Integer.MAX_VALUE})assertFalse(call(s,"beginKey",metadata(c,size)).path("ok").asBoolean());
        assertFalse(call(s,"beginKey",metadata(c,1).put("profile","unbounded")).path("ok").asBoolean());
        String id=ok(s,"beginKey",metadata(c,cap)).path("upload").asText();
        assertFalse(call(s,"beginKey",metadata(c,1)).path("ok").asBoolean());
        ok(s,"abortKey",Boundary.object().put("circuit",c.path("handle").asText()).put("upload",id));
        var r=ok(s,"keyResources",Boundary.object().put("circuit",c.path("handle").asText()));assertEquals(0,r.path("reservedBytes").asInt());assertEquals(cap,r.path("peakStagingBytes").asInt());
    }
    @Test void circuitStateRetainsItsOriginalPolicyAcrossJavaAdapterInstances() {
        var standard=new CircuitAdapter();var research=new CircuitAdapter(CircuitKeyProfile.RESEARCH_MERKLE);
        var s=new BindingSession(Map.of("circuit",standard),false);var c=compile(s,1);
        var error=assertThrows(BindingException.class,()->research.invoke("beginKey",metadata(c,2097153),s));
        assertEquals("INVALID_REQUEST",error.code());
        var r=ok(s,"keyResources",Boundary.object().put("circuit",c.path("handle").asText()));
        assertEquals(0,r.path("peakStagingBytes").asInt());
        assertEquals("circuit-key-v1",r.path("profile").asText());
    }
    @Test void dimensionBoundaryCountsBindingRowsAndPreservesGlobalPublicInputLimit() {
        var p=CircuitKeyProfile.RESEARCH_MERKLE;
        assertTrue(p.admits(65536,64,8127));assertFalse(p.admits(65537,64,8127));
        assertFalse(p.admits(65536,65,8126));assertFalse(p.admits(65536,64,8128));
        assertFalse(p.admits(65536,64,Integer.MAX_VALUE));
        assertThrows(NullPointerException.class,()->new CircuitAdapter(null));
    }
}
