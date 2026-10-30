package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import static org.junit.jupiter.api.Assertions.*;

/** Public, synthetic key bytes exercise transport allocation/state; real keys run in Wasm interop. */
class KeyUploadTest {
    private final BindingSession session = new BindingSession(Map.of("circuit", new CircuitAdapter()), false);
    private final String circuit;
    private final String fingerprint;
    KeyUploadTest() {
        var graph = MultiplierCircuit.build().constraintGraph();
        fingerprint = new CompiledGraph(graph).fingerprint();
        String text = GraphCodec.encode(graph);
        ok("beginGraph", Boundary.object().put("length",text.length()).put("expectedGraphSha256",GraphCodec.hash(text)).put("fingerprint",fingerprint));
        ok("appendGraph", Boundary.object().put("offset",0).put("text",text));
        circuit = ok("compileGraph",Boundary.object()).path("handle").asText();
    }
    private JsonNode call(String op, ObjectNode args) {
        var request=Boundary.object().put("apiVersion",1).put("capability","circuit").put("operation",op);
        request.set("arguments",args);
        return Boundary.parse(session.call(request.toString()));
    }
    private JsonNode ok(String op, ObjectNode args) {
        var result=call(op,args); assertTrue(result.path("ok").asBoolean(),result.toString());return result.path("value");
    }
    private ObjectNode args() {return Boundary.object().put("circuit",circuit);}
    private ObjectNode metadata(int length) {
        var vk=Boundary.object().put("protocol","groth16").put("curve","bls12381").put("nPublic",1);
        for(String name:new String[]{"vk_alpha_1","vk_beta_2","vk_gamma_2","vk_delta_2","vk_alphabeta_12","IC"})vk.putArray(name).add("0");
        var args=args().put("fingerprint",fingerprint).put("length",length).put("expectedSha256","0".repeat(64));
        args.set("verificationKey",vk);return args;
    }
    private String begin(int length) {return ok("beginKey",metadata(length)).path("upload").asText();}
    private ObjectNode upload(String id) {return args().put("upload",id);}
    private void empty() {assertEquals(0,ok("keyResources",args()).path("reservedBytes").asInt());}
    @Test void lengthAndMetadataAreCheckedBeforeAllocation() {
        for(int n:new int[]{0,-1,CircuitAdapter.MAX_KEY_BYTES+1,Integer.MAX_VALUE})assertFalse(call("beginKey",metadata(n)).path("ok").asBoolean());
        assertFalse(call("beginKey",metadata(10).put("fingerprint","wrong")).path("ok").asBoolean());
        assertFalse(call("beginKey",metadata(10).put("expectedSha256","00")).path("ok").asBoolean());
        empty();assertEquals(0,ok("keyResources",args()).path("peakStagingBytes").asInt());
    }
    @Test void exactMaximumReservationIsBoundedAndAbortIsTerminal() {
        String id=begin(CircuitAdapter.MAX_KEY_BYTES);
        assertEquals(CircuitAdapter.MAX_KEY_BYTES,ok("keyResources",args()).path("reservedBytes").asInt());
        assertFalse(call("beginKey",metadata(1)).path("ok").asBoolean());
        for(int offset=0;offset<CircuitAdapter.MAX_KEY_BYTES;offset+=CircuitAdapter.KEY_CHUNK_BYTES)
            ok("appendKey",upload(id).put("offset",offset).put("chunk","00".repeat(CircuitAdapter.KEY_CHUNK_BYTES)));
        assertEquals(CircuitAdapter.MAX_KEY_BYTES,ok("keyResources",args()).path("receivedBytes").asInt());
        ok("abortKey",upload(id));empty();assertFalse(call("finishKey",upload(id)).path("ok").asBoolean());
        ok("abortKey",upload(begin(1)));empty();
    }
    @Test void badChunksTerminateAndReleaseTheReservation() {
        for(ObjectNode bad:new ObjectNode[]{Boundary.object().put("offset",1).put("chunk","00"),
                Boundary.object().put("offset",0).put("chunk",""),Boundary.object().put("offset",0).put("chunk","AA"),
                Boundary.object().put("offset",0).put("chunk","0000"),
                Boundary.object().put("offset",0).put("chunk","00".repeat(CircuitAdapter.KEY_CHUNK_BYTES+1))}) {
            String id=begin(1);bad.put("circuit",circuit).put("upload",id);
            assertFalse(call("appendKey",bad).path("ok").asBoolean());empty();
            assertFalse(call("appendKey",upload(id).put("offset",0).put("chunk","00")).path("ok").asBoolean());
        }
        String id=begin(2);ok("appendKey",upload(id).put("offset",0).put("chunk","00"));
        assertFalse(call("appendKey",upload(id).put("offset",0).put("chunk","00")).path("ok").asBoolean());empty();
    }
    @Test void truncationIntegrityAndMalformedKeysNeverCreateHandles() {
        String id=begin(2);ok("appendKey",upload(id).put("offset",0).put("chunk","00"));
        assertEquals("INCOMPLETE_KEY",call("finishKey",upload(id)).path("error").path("code").asText());empty();
        id=begin(1);ok("appendKey",upload(id).put("offset",0).put("chunk","00"));
        assertEquals("INVALID_PROVING_KEY",call("finishKey",upload(id)).path("error").path("code").asText());empty();
        assertEquals(0,ok("keyResources",args()).path("importedKeys").asInt());
    }
    @Test void foreignHandlesCannotConsumeUploadAndClosingCircuitReleasesIt() {
        String id=begin(1);
        assertFalse(call("abortKey",upload(circuit)).path("ok").asBoolean());
        assertEquals(1,ok("keyResources",args()).path("reservedBytes").asInt());
        session.release(circuit);
        assertFalse(call("appendKey",upload(id).put("offset",0).put("chunk","00")).path("ok").asBoolean());
        assertFalse(session.release(id));
    }
}
