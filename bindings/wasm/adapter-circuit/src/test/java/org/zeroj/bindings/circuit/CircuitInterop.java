package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.HexFormat;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Map;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;

/** Test-only: verify browser/Node proofs on the JVM, and export a JVM proof for the JS oracles. */
public final class CircuitInterop {
    private static JsonNode call(BindingSession s, String op, JsonNode args) {
        var request=Boundary.object().put("apiVersion",1).put("capability","circuit").put("operation",op);
        request.set("arguments",args);
        var response=Boundary.parse(s.call(request.toString()));
        if(!response.path("ok").asBoolean())throw new AssertionError(response.toString());
        return response.path("value");
    }
    public static void main(String[] args) throws Exception {
        for(String name:new String[]{"poseidon_opening","allowlist_d1","merkle_d2"}) run(Path.of(args[0]).resolve(name),name);
    }
    private static void run(Path dir,String name) throws Exception {
        var vk=Boundary.parse(Files.readString(dir.resolve("vk.json")));
        for(String engine:new String[]{"node","chromium","firefox"}) {
            var result=Boundary.parse(Files.readString(dir.resolve(engine+"-proof.json")));
            var values=Groth16VerifierAdapter.scalars(result.get("publicInputs"));
            if(!Groth16VerifierAdapter.verify(result.get("proof"),vk,values))throw new AssertionError(engine);
            values.set(0,values.getFirst().add(BigInteger.ONE));
            if(Groth16VerifierAdapter.verify(result.get("proof"),vk,values))throw new AssertionError("tamper "+engine);
            System.out.println("JVM verified "+engine+" "+name+" proof and rejected changed public input");
        }
        var session=new BindingSession(Map.of("circuit",new CircuitAdapter()),true);
        String graph=Files.readString(dir.resolve("graph.json"));
        String fingerprint=new CompiledGraph(GraphCodec.decode(graph)).fingerprint();
        call(session,"beginGraph",Boundary.object().put("length",graph.length()).put("expectedGraphSha256",GraphCodec.hash(graph)).put("fingerprint",fingerprint));
        for(int offset=0;offset<graph.length();offset+=200_000)
            call(session,"appendGraph",Boundary.object().put("offset",offset).put("text",graph.substring(offset,Math.min(offset+200_000,graph.length()))));
        String circuit=call(session,"compileGraph",Boundary.object()).path("handle").asText();
        byte[] key=Files.readAllBytes(dir.resolve("key.zkey"));
        var begin=Boundary.object().put("circuit",circuit).put("length",key.length).put("fingerprint",fingerprint)
                .put("expectedSha256",Boundary.hex(MessageDigest.getInstance("SHA-256").digest(key)));
        begin.set("verificationKey",vk);
        String upload=call(session,"beginKey",begin).path("upload").asText();
        for(int offset=0;offset<key.length;offset+=CircuitAdapter.KEY_CHUNK_BYTES)
            call(session,"appendKey",Boundary.object().put("circuit",circuit).put("upload",upload).put("offset",offset)
                    .put("chunk",HexFormat.of().formatHex(key,offset,Math.min(offset+CircuitAdapter.KEY_CHUNK_BYTES,key.length))));
        String keyHandle=call(session,"finishKey",Boundary.object().put("circuit",circuit).put("upload",upload)).path("handle").asText();
        var prove=Boundary.object().put("circuit",circuit).put("key",keyHandle);
        prove.set("input",Fixtures.inputs(name));
        Files.writeString(dir.resolve("jvm-proof.json"),call(session,"prove",prove).toString());
        session.release(circuit);
        System.out.println("JVM chunk import / "+name+" proof / self-verification PASS");
    }
}
