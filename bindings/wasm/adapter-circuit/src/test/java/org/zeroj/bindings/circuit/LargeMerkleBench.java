package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;

/** JVM-only benchmark of the actual adapter; test witnesses and development keys only. */
public final class LargeMerkleBench {
    private static JsonNode invoke(BindingSession s,String op,JsonNode args,boolean expected) {
        var n=Boundary.object().put("apiVersion",1).put("capability","circuit").put("operation",op);n.set("arguments",args);
        var result=Boundary.parse(s.call(n.toString()));
        if(result.path("ok").asBoolean()!=expected)throw new AssertionError(op+": "+result);
        return result.path(expected?"value":"error");
    }
    private static JsonNode call(BindingSession s,String op,JsonNode args){return invoke(s,op,args,true);}
    public static void main(String[] args)throws Exception {
        Path root=Path.of(args[0]);String name=args[1],heap=args[2];
        if(!name.matches("merkle_d(8|16|32)")||!heap.matches("[68]g"))throw new IllegalArgumentException("Bounded experiment only");
        Path dir=root.resolve(name);JsonNode f=null;
        for(var x:Boundary.JSON.readTree(Files.readString(root.resolve("manifest.json"))))if(x.path("name").asText().equals(name))f=x;
        if(f==null||!f.path("developmentOnly").asBoolean()||!f.path("proofSupported").asBoolean())throw new IllegalStateException("Research fixture is not ready");
        var report=Boundary.object().put("name",name).put("maxHeapLabel",heap).put("maxHeapBytes",Runtime.getRuntime().maxMemory());
        report.put("graphSha256",f.path("graphSha256").asText()).put("keySha256",f.path("keySha256").asText()).put("keyBytes",f.path("keyBytes").asInt());
        var times=report.putObject("timingsMs");var memory=ManagementFactory.getMemoryMXBean();var peak=new AtomicLong(memory.getHeapMemoryUsage().getUsed());
        long baseline=peak.get();var phase=new AtomicReference<>("baseline");var phasePeaks=new ConcurrentHashMap<String,AtomicLong>();var sampler=Executors.newSingleThreadScheduledExecutor(r->{Thread t=new Thread(r,"heap-sampler");t.setDaemon(true);return t;});
        sampler.scheduleAtFixedRate(()->{long used=memory.getHeapMemoryUsage().getUsed();peak.accumulateAndGet(used,Math::max);phasePeaks.computeIfAbsent(phase.get(),k->new AtomicLong()).accumulateAndGet(used,Math::max);},0,10,TimeUnit.MILLISECONDS);
        var s=new BindingSession(Map.of("circuit",new CircuitAdapter(CircuitKeyProfile.RESEARCH_MERKLE)),true);String circuit=null;
        try{
            phase.set("compile");String graph=Files.readString(dir.resolve("graph.json"));long t=System.nanoTime();
            call(s,"beginGraph",Boundary.object().put("length",graph.length()).put("expectedGraphSha256",f.path("graphSha256").asText()).put("fingerprint",f.path("fingerprint").asText()));
            for(int offset=0;offset<graph.length();offset+=200000)call(s,"appendGraph",Boundary.object().put("offset",offset).put("text",graph.substring(offset,Math.min(offset+200000,graph.length()))));
            var description=call(s,"compileGraph",Boundary.object());circuit=description.path("handle").asText();report.set("description",description);times.put("compile",(System.nanoTime()-t)/1e6);
            var input=Boundary.parse(Files.readString(dir.resolve("inputs.json")));var check=Boundary.object().put("circuit",circuit);check.set("input",input);
            phase.set("witnessAndCheck");t=System.nanoTime();call(s,"checkWitness",check);times.put("witnessAndCheck",(System.nanoTime()-t)/1e6);
            var bad=input.deepCopy();((ObjectNode)bad).put("siblings_0",new BigInteger(input.path("siblings_0").asText()).add(BigInteger.ONE).toString());
            check.set("input",bad);invoke(s,"checkWitness",check,false);report.put("invalidWitnessRejected",true);
            phase.set("keyRead");byte[] key=Files.readAllBytes(dir.resolve("key.zkey"));var vk=Boundary.parse(Files.readString(dir.resolve("vk.json")));
            var meta=Boundary.object().put("circuit",circuit).put("fingerprint",f.path("fingerprint").asText()).put("length",key.length).put("expectedSha256",f.path("keySha256").asText());meta.set("verificationKey",vk);
            phase.set("keyLoad");t=System.nanoTime();String upload=call(s,"beginKey",meta).path("upload").asText();
            for(int off=0;off<key.length;off+=CircuitAdapter.KEY_CHUNK_BYTES)call(s,"appendKey",Boundary.object().put("circuit",circuit).put("upload",upload).put("offset",off).put("chunk",HexFormat.of().formatHex(key,off,Math.min(off+CircuitAdapter.KEY_CHUNK_BYTES,key.length))));
            var loaded=call(s,"finishKey",Boundary.object().put("circuit",circuit).put("upload",upload));times.put("keyLoad",(System.nanoTime()-t)/1e6);times.put("keyImport",loaded.path("importMs").asDouble());key=null;
            var prove=Boundary.object().put("circuit",circuit).put("key",loaded.path("handle").asText());prove.set("input",input);
            phase.set("firstProofAndSelfVerify");t=System.nanoTime();var proof=call(s,"prove",prove);times.put("firstProofAndSelfVerify",(System.nanoTime()-t)/1e6);
            phase.set("reusedProofAndSelfVerify");t=System.nanoTime();var repeated=call(s,"prove",prove);times.put("reusedProofAndSelfVerify",(System.nanoTime()-t)/1e6);
            phase.set("verify");t=System.nanoTime();var values=Groth16VerifierAdapter.scalars(proof.get("publicInputs"));
            if(!Groth16VerifierAdapter.verify(proof.get("proof"),vk,values)||!Groth16VerifierAdapter.verify(repeated.get("proof"),vk,values))throw new AssertionError("Proof rejected");
            times.put("verifyTwo",(System.nanoTime()-t)/1e6);values.set(0,values.getFirst().add(BigInteger.ONE));
            if(Groth16VerifierAdapter.verify(proof.get("proof"),vk,values))throw new AssertionError("Changed root accepted");
            report.put("changedRootRejected",true);report.put("proofVerified",true);
            report.set("resources",call(s,"keyResources",Boundary.object().put("circuit",circuit)));
            Files.writeString(dir.resolve("jvm-"+heap+"-proof.json"),proof.toString());
        }finally{
            if(circuit!=null)s.release(circuit);sampler.shutdownNow();
            var byPhase=report.putObject("sampledPeakHeapByPhase");phasePeaks.forEach((k,v)->byPhase.put(k,v.get()));
            report.put("baselineHeapBytes",baseline).put("sampledPeakHeapBytes",peak.get()).put("heapAtEndBytes",memory.getHeapMemoryUsage().getUsed());
            Files.writeString(dir.resolve("jvm-"+heap+"-result.json"),report.toPrettyString());
        }
        System.out.println(report.toPrettyString());
    }
}
