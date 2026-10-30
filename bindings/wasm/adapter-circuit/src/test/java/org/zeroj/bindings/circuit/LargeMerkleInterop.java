package org.zeroj.bindings.circuit;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.io.IOException;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;
import org.zeroj.crypto.groth16.ZkeyImporterBLS381;

/** Independent JVM verification of every measured engine; cheap parser-policy boundary checks. */
public final class LargeMerkleInterop {
    public static void main(String[] args)throws Exception {
        Path root=Path.of(args[0]);
        for(String name:new String[]{"merkle_d8","merkle_d16","merkle_d32"}){
            Path dir=root.resolve(name);var vk=Boundary.parse(Files.readString(dir.resolve("vk.json")));
            for(String engine:new String[]{"node","chromium","firefox","jvm-6g","jvm-8g"}){
                var result=Boundary.parse(Files.readString(dir.resolve(engine+"-proof.json")));
                var values=Groth16VerifierAdapter.scalars(result.get("publicInputs"));
                if(!Groth16VerifierAdapter.verify(result.get("proof"),vk,values))throw new AssertionError(name+" "+engine);
                values.set(0,values.getFirst().add(BigInteger.ONE));
                if(Groth16VerifierAdapter.verify(result.get("proof"),vk,values))throw new AssertionError("changed root");
                System.out.println("JVM verified "+name+" "+engine+" and rejected changed root");
            }
        }
        var manifest=Boundary.JSON.readTree(Files.readString(root.resolve("manifest.json")));var f=manifest.get(0);
        if(!f.path("name").asText().equals("merkle_d8"))throw new AssertionError("fixture order");
        byte[] key=Files.readAllBytes(root.resolve("merkle_d8/key.zkey")),digest=MessageDigest.getInstance("SHA-256").digest(key);
        for(var limit:new ZkeyImporterBLS381.Limits[]{
                new ZkeyImporterBLS381.Limits(key.length-1,65536,8192,262144),
                new ZkeyImporterBLS381.Limits(key.length,f.path("wires").asInt()-1,8192,262144),
                new ZkeyImporterBLS381.Limits(key.length,65536,1024,262144),
                new ZkeyImporterBLS381.Limits(key.length,65536,8192,f.path("coefficients").asInt()-1)}){
            boolean rejected=false;
            try{ZkeyImporterBLS381.importZkeyFull(key,digest,limit);}catch(IOException e){
                rejected=e.getMessage().contains("limit");
            }
            if(!rejected)throw new AssertionError("Importer resource boundary did not reject");
        }
        System.out.println("Unchanged importer independently enforced byte, wire, domain and coefficient boundaries");
    }
}
