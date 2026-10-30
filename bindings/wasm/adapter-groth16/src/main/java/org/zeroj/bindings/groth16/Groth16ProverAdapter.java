package org.zeroj.bindings.groth16;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.bindings.common.*;
import org.zeroj.crypto.groth16.*;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;

/** Supplied ceremony keys only. No trusted setup is reachable from this adapter. */
public final class Groth16ProverAdapter implements Adapter {
    private final Map<String,CompiledCircuit> circuits;
    private record Loaded(CompiledCircuit circuit, ZkeyDataBLS381 data, JsonNode vk) {}
    public Groth16ProverAdapter(Map<String,CompiledCircuit> circuits) { this.circuits = Map.copyOf(circuits); }
    @Override public JsonNode invoke(String operation, JsonNode args, BindingSession session) {
        if (operation.equals("describe")) {
            Boundary.fields(args,"circuit");
            var c = circuit(args);
            return Boundary.object().put("circuit",c.id()).put("fingerprint",c.fingerprint())
                    .put("numPublic",c.numPublic()).put("numWires",c.numWires()).put("constraints",c.constraints().size());
        }
        if (operation.equals("loadKey")) {
            Boundary.fields(args,"circuit","fingerprint","zkey","expectedSha256","verificationKey");
            byte[] bytes = Boundary.bytes(args,"zkey",1,Boundary.MAX_BYTES);
            ObjectNode metadata = args.deepCopy();
            metadata.remove("zkey");
            return loadKeyBytes(metadata, bytes, session,
                    new ZkeyImporterBLS381.Limits(Boundary.MAX_BYTES,4096,4096,16384));
        }
        if (operation.equals("prove")) {
            Boundary.fields(args,"key","input");
            session.requireSecrets();
            var loaded = session.get(Boundary.text(args,"key"),Loaded.class);
            BigInteger[] witness = loaded.circuit.witness(args.get("input"));
            try {
                checkWitness(loaded.circuit,witness);
                var data = loaded.data;
                var proof = Groth16ProverBLS381.prove(data.provingKey(),witness,data.constraints(),data.numWires());
                var json = Boundary.parse(SnarkjsGroth16Json.proofJson(proof));
                var values = Arrays.asList(Arrays.copyOfRange(witness,1,loaded.circuit.numPublic()+1));
                if (!Groth16VerifierAdapter.verify(json,loaded.vk,values)) throw new BindingException("KEY_PROOF_MISMATCH");
                var result = Boundary.object(); result.set("proof",json);
                var inputs = result.putArray("publicInputs"); values.forEach(v -> inputs.add(v.toString()));
                return result;
            } finally { Arrays.fill(witness,BigInteger.ZERO); }
        }
        throw new BindingException("UNSUPPORTED_OPERATION");
    }
    /** Java-only entry point for bounded chunk transports. No alternate key parser. */
    public JsonNode loadKeyBytes(JsonNode metadata, byte[] bytes, BindingSession session,
                                 ZkeyImporterBLS381.Limits limits) {
        validateKeyMetadata(metadata);
        var c = circuit(metadata);
        byte[] digest = Boundary.bytes(metadata,"expectedSha256",32,32);
        long start = System.nanoTime();
        try {
            var data = ZkeyImporterBLS381.importZkeyFull(bytes,digest,limits);
            checkRelation(c,data);
            return Boundary.object().put("handle",session.retain(new Loaded(c,data,metadata.get("verificationKey").deepCopy())))
                    .put("keyBytes",bytes.length).put("importMs",(System.nanoTime()-start)/1e6)
                    .put("domainSize",data.domainSize());
        } catch (IOException e) { throw new BindingException("INVALID_PROVING_KEY"); }
    }
    /** Validate small metadata before the transport reserves a key-sized buffer. */
    public void validateKeyMetadata(JsonNode metadata) {
        Boundary.fields(metadata,"circuit","fingerprint","expectedSha256","verificationKey");
        var c = circuit(metadata);
        if (!c.fingerprint().equals(Boundary.text(metadata,"fingerprint"))) throw new BindingException("CIRCUIT_MISMATCH");
        Boundary.bytes(metadata,"expectedSha256",32,32);
        JsonNode vk = metadata.get("verificationKey");
        Groth16VerifierAdapter.keyShape(vk);
        if (Boundary.integer(vk,"nPublic",0,64) != c.numPublic()) throw new BindingException("CIRCUIT_MISMATCH");
    }
    private CompiledCircuit circuit(JsonNode args) {
        var c = circuits.get(Boundary.text(args,"circuit"));
        if (c == null) throw new BindingException("UNSUPPORTED_CIRCUIT");
        return c;
    }
    private static void checkRelation(CompiledCircuit c, ZkeyDataBLS381 d) {
        if (d.numWires()!=c.numWires() || d.provingKey().numPublic()!=c.numPublic()
                || d.constraints().size()<c.constraints().size()+c.numPublic()+1) throw new BindingException("CIRCUIT_MISMATCH");
        // snarkjs zkeys carry A/B and append public binding rows; C is omitted and reconstructed by the prover.
        for (int i=0;i<d.constraints().size();i++) {
            R1CSConstraint actual=d.constraints().get(i);
            R1CSConstraint expected=i<c.constraints().size()?c.constraints().get(i):
                    new R1CSConstraint(i<c.constraints().size()+c.numPublic()+1?
                            Map.of(i-c.constraints().size(),BigInteger.ONE):Map.of(),Map.of(),Map.of());
            if (!actual.a().equals(expected.a()) || !actual.b().equals(expected.b())
                    || (!actual.c().isEmpty() && !actual.c().equals(expected.c())))
                throw new BindingException("CIRCUIT_MISMATCH");
        }
    }
    private static void checkWitness(CompiledCircuit c, BigInteger[] w) {
        if (w.length!=c.numWires() || !BigInteger.ONE.equals(w[0])) throw new BindingException("INVALID_WITNESS");
        for (var v:w) if(v==null || v.signum()<0 || v.compareTo(Groth16VerifierAdapter.FR)>=0) throw new BindingException("INVALID_WITNESS");
        for (var row:c.constraints()) if(!dot(row.a(),w).multiply(dot(row.b(),w)).mod(Groth16VerifierAdapter.FR).equals(dot(row.c(),w)))
            throw new BindingException("INVALID_WITNESS");
    }
    private static BigInteger dot(Map<Integer,BigInteger> lc, BigInteger[] w) {
        var value=BigInteger.ZERO;
        for (var term:lc.entrySet()) value=value.add(w[term.getKey()].multiply(term.getValue()));
        return value.mod(Groth16VerifierAdapter.FR);
    }
}
