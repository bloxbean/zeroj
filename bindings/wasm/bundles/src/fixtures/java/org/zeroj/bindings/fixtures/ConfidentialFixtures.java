package org.zeroj.bindings.fixtures;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.zeroj.api.CurveId;
import org.zeroj.api.SecureRandoms;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.*;
import org.zeroj.crypto.groth16.Groth16ProverBLS381;
import org.zeroj.crypto.setup.Groth16SetupBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;

/** Public disposable development fixtures. No keys from this setup are suitable for production. */
public final class ConfidentialFixtures {
    public static void main(String[] args) throws Exception {
        var dir=Path.of(args[0]);Files.createDirectories(dir);
        var secret=ElGamalSecretKey.of(BigInteger.valueOf(3));
        var encryption=ElGamal.encryptWithOpening(NOfNKeyContext.singleKey(secret),BigInteger.ONE,1,SecureRandoms.create());
        var share=ElGamal.decryptionShare(secret,encryption.ciphertext());
        var dleq=CircuitBuilder.create("binding-dleq-v1")
                .publicVar("xU").publicVar("xV").publicVar("pU").publicVar("pV").publicVar("dU").publicVar("dV")
                .secretVar("x").define(api->InCircuitElGamal.assertDiscreteLogEquality(api,api.decompose(api.var("x"),252),
                        api.var("xU"),api.var("xV"),api.var("pU"),api.var("pV"),api.var("dU"),api.var("dV")));
        var d=dleq.compileR1CS(CurveId.BLS12_381);
        var ds=Groth16SetupBLS381.setup(d.constraints(),d.numWires(),d.numPublicInputs(),BigInteger.valueOf(17));
        Files.writeString(dir.resolve("dleq-vk.json"),SnarkjsGroth16Json.verificationKeyJson(ds));
        for(String name:List.of("possession","share")) {
            var statement=name.equals("possession")?secret.possessionStatement():share.statement();
            var input=new HashMap<String,List<BigInteger>>();
            String[] names={"xU","xV","pU","pV","dU","dV"};
            for(int i=0;i<6;i++)input.put(names[i],List.of(statement.publicInputs().get(i)));
            input.put("x",List.of(secret.secretScalar()));
            var witness=dleq.calculateWitness(input,CurveId.BLS12_381);
            var proof=Groth16ProverBLS381.prove(ds.provingKey(),witness,d.constraints(),d.numWires());
            Files.writeString(dir.resolve(name+"-proof.json"),SnarkjsGroth16Json.proofJson(proof));
            Files.writeString(dir.resolve(name+"-public.json"),SnarkjsGroth16Json.publicJson(statement.publicInputs().toArray(BigInteger[]::new)));
        }
        var enc=CircuitBuilder.create("binding-encryption-w1-v1").publicVar("pkU").publicVar("pkV")
                .publicVar("aU").publicVar("aV").publicVar("bU").publicVar("bV").secretVar("m").secretVar("k")
                .define(api->{
                    var key=InCircuitElGamal.keyFromVerifierFixedPublic(api,api.var("pkU"),api.var("pkV"));
                    var ct=InCircuitElGamal.encrypt(api,key,api.decompose(api.var("m"),1),api.decompose(api.var("k"),252));
                    InCircuitElGamal.assertAffineEquals(api,ct.handle(),api.var("aU"),api.var("aV"));
                    InCircuitElGamal.assertAffineEquals(api,ct.blinded(),api.var("bU"),api.var("bV"));
                });
        var c=enc.compileR1CS(CurveId.BLS12_381);
        var setup=Groth16SetupBLS381.setup(c.constraints(),c.numWires(),c.numPublicInputs(),BigInteger.valueOf(19));
        var input=new HashMap<String,List<BigInteger>>();
        String[] names={"pkU","pkV","aU","aV","bU","bV"};var values=encryption.statement().publicInputs();
        for(int i=0;i<6;i++)input.put(names[i],List.of(values.get(i)));
        input.put("m",List.of(encryption.message()));input.put("k",List.of(encryption.randomness()));
        var proof=Groth16ProverBLS381.prove(setup.provingKey(),enc.calculateWitness(input,CurveId.BLS12_381),c.constraints(),c.numWires());
        Files.writeString(dir.resolve("encryption-vk.json"),SnarkjsGroth16Json.verificationKeyJson(setup));
        Files.writeString(dir.resolve("encryption-proof.json"),SnarkjsGroth16Json.proofJson(proof));
        Files.writeString(dir.resolve("encryption-public.json"),SnarkjsGroth16Json.publicJson(values.toArray(BigInteger[]::new)));
        Files.writeString(dir.resolve("manifest.json"),Boundary.object().put("developmentOnly",true)
                .put("dleqConstraints",d.numConstraints()).put("encryptionConstraints",c.numConstraints())
                .put("publicKey",Boundary.hex(secret.publicKey().encode())).put("ciphertext",Boundary.hex(encryption.ciphertext().encode()))
                .put("decryptionShare",Boundary.hex(share.encode())).toPrettyString());
        System.out.println("Generated development admission fixtures; DLEQ "+d.numConstraints()+", encryption "+c.numConstraints()+" rows");
    }
}
