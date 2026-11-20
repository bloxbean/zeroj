package org.zeroj.bindings.elgamal;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.zeroj.bindings.common.*;
import org.zeroj.bindings.groth16.Groth16VerifierAdapter;
import org.zeroj.circuit.lib.jubjub.*;

/** Keeps admitted ciphertexts and verified shares as Java objects, never caller booleans. */
public final class ElGamalAdapter implements Adapter {
    private record RelationKey(String relation, int width, JsonNode vk) {}
    @Override public JsonNode invoke(String op, JsonNode a, BindingSession s) {
        return switch(op) {
            case "generateKey", "importKey" -> {
                Boundary.fields(a,op.equals("generateKey")?new String[]{}:new String[]{"secret"});
                s.requireSecrets();
                var key=op.equals("generateKey")?ElGamalSecretKey.generate(s.random()):
                        ElGamalSecretKey.of(Boundary.scalar(a,"secret",JubjubCurve.SUBGROUP_ORDER));
                yield Boundary.object().put("secret",s.retain(key)).put("share",s.retain(VerifiedKeyShare.fromSecret(key)))
                        .put("publicKey",Boundary.hex(key.publicKey().encode()));
            }
            case "exportKey" -> {
                Boundary.fields(a,"secret");s.requireSecrets();
                yield Boundary.object().put("secret",s.get(Boundary.text(a,"secret"),ElGamalSecretKey.class).secretScalar().toString());
            }
            case "aggregate" -> {
                Boundary.fields(a,"shares");
                var shares=handles(a.get("shares"),s,VerifiedKeyShare.class,64);
                yield context(s,ElGamalPublicKey.aggregate(shares));
            }
            case "encrypt" -> {
                Boundary.fields(a,"context","message","width");s.requireSecrets();
                var c=s.get(Boundary.text(a,"context"),ElGamalKeyContext.class);
                yield ciphertext(s,ElGamal.encrypt(c,Boundary.scalar(a,"message",BigInteger.ONE.shiftLeft(64)),
                        Boundary.integer(a,"width",1,64),s.random()));
            }
            case "add" -> {
                Boundary.fields(a,"ciphertexts");yield ciphertext(s,ElGamalCiphertext.sum(handles(a.get("ciphertexts"),s,ElGamalCiphertext.class,128)));
            }
            case "scale" -> {
                Boundary.fields(a,"ciphertext","factor");yield ciphertext(s,cipher(a,s).scale(Boundary.scalar(a,"factor",JubjubCurve.SUBGROUP_ORDER)));
            }
            case "decryptionShare" -> {
                Boundary.fields(a,"ciphertext","secret");s.requireSecrets();
                yield share(s,ElGamal.decryptionShare(s.get(Boundary.text(a,"secret"),ElGamalSecretKey.class),cipher(a,s)));
            }
            case "decrypt" -> {
                Boundary.fields(a,"ciphertext","shares","maxPlaintext");s.requireSecrets();
                yield Boundary.object().put("message",Long.toString(ElGamal.decrypt(cipher(a,s),
                        handles(a.get("shares"),s,VerifiedDecryptionShare.class,64),Boundary.integer(a,"maxPlaintext",0,1_000_000))));
            }
            case "registerRelationKey" -> {
                Boundary.fields(a,"relation","width","verificationKey");
                String relation=Boundary.text(a,"relation");int width=Boundary.integer(a,"width",0,64);
                if (!(relation.equals("dleq")&&width==0) && !(relation.equals("encryption")&&width>=1)) throw Boundary.invalid();
                JsonNode vk=a.get("verificationKey");Groth16VerifierAdapter.keyShape(vk);
                if(Boundary.integer(vk,"nPublic",0,64)!=6)throw Boundary.invalid();
                yield Boundary.object().put("handle",s.retain(new RelationKey(relation,width,vk.deepCopy())));
            }
            case "importKeyShare" -> {
                Boundary.fields(a,"relationKey","proof","publicKey");
                var k=relation(a,s,"dleq",0);
                var verified=VerifiedKeyShare.verify(Boundary.bytes(a,"publicKey",32,32),
                        statement->Groth16VerifierAdapter.verify(a.get("proof"),k.vk,statement.publicInputs()));
                yield Boundary.object().put("handle",s.retain(verified)).put("publicKey",Boundary.hex(verified.publicKey().encode()));
            }
            case "admitCiphertext" -> {
                Boundary.fields(a,"relationKey","proof","context","bytes","width");
                int width=Boundary.integer(a,"width",1,64);var k=relation(a,s,"encryption",width);
                var context=s.get(Boundary.text(a,"context"),ElGamalKeyContext.class);
                var raw=RawElGamalCiphertext.decode(Boundary.bytes(a,"bytes",64,64));
                yield ciphertext(s,ElGamal.admit(raw,context,width,
                        statement->Groth16VerifierAdapter.verify(a.get("proof"),k.vk,statement.publicInputs())));
            }
            case "importDecryptionShare" -> {
                Boundary.fields(a,"relationKey","proof","ciphertext","trustee","bytes");
                var k=relation(a,s,"dleq",0);
                var trustee=s.get(Boundary.text(a,"trustee"),VerifiedKeyShare.class);
                yield share(s,VerifiedDecryptionShare.verify(cipher(a,s),trustee.publicKey(),Boundary.bytes(a,"bytes",32,32),
                        statement->Groth16VerifierAdapter.verify(a.get("proof"),k.vk,statement.publicInputs())));
            }
            case "importThresholdDecryptionShare" -> {
                Boundary.fields(a,"relationKey","proof","ciphertext","participantId","bytes");
                var k=relation(a,s,"dleq",0);
                yield share(s,VerifiedDecryptionShare.verify(cipher(a,s),Boundary.integer(a,"participantId",1,64),Boundary.bytes(a,"bytes",32,32),
                        statement->Groth16VerifierAdapter.verify(a.get("proof"),k.vk,statement.publicInputs())));
            }
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
    }
    private static RelationKey relation(JsonNode a, BindingSession s, String type, int width) {
        var key=s.get(Boundary.text(a,"relationKey"),RelationKey.class);
        if(!key.relation.equals(type)||key.width!=width)throw new BindingException("RELATION_MISMATCH");
        return key;
    }
    public static ElGamalCiphertext cipher(JsonNode a, BindingSession s) {
        return s.get(Boundary.text(a,"ciphertext"),ElGamalCiphertext.class);
    }
    public static JsonNode ciphertext(BindingSession s, ElGamalCiphertext value) {
        return Boundary.object().put("handle",s.retain(value)).put("bytes",Boundary.hex(value.encode())).put("bound",value.bound().toString());
    }
    public static JsonNode context(BindingSession s, ElGamalKeyContext value) {
        return Boundary.object().put("handle",s.retain(value)).put("publicKey",Boundary.hex(value.jointKey().encode()));
    }
    public static JsonNode share(BindingSession s, VerifiedDecryptionShare value) {
        var result=Boundary.object().put("handle",s.retain(value)).put("bytes",Boundary.hex(value.encode()));
        var inputs=result.putArray("publicInputs");value.statement().publicInputs().forEach(x->inputs.add(x.toString()));
        return result;
    }
    public static <T> List<T> handles(JsonNode node, BindingSession s, Class<T> type, int max) {
        if(node==null||!node.isArray()||node.isEmpty()||node.size()>max)throw Boundary.invalid();
        var values=new ArrayList<T>();
        for(var v:node){if(!v.isTextual())throw Boundary.invalid();values.add(s.get(v.textValue(),type));}
        return values;
    }
}
