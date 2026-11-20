package org.zeroj.bindings.bbs;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.HexFormat;
import org.zeroj.bbs.BbsCiphersuite;
import org.zeroj.bbs.BbsKeyPair;
import org.zeroj.bbs.BbsPublicKey;
import org.zeroj.bbs.BbsSecretKey;
import org.zeroj.bbs.BbsSignature;
import org.zeroj.bbs.BbsProof;
import org.zeroj.bbs.spi.BbsProviders;
import org.zeroj.bindings.common.Adapter;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.BindingException;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bls12381.field.MontFr381;

/** Existing CFRG suites, explicit headers, bounded inputs and worker-local secret keys. */
public final class BbsAdapter implements Adapter {
    private static List<byte[]> messages(JsonNode args) {
        JsonNode list=args.get("messages");
        if(list==null || !list.isArray() || list.size()>64) throw Boundary.invalid();
        List<byte[]> out=new ArrayList<>();
        for(JsonNode value:list) {
            if(!value.isTextual()) throw Boundary.invalid();
            var item=Boundary.object().put("data",value.textValue());
            out.add(Boundary.bytes(item,"data",0,4096));
        }
        return out;
    }
    private static int[] indexes(JsonNode args) {
        JsonNode list=args.get("disclosedIndexes");
        if(list==null || !list.isArray() || list.size()>64) throw Boundary.invalid();
        int[] out=new int[list.size()];
        for(int i=0;i<out.length;i++) {
            var item=Boundary.object().set("n",list.get(i));
            out[i]=Boundary.integer(item,"n",0,63);
            if(i>0 && out[i]<=out[i-1]) throw Boundary.invalid();
        }
        return out;
    }
    @Override public JsonNode invoke(String operation,JsonNode args,BindingSession session) {
        var suite=BbsCiphersuite.valueOf(Boundary.text(args,"suite"));
        var provider=BbsProviders.pureJava(suite);
        return switch(operation) {
            case "generateKey" -> {
                Boundary.fields(args,"suite","keyInfo");
                byte[] ikm=new byte[32];
                session.random().nextBytes(ikm);
                try {
                    BbsKeyPair key=provider.keyPair(ikm,Boundary.bytes(args,"keyInfo",0,4096));
                    yield Boundary.object().put("handle",session.retain(key))
                            .put("publicKey",Boundary.hex(key.publicKey().bytes()));
                } finally { Arrays.fill(ikm,(byte)0); }
            }
            case "importKey" -> {
                Boundary.fields(args,"suite","secret");
                session.requireSecrets();
                var scalar=Boundary.scalar(args,"secret",MontFr381.modulus());
                if(scalar.signum()==0) throw Boundary.invalid();
                var secret=new BbsSecretKey(scalar,suite);
                var key=new BbsKeyPair(secret,provider.skToPk(secret));
                yield Boundary.object().put("handle",session.retain(key))
                        .put("publicKey",Boundary.hex(key.publicKey().bytes()));
            }
            case "exportKey" -> {
                Boundary.fields(args,"suite","handle");
                session.requireSecrets();
                var key=session.get(Boundary.text(args,"handle"),BbsKeyPair.class);
                if(key.secretKey().ciphersuite()!=suite) throw Boundary.invalid();
                yield Boundary.object().put("secret",key.secretKey().value().toString());
            }
            case "sign" -> {
                Boundary.fields(args,"suite","handle","messages","header");
                session.requireSecrets();
                var key=session.get(Boundary.text(args,"handle"),BbsKeyPair.class);
                if(key.secretKey().ciphersuite()!=suite) throw Boundary.invalid();
                var sig=provider.sign(key.secretKey(),key.publicKey(),messages(args),Boundary.bytes(args,"header",0,4096));
                yield Boundary.object().put("signature",Boundary.hex(sig.bytes()));
            }
            case "verify" -> {
                Boundary.fields(args,"suite","publicKey","signature","messages","header");
                yield Boundary.object().put("valid",provider.verify(
                        new BbsPublicKey(Boundary.bytes(args,"publicKey",96,96),suite),
                        new BbsSignature(Boundary.bytes(args,"signature",80,80),suite),
                        messages(args),Boundary.bytes(args,"header",0,4096)));
            }
            case "deriveProof" -> {
                Boundary.fields(args,"suite","publicKey","signature","messages","header","presentationHeader","disclosedIndexes");
                var random=session.random();
                var proof=provider.proofGen(
                        new BbsPublicKey(Boundary.bytes(args,"publicKey",96,96),suite),
                        new BbsSignature(Boundary.bytes(args,"signature",80,80),suite),messages(args),
                        Boundary.bytes(args,"header",0,4096),Boundary.bytes(args,"presentationHeader",0,4096),
                        indexes(args),random);
                yield Boundary.object().put("proof",Boundary.hex(proof.bytes()));
            }
            case "verifyProof" -> {
                Boundary.fields(args,"suite","publicKey","proof","messages","header","presentationHeader","disclosedIndexes");
                yield Boundary.object().put("valid",provider.proofVerify(
                        new BbsPublicKey(Boundary.bytes(args,"publicKey",96,96),suite),
                        new BbsProof(Boundary.bytes(args,"proof",272,8192),suite),
                        Boundary.bytes(args,"header",0,4096),Boundary.bytes(args,"presentationHeader",0,4096),
                        messages(args),indexes(args)));
            }
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
    }
}
