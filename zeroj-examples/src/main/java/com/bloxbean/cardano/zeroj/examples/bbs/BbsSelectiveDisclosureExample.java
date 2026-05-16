package com.bloxbean.cardano.zeroj.examples.bbs;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.PublicInputs;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentation;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentationCodec;
import com.bloxbean.cardano.zeroj.bbs.BbsService;
import com.bloxbean.cardano.zeroj.bbs.BbsSignature;
import com.bloxbean.cardano.zeroj.bbs.verifier.BbsZkVerifier;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Minimal BBS selective-disclosure flow.
 */
public final class BbsSelectiveDisclosureExample {
    private BbsSelectiveDisclosureExample() {}

    public static void main(String[] args) {
        var service = BbsService.pureJava();
        var keyPair = service.keyPair(bytes("01234567890123456789012345678901"), bytes("issuer-key-v1"));

        List<byte[]> messages = List.of(
                bytes("given_name:Alice"),
                bytes("family_name:Liddell"),
                bytes("age_over_18:true"),
                bytes("membership:gold"));
        byte[] header = bytes("example-credential-v1");
        byte[] presentationHeader = bytes("verifier-session-123");

        BbsSignature signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);
        boolean signatureValid = service.verify(keyPair.publicKey(), signature, messages, header);

        BbsPresentation presentation = service.derivePresentation(
                keyPair.publicKey(),
                signature,
                messages,
                header,
                presentationHeader,
                new int[]{0, 2});
        boolean presentationValid = service.verifyPresentation(keyPair.publicKey(), presentation);

        ZkProofEnvelope envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.BBS)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("bbs-selective-disclosure"))
                .proofBytes(BbsPresentationCodec.encode(presentation))
                .publicInputs(new PublicInputs(List.of()))
                .vkRef(new VerificationKeyRef.ById("issuer-key-v1"))
                .proofFormat(BbsCiphersuite.DEFAULT_PROOF_FORMAT)
                .build();
        VerificationMaterial material = VerificationMaterial.of(
                keyPair.publicKey().bytes(),
                ProofSystemId.BBS,
                CurveId.BLS12_381,
                new CircuitId("bbs-selective-disclosure"));
        boolean envelopeValid = new BbsZkVerifier(service).verify(envelope, material).proofValid();

        System.out.println("signatureValid=" + signatureValid);
        System.out.println("presentationValid=" + presentationValid);
        System.out.println("envelopeValid=" + envelopeValid);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
