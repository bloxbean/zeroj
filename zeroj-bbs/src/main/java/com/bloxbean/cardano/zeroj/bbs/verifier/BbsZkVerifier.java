package com.bloxbean.cardano.zeroj.bbs.verifier;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite;
import com.bloxbean.cardano.zeroj.bbs.BbsPresentationCodec;
import com.bloxbean.cardano.zeroj.bbs.BbsPublicKey;
import com.bloxbean.cardano.zeroj.bbs.BbsService;

/**
 * ZeroJ verifier adapter for CFRG BBS draft-10 presentations.
 */
public final class BbsZkVerifier implements ZkVerifier {
    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.BBS, CurveId.BLS12_381, "bbs-bls12381-java");

    private final BbsService service;

    public BbsZkVerifier() {
        this(BbsService.pureJava());
    }

    public BbsZkVerifier(BbsService service) {
        this.service = java.util.Objects.requireNonNull(service, "BBS service required");
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            if (envelope.proofSystem() != ProofSystemId.BBS || material.proofSystemId() != ProofSystemId.BBS) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                        "BBS verifier only supports proof system bbs");
            }
            if (envelope.curve() != CurveId.BLS12_381 || material.curveId() != CurveId.BLS12_381) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_CURVE,
                        "BBS verifier only supports BLS12-381");
            }
            if (envelope.proofFormat().isPresent()
                    && !BbsCiphersuite.DEFAULT_PROOF_FORMAT.equals(envelope.proofFormat().get())) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        "Unsupported BBS proof format: " + envelope.proofFormat().get());
            }

            var presentation = BbsPresentationCodec.decode(envelope.proofBytes());
            BbsCiphersuite ciphersuite = presentation.proof().ciphersuite();
            BbsService verifierService = service.provider().ciphersuite() == ciphersuite
                    ? service
                    : BbsService.pureJava(ciphersuite);
            BbsPublicKey publicKey = new BbsPublicKey(material.vkBytes(), ciphersuite);
            boolean valid = verifierService.verifyPresentation(publicKey, presentation);
            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("BBS proof verification failed");
        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "BBS verification error: " + e.getMessage());
        }
    }

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }
}
