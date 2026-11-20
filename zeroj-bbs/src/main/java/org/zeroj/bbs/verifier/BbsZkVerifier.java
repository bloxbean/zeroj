package org.zeroj.bbs.verifier;

import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.VerificationResult;
import org.zeroj.api.ZkProofEnvelope;
import org.zeroj.backend.spi.BackendDescriptor;
import org.zeroj.backend.spi.EnvelopeBinding;
import org.zeroj.backend.spi.ZkVerifier;
import org.zeroj.bbs.BbsCiphersuite;
import org.zeroj.bbs.BbsException;
import org.zeroj.bbs.BbsPresentationCodec;
import org.zeroj.bbs.BbsPublicKey;
import org.zeroj.bbs.BbsService;

import java.util.Objects;

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
        this.service = Objects.requireNonNull(service, "BBS service required");
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        if (envelope == null) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Proof envelope must not be null");
        }
        if (envelope.proofSystem() != ProofSystemId.BBS) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                    "BBS verifier only supports proof system bbs");
        }
        if (envelope.curve() != CurveId.BLS12_381) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNSUPPORTED_CURVE,
                    "BBS verifier only supports BLS12-381");
        }
        var bindingError = EnvelopeBinding.validateBinding(envelope, material);
        if (bindingError.isPresent()) {
            return bindingError.get();
        }
        if (envelope.proofFormat().isPresent()
                && !BbsCiphersuite.DEFAULT_PROOF_FORMAT.equals(envelope.proofFormat().get())) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Unsupported BBS proof format: " + envelope.proofFormat().get());
        }

        try {
            var presentation = BbsPresentationCodec.decode(envelope.proofBytes());
            BbsCiphersuite ciphersuite = presentation.proof().ciphersuite();
            BbsService verifierService = service.provider().ciphersuite() == ciphersuite
                    ? service
                    : BbsService.pureJava(ciphersuite);
            BbsPublicKey publicKey = new BbsPublicKey(material.vkBytes(), ciphersuite);
            boolean valid = verifierService.verifyPresentation(publicKey, presentation);
            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("BBS proof verification failed");
        } catch (BbsException | IllegalArgumentException e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Malformed BBS presentation or public key: " + e.getMessage());
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
