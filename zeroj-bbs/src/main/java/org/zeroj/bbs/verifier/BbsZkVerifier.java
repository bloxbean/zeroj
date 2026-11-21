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

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * ZeroJ verifier adapter for CFRG BBS draft-10 presentations.
 *
 * <p>Authenticated BBS disclosures (revealed messages, header, and presentation header) are carried
 * inside the canonical CBOR presentation in {@code envelope.proofBytes()}, not in the SNARK-oriented
 * {@code envelope.publicInputs()} field-element vector. Consequently, {@code envelope.publicInputs()}
 * must be empty.</p>
 */
public final class BbsZkVerifier implements ZkVerifier {
    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.BBS, CurveId.BLS12_381, "bbs-bls12381-java");

    private final BbsService service;
    private final Set<BbsCiphersuite> acceptedCiphersuites;
    private final boolean allowPureJavaDispatch;

    /**
     * Default verifier accepting all supported CFRG BBS ciphersuites via pure-Java providers.
     */
    public BbsZkVerifier() {
        this.service = BbsService.pureJava();
        this.acceptedCiphersuites = EnumSet.allOf(BbsCiphersuite.class);
        this.allowPureJavaDispatch = true;
    }

    /**
     * Verifier pinned to the explicit {@link BbsService} and its configured ciphersuite
     * (never silently downgrading a caller-configured provider to another provider or suite).
     */
    public BbsZkVerifier(BbsService service) {
        this(service, EnumSet.of(Objects.requireNonNull(service, "BBS service required")
                .provider().ciphersuite()));
    }

    /**
     * Verifier with an explicit accepted-ciphersuite policy.
     */
    public BbsZkVerifier(BbsService service, Set<BbsCiphersuite> acceptedCiphersuites) {
        this.service = Objects.requireNonNull(service, "BBS service required");
        Objects.requireNonNull(acceptedCiphersuites, "acceptedCiphersuites required");
        if (acceptedCiphersuites.isEmpty()) {
            throw new IllegalArgumentException("acceptedCiphersuites must not be empty");
        }
        this.acceptedCiphersuites = EnumSet.copyOf(acceptedCiphersuites);
        this.allowPureJavaDispatch = false;
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
        if (envelope.publicInputs().size() != 0) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                    "BBS proof envelopes carry disclosures in the CBOR presentation; publicInputs must be empty");
        }

        try {
            var presentation = BbsPresentationCodec.decode(envelope.proofBytes());
            BbsCiphersuite ciphersuite = presentation.proof().ciphersuite();
            if (!acceptedCiphersuites.contains(ciphersuite)) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                        "BBS ciphersuite is not accepted by verifier policy: " + ciphersuite);
            }
            BbsService verifierService;
            if (service.provider().ciphersuite() == ciphersuite) {
                verifierService = service;
            } else if (allowPureJavaDispatch) {
                verifierService = BbsService.pureJava(ciphersuite);
            } else {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                        "Configured BBS service does not support presentation ciphersuite: " + ciphersuite);
            }
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
