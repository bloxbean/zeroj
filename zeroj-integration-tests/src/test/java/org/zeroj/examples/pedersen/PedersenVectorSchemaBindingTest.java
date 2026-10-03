package org.zeroj.examples.pedersen;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.backend.spi.ZkVerifier;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenSchemaRegistry;
import org.zeroj.circuit.lib.jubjub.PedersenVectorCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.lib.zk.ZkPedersenVector;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 M3: {@code pedersen-jubjub-vector-v1} schema binding at the real verifier boundary.
 *
 * <p>Everything here crosses the same boundary a deployment does: Groth16 proofs from the
 * pure-Java prover, serialised to snarkjs JSON, verified by the pure-Java verifier from the
 * serialised verification key, with the schema-digest public input checked against a
 * {@link PedersenSchemaRegistry}. No typed Java wrapper is trusted on the verifier side.
 *
 * <p>Schemas B differ from A only in version, identifier or per-index meaning — same dimension,
 * same widths, so their circuits have identical shape — or only in one width.
 */
class PedersenVectorSchemaBindingTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final ZkVerifier VERIFIER = new Groth16BLS12381PureJavaVerifier();

    private static final List<Entry> ENTRIES = List.of(new Entry("amount", 64), new Entry("asset", 32));
    private static final PedersenVectorSchema A = PedersenVectorSchema.of("zeroj.example.balance", 1, ENTRIES);
    private static final PedersenVectorSchema B_VERSION = PedersenVectorSchema.of("zeroj.example.balance", 2, ENTRIES);
    private static final PedersenVectorSchema B_ID = PedersenVectorSchema.of("zeroj.example.other", 1, ENTRIES);
    private static final PedersenVectorSchema B_MEANING = PedersenVectorSchema.of("zeroj.example.balance", 1,
            List.of(new Entry("fee", 64), new Entry("asset", 32)));
    private static final PedersenVectorSchema B_WIDTH = PedersenVectorSchema.of("zeroj.example.balance", 1,
            List.of(new Entry("amount", 64), new Entry("asset", 33)));

    private static Deployment deployA;
    private static Map<PedersenVectorSchema, Deployment> deployB;

    /** One deployed circuit: its schema, constraint system, keys and serialised verification key. */
    record Deployment(PedersenVectorSchema schema, CircuitBuilder circuit, R1CSConstraintSystem r1cs,
                      Groth16Keys keys, String vkJson, byte[] vkId) {}

    /** A serialised proof as it travels to a verifier. */
    record Presentation(String proofJson, String publicJson, BigInteger[] publicInputs) {}

    @BeforeAll
    static void deploy() throws Exception {
        deployA = deploy(A, 11);
        deployB = new HashMap<>();
        int seed = 12;
        for (var b : List.of(B_VERSION, B_ID, B_MEANING, B_WIDTH)) {
            deployB.put(b, deploy(b, seed++));
        }
    }

    // ------------------------------------------------------------------
    //  Statement binding (spec §5)
    // ------------------------------------------------------------------

    @Test
    @DisplayName("An honest proof under A is accepted by A's verifier and registry")
    void honestProofAccepted() {
        var opening = opening();
        var c = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding());
        var presentation = prove(deployA, A.digest(), c, opening);
        assertTrue(accepts(registryFor(deployA), deployA, presentation));
    }

    @Test
    @DisplayName("Cross-schema reuse with identical shape is rejected at the serialised verifier boundary")
    void crossSchemaSameShapeRejected() {
        var opening = opening();
        var c = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding());
        var proofUnderA = prove(deployA, A.digest(), c, opening);

        for (var b : List.of(B_VERSION, B_ID, B_MEANING)) {
            Deployment verifierB = deployB.get(b);
            var registryB = registryFor(verifierB);

            // The B verifier with its own key rejects A's proof on the pairing check...
            assertFalse(groth16Valid(verifierB, proofUnderA), b + ": A's proof must not verify under B's key");
            // ...and its registry rejects A's digest regardless of the pairing outcome.
            assertThrows(IllegalArgumentException.class,
                    () -> registryB.requireStatement(verifierB.vkId(), proofUnderA.publicInputs()[0]), b.toString());
            // Swapping in A's verification key does not help: B's registry does not know it.
            assertTrue(groth16Valid(deployA, proofUnderA), "sanity: the proof is valid under A's own key");
            assertThrows(IllegalArgumentException.class,
                    () -> registryB.requireStatement(deployA.vkId(), proofUnderA.publicInputs()[0]), b.toString());
            assertFalse(accepts(registryB, verifierB, proofUnderA));

            // A prover cannot put B's digest into A's statement: A's circuit constrains it.
            assertThrows(ArithmeticException.class,
                    () -> deployA.circuit().calculateWitness(witness(b.digest(), c, opening), CurveId.BLS12_381),
                    b + ": A's circuit must refuse B's digest");
        }
    }

    @Test
    @DisplayName("A width-only difference is an incompatible schema and is rejected the same way")
    void widthOnlyDifferenceRejected() {
        assertNotEquals(A.digest(), B_WIDTH.digest());
        var opening = opening();
        var c = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding());
        var proofUnderA = prove(deployA, A.digest(), c, opening);
        Deployment verifier = deployB.get(B_WIDTH);
        assertFalse(groth16Valid(verifier, proofUnderA));
        assertThrows(IllegalArgumentException.class,
                () -> registryFor(verifier).requireStatement(verifier.vkId(), proofUnderA.publicInputs()[0]));
    }

    // ------------------------------------------------------------------
    //  Provenance (spec §6): a valid proof is not provenance
    // ------------------------------------------------------------------

    /**
     * The relabelling attack the provenance rule exists for. {@code C} is issued under A and its
     * opening leaks. The adversary produces a fresh proof under B_MEANING — same shape — with
     * B's correct digest and key. Every B cryptographic check passes. Only the authenticated
     * issuance record, which binds {@code C} to A's digest, stops the reinterpretation; and a
     * consumer without a record must fail closed.
     */
    @Test
    @DisplayName("Adversarial relabelling: a fresh valid proof under B for a commitment issued under A is rejected by provenance")
    void adversarialRelabelling() {
        var opening = opening();
        var issued = PedersenVectorCommitment.commit(A, opening.values(), opening.blinding());

        // Trusted issuance: the issuer verifies its own proof and writes the authenticated record.
        var issuerProof = prove(deployA, A.digest(), issued, opening);
        assertTrue(accepts(registryFor(deployA), deployA, issuerProof));
        IssuanceRecords records = new IssuanceRecords();
        records.issue(issued, A);

        // The adversary knows the opening and proves the SAME point under B_MEANING.
        Deployment b = deployB.get(B_MEANING);
        var relabelled = PedersenVectorCommitment.commit(B_MEANING, opening.values(), opening.blinding());
        assertEquals(HexFormat.of().formatHex(issued.toBytes()), HexFormat.of().formatHex(relabelled.toBytes()),
                "same opening, same shape: the point is identical under both schemas");
        var adversaryProof = prove(b, B_MEANING.digest(), relabelled, opening);
        assertTrue(groth16Valid(b, adversaryProof), "the adversary's proof is cryptographically valid");
        assertDoesNotThrow(() -> registryFor(b).requireStatement(b.vkId(), adversaryProof.publicInputs()[0]),
                "and its digest matches B's registry entry");

        byte[] presentedPoint = pointBytes(adversaryProof);
        BigInteger presentedDigest = adversaryProof.publicInputs()[0];
        // A consumer of B-artifacts with the issuance record rejects: C was issued under A.
        assertThrows(IllegalArgumentException.class,
                () -> records.requireIssuedUnder(presentedPoint, B_MEANING, presentedDigest));
        // A consumer of A-artifacts rejects the B-labelled presentation as well.
        assertThrows(IllegalArgumentException.class,
                () -> records.requireIssuedUnder(presentedPoint, A, presentedDigest));
        // Fail closed: no record, no acceptance.
        assertThrows(IllegalArgumentException.class,
                () -> new IssuanceRecords().requireIssuedUnder(presentedPoint, B_MEANING, presentedDigest));
        // The genuine A presentation passes.
        assertDoesNotThrow(() -> records.requireIssuedUnder(pointBytes(issuerProof), A, issuerProof.publicInputs()[0]));
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    /**
     * Test stand-in for an application's authenticated issuance store (spec §6). In production the
     * record is an output guarded by the issuing policy or an authorised issuer's signed record;
     * this map only models the binding it must provide: exact commitment encoding to schema digest.
     */
    static final class IssuanceRecords {
        private final Map<String, BigInteger> byCommitment = new HashMap<>();

        void issue(PedersenVectorCommitment c, PedersenVectorSchema schema) {
            byCommitment.put(HexFormat.of().formatHex(c.toBytes()), schema.digest());
        }

        void requireIssuedUnder(byte[] commitment, PedersenVectorSchema expected, BigInteger presentedDigest) {
            BigInteger recorded = byCommitment.get(HexFormat.of().formatHex(commitment));
            if (recorded == null) {
                throw new IllegalArgumentException("no issuance record for this commitment (fail closed)");
            }
            if (!recorded.equals(expected.digest()) || !recorded.equals(presentedDigest)) {
                throw new IllegalArgumentException("commitment was issued under a different schema");
            }
        }
    }

    record Opening(List<BigInteger> values, BigInteger blinding) {}

    private static Opening opening() {
        return new Opening(List.of(BigInteger.valueOf(1_000_000), BigInteger.valueOf(7)),
                PedersenCommitment.randomBlinding(RANDOM));
    }

    private static Deployment deploy(PedersenVectorSchema schema, int seed) throws Exception {
        var circuit = CircuitBuilder.create("vector-binding-" + seed)
                .publicVar("schemaDigest").publicVar("u").publicVar("v")
                .secretVar("x0").secretVar("x1").secretVar("r")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    var binding = ZkPedersenVector.bindSchema(zk, schema, ZkField.publicInput(cs, "schemaDigest"));
                    ZkPedersenVector.commit(zk, binding,
                                    List.of(ZkUInt.secret(cs, "x0", schema.width(0)),
                                            ZkUInt.secret(cs, "x1", schema.width(1))),
                                    ZkUInt.secret(cs, "r", 252))
                            .assertAffineEquals(zk, ZkField.publicInput(cs, "u"), ZkField.publicInput(cs, "v"));
                });
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(0x5eed00L + seed));
        String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
        byte[] vkId = MessageDigest.getInstance("SHA-256").digest(vkJson.getBytes(StandardCharsets.UTF_8));
        return new Deployment(schema, circuit, r1cs, keys, vkJson, vkId);
    }

    private static Map<String, List<BigInteger>> witness(BigInteger digest, PedersenVectorCommitment c, Opening o) {
        return Map.of(
                "schemaDigest", List.of(digest),
                "u", List.of(c.point().affineU()),
                "v", List.of(c.point().affineV()),
                "x0", List.of(o.values().get(0)),
                "x1", List.of(o.values().get(1)),
                "r", List.of(o.blinding()));
    }

    private static Presentation prove(Deployment d, BigInteger digest, PedersenVectorCommitment c, Opening o) {
        BigInteger[] w = d.circuit().calculateWitness(witness(digest, c, o), CurveId.BLS12_381);
        var proof = d.keys().prove(w, d.r1cs().constraints());
        BigInteger[] pub = new BigInteger[d.r1cs().numPublicInputs()];
        System.arraycopy(w, 1, pub, 0, pub.length);
        return new Presentation(SnarkjsGroth16Json.proofJson(proof), SnarkjsGroth16Json.publicJson(pub), pub);
    }

    private static boolean groth16Valid(Deployment verifierKey, Presentation p) {
        var circuitId = new CircuitId("adr-0051-vector-" + verifierKey.schema().id());
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(p.proofJson(), verifierKey.vkJson(), p.publicJson(), circuitId);
        var material = VerificationMaterial.of(verifierKey.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, circuitId);
        return VERIFIER.verify(envelope, material).proofValid();
    }

    /** A verifier deployment: pairing check under its own key, then the registry statement check. */
    private static boolean accepts(PedersenSchemaRegistry registry, Deployment verifierKey, Presentation p) {
        if (!groth16Valid(verifierKey, p)) return false;
        try {
            registry.requireStatement(verifierKey.vkId(), p.publicInputs()[0]);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private static PedersenSchemaRegistry registryFor(Deployment d) {
        return PedersenSchemaRegistry.builder().accept(d.vkId(), d.schema()).build();
    }

    private static byte[] pointBytes(Presentation p) {
        return JubjubPoint.fromAffine(p.publicInputs()[1], p.publicInputs()[2]).toBytes();
    }
}
