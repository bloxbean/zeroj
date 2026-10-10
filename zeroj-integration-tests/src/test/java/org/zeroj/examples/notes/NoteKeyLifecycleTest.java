package org.zeroj.examples.notes;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.ConfidentialNotes;
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteReaderKey;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.examples.annotation.AnnotatedElGamalDleqCircuit;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0055 D2 and Q6 through the public API, from outside the library's package: a wallet proves
 * possession of its viewing key with a real Groth16 DLEQ proof (the {@code elgamal-jubjub-v1}
 * §9.2 relation), a registry verifies it, and a viewing key survives a restart through
 * {@code exportSecret}/{@code restore} and still reads its old deliveries.
 */
class NoteKeyLifecycleTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static CircuitBuilder circuit;
    private static Groth16Keys keys;
    private static String vkJson;

    @BeforeAll
    static void setup() {
        circuit = AnnotatedElGamalDleqCircuit.build();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(0x55d1L));
        vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
    }

    private static String prove(DleqStatement statement, BigInteger secret) {
        List<BigInteger> pub = statement.publicInputs();
        String[] names = {"baseU", "baseV", "keyU", "keyV", "shareU", "shareV"};
        Map<String, List<BigInteger>> w = new HashMap<>();
        for (int i = 0; i < 6; i++) w.put(names[i], List.of(pub.get(i)));
        w.put("secret", List.of(secret));
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        BigInteger[] witness = circuit.calculateWitness(w, CurveId.BLS12_381);
        return SnarkjsGroth16Json.proofJson(keys.prove(witness, r1cs.constraints()));
    }

    private static boolean verify(String proofJson, List<BigInteger> publicInputs) {
        var circuitId = new CircuitId("note-viewing-key-possession");
        String publicJson = SnarkjsGroth16Json.publicJson(publicInputs.toArray(new BigInteger[0]));
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, circuitId);
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, circuitId);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }

    @Test
    @DisplayName("Possession: a wallet proves its viewing key; the registry admits it, and refuses the same proof for another key")
    void possession() {
        NoteViewingKey wallet = NoteViewingKey.generate(RANDOM);
        String proof = wallet.provePossession(NoteKeyLifecycleTest::prove);
        byte[] encoded = wallet.readerKey().encode();

        NoteReaderKey registered = NoteReaderKey.verified(encoded,
                s -> s.kind() == DleqStatement.Kind.POSSESSION && verify(proof, s.publicInputs()));
        assertEquals(wallet.readerKey(), registered);

        byte[] otherKey = NoteViewingKey.generate(RANDOM).readerKey().encode();
        assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.verified(otherKey,
                s -> s.kind() == DleqStatement.Kind.POSSESSION && verify(proof, s.publicInputs())),
                "a proof for one key does not register another");

        wallet.destroy();
        assertThrows(IllegalStateException.class, () -> wallet.provePossession(NoteKeyLifecycleTest::prove));
    }

    @Test
    @DisplayName("Restore: an exported secret restores the key, which reads the deliveries made before the restart")
    void restoreReadsOldDeliveries() {
        NoteViewingKey original = NoteViewingKey.generate(RANDOM);
        NoteOpening opening = NoteOpening.random(BigInteger.valueOf(123_456_789L), RANDOM);
        byte[] delivery = ConfidentialNotes.seal(opening, List.of(original.readerKey()), RANDOM).get(0);

        byte[] stored = original.exportSecret();
        original.destroy();
        NoteViewingKey restored = NoteViewingKey.restore(stored);
        Arrays.fill(stored, (byte) 0);

        assertEquals(original.readerKey(), restored.readerKey());
        JubjubPoint c = opening.commitment().normalized();
        NoteOpening opened = NoteScanner.of(restored).open(delivery, c.affineU(), c.affineV()).orElseThrow();
        assertEquals(opening.value(), opened.value());
        assertEquals(opening.blinding(), opened.blinding());
        assertThrows(IllegalStateException.class, original::exportSecret, "a destroyed key exports nothing");
    }

    @Test
    @DisplayName("Restore refuses anything but a canonical 32-byte secret in [1, l)")
    void restoreRefusals() {
        assertThrows(IllegalArgumentException.class, () -> NoteViewingKey.restore(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> NoteViewingKey.restore(new byte[33]));
        assertThrows(IllegalArgumentException.class, () -> NoteViewingKey.restore(new byte[32]), "zero");
        byte[] l = JubjubCurve.SUBGROUP_ORDER.toByteArray();
        byte[] l32 = new byte[32];
        System.arraycopy(l, Math.max(0, l.length - 32), l32, Math.max(0, 32 - l.length), Math.min(32, l.length));
        assertThrows(IllegalArgumentException.class, () -> NoteViewingKey.restore(l32), "sk = l");
        byte[] exported = NoteViewingKey.generate(RANDOM).exportSecret();
        byte[] copy = exported.clone();
        NoteViewingKey restored = NoteViewingKey.restore(exported);
        Arrays.fill(exported, (byte) 0);
        assertArrayEquals(copy, restored.exportSecret(), "restore does not keep the caller's array");
        assertTrue(restored.toString().contains("redacted"));
    }
}
