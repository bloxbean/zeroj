package org.zeroj.examples.annotation;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.lib.jubjub.AuthenticatedDkgMessage;
import org.zeroj.circuit.lib.jubjub.DkgAdmissionVerifier;
import org.zeroj.circuit.lib.jubjub.DkgConfig;
import org.zeroj.circuit.lib.jubjub.DkgKeyDirectory;
import org.zeroj.circuit.lib.jubjub.DkgMessage;
import org.zeroj.circuit.lib.jubjub.DkgParticipant;
import org.zeroj.circuit.lib.jubjub.DkgShareDelivery;
import org.zeroj.circuit.lib.jubjub.DkgShareDeliveryKeys;
import org.zeroj.circuit.lib.jubjub.DkgTranscript;
import org.zeroj.circuit.lib.jubjub.DleqStatement;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.EncryptionStatement;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ThresholdKeyContext;
import org.zeroj.circuit.lib.jubjub.ThresholdKeyShare;
import org.zeroj.circuit.lib.jubjub.VerifiedDecryptionShare;
import org.zeroj.circuit.lib.jubjub.VerifiedKeyShare;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0052 M2 end to end with Groth16 on BLS12-381: the {@code elgamal-jubjub-v1} relations
 * through the annotation path, driving the host API's verified admission, possession checks and
 * share verification.
 *
 * <p>The verifiers below check a real Groth16 proof against the statement the library hands
 * them, verbatim. That is the adapter shape the delegated-verifier obligation describes.
 * Changing any single public input makes verification fail, so every public input is bound
 * (ADR-0045; setup additionally refuses unconstrained public wires).
 */
class AnnotatedElGamalTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static Keys ballotKeys;
    private static Keys dleqKeys;

    private record Keys(CircuitBuilder circuit, Groth16Keys keys, String vkJson, String name) {}

    @BeforeAll
    static void setup() {
        ballotKeys = keys(AnnotatedElGamalBallotCircuit.build(), "annotation-elgamal-ballot", 0xe1L);
        dleqKeys = keys(AnnotatedElGamalDleqCircuit.build(), "annotation-elgamal-dleq", 0xd1L);
    }

    private static Keys keys(CircuitBuilder circuit, String name, long seed) {
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        var keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(seed));
        return new Keys(circuit, keys, SnarkjsGroth16Json.verificationKeyJson(keys), name);
    }

    private static String prove(Keys k, Map<String, List<BigInteger>> witnessMap) {
        var r1cs = k.circuit().compileR1CS(CurveId.BLS12_381);
        BigInteger[] witness = k.circuit().calculateWitness(witnessMap, CurveId.BLS12_381);
        return SnarkjsGroth16Json.proofJson(k.keys().prove(witness, r1cs.constraints()));
    }

    private static boolean verify(Keys k, String proofJson, List<BigInteger> publicInputs) {
        var circuitId = new CircuitId(k.name());
        String publicJson = SnarkjsGroth16Json.publicJson(publicInputs.toArray(new BigInteger[0]));
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, k.vkJson(), publicJson, circuitId);
        var material = VerificationMaterial.of(k.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, circuitId);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }

    private static Map<String, List<BigInteger>> ballotWitness(EncryptionStatement s, ElGamalEncryption e) {
        List<BigInteger> pub = s.publicInputs();
        String[] names = {"keyU", "keyV", "handleU", "handleV", "blindedU", "blindedV"};
        Map<String, List<BigInteger>> w = new HashMap<>();
        for (int i = 0; i < 6; i++) w.put(names[i], List.of(pub.get(i)));
        w.put("vote", List.of(e.message()));
        w.put("randomness", List.of(e.randomness()));
        return w;
    }

    private static Map<String, List<BigInteger>> dleqWitness(DleqStatement s, BigInteger secret) {
        List<BigInteger> pub = s.publicInputs();
        String[] names = {"baseU", "baseV", "keyU", "keyV", "shareU", "shareV"};
        Map<String, List<BigInteger>> w = new HashMap<>();
        for (int i = 0; i < 6; i++) w.put(names[i], List.of(pub.get(i)));
        w.put("secret", List.of(secret));
        return w;
    }

    @Test
    @DisplayName("Full flow: possession proofs → joint key → proved ballots admitted → proved shares → tally")
    void endToEnd() {
        // Three trustees, each proving possession of its key share.
        List<ElGamalSecretKey> trustees = List.of(
                ElGamalSecretKey.generate(RANDOM), ElGamalSecretKey.generate(RANDOM), ElGamalSecretKey.generate(RANDOM));
        Map<String, String> possessionProofs = new HashMap<>();
        for (ElGamalSecretKey t : trustees) {
            DleqStatement pop = t.possessionStatement();
            possessionProofs.put(pop.publicInputs().toString(), prove(dleqKeys, dleqWitness(pop, t.secretScalar())));
        }
        List<VerifiedKeyShare> shares = new ArrayList<>();
        for (ElGamalSecretKey t : trustees) {
            shares.add(VerifiedKeyShare.verify(t.publicKey().encode(), s ->
                    s.kind() == DleqStatement.Kind.POSSESSION
                            && verify(dleqKeys, possessionProofs.get(s.publicInputs().toString()), s.publicInputs())));
        }
        NOfNKeyContext election = ElGamalPublicKey.aggregate(shares);

        // Voters encrypt and prove; the tallier admits each ballot by verifying its proof.
        int[] votes = {1, 0, 1, 1};
        List<ElGamalCiphertext> admitted = new ArrayList<>();
        for (int vote : votes) {
            ElGamalEncryption ballot = ElGamal.encryptWithOpening(election, BigInteger.valueOf(vote), 1, RANDOM);
            String proof = prove(ballotKeys, ballotWitness(ballot.statement(), ballot));
            RawElGamalCiphertext received = RawElGamalCiphertext.decode(ballot.ciphertext().encode());
            admitted.add(ElGamal.admit(received, election, 1,
                    s -> s.width() == 1 && verify(ballotKeys, proof, s.publicInputs())));
        }
        ElGamalCiphertext total = ElGamalCiphertext.sum(admitted);

        // Each trustee publishes a share and proves it; the tallier verifies every share.
        List<VerifiedDecryptionShare> verified = new ArrayList<>();
        for (ElGamalSecretKey t : trustees) {
            VerifiedDecryptionShare own = ElGamal.decryptionShare(t, total);
            String proof = prove(dleqKeys, dleqWitness(own.statement(), t.secretScalar()));
            verified.add(VerifiedDecryptionShare.verify(total, t.publicKey(), own.encode(), s ->
                    s.kind() == DleqStatement.Kind.DECRYPTION_SHARE && verify(dleqKeys, proof, s.publicInputs())));
        }
        assertEquals(3, ElGamal.decrypt(total, verified, total.bound().longValueExact()));
    }

    @Test
    @DisplayName("Ballot proof: every one of the six public inputs is bound; another key's statement fails")
    void ballotPublicInputsBound() {
        ElGamalSecretKey sk = ElGamalSecretKey.generate(RANDOM);
        NOfNKeyContext ctx = NOfNKeyContext.singleKey(sk);
        ElGamalEncryption ballot = ElGamal.encryptWithOpening(ctx, BigInteger.ONE, 1, RANDOM);
        List<BigInteger> pub = ballot.statement().publicInputs();
        String proof = prove(ballotKeys, ballotWitness(ballot.statement(), ballot));
        assertTrue(verify(ballotKeys, proof, pub));
        for (int i = 0; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, pub.get(i).add(BigInteger.ONE));
            assertFalse(verify(ballotKeys, proof, changed), "public input " + i);
        }
        // Admission under a different context presents a different statement: rejected.
        NOfNKeyContext other = NOfNKeyContext.singleKey(ElGamalSecretKey.generate(RANDOM));
        assertThrows(IllegalArgumentException.class, () -> ElGamal.admit(ballot.ciphertext().raw(), other, 1,
                s -> verify(ballotKeys, proof, s.publicInputs())));
    }

    @Test
    @DisplayName("DLEQ proof: every public input bound; P = D = O with x = 0 proves and verifies (threshold zero share)")
    void dleqPublicInputsAndIdentity() {
        ElGamalSecretKey sk = ElGamalSecretKey.generate(RANDOM);
        DleqStatement pop = sk.possessionStatement();
        String proof = prove(dleqKeys, dleqWitness(pop, sk.secretScalar()));
        List<BigInteger> pub = pop.publicInputs();
        assertTrue(verify(dleqKeys, proof, pub));
        for (int i = 0; i < pub.size(); i++) {
            List<BigInteger> changed = new ArrayList<>(pub);
            changed.set(i, pub.get(i).add(BigInteger.ONE));
            assertFalse(verify(dleqKeys, proof, changed), "public input " + i);
        }
        JubjubPoint base = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(12345)).normalized();
        JubjubPoint identity = JubjubPoint.IDENTITY;
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("baseU", List.of(base.u()));
        w.put("baseV", List.of(base.v()));
        w.put("keyU", List.of(identity.u()));
        w.put("keyV", List.of(identity.v()));
        w.put("shareU", List.of(identity.u()));
        w.put("shareV", List.of(identity.v()));
        w.put("secret", List.of(BigInteger.ZERO));
        String zeroProof = prove(dleqKeys, w);
        assertTrue(verify(dleqKeys, zeroProof,
                List.of(base.u(), base.v(), BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO, BigInteger.ONE)));
    }

    @Test
    @DisplayName("Threshold E2E (ADR-0053): 2-of-3 DKG → proved ballots admitted → two proved shares decrypt")
    void thresholdEndToEnd() {
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            byte[] key = new byte[32];
            Arrays.fill(key, (byte) j);
            roster.add(key);
        }
        DkgConfig config = DkgConfig.create(1, 3, roster, "e2e".getBytes(StandardCharsets.UTF_8), 1);
        List<DkgParticipant> participants = new ArrayList<>();
        for (int j = 1; j <= 3; j++) participants.add(DkgParticipant.create(config, j, RANDOM));
        List<DkgMessage> outgoing = new ArrayList<>();
        for (DkgParticipant p : participants) outgoing.addAll(p.start());
        for (int round = 1; round <= 7; round++) {
            for (DkgMessage m : outgoing) {
                for (DkgParticipant p : participants) {
                    if (m.kind() == DkgMessage.Kind.SHARE) {
                        if (m.subject() == p.id()) p.receivePrivate(m.sender(), m.encode());
                    } else {
                        p.receiveBroadcast(m.sender(), m.encode());
                    }
                }
            }
            outgoing = new ArrayList<>();
            for (DkgParticipant p : participants) outgoing.addAll(p.closeRound());
        }
        List<ThresholdKeyShare> keys = new ArrayList<>();
        for (DkgParticipant p : participants) keys.add(p.result());
        ThresholdKeyContext context = keys.get(0).context();
        assertNotNull(context);

        int[] votes = {1, 1, 0};
        List<ElGamalCiphertext> admitted = new ArrayList<>();
        for (int vote : votes) {
            ElGamalEncryption ballot = ElGamal.encryptWithOpening(context, BigInteger.valueOf(vote), 1, RANDOM);
            String proof = prove(ballotKeys, ballotWitness(ballot.statement(), ballot));
            admitted.add(ElGamal.admit(RawElGamalCiphertext.decode(ballot.ciphertext().encode()), context, 1,
                    s -> s.width() == 1 && verify(ballotKeys, proof, s.publicInputs())));
        }
        ElGamalCiphertext total = ElGamalCiphertext.sum(admitted);
        List<VerifiedDecryptionShare> verified = new ArrayList<>();
        for (ThresholdKeyShare k : List.of(keys.get(0), keys.get(2))) {
            VerifiedDecryptionShare own = ElGamal.decryptionShare(k, total);
            String proof = prove(dleqKeys, dleqWitness(own.statement(), k.secretScalar()));
            verified.add(VerifiedDecryptionShare.verify(total, k.id(), own.encode(),
                    s -> verify(dleqKeys, proof, s.publicInputs())));
        }
        assertEquals(2, ElGamal.decrypt(total, verified, total.bound().longValueExact()));
    }

    /** Board authenticity for the encrypted end-to-end test: a keyed hash under the roster key. */
    private static final class BoardAuth implements DkgAdmissionVerifier {
        static byte[] tag(byte[] key, byte[] message) {
            try {
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                sha.update(key);
                sha.update(message);
                return sha.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
            return Arrays.equals(tag(rosterKey, message), authenticator);
        }

        @Override
        public boolean roundClosed(DkgConfig config, int round, List<byte[]> canonicalMessages, byte[] evidence) {
            return true; // every post below is in its window
        }
    }

    @Test
    @DisplayName("ADR-0054: DKG with HPKE-encrypted SHARE delivery on one board, admission from the board, then a Groth16-proved tally")
    void thresholdEndToEndOverEncryptedBoard() {
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            byte[] key = new byte[32];
            Arrays.fill(key, (byte) (j + 10));
            roster.add(key);
        }
        DkgConfig config = DkgConfig.create(1, 3, roster, "e2e-hpke".getBytes(StandardCharsets.UTF_8), 1);
        BoardAuth auth = new BoardAuth();
        List<DkgParticipant> participants = new ArrayList<>();
        List<DkgShareDeliveryKeys> deliveryKeys = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            participants.add(DkgParticipant.create(config, j, RANDOM));
            deliveryKeys.add(DkgShareDeliveryKeys.generate(config, j, RANDOM));
        }

        // Round 0: announcements; the directory from the final window.
        List<AuthenticatedDkgMessage> round0 = new ArrayList<>();
        for (DkgShareDeliveryKeys k : deliveryKeys) {
            round0.add(new AuthenticatedDkgMessage(k.announcement(), BoardAuth.tag(config.rosterKey(k.id()), k.announcement())));
        }
        DkgKeyDirectory directory = DkgKeyDirectory.fromRound0(config, round0, auth);

        // Round 1: envelopes first, then COMMITMENTS (D7a); closeRound1 is the barrier.
        List<AuthenticatedDkgMessage> envelopes = new ArrayList<>();
        List<AuthenticatedDkgMessage> commitments = new ArrayList<>();
        for (DkgParticipant p : participants) {
            DkgShareDelivery.SealedDealing dealing = DkgShareDelivery.start(p, directory, deliveryKeys.get(p.id() - 1), RANDOM);
            assertEquals(2, dealing.envelopes().size());
            for (byte[] e : dealing.envelopes()) envelopes.add(new AuthenticatedDkgMessage(e, BoardAuth.tag(config.rosterKey(p.id()), e)));
            for (DkgMessage m : dealing.broadcasts()) {
                commitments.add(new AuthenticatedDkgMessage(m.encode(), BoardAuth.tag(config.rosterKey(p.id()), m.encode())));
            }
        }
        List<AuthenticatedDkgMessage> round1 = new ArrayList<>(envelopes);
        round1.addAll(commitments);
        List<List<AuthenticatedDkgMessage>> board = new ArrayList<>();
        for (int r = 0; r <= 7; r++) board.add(new ArrayList<>());
        board.get(1).addAll(round1);
        List<DkgMessage> outgoing = new ArrayList<>();
        for (DkgParticipant p : participants) {
            outgoing.addAll(DkgShareDelivery.closeRound1(p, directory, deliveryKeys.get(p.id() - 1), round1, auth));
        }
        assertTrue(deliveryKeys.stream().allMatch(DkgShareDeliveryKeys::isDestroyed));
        assertTrue(outgoing.isEmpty(), "no complaints");

        // Rounds 2–7 unchanged.
        for (int round = 2; round <= 7; round++) {
            for (DkgMessage m : outgoing) {
                board.get(round).add(new AuthenticatedDkgMessage(m.encode(), BoardAuth.tag(config.rosterKey(m.sender()), m.encode())));
                for (DkgParticipant p : participants) p.receiveBroadcast(m.sender(), m.encode());
            }
            outgoing = new ArrayList<>();
            for (DkgParticipant p : participants) outgoing.addAll(p.closeRound());
        }
        ThresholdKeyContext own = participants.get(0).result().context();

        // Admission from the board: envelopes are junk to the threshold profile and drop out of round 1.
        assertEquals(3, DkgTranscript.deliveredRound(config, 1, board.get(1), auth).size(), "only the COMMITMENTS");
        List<AuthenticatedDkgMessage> transcript = new ArrayList<>();
        for (int r = 1; r <= 6; r++) {
            for (byte[] m : DkgTranscript.deliveredRound(config, r, board.get(r), auth)) {
                transcript.add(new AuthenticatedDkgMessage(m, BoardAuth.tag(config.rosterKey(m[34] & 0xFF), m)));
            }
        }
        Map<Integer, byte[]> closure = new HashMap<>();
        for (int r = 1; r <= 7; r++) closure.put(r, new byte[0]);
        ThresholdKeyContext admitted = ThresholdKeyContext.admit(config, transcript, closure, board.get(7), auth);
        assertEquals(own, admitted);

        // Ballots, Groth16-proved shares and the tally, as in thresholdEndToEnd.
        List<ElGamalCiphertext> ballots = new ArrayList<>();
        for (int vote : new int[]{1, 0, 1}) {
            ElGamalEncryption ballot = ElGamal.encryptWithOpening(admitted, BigInteger.valueOf(vote), 1, RANDOM);
            String proof = prove(ballotKeys, ballotWitness(ballot.statement(), ballot));
            ballots.add(ElGamal.admit(RawElGamalCiphertext.decode(ballot.ciphertext().encode()), admitted, 1,
                    st -> st.width() == 1 && verify(ballotKeys, proof, st.publicInputs())));
        }
        ElGamalCiphertext total = ElGamalCiphertext.sum(ballots);
        List<VerifiedDecryptionShare> shares = new ArrayList<>();
        for (int id : new int[]{2, 3}) {
            ThresholdKeyShare k = ThresholdKeyShare.restore(admitted, id, participants.get(id - 1).result().secretScalar());
            VerifiedDecryptionShare mine = ElGamal.decryptionShare(k, total);
            String proof = prove(dleqKeys, dleqWitness(mine.statement(), k.secretScalar()));
            shares.add(VerifiedDecryptionShare.verify(total, id, mine.encode(), st -> verify(dleqKeys, proof, st.publicInputs())));
        }
        assertEquals(2, ElGamal.decrypt(total, shares, total.bound().longValueExact()));
    }
}
