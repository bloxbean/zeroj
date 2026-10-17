package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentAcceptance;
import org.zeroj.api.commitment.CommitmentCheck;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentEnvelope;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentGroup;
import org.zeroj.api.commitment.CommitmentKey;
import org.zeroj.api.commitment.CommitmentKind;
import org.zeroj.api.commitment.CommitmentProfile;
import org.zeroj.api.commitment.CommitmentProfileId;
import org.zeroj.api.commitment.ProvenancePolicy;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.zeroj.circuit.lib.jubjub.PedersenScalarCommitmentTest.assertError;
import static org.zeroj.circuit.lib.jubjub.PedersenScalarCommitmentTest.concat;

/**
 * ADR-0059 M1 across the three Jubjub profiles: descriptors, envelopes (§9), the expected-profile
 * rule (§6.3), {@code CommitmentKey} (§12.1) and {@code CommitmentAcceptance} with real openings.
 */
class JubjubCommitmentProfilesTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] DOC = "invoice 2026-10-17 #42".getBytes(StandardCharsets.UTF_8);
    private static final PedersenVectorSchema SCHEMA_A = PedersenVectorSchema.of("zeroj.test.a", 1, List.of(
            new PedersenVectorSchema.Entry("amount", 64), new PedersenVectorSchema.Entry("asset", 32)));
    private static final PedersenVectorSchema SCHEMA_B = PedersenVectorSchema.of("zeroj.test.b", 1, List.of(
            new PedersenVectorSchema.Entry("amount", 64), new PedersenVectorSchema.Entry("asset", 32)));

    @Test
    @DisplayName("Descriptors carry the registry identifiers, kinds, group and 32-octet points (spec §2.3, §4)")
    void descriptors() {
        assertDescriptor(PedersenScalarCommitment.PROFILE, "pedersen-jubjub-v1", CommitmentKind.SCALAR);
        assertDescriptor(PedersenVectorCommitment.PROFILE, "pedersen-jubjub-vector-v1", CommitmentKind.VECTOR);
        assertDescriptor(PedersenBytesCommitment.PROFILE, "pedersen-jubjub-bytes-v1", CommitmentKind.BYTES);
        assertEquals(PedersenBytesCommitment.PROFILE_ID, PedersenBytesCommitment.PROFILE.id().value());
        assertSame(PedersenScalarCommitment.PROFILE, PedersenScalarCommitment.CODEC.profile());
        assertSame(PedersenBytesCommitment.PROFILE, PedersenBytesCommitment.CODEC.profile());
        assertSame(PedersenVectorCommitment.PROFILE, PedersenVectorCommitment.codec(SCHEMA_A).profile());
    }

    @Test
    @DisplayName("A second descriptor for a registered identifier is INVALID_CONFIGURATION (fail-closed duplicate)")
    void duplicateDescriptor() {
        // Force class initialization first, so this test cannot pre-empt the real definition.
        assertSame(PedersenScalarCommitment.PROFILE, PedersenScalarCommitment.CODEC.profile());
        assertSame(PedersenBytesCommitment.PROFILE, PedersenBytesCommitment.CODEC.profile());
        assertSame(PedersenVectorCommitment.PROFILE, PedersenVectorCommitment.codec(SCHEMA_A).profile());
        for (String id : List.of("pedersen-jubjub-v1", "pedersen-jubjub-vector-v1", "pedersen-jubjub-bytes-v1")) {
            assertError(CommitmentError.INVALID_CONFIGURATION, () -> CommitmentProfile.define(
                    CommitmentProfileId.of(id), CommitmentKind.SCALAR, CommitmentGroup.JUBJUB, 32));
        }
    }

    @Test
    @DisplayName("Envelopes are 52, 59 and 58 octets and round-trip under the expected codec")
    void envelopeLengths() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenScalarCommitment scalar = PedersenCommitment.commitScalar(BigInteger.TEN, r);
        PedersenVectorCommitment vector = PedersenVectorCommitment.commit(SCHEMA_A, values(10, 1), r);
        PedersenBytesCommitment bytes = PedersenCommitment.commitBytes(DOC, r);

        byte[] es = CommitmentEnvelope.encode(scalar);
        byte[] ev = CommitmentEnvelope.encode(vector);
        byte[] eb = CommitmentEnvelope.encode(bytes);
        assertEquals(52, es.length);
        assertEquals(59, ev.length);
        assertEquals(58, eb.length);
        assertArrayEquals(concat(new byte[]{1, 18}, "pedersen-jubjub-v1".getBytes(StandardCharsets.US_ASCII),
                scalar.toPointBytes()), es);

        assertEquals(scalar, CommitmentEnvelope.decode(es, PedersenScalarCommitment.CODEC));
        assertEquals(bytes, CommitmentEnvelope.decode(eb, PedersenBytesCommitment.CODEC));
        PedersenVectorCommitment back = CommitmentEnvelope.decode(ev, PedersenVectorCommitment.codec(SCHEMA_A));
        assertEquals(SCHEMA_A, back.schema());
        assertArrayEquals(vector.toBytes(), back.toPointBytes());
        assertTrue(back.verifyOpening(values(10, 1), r, PedersenVectorBoundPolicy.schemaWidths(SCHEMA_A)));
    }

    @Test
    @DisplayName("Envelope step 5 classes for every Jubjub codec: torsion and mixed NOT_IN_SUBGROUP, sign aliases MALFORMED")
    void envelopePointClasses() {
        List<CommitmentCodec<?>> codecs = List.of(PedersenScalarCommitment.CODEC, PedersenBytesCommitment.CODEC,
                PedersenVectorCommitment.codec(SCHEMA_A));
        for (CommitmentCodec<?> codec : codecs) {
            byte[] id = codec.profile().id().toAsciiBytes();
            for (byte[] small : new byte[][]{CommitmentTestPoints.ORDER_2, CommitmentTestPoints.ORDER_4,
                    CommitmentTestPoints.ORDER_8, CommitmentTestPoints.MIXED}) {
                byte[] envelope = concat(new byte[]{1, (byte) id.length}, id, small);
                assertError(CommitmentError.NOT_IN_SUBGROUP, () -> CommitmentEnvelope.decode(envelope, codec));
            }
            for (byte[] bad : new byte[][]{CommitmentTestPoints.ALIAS_IDENTITY, CommitmentTestPoints.ALIAS_ORDER_2,
                    CommitmentTestPoints.OFF_CURVE, CommitmentTestPoints.V_NOT_BELOW_P}) {
                byte[] envelope = concat(new byte[]{1, (byte) id.length}, id, bad);
                assertError(CommitmentError.MALFORMED_ENCODING, () -> CommitmentEnvelope.decode(envelope, codec));
            }
            byte[] identity = concat(new byte[]{1, (byte) id.length}, id, CommitmentTestPoints.IDENTITY);
            assertArrayEquals(CommitmentTestPoints.IDENTITY, CommitmentEnvelope.decode(identity, codec).toPointBytes());
        }
    }

    @Test
    @DisplayName("Substitution: a bytes envelope under the scalar codec is PROFILE_MISMATCH, though H(B) opens the raw point")
    void substitution() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment bytes = PedersenCommitment.commitBytes(DOC, r);
        byte[] eb = CommitmentEnvelope.encode(bytes);
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(eb, PedersenScalarCommitment.CODEC));
        assertError(CommitmentError.PROFILE_MISMATCH,
                () -> CommitmentEnvelope.decode(eb, PedersenVectorCommitment.codec(SCHEMA_A)));
        byte[] es = CommitmentEnvelope.encode(PedersenScalarCommitment.decode(bytes.toPointBytes()));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(es, PedersenBytesCommitment.CODEC));
        // The raw point is the same point: only configuration tells the profiles apart (spec §6.3).
        BigInteger s = PedersenBytesHash.hashToScalar(DOC);
        assertTrue(PedersenCommitment.verifyScalar(PedersenScalarCommitment.decode(bytes.toPointBytes()), s, r));
        assertTrue(PedersenCommitment.verify(bytes.point(), s, r));
    }

    @Test
    @DisplayName("A vector envelope decodes under a codec for another schema; requireContext and verifyOpening enforce the schema")
    void vectorSchemaIsNotInTheEnvelope() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenVectorCommitment a = PedersenVectorCommitment.commit(SCHEMA_A, values(10, 1), r);
        byte[] ev = CommitmentEnvelope.encode(a);
        PedersenVectorCommitment underB = CommitmentEnvelope.decode(ev, PedersenVectorCommitment.codec(SCHEMA_B));
        assertEquals(SCHEMA_B, underB.schema());
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(a, PedersenVectorCommitment.codec(SCHEMA_B)));
        assertError(CommitmentError.PROFILE_MISMATCH,
                () -> PedersenVectorCommitment.codec(SCHEMA_B).requireContext(a));
        assertError(CommitmentError.PROFILE_MISMATCH,
                () -> a.verifyOpening(values(10, 1), r, PedersenVectorBoundPolicy.schemaWidths(SCHEMA_B)));
    }

    @Test
    @DisplayName("CommitmentKey separates profiles sharing a point and schemas sharing a point")
    void keys() {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        PedersenBytesCommitment bytes = PedersenCommitment.commitBytes(DOC, r);
        PedersenScalarCommitment scalar = PedersenScalarCommitment.decode(bytes.toPointBytes());
        CommitmentKey kb = CommitmentKey.of(bytes, PedersenBytesCommitment.CODEC);
        CommitmentKey ks = CommitmentKey.of(scalar, PedersenScalarCommitment.CODEC);
        assertNotEquals(kb, ks);
        assertEquals(kb, CommitmentKey.of(PedersenBytesCommitment.decode(bytes.toPointBytes()), PedersenBytesCommitment.CODEC));

        PedersenVectorCommitment va = PedersenVectorCommitment.commit(SCHEMA_A, values(1, 2), r);
        PedersenVectorCommitment vb = PedersenVectorCommitment.decode(SCHEMA_B, va.toBytes());
        CommitmentKey ka = CommitmentKey.of(va, PedersenVectorCommitment.codec(SCHEMA_A));
        CommitmentKey kbv = CommitmentKey.of(vb, PedersenVectorCommitment.codec(SCHEMA_B));
        assertNotEquals(ka, kbv);
        PedersenVectorCommitment va2 = PedersenVectorCommitment.decode(SCHEMA_A, va.toBytes());
        assertNotEquals(va, va2, "legacy vector equality stays reference identity");
        assertEquals(ka, CommitmentKey.of(va2, PedersenVectorCommitment.codec(SCHEMA_A)));
        Set<CommitmentKey> set = new HashSet<>(Set.of(kb, ks, ka, kbv));
        assertEquals(4, set.size());

        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(bytes, PedersenScalarCommitment.CODEC));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(scalar, PedersenBytesCommitment.CODEC));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(va, PedersenScalarCommitment.CODEC));
    }

    @Test
    @DisplayName("A foreign Commitment claiming a Jubjub descriptor is PROFILE_MISMATCH in keys and envelopes")
    void foreignImplementation() {
        Commitment impostor = new Commitment() {
            @Override
            public CommitmentProfile profile() {
                return PedersenScalarCommitment.PROFILE;
            }

            @Override
            public byte[] toPointBytes() {
                return JubjubPoint.IDENTITY.toBytes();
            }
        };
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(impostor, PedersenScalarCommitment.CODEC));
        // The envelope encoder trusts its producer; decoding still yields only the real type.
        byte[] envelope = CommitmentEnvelope.encode(impostor);
        assertEquals(PedersenScalarCommitment.class,
                CommitmentEnvelope.decode(envelope, PedersenScalarCommitment.CODEC).getClass());
    }

    @Test
    @DisplayName("Codecs: commitmentType is the exact class; the vector context is I2OSP(σ, 32), a fresh copy")
    void codecs() {
        assertEquals(PedersenScalarCommitment.class, PedersenScalarCommitment.CODEC.commitmentType());
        assertEquals(PedersenBytesCommitment.class, PedersenBytesCommitment.CODEC.commitmentType());
        CommitmentCodec<PedersenVectorCommitment> codec = PedersenVectorCommitment.codec(SCHEMA_A);
        assertEquals(PedersenVectorCommitment.class, codec.commitmentType());
        assertArrayEquals(new byte[0], PedersenScalarCommitment.CODEC.keyContext());
        assertArrayEquals(PedersenScalarCommitmentTest.i2osp(SCHEMA_A.digest()), codec.keyContext());
        // Independent of the code under test: σ pinned by pedersen-jubjub-vector-v1.md §4.3.
        PedersenVectorSchema balance = PedersenVectorSchema.of("zeroj.example.balance", 1, List.of(
                new PedersenVectorSchema.Entry("amount", 64), new PedersenVectorSchema.Entry("asset", 32)));
        assertArrayEquals(CommitmentTestPoints.hex("26a0f201bd5af51641a74a2b9193d2a361dfa1b629e358f99ae97ff72fe2870d"),
                PedersenVectorCommitment.codec(balance).keyContext());
        assertNotSame(codec.keyContext(), codec.keyContext());
        assertThrows(NullPointerException.class, () -> PedersenVectorCommitment.codec(null));
        assertThrows(NullPointerException.class, () -> codec.decodePoint(null));
        // Legacy vector decode keeps a plain IllegalArgumentException for a null array.
        IllegalArgumentException legacy = assertThrows(IllegalArgumentException.class,
                () -> PedersenVectorCommitment.decode(SCHEMA_A, null));
        assertFalse(legacy instanceof CommitmentFormatException);
        assertError(CommitmentError.NOT_IN_SUBGROUP, () -> codec.decodePoint(CommitmentTestPoints.ORDER_8));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> codec.decodePoint(CommitmentTestPoints.ALIAS_IDENTITY));
    }

    @Test
    @DisplayName("CommitmentAcceptance with strict openings: accept, OPENING_MISMATCH, check-2 OUT_OF_RANGE, provenance, misconfiguration")
    void acceptance() throws IOException {
        BigInteger m = BigInteger.valueOf(1_000), r = PedersenCommitment.randomBlinding(RANDOM);
        byte[] envelope = CommitmentEnvelope.encode(PedersenCommitment.commitScalar(m, r));
        ProvenancePolicy<Object> ok = c -> ProvenancePolicy.Result.OK;

        assertTrue(CommitmentAcceptance.accept(envelope, PedersenScalarCommitment.CODEC, ok,
                c -> PedersenCommitment.verifyScalar(c, m, r, 64)).accepted());
        assertReason(CommitmentAcceptance.accept(envelope, PedersenScalarCommitment.CODEC, ok,
                c -> PedersenCommitment.verifyScalar(c, m.add(BigInteger.ONE), r)), CommitmentError.OPENING_MISMATCH);
        assertReason(CommitmentAcceptance.accept(envelope, PedersenScalarCommitment.CODEC, ok,
                c -> PedersenCommitment.verifyScalar(c, m, r, 8)), CommitmentError.OUT_OF_RANGE);
        assertReason(CommitmentAcceptance.accept(envelope, PedersenScalarCommitment.CODEC, ok,
                c -> PedersenCommitment.verifyScalar(c, CommitmentTestPoints.L, r)), CommitmentError.NON_CANONICAL_SCALAR);
        CommitmentCheck missing = CommitmentAcceptance.accept(envelope, PedersenScalarCommitment.CODEC,
                c -> ProvenancePolicy.Result.MISSING, c -> true);
        assertTrue(missing.policyRejected());
        assertReason(CommitmentAcceptance.accept(envelope, PedersenBytesCommitment.CODEC, ok,
                c -> true), CommitmentError.PROFILE_MISMATCH);
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> CommitmentAcceptance.accept(envelope,
                PedersenScalarCommitment.CODEC, ok, c -> PedersenCommitment.verifyScalar(c, m, r, 0)));

        byte[] bytesEnvelope = CommitmentEnvelope.encode(PedersenCommitment.commitBytes(DOC, r));
        assertTrue(CommitmentAcceptance.accept(bytesEnvelope, PedersenBytesCommitment.CODEC, ok,
                c -> PedersenCommitment.verifyBytes(c, DOC, PedersenBlinding.decode(PedersenBlinding.encode(r)))).accepted());

        PedersenVectorCommitment sum = PedersenVectorCommitment.commit(SCHEMA_A, values(5, 1), r)
                .add(PedersenVectorCommitment.commit(SCHEMA_A, values(7, 1), BigInteger.ONE));
        byte[] vectorEnvelope = CommitmentEnvelope.encode(sum);
        PedersenVectorOpening opening = PedersenVectorOpening.of(PedersenVectorBoundPolicy.widened(SCHEMA_A, 2),
                values(12, 2), r.add(BigInteger.ONE).mod(CommitmentTestPoints.L));
        assertTrue(CommitmentAcceptance.accept(vectorEnvelope, PedersenVectorCommitment.codec(SCHEMA_A), ok,
                c -> c.verifyOpening(opening.values(), opening.blinding(), opening.policy())).accepted());
        assertReason(CommitmentAcceptance.accept(vectorEnvelope, PedersenVectorCommitment.codec(SCHEMA_B), ok,
                c -> c.verifyOpening(opening.values(), opening.blinding(), opening.policy())), CommitmentError.PROFILE_MISMATCH);
    }

    private static void assertDescriptor(CommitmentProfile profile, String id, CommitmentKind kind) {
        assertEquals(id, profile.id().value());
        assertEquals(kind, profile.kind());
        assertEquals(CommitmentGroup.JUBJUB, profile.group());
        assertEquals(32, profile.pointEncodingLength());
    }

    private static void assertReason(CommitmentCheck check, CommitmentError reason) {
        assertFalse(check.accepted());
        assertEquals(Optional.of(reason), check.reason());
    }

    private static List<BigInteger> values(long... v) {
        BigInteger[] out = new BigInteger[v.length];
        for (int i = 0; i < v.length; i++) out[i] = BigInteger.valueOf(v[i]);
        return List.of(out);
    }
}
