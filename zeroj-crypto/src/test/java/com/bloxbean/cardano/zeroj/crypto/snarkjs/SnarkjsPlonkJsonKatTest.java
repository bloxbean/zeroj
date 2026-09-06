package com.bloxbean.cardano.zeroj.crypto.snarkjs;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec;
import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkProof;
import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkVerificationKey;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.poly.FieldFFTBLS381;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0047 M3 known-answer tests for {@link SnarkjsPlonkJson}: the snarkjs 0.7.6 PlonK artifacts in
 * zeroj-test-vectors are parsed, re-exported and required to be byte-identical. The in-JVM and
 * live-CLI round trips of ZeroJ-produced PlonK proofs live in zeroj-integration-tests.
 */
class SnarkjsPlonkJsonKatTest {

    private static final String TV = "/test-vectors/snarkjs-plonk-bls12381/";
    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void verificationKey_reexportIsByteIdenticalToSnarkjs() throws IOException {
        String original = load(TV + "verification_key.json");
        var vk = SnarkjsPlonkCodec.parseVerificationKey(original);
        // fixture sanity: this VK carries identity selector commitments (Qr, Qc of a bare multiplier)
        assertEquals(List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO), vk.Qr());
        assertEquals(List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO), vk.Qc());
        assertEquals(original, export(vk));
        assertFalse(original.endsWith("\n"));
    }

    @Test
    void proof_reexportIsByteIdenticalToSnarkjs() throws IOException {
        String original = load(TV + "proof.json");
        var p = SnarkjsPlonkCodec.parseProof(original);
        assertEquals(original, SnarkjsPlonkJson.proofJson(proof(p)));
    }

    @Test
    void publicInputs_reexportIsByteIdenticalToSnarkjs() throws IOException {
        String original = load(TV + "public.json");
        assertEquals("[\n \"33\"\n]", original, "fixture sanity");
        assertEquals(original, SnarkjsPlonkJson.publicJson(new BigInteger[]{BigInteger.valueOf(33)}));
    }

    @Test
    void verificationKey_wIsTheCanonicalRootSnarkjsDerives_andOtherGeneratorsAreRejected() throws IOException {
        var vk = SnarkjsPlonkCodec.parseVerificationKey(load(TV + "verification_key.json"));
        // Independent pin: the w snarkjs wrote equals ZeroJ's rootOfUnity(power) — the two
        // implementations agree on the domain generator, so snarkjs (which ignores vk.w and derives
        // Fr.w[power]) and ZeroJ (which reads w) verify against the same domain.
        assertEquals(FieldFFTBLS381.rootOfUnity(vk.power()).toBigInteger(), vk.w());

        // w^3 is another primitive 2^power-th root (3 is odd); ZeroJ's verifier would accept it as a
        // generator but snarkjs would silently use the canonical one — export must refuse it.
        BigInteger other = vk.w().modPow(BigInteger.valueOf(3), FR);
        assertEquals(BigInteger.ONE, other.modPow(BigInteger.valueOf(1L << vk.power()), FR), "fixture sanity: still an n-th root");
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.verificationKeyJson(
                1 << vk.power(), vk.nPublic(), vk.k1(), vk.k2(), other,
                g1(vk.Qm()), g1(vk.Ql()), g1(vk.Qr()), g1(vk.Qo()), g1(vk.Qc()),
                g1(vk.S1()), g1(vk.S2()), g1(vk.S3()), g2(vk.X_2())));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.verificationKeyJson(
                1 << vk.power(), vk.nPublic(), vk.k1(), vk.k2(), null,
                g1(vk.Qm()), g1(vk.Ql()), g1(vk.Qr()), g1(vk.Qo()), g1(vk.Qc()),
                g1(vk.S1()), g1(vk.S2()), g1(vk.S3()), g2(vk.X_2())));
    }

    /**
     * The V6a egress check accepts ZeroJ's {@code rootOfUnity(power)}; interop at every domain size
     * therefore rests on ZeroJ's 2^32 root chain equalling ffjavascript's {@code Fr.w[]}, which is what
     * {@code snarkjs plonk verify} uses. The checked-in vector pins power 3; this pins the chain at
     * powers a real circuit exports at. Values: ffjavascript 0.3.1 (snarkjs 0.7.6's dependency),
     * {@code getCurveFromName("bls12381").Fr.w[i]} printed with {@code Fr.toString}, 2026-09-06.
     */
    @Test
    void rootOfUnityChain_matchesFfjavascriptFrW() {
        String[][] ffjavascript = {
                {"3", "28761180743467419819834788392525162889723178799021384024940474588120723734663"},
                {"8", "21071158244812412064791010377580296085971058123779034548857891862303448703672"},
                {"16", "46605497109352149548364111935960392432509601054990529243781317021485154656122"},
                {"24", "13205172441828670567663721566567600707419662718089030114959677511969243860524"},
                {"32", "937917089079007706106976984802249742464848817460758522850752807661925904159"},
        };
        for (var row : ffjavascript) {
            int power = Integer.parseInt(row[0]);
            assertEquals(new BigInteger(row[1]), FieldFFTBLS381.rootOfUnity(power).toBigInteger(),
                    "Fr.w[" + power + "] (ffjavascript) must equal FieldFFTBLS381.rootOfUnity(" + power + ")");
        }
    }

    @Test
    void verificationKey_rejectsBadDomainAndCounts() throws IOException {
        var vk = SnarkjsPlonkCodec.parseVerificationKey(load(TV + "verification_key.json"));
        assertThrows(IllegalArgumentException.class, () -> export(vk, 6, vk.nPublic()), "not a power of two");
        assertThrows(IllegalArgumentException.class, () -> export(vk, 1, vk.nPublic()), "domain of size 1");
        assertThrows(IllegalArgumentException.class, () -> export(vk, 0, vk.nPublic()));
        assertThrows(IllegalArgumentException.class, () -> export(vk, 1 << vk.power(), -1), "negative nPublic");
    }

    @Test
    void rejectsInfinityAndNonCanonicalValues() throws IOException {
        var p = SnarkjsPlonkCodec.parseProof(load(TV + "proof.json"));
        var vk = SnarkjsPlonkCodec.parseVerificationKey(load(TV + "verification_key.json"));
        var ok = proof(p);

        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.proofJson(new PlonKProofBLS381(
                AffineG1.INFINITY, ok.commitB(), ok.commitC(), ok.commitZ(), ok.commitT1(), ok.commitT2(), ok.commitT3(),
                ok.evalA(), ok.evalB(), ok.evalC(), ok.evalS1(), ok.evalS2(), ok.evalZw(), ok.commitWxi(), ok.commitWxiw())));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.proofJson(new PlonKProofBLS381(
                ok.commitA(), ok.commitB(), ok.commitC(), ok.commitZ(), ok.commitT1(), ok.commitT2(), ok.commitT3(),
                ok.evalA(), ok.evalB(), ok.evalC(), ok.evalS1(), ok.evalS2(), ok.evalZw(), ok.commitWxi(), AffineG1.INFINITY)));
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.proofJson(new PlonKProofBLS381(
                ok.commitA(), ok.commitB(), ok.commitC(), ok.commitZ(), ok.commitT1(), ok.commitT2(), ok.commitT3(),
                FR, ok.evalB(), ok.evalC(), ok.evalS1(), ok.evalS2(), ok.evalZw(), ok.commitWxi(), ok.commitWxiw())),
                "eval_a == r is not canonical");
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.proofJson(new PlonKProofBLS381(
                ok.commitA(), ok.commitB(), ok.commitC(), ok.commitZ(), ok.commitT1(), ok.commitT2(), ok.commitT3(),
                ok.evalA(), ok.evalB(), ok.evalC(), ok.evalS1(), ok.evalS2(), BigInteger.ONE.negate(), ok.commitWxi(), ok.commitWxiw())),
                "negative eval_zw");

        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.verificationKeyJson(
                1 << vk.power(), vk.nPublic(), FR, vk.k2(), vk.w(),
                g1(vk.Qm()), g1(vk.Ql()), g1(vk.Qr()), g1(vk.Qo()), g1(vk.Qc()),
                g1(vk.S1()), g1(vk.S2()), g1(vk.S3()), g2(vk.X_2())), "k1 == r is not canonical");
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.verificationKeyJson(
                1 << vk.power(), vk.nPublic(), vk.k1(), vk.k2(), vk.w(),
                g1(vk.Qm()), g1(vk.Ql()), g1(vk.Qr()), g1(vk.Qo()), g1(vk.Qc()),
                g1(vk.S1()), g1(vk.S2()), g1(vk.S3()), AffineG2.INFINITY), "X_2 at infinity");
        assertThrows(IllegalArgumentException.class, () -> SnarkjsPlonkJson.publicJson(new BigInteger[]{FR}));
    }

    // ---------------------------------------------------------------- helpers

    private static String export(SnarkjsPlonkVerificationKey vk) {
        return export(vk, 1 << vk.power(), vk.nPublic());
    }

    private static String export(SnarkjsPlonkVerificationKey vk, int domainSize, int nPublic) {
        return SnarkjsPlonkJson.verificationKeyJson(domainSize, nPublic, vk.k1(), vk.k2(), vk.w(),
                g1(vk.Qm()), g1(vk.Ql()), g1(vk.Qr()), g1(vk.Qo()), g1(vk.Qc()),
                g1(vk.S1()), g1(vk.S2()), g1(vk.S3()), g2(vk.X_2()));
    }

    private static PlonKProofBLS381 proof(SnarkjsPlonkProof p) {
        return new PlonKProofBLS381(g1(p.A()), g1(p.B()), g1(p.C()), g1(p.Z()), g1(p.T1()), g1(p.T2()), g1(p.T3()),
                p.evalA(), p.evalB(), p.evalC(), p.evalS1(), p.evalS2(), p.evalZw(), g1(p.Wxi()), g1(p.Wxiw()));
    }

    /** snarkjs projective {@code [x, y, z]}: {@code z == 0} is the identity ({@code ["0","1","0"]}). */
    private static AffineG1 g1(List<BigInteger> c) {
        if (c.size() == 3 && c.get(2).signum() == 0) return AffineG1.INFINITY;
        return new AffineG1(MontFp381.fromBigInteger(c.get(0)), MontFp381.fromBigInteger(c.get(1)));
    }

    private static AffineG2 g2(List<List<BigInteger>> c) {
        return new AffineG2(MontFp2_381.of(c.get(0).get(0), c.get(0).get(1)),
                MontFp2_381.of(c.get(1).get(0), c.get(1).get(1)));
    }

    private String load(String resource) throws IOException {
        try (var in = getClass().getResourceAsStream(resource)) {
            if (in == null) throw new IOException("missing test resource " + resource);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
