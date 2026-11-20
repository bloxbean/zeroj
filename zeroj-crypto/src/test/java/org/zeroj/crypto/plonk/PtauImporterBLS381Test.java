package org.zeroj.crypto.plonk;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.api.CurveId;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.plonk.PlonKConstraintSystem;
import org.zeroj.crypto.snarkjs.SnarkjsPlonkJson;
import org.zeroj.crypto.testsupport.SnarkjsCliLocator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class PtauImporterBLS381Test {

    private static final BigInteger FP = MontFp381.modulus();
    private static final AffineG1 G1 = JacobianG1BLS381.GENERATOR.toAffine();
    private static final AffineG2 G2 = JacobianG2BLS381.GENERATOR.toAffine();
    private static final AffineG1 SMALL_SUBGROUP_G1 = new AffineG1(MontFp381.ZERO, MontFp381.TWO);
    private static final AffineG1 OFF_CURVE_G1 = new AffineG1(G1.x(), G1.y().add(MontFp381.ONE));

    // ---- Positive offline tests ----

    @Test
    void importPtau_parsesValidSyntheticPtauWithPinAndBoundedMaxPoints() throws Exception {
        BigInteger tau = BigInteger.valueOf(7);
        byte[] ptau = buildSyntheticPtau(2, tau); // power=2 => 7 G1 points, 4 G2 points
        byte[] sha256 = MessageDigest.getInstance("SHA-256").digest(ptau);

        // Full import with SHA-256 pin
        PtauImporterBLS381.SRS full = PtauImporterBLS381.importPtau(new ByteArrayInputStream(ptau), sha256);
        assertEquals(2, full.power());
        assertEquals(7, full.tauG1().length);
        assertEquals(2, full.tauG2().length);
        assertEquals(G1, full.tauG1()[0]);
        assertEquals(JacobianG1BLS381.GENERATOR.scalarMul(tau).toAffine(), full.tauG1()[1]);
        assertEquals(G2, full.tauG2()[0]);
        assertEquals(JacobianG2BLS381.GENERATOR.scalarMul(tau).toAffine(), full.tauG2()[1]);

        // Bounded maxPoints import with SHA-256 pin (still hashes full stream)
        PtauImporterBLS381.SRS bounded = PtauImporterBLS381.importPtau(new ByteArrayInputStream(ptau), 4, sha256);
        assertEquals(4, bounded.tauG1().length);
        assertEquals(2, bounded.tauG2().length);

        // 1-bit flipped SHA-256 rejected
        byte[] wrongHash = sha256.clone();
        wrongHash[0] ^= 0x01;
        IOException ex = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(ptau), 4, wrongHash));
        assertTrue(ex.getMessage().contains("SHA-256 hash mismatch"), ex.getMessage());
    }

    @Test
    void importPtau_streamsBeyond64MiBWithoutBufferingFullFile() throws Exception {
        // Virtual stream with valid power=2 sections 1-3 + a 70 MiB dummy section 4 (> old 64 MiB cap)
        BigInteger tau = BigInteger.valueOf(5);
        byte[] prefix = buildSyntheticPtauSections1To3(2, tau, 4); // declares 4 sections
        long extraSectionBytes = 70L * 1024 * 1024;
        ByteArrayOutputStream sec4Hdr = new ByteArrayOutputStream();
        sec4Hdr.write(leInt(4));
        sec4Hdr.write(leLong(extraSectionBytes));
        byte[] sec4HdrBytes = sec4Hdr.toByteArray();

        // Compute exact SHA-256 in streaming fashion too
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(prefix);
        md.update(sec4HdrBytes);
        byte[] zeros = new byte[65536];
        long rem = extraSectionBytes;
        while (rem > 0) {
            int n = (int) Math.min(rem, zeros.length);
            md.update(zeros, 0, n);
            rem -= n;
        }
        byte[] expectedSha = md.digest();

        InputStream largeStream = new LargeZeroSectionStream(prefix, sec4HdrBytes, extraSectionBytes);
        PtauImporterBLS381.SRS srs = PtauImporterBLS381.importPtau(largeStream, 4, expectedSha);
        assertEquals(2, srs.power());
        assertEquals(4, srs.tauG1().length);
        assertEquals(2, srs.tauG2().length);
    }

    // ---- Live snarkjs 0.7.6 same-power .ptau -> setup -> prove -> snarkjs plonk verify ----

    @Test
    void importPtau_liveSnarkjsSamePowerPtau_setupProveAndVerifyWithSnarkjs(@TempDir Path dir) throws Exception {
        String snarkjs = requireSnarkjs();

        // Same-power .ptau: power = 3 => domainSize = 8, available G1 = 2^4 - 1 = 15 >= n + 6 = 14
        run(dir, snarkjs, "powersoftau", "new", "bls12-381", "3", "pot0.ptau");
        run(dir, snarkjs, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=p4", "-e=ptau-interop-e1");
        run(dir, snarkjs, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot.ptau");

        Path ptauFile = dir.resolve("pot.ptau");
        byte[] ptauSha = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(ptauFile));

        // Import exact n + 6 = 14 points from the live snarkjs .ptau with SHA-256 pin
        PtauImporterBLS381.SRS srs;
        try (InputStream in = Files.newInputStream(ptauFile)) {
            srs = PtauImporterBLS381.importPtau(in, 14, ptauSha);
        }
        assertEquals(3, srs.power());
        assertEquals(14, srs.tauG1().length);
        assertEquals(2, srs.tauG2().length);

        // Tampered SHA-256 rejected on live .ptau
        byte[] badSha = ptauSha.clone();
        badSha[31] ^= 0x01;
        try (InputStream in = Files.newInputStream(ptauFile)) {
            assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(in, 14, badSha));
        }

        // Build multiplier circuit, run PlonK setup + prove with the imported same-power SRS,
        // and verify with live `snarkjs plonk verify`.
        var circuit = CircuitBuilder.create("ptau-mul")
                .publicVar("c")
                .secretVar("a")
                .secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "c", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);
        PlonKConstraintSystem plonk = circuit.compilePlonK(CurveId.BLS12_381);
        int numGates = plonk.numGates();
        BigInteger[][] selectors = new BigInteger[numGates][];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            selectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }
        PlonKProvingKeyBLS381 pk = PlonKSetupBLS381.setup(
                numGates, plonk.numPublicInputs(), selectors,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);
        assertEquals(8, pk.domainSize());

        BigInteger[] ext = plonk.extendWitness(witness);
        int n = pk.domainSize();
        MontFr381[] wireA = new MontFr381[n];
        MontFr381[] wireB = new MontFr381[n];
        MontFr381[] wireC = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            if (i < numGates) {
                var row = plonk.gateRows().get(i);
                wireA[i] = MontFr381.fromBigInteger(ext[row.wireA()]);
                wireB[i] = MontFr381.fromBigInteger(ext[row.wireB()]);
                wireC[i] = MontFr381.fromBigInteger(ext[row.wireC()]);
            } else {
                wireA[i] = wireB[i] = wireC[i] = MontFr381.ZERO;
            }
        }
        BigInteger[] publicInputs = Arrays.copyOfRange(witness, 1, 1 + plonk.numPublicInputs());
        PlonKProofBLS381 proof = PlonKProverBLS381.prove(pk, wireA, wireB, wireC, publicInputs);

        Files.writeString(dir.resolve("verification_key.json"), SnarkjsPlonkJson.verificationKeyJson(pk));
        Files.writeString(dir.resolve("proof.json"), SnarkjsPlonkJson.proofJson(proof));
        Files.writeString(dir.resolve("public.json"), SnarkjsPlonkJson.publicJson(publicInputs));

        String verifyOut = run(dir, snarkjs, "plonk", "verify",
                "verification_key.json", "public.json", "proof.json");
        assertTrue(verifyOut.contains("OK!"), "snarkjs plonk verify did not report OK!: " + verifyOut);
    }

    // ---- Negative tests ----

    @Test
    void importPtau_rejectsNullInput() {
        assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(null, 1));
    }

    @Test
    void importPtau_rejectsTruncatedHeader() {
        assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(
                new ByteArrayInputStream(new byte[]{'p', 't', 'a', 'u'}), 1));
    }

    @Test
    void importPtau_rejectsExpectedHashLengthMismatch() {
        assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(
                new ByteArrayInputStream(new byte[]{'p', 't', 'a', 'u'}), 1, new byte[31]));
    }

    @Test
    void importPtau_rejectsExpectedHashMismatchBeforePointValidation() throws Exception {
        // Structurally framed .ptau containing an off-curve point in tauG1[1]:
        // - with a WRONG pin, must fail on SHA-256 BEFORE point decoding/subgroup validation;
        // - with the CORRECT pin, must pass SHA-256 and then fail on curve validation.
        byte[] badPointPtau = buildSyntheticPtau(2, BigInteger.valueOf(7));
        int sec2PayloadOff = 12 + 12 + 60 + 12;
        System.arraycopy(g1Lem(OFF_CURVE_G1), 0, badPointPtau, sec2PayloadOff + 96, 96);

        byte[] correctPin = MessageDigest.getInstance("SHA-256").digest(badPointPtau);
        byte[] wrongPin = correctPin.clone();
        wrongPin[0] ^= 0x01;

        IOException wrongPinEx = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(badPointPtau), 7, wrongPin));
        assertTrue(wrongPinEx.getMessage().contains("SHA-256 hash mismatch"), wrongPinEx.getMessage());

        IOException rightPinEx = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(badPointPtau), 7, correctPin));
        assertTrue(rightPinEx.getMessage().contains("not on curve"), rightPinEx.getMessage());
    }

    @Test
    void resolvedG1Count_alignsWithMaxDomain24Plus6() throws Exception {
        long power24AvailableG1 = (1L << 25) - 1L;
        int maxDomainPlus6 = (1 << 24) + 6;
        assertEquals(maxDomainPlus6, PtauImporterBLS381.resolvedG1Count(power24AvailableG1, maxDomainPlus6));
        IOException ex = assertThrows(IOException.class,
                () -> PtauImporterBLS381.resolvedG1Count(power24AvailableG1, maxDomainPlus6 + 1));
        assertTrue(ex.getMessage().contains("exceeds maximum"), ex.getMessage());
    }

    @Test
    void importPtau_rejectsDuplicateSectionsWithValidFirstHeader() throws IOException {
        byte[] validSec1 = buildValidSection1(2, 2);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'p', 't', 'a', 'u'});
        out.write(leInt(1));
        out.write(leInt(2));
        writeSection(out, 1, validSec1);
        writeSection(out, 1, validSec1);

        IOException ex = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(out.toByteArray()), 1));
        assertTrue(ex.getMessage().contains("Duplicate .ptau section: 1"), ex.getMessage());
    }

    @Test
    void importPtau_rejectsInvalidCeremonyPowerOutOfOrderAndSectionSizeMismatches() throws IOException {
        // ceremonyPower < power (with valid prime & n8)
        ByteArrayOutputStream badCeremony = new ByteArrayOutputStream();
        badCeremony.write(new byte[]{'p', 't', 'a', 'u'});
        badCeremony.write(leInt(1));
        badCeremony.write(leInt(1));
        writeSection(badCeremony, 1, buildValidSection1(4, 3));
        IOException exCp = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(badCeremony.toByteArray()), 1));
        assertTrue(exCp.getMessage().contains("ceremonyPower"), exCp.getMessage());

        // Section 2 appearing before Section 1
        ByteArrayOutputStream outOfOrder = new ByteArrayOutputStream();
        outOfOrder.write(new byte[]{'p', 't', 'a', 'u'});
        outOfOrder.write(leInt(1));
        outOfOrder.write(leInt(2));
        writeSection(outOfOrder, 2, new byte[96]);
        writeSection(outOfOrder, 1, buildValidSection1(2, 2));
        IOException exOrder = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(outOfOrder.toByteArray()), 1));
        assertTrue(exOrder.getMessage().contains("before header section 1"), exOrder.getMessage());

        // Section 2 size mismatch (valid power=2 header expects 7*96 bytes, provide 6*96)
        ByteArrayOutputStream badSec2 = new ByteArrayOutputStream();
        badSec2.write(new byte[]{'p', 't', 'a', 'u'});
        badSec2.write(leInt(1));
        badSec2.write(leInt(2));
        writeSection(badSec2, 1, buildValidSection1(2, 2));
        writeSection(badSec2, 2, new byte[6 * 96]);
        IOException exSec2 = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(badSec2.toByteArray()), 4));
        assertTrue(exSec2.getMessage().contains("G1 section size"), exSec2.getMessage());

        // Section 3 size mismatch (valid power=2 header + valid section 2, section 3 has 3*192 instead of 4*192)
        ByteArrayOutputStream badSec3 = new ByteArrayOutputStream();
        badSec3.write(new byte[]{'p', 't', 'a', 'u'});
        badSec3.write(leInt(1));
        badSec3.write(leInt(3));
        writeSection(badSec3, 1, buildValidSection1(2, 2));
        writeSection(badSec3, 2, new byte[7 * 96]);
        writeSection(badSec3, 3, new byte[3 * 192]);
        IOException exSec3 = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(badSec3.toByteArray()), 4));
        assertTrue(exSec3.getMessage().contains("G2 section size"), exSec3.getMessage());
    }

    @Test
    void importPtau_rejectsWrongBaseFieldPrime() throws IOException {
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(leInt(48));
        header.write(new byte[48]);
        header.write(leInt(4));
        header.write(leInt(4));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'p', 't', 'a', 'u'});
        out.write(leInt(1));
        out.write(leInt(3));
        writeSection(out, 1, header.toByteArray());
        writeSection(out, 2, new byte[0]);
        writeSection(out, 3, new byte[0]);

        assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(
                new ByteArrayInputStream(out.toByteArray()), 1));
    }

    @Test
    void importPtau_rejectsInfinityOffCurveSmallSubgroupNonCanonicalAndInconsistentSrs() throws IOException {
        byte[] valid = buildSyntheticPtau(2, BigInteger.valueOf(7));
        int sec2PayloadOff = 12 + 12 + 60 + 12; // global(12) + sec1(12+60) + sec2hdr(12)
        int sec3PayloadOff = sec2PayloadOff + 7 * 96 + 12;

        // Infinity in tauG1[1]
        byte[] infG1 = valid.clone();
        Arrays.fill(infG1, sec2PayloadOff + 96, sec2PayloadOff + 192, (byte) 0);
        IOException exInf1 = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(infG1), 7));
        assertTrue(exInf1.getMessage().contains("infinity"), exInf1.getMessage());

        // Infinity in tauG2[1]
        byte[] infG2 = valid.clone();
        Arrays.fill(infG2, sec3PayloadOff + 192, sec3PayloadOff + 384, (byte) 0);
        IOException exInf2 = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(infG2), 7));
        assertTrue(exInf2.getMessage().contains("infinity"), exInf2.getMessage());

        // Off-curve G1 in tauG1[1]
        byte[] offCurve = valid.clone();
        System.arraycopy(g1Lem(OFF_CURVE_G1), 0, offCurve, sec2PayloadOff + 96, 96);
        IOException exOff = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(offCurve), 7));
        assertTrue(exOff.getMessage().contains("not on curve"), exOff.getMessage());

        // Small-subgroup G1 in tauG1[1]
        byte[] smallSub = valid.clone();
        System.arraycopy(g1Lem(SMALL_SUBGROUP_G1), 0, smallSub, sec2PayloadOff + 96, 96);
        IOException exSub = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(smallSub), 7));
        assertTrue(exSub.getMessage().contains("not in subgroup"), exSub.getMessage());

        // Non-canonical (>= p) coordinate in tauG1[1]
        byte[] nonCanon = valid.clone();
        System.arraycopy(unsignedLE(FP, 48), 0, nonCanon, sec2PayloadOff + 96, 48);
        IOException exCanon = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(nonCanon), 7));
        assertTrue(exCanon.getMessage().contains("not canonical"), exCanon.getMessage());

        // Pairing-inconsistent SRS power (replace tauG1[2] with G1)
        byte[] inconsistent = valid.clone();
        System.arraycopy(g1Lem(G1), 0, inconsistent, sec2PayloadOff + 2 * 96, 96);
        IOException exPair = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(inconsistent), 7));
        assertTrue(exPair.getMessage().contains("inconsistent"), exPair.getMessage());

        // Trailing bytes rejected
        byte[] trailing = Arrays.copyOf(valid, valid.length + 1);
        IOException exTrail = assertThrows(IOException.class,
                () -> PtauImporterBLS381.importPtau(new ByteArrayInputStream(trailing), 7));
        assertTrue(exTrail.getMessage().contains("Trailing"), exTrail.getMessage());
    }

    // ---- Helpers ----

    private static byte[] buildValidSection1(int power, int ceremonyPower) throws IOException {
        ByteArrayOutputStream sec1 = new ByteArrayOutputStream();
        sec1.write(leInt(48));
        sec1.write(unsignedLE(FP, 48));
        sec1.write(leInt(power));
        sec1.write(leInt(ceremonyPower));
        return sec1.toByteArray();
    }

    private static byte[] buildSyntheticPtau(int power, BigInteger tau) throws IOException {
        return buildSyntheticPtauSections1To3(power, tau, 3);
    }

    private static byte[] buildSyntheticPtauSections1To3(int power, BigInteger tau, int declaredSections)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'p', 't', 'a', 'u'});
        out.write(leInt(1));
        out.write(leInt(declaredSections));

        // Section 1: 60 bytes (n8, prime, power, ceremonyPower)
        ByteArrayOutputStream sec1 = new ByteArrayOutputStream();
        sec1.write(leInt(48));
        sec1.write(unsignedLE(FP, 48));
        sec1.write(leInt(power));
        sec1.write(leInt(power));
        writeSection(out, 1, sec1.toByteArray());

        // Section 2: 2^(power+1) - 1 G1 powers
        int nG1 = (1 << (power + 1)) - 1;
        ByteArrayOutputStream sec2 = new ByteArrayOutputStream();
        BigInteger cur = BigInteger.ONE;
        BigInteger r = MontFr381.modulus();
        for (int i = 0; i < nG1; i++) {
            sec2.write(g1Lem(JacobianG1BLS381.GENERATOR.scalarMul(cur).toAffine()));
            cur = cur.multiply(tau).mod(r);
        }
        writeSection(out, 2, sec2.toByteArray());

        // Section 3: 2^power G2 powers
        int nG2 = 1 << power;
        ByteArrayOutputStream sec3 = new ByteArrayOutputStream();
        cur = BigInteger.ONE;
        for (int i = 0; i < nG2; i++) {
            sec3.write(g2Lem(JacobianG2BLS381.GENERATOR.scalarMul(cur).toAffine()));
            cur = cur.multiply(tau).mod(r);
        }
        writeSection(out, 3, sec3.toByteArray());

        return out.toByteArray();
    }

    private static final class LargeZeroSectionStream extends InputStream {
        private final byte[] p1;
        private final byte[] p2;
        private int pos1 = 0;
        private int pos2 = 0;
        private long zerosRemaining;

        LargeZeroSectionStream(byte[] p1, byte[] p2, long zerosRemaining) {
            this.p1 = p1;
            this.p2 = p2;
            this.zerosRemaining = zerosRemaining;
        }

        @Override
        public int read() {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (pos1 < p1.length) {
                int n = Math.min(len, p1.length - pos1);
                System.arraycopy(p1, pos1, b, off, n);
                pos1 += n;
                return n;
            }
            if (pos2 < p2.length) {
                int n = Math.min(len, p2.length - pos2);
                System.arraycopy(p2, pos2, b, off, n);
                pos2 += n;
                return n;
            }
            if (zerosRemaining > 0) {
                int n = (int) Math.min(len, zerosRemaining);
                Arrays.fill(b, off, off + n, (byte) 0);
                zerosRemaining -= n;
                return n;
            }
            return -1;
        }
    }

    private static String requireSnarkjs() {
        var res = SnarkjsCliLocator.resolvePinned();
        if (!res.isReady()) {
            if (SnarkjsCliLocator.isRequired()) {
                fail(res.reason() + " — required by -PrequireSnarkjs");
            }
            assumeTrue(false, res.reason() + " — skipping");
        }
        return res.binary();
    }

    private static String run(Path dir, String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        assertTrue(p.waitFor(180, TimeUnit.SECONDS), "snarkjs timed out: " + String.join(" ", cmd));
        assertEquals(0, p.exitValue(), "snarkjs failed: " + String.join(" ", cmd) + "\n" + out);
        return out;
    }

    private static byte[] g1Lem(AffineG1 p) {
        byte[] out = new byte[96];
        if (p.isInfinity()) return out;
        putLimbs(p.x().toLimbs(), out, 0);
        putLimbs(p.y().toLimbs(), out, 48);
        return out;
    }

    private static byte[] g2Lem(AffineG2 p) {
        byte[] out = new byte[192];
        if (p.isInfinity()) return out;
        putLimbs(p.x().re().toLimbs(), out, 0);
        putLimbs(p.x().im().toLimbs(), out, 48);
        putLimbs(p.y().re().toLimbs(), out, 96);
        putLimbs(p.y().im().toLimbs(), out, 144);
        return out;
    }

    private static void putLimbs(long[] limbs, byte[] out, int off) {
        ByteBuffer bb = ByteBuffer.wrap(out, off, 48).order(ByteOrder.LITTLE_ENDIAN);
        for (long l : limbs) bb.putLong(l);
    }

    private static byte[] unsignedLE(BigInteger v, int len) {
        byte[] out = new byte[len];
        byte[] be = v.toByteArray();
        int start = Math.max(0, be.length - len);
        int count = be.length - start;
        for (int i = 0; i < count; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static void writeSection(ByteArrayOutputStream out, int sectionType, byte[] data) throws IOException {
        out.write(leInt(sectionType));
        out.write(leLong(data.length));
        out.write(data);
    }

    private static byte[] leInt(int value) {
        return ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array();
    }

    private static byte[] leLong(long value) {
        return ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array();
    }
}
