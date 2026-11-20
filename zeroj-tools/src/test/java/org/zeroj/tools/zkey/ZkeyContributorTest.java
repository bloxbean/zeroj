package org.zeroj.tools.zkey;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.bls12381.pairing.BLS12381Pairing;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Offline unit and adversarial-input tests for {@link ZkeyContributor} (ADR-0031 R3 hardening
 * amendment).
 */
class ZkeyContributorTest {

    private static final BigInteger P = MontFp381.modulus();
    private static final BigInteger R = MontFr381.modulus();

    private static final AffineG1 G1 = JacobianG1BLS381.GENERATOR.toAffine();
    private static final AffineG2 G2 = JacobianG2BLS381.GENERATOR.toAffine();
    private static final G1Point G1_GEN = toG1(G1);
    private static final G2Point G2_GEN = toG2(G2);

    // (0, 2) satisfies y^2 = x^3 + 4 over Fp, has order 3 (not in the r-order subgroup).
    private static final AffineG1 SMALL_SUBGROUP_G1 = new AffineG1(MontFp381.ZERO, MontFp381.TWO);

    // Off-curve G1 point: (G1.x, G1.y + 1).
    private static final AffineG1 OFF_CURVE_G1 = new AffineG1(G1.x(), G1.y().add(MontFp381.ONE));

    // Off-curve G2 point: (G2.x, G2.y + (1, 0)).
    private static final AffineG2 OFF_CURVE_G2 = new AffineG2(G2.x(), G2.y().add(MontFp2_381.ONE));

    // On-curve non-subgroup G2 point: (0, sqrt(4*(1+u))) on y^2 = x^3 + 4*(1+u).
    private static final AffineG2 SMALL_SUBGROUP_G2 = buildSmallSubgroupG2();

    // ---- Positive controls ----

    @Test
    void validGenesisAndChainedContribution_preservesInfinityInLAndH_andUpdatesPairings(@TempDir Path dir)
            throws Exception {
        // Verify our adversarial test points have the exact algebraic properties we assert.
        assertTrue(SMALL_SUBGROUP_G1.isOnCurve());
        assertFalse(JacobianG1BLS381.fromAffine(SMALL_SUBGROUP_G1.x(), SMALL_SUBGROUP_G1.y()).scalarMul(R).isInfinity());
        assertFalse(OFF_CURVE_G1.isOnCurve());
        assertTrue(SMALL_SUBGROUP_G2.isOnCurve());
        assertFalse(JacobianG2BLS381.fromAffine(SMALL_SUBGROUP_G2.x(), SMALL_SUBGROUP_G2.y()).scalarMul(R).isInfinity());
        assertFalse(OFF_CURVE_G2.isOnCurve());

        // nVars = 4, nPublic = 1 => nL = 2; domainSize = 4 => nH = 4.
        // Include AffineG1.INFINITY in both L[1] and H[3] (snarkjs 0.7.6 infinity semantics).
        AffineG1 l0 = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(7)).toAffine();
        AffineG1[] lPoints = {l0, AffineG1.INFINITY};
        AffineG1[] hPoints = {
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(11)).toAffine(),
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(13)).toAffine(),
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(17)).toAffine(),
                AffineG1.INFINITY
        };

        Path z0 = dir.resolve("key0.zkey");
        Files.write(z0, buildSyntheticZkey(G1, G2, lPoints, hPoints, null));

        Path z1 = dir.resolve("key1.zkey");
        byte[] hash1 = ZkeyContributor.contribute(z0, z1, "alice");
        assertEquals(64, hash1.length);
        assertTrue(Files.exists(z1));
        assertNoTempFiles(dir);

        // Verify key1: delta1New != G1, e(delta1New, G2) == e(G1, delta2New),
        // e(L_new[0], delta2New) == e(L_old[0], G2), L_new[1] == INFINITY, H_new[3] == INFINITY.
        byte[] z1Bytes = Files.readAllBytes(z1);
        long s2Off = findSectionOffset(z1Bytes, 2);
        AffineG1 d1New = readG1(z1Bytes, (int) (s2Off + 676));
        AffineG2 d2New = readG2(z1Bytes, (int) (s2Off + 772));
        assertFalse(d1New.equals(G1));
        assertTrue(BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(d1New), G1_GEN.negate()},
                new G2Point[]{G2_GEN, toG2(d2New)}));

        long s8Off = findSectionOffset(z1Bytes, 8);
        AffineG1 l0New = readG1(z1Bytes, (int) s8Off);
        AffineG1 l1New = readG1(z1Bytes, (int) (s8Off + 96));
        assertTrue(l1New.isInfinity(), "L infinity entry must be preserved");
        assertTrue(BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(l0New), toG1(l0).negate()},
                new G2Point[]{toG2(d2New), G2_GEN}));

        long s9Off = findSectionOffset(z1Bytes, 9);
        AffineG1 h0New = readG1(z1Bytes, (int) s9Off);
        AffineG1 h3New = readG1(z1Bytes, (int) (s9Off + 3 * 96));
        assertTrue(h3New.isInfinity(), "H infinity entry must be preserved");
        assertTrue(BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(h0New), toG1(hPoints[0]).negate()},
                new G2Point[]{toG2(d2New), G2_GEN}));

        // Chain a second contribution with a 64-emoji name (tests multibyte UTF-8 TLV truncation <= 255B).
        String emojiName = "\uD83D\uDE80".repeat(64);
        Path z2 = dir.resolve("key2.zkey");
        byte[] hash2 = ZkeyContributor.contribute(z1, z2, emojiName);
        assertEquals(64, hash2.length);
        assertFalse(Arrays.equals(hash1, hash2));

        // Verify the third contribution can parse key2's multi-byte TLV params without error.
        Path z3 = dir.resolve("key3.zkey");
        byte[] hash3 = ZkeyContributor.contribute(z2, z3, "carol");
        assertEquals(64, hash3.length);
        assertNoTempFiles(dir);
    }

    // ---- S1 & S2: Framing, sections, and exact header primes ----

    @Test
    void rejectsTruncatedAndBadFramingFiles(@TempDir Path dir) throws Exception {
        byte[] valid = buildValidGenesisBytes();

        assertRejects(dir, "too-short.zkey", new byte[]{1, 2, 3}, "Truncated");

        byte[] badMagic = valid.clone();
        badMagic[0] ^= 0x01;
        assertRejects(dir, "bad-magic.zkey", badMagic, "magic");

        byte[] badVersion = valid.clone();
        putU32(badVersion, 4, 3);
        assertRejects(dir, "bad-version.zkey", badVersion, "version");

        byte[] trailing = Arrays.copyOf(valid, valid.length + 4);
        assertRejects(dir, "trailing.zkey", trailing, "Trailing");

        // Duplicate section: turn section 3's type into 2 (after section 2)
        byte[] dupSec = valid.clone();
        int sec3HeaderOff = findSectionHeaderOffset(dupSec, 3);
        putU32(dupSec, sec3HeaderOff, 2);
        assertRejects(dir, "dup-sec.zkey", dupSec, "Duplicate");

        // Out-of-bounds section size
        byte[] oobSec = valid.clone();
        int sec9HeaderOff = findSectionHeaderOffset(oobSec, 9);
        putU64(oobSec, sec9HeaderOff + 4, 1L << 40);
        assertRejects(dir, "oob-sec.zkey", oobSec, "Out-of-bounds");

        // Unaligned / wrong-size L section (add 4 bytes to section 8 size and file)
        byte[] badLSize = mutateSectionSize(valid, 8, 4);
        assertRejects(dir, "bad-l-size.zkey", badLSize, "Section 8 (L)");

        // Unaligned / wrong-size H section (add 4 bytes to section 9 size and file)
        byte[] badHSize = mutateSectionSize(valid, 9, 4);
        assertRejects(dir, "bad-h-size.zkey", badHSize, "Section 9 (H)");
    }

    @Test
    void rejectsWrongHeaderPrimes(@TempDir Path dir) throws Exception {
        byte[] valid = buildValidGenesisBytes();
        int s2Off = (int) findSectionOffset(valid, 2);

        byte[] badQ = valid.clone();
        badQ[s2Off + 4] ^= 0x01; // flip LSB of prime q
        assertRejects(dir, "bad-q.zkey", badQ, "base field prime q");

        byte[] badR = valid.clone();
        badR[s2Off + 56] ^= 0x01; // flip LSB of prime r
        assertRejects(dir, "bad-r.zkey", badR, "scalar field prime r");
    }

    // ---- S3 & S4: Canonical < p, delta1/delta2 validity, pairing, chain ----

    @Test
    void rejectsInvalidDelta1AndDelta2(@TempDir Path dir) throws Exception {
        // Identity delta1
        assertRejects(dir, "id-d1.zkey",
                buildSyntheticZkey(AffineG1.INFINITY, G2, defaultL(), defaultH(), null),
                "Identity G1");

        // Identity delta2 (also exercises G2 infinity sentinel)
        assertRejects(dir, "id-d2.zkey",
                buildSyntheticZkey(G1, AffineG2.INFINITY, defaultL(), defaultH(), null),
                "Identity G2");

        // Off-curve delta1
        assertRejects(dir, "offcurve-d1.zkey",
                buildSyntheticZkey(OFF_CURVE_G1, G2, defaultL(), defaultH(), null),
                "Off-curve G1");

        // Off-curve delta2
        assertRejects(dir, "offcurve-d2.zkey",
                buildSyntheticZkey(G1, OFF_CURVE_G2, defaultL(), defaultH(), null),
                "Off-curve G2");

        // Small-subgroup delta1
        assertRejects(dir, "subgrp-d1.zkey",
                buildSyntheticZkey(SMALL_SUBGROUP_G1, G2, defaultL(), defaultH(), null),
                "Non-subgroup G1");

        // Small-subgroup delta2
        assertRejects(dir, "subgrp-d2.zkey",
                buildSyntheticZkey(G1, SMALL_SUBGROUP_G2, defaultL(), defaultH(), null),
                "Non-subgroup G2");

        // Non-canonical (>= p) coordinate in delta1
        byte[] nonCanonD1 = buildValidGenesisBytes();
        int s2Off = (int) findSectionOffset(nonCanonD1, 2);
        putUnsignedLE(nonCanonD1, s2Off + 676, P, 48); // exact modulus p (>= p)
        assertRejects(dir, "noncanon-d1.zkey", nonCanonD1, "Non-canonical G1");

        // Non-canonical (>= p) coordinate in delta2
        byte[] nonCanonD2 = buildValidGenesisBytes();
        putUnsignedLE(nonCanonD2, s2Off + 772, P, 48);
        assertRejects(dir, "noncanon-d2.zkey", nonCanonD2, "Non-canonical G2");

        // Pairing mismatch: delta1 = G1, delta2 = 2*G2 (both valid subgroup, non-identity, wrong pairing)
        AffineG2 twoG2 = JacobianG2BLS381.GENERATOR.doublePoint().toAffine();
        assertRejects(dir, "pairing-mismatch.zkey",
                buildSyntheticZkey(G1, twoG2, defaultL(), defaultH(), null),
                "pairing check");

        // Chain mismatch at 0 priors: delta1 = 2*G1, delta2 = 2*G2 (pairing holds, but delta1 != G1)
        AffineG1 twoG1 = JacobianG1BLS381.GENERATOR.doublePoint().toAffine();
        assertRejects(dir, "genesis-chain-mismatch.zkey",
                buildSyntheticZkey(twoG1, twoG2, defaultL(), defaultH(), null),
                "G1 generator");
    }

    @Test
    void rejectsBrokenPriorChainAndMalformedPriorRecords(@TempDir Path dir) throws Exception {
        // Generate a legitimate key1 first
        Path z0 = dir.resolve("base0.zkey");
        Path z1 = dir.resolve("base1.zkey");
        Files.write(z0, buildValidGenesisBytes());
        ZkeyContributor.contribute(z0, z1, "alice");
        byte[] z1Bytes = Files.readAllBytes(z1);

        // Tamper prior[0].deltaAfter to G1 (valid subgroup, non-identity, but != header.delta1)
        byte[] brokenChain = z1Bytes.clone();
        int s10Off = (int) findSectionOffset(brokenChain, 10);
        System.arraycopy(g1Lem(G1), 0, brokenChain, s10Off + 68, 96);
        assertRejects(dir, "broken-chain.zkey", brokenChain, "last contribution deltaAfter");

        // Tamper prior[0].g1_s to identity
        byte[] idPrior = z1Bytes.clone();
        Arrays.fill(idPrior, s10Off + 68 + 96, s10Off + 68 + 192, (byte) 0);
        assertRejects(dir, "id-prior.zkey", idPrior, "Identity G1");

        // Tamper prior[0].g2_spx to non-canonical (>= p)
        byte[] nonCanonPrior = z1Bytes.clone();
        putUnsignedLE(nonCanonPrior, s10Off + 68 + 288, P, 48);
        assertRejects(dir, "noncanon-prior.zkey", nonCanonPrior, "Non-canonical G2");

        // Malformed TLV params in prior contribution: unsorted tag order (tag 2 then tag 1)
        ByteArrayOutputStream badTlvSec10 = new ByteArrayOutputStream();
        badTlvSec10.write(new byte[64]); // csHash
        writeU32(badTlvSec10, 1);        // nContrib = 1
        badTlvSec10.write(g1Lem(G1));    // deltaAfter = G1 (matches header.delta1)
        badTlvSec10.write(g1Lem(G1));    // g1_s
        badTlvSec10.write(g1Lem(G1));    // g1_sx
        badTlvSec10.write(g2Lem(G2));    // g2_spx
        badTlvSec10.write(new byte[64]); // transcript
        writeU32(badTlvSec10, 1);        // type = beacon
        byte[] badParams = new byte[]{2, 10, 1, 1, 'a'}; // tag 2 followed by tag 1 (unsorted)
        writeU32(badTlvSec10, badParams.length);
        badTlvSec10.write(badParams);
        assertRejects(dir, "unsorted-tlv.zkey",
                buildSyntheticZkey(G1, G2, defaultL(), defaultH(), badTlvSec10.toByteArray()),
                "strictly sorted");

        // Valid beacon prior (type = 1, sorted tags 1, 2, 3) accepted cleanly
        ByteArrayOutputStream validBeaconSec10 = new ByteArrayOutputStream();
        validBeaconSec10.write(new byte[64]);
        writeU32(validBeaconSec10, 1);
        validBeaconSec10.write(g1Lem(G1));
        validBeaconSec10.write(g1Lem(G1));
        validBeaconSec10.write(g1Lem(G1));
        validBeaconSec10.write(g2Lem(G2));
        validBeaconSec10.write(new byte[64]);
        writeU32(validBeaconSec10, 1);
        byte[] beaconParams = new byte[]{1, 1, 'b', 2, 10, 3, 2, 0x12, 0x34};
        writeU32(validBeaconSec10, beaconParams.length);
        validBeaconSec10.write(beaconParams);
        Path beaconIn = dir.resolve("valid-beacon.zkey");
        Path beaconOut = dir.resolve("valid-beacon.out.zkey");
        Files.write(beaconIn, buildSyntheticZkey(G1, G2, defaultL(), defaultH(), validBeaconSec10.toByteArray()));
        assertEquals(64, ZkeyContributor.contribute(beaconIn, beaconOut, "post-beacon").length);
    }

    // ---- S5: L and H validation + atomic cleanup ----

    @Test
    void rejectsInvalidPointsInLAndH_withoutCreatingOutputOrTempFiles(@TempDir Path dir) throws Exception {
        // Off-curve in L
        assertRejects(dir, "offcurve-l.zkey",
                buildSyntheticZkey(G1, G2, new AffineG1[]{OFF_CURVE_G1, G1}, defaultH(), null),
                "L (section 8)");

        // Small-subgroup in L
        assertRejects(dir, "subgrp-l.zkey",
                buildSyntheticZkey(G1, G2, new AffineG1[]{SMALL_SUBGROUP_G1, G1}, defaultH(), null),
                "L (section 8)");

        // Non-canonical (>= p) in L
        byte[] nonCanonL = buildValidGenesisBytes();
        int s8Off = (int) findSectionOffset(nonCanonL, 8);
        putUnsignedLE(nonCanonL, s8Off, P, 48);
        assertRejects(dir, "noncanon-l.zkey", nonCanonL, "L (section 8)");

        // Off-curve in H
        AffineG1[] badHOff = defaultH();
        badHOff[2] = OFF_CURVE_G1;
        assertRejects(dir, "offcurve-h.zkey",
                buildSyntheticZkey(G1, G2, defaultL(), badHOff, null),
                "H (section 9)");

        // Small-subgroup in H
        AffineG1[] badHSub = defaultH();
        badHSub[1] = SMALL_SUBGROUP_G1;
        assertRejects(dir, "subgrp-h.zkey",
                buildSyntheticZkey(G1, G2, defaultL(), badHSub, null),
                "H (section 9)");

        // Non-canonical (>= p) in H
        byte[] nonCanonH = buildValidGenesisBytes();
        int s9Off = (int) findSectionOffset(nonCanonH, 9);
        putUnsignedLE(nonCanonH, s9Off + 96, P, 48);
        assertRejects(dir, "noncanon-h.zkey", nonCanonH, "H (section 9)");
    }

    // ---- S7: Overwrite & in-place protection ----

    @Test
    void overwriteProtectionAndAtomicFailureRollback(@TempDir Path dir) throws Exception {
        byte[] genesisBytes = buildValidGenesisBytes();
        Path in = dir.resolve("in.zkey");
        Files.write(in, genesisBytes);

        // In-place overwrite always rejected (even with overwrite=true)
        assertThrows(IOException.class, () -> ZkeyContributor.contribute(in, in, "alice", false));
        assertThrows(IOException.class, () -> ZkeyContributor.contribute(in, in, "alice", true));
        assertArrayEquals(genesisBytes, Files.readAllBytes(in), "input file must remain intact");

        // Symlink pointing to input also rejected
        Path symlink = dir.resolve("alias.zkey");
        Files.createSymbolicLink(symlink, in);
        assertThrows(IOException.class, () -> ZkeyContributor.contribute(in, symlink, "alice", true));
        assertArrayEquals(genesisBytes, Files.readAllBytes(in), "symlinked input must remain intact");

        // Existing output rejected unless overwrite=true
        Path existing = dir.resolve("existing.zkey");
        byte[] sentinel = "do-not-clobber".getBytes();
        Files.write(existing, sentinel);
        assertThrows(IOException.class, () -> ZkeyContributor.contribute(in, existing, "alice"));
        assertArrayEquals(sentinel, Files.readAllBytes(existing), "existing output must not be clobbered");

        // Failed contribution with overwrite=true must NOT clobber existing output
        Path badIn = dir.resolve("bad-l.zkey");
        Files.write(badIn, buildSyntheticZkey(G1, G2, new AffineG1[]{SMALL_SUBGROUP_G1, G1}, defaultH(), null));
        assertThrows(IOException.class, () -> ZkeyContributor.contribute(badIn, existing, "alice", true));
        assertArrayEquals(sentinel, Files.readAllBytes(existing), "failed overwrite must leave existing output intact");
        assertNoTempFiles(dir);

        // Explicit overwrite=true succeeds on valid input
        byte[] hash = ZkeyContributor.contribute(in, existing, "alice", true);
        assertEquals(64, hash.length);
        assertFalse(Arrays.equals(sentinel, Files.readAllBytes(existing)));
        assertNoTempFiles(dir);
    }

    // ---- Helpers ----

    private static void assertRejects(Path dir, String name, byte[] inputBytes, String expectedMessagePart)
            throws IOException {
        Path in = dir.resolve(name);
        Path out = dir.resolve(name + ".out");
        Files.write(in, inputBytes);
        IOException ex = assertThrows(IOException.class, () -> ZkeyContributor.contribute(in, out, "tester"),
                "Expected rejection for " + name);
        assertTrue(ex.getMessage().contains(expectedMessagePart),
                "Expected message containing '" + expectedMessagePart + "', got: " + ex.getMessage());
        assertFalse(Files.exists(out), "Output file must not exist after failed contribution: " + name);
        assertNoTempFiles(dir);
    }

    private static void assertNoTempFiles(Path dir) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> temps = files.filter(p -> p.getFileName().toString().startsWith(".zeroj-zkey-")).toList();
            assertTrue(temps.isEmpty(), "Leftover temp files found: " + temps);
        }
    }

    private static byte[] buildValidGenesisBytes() throws IOException {
        return buildSyntheticZkey(G1, G2, defaultL(), defaultH(), null);
    }

    private static AffineG1[] defaultL() {
        return new AffineG1[]{
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(3)).toAffine(),
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(5)).toAffine()
        };
    }

    private static AffineG1[] defaultH() {
        return new AffineG1[]{
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(7)).toAffine(),
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(11)).toAffine(),
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(13)).toAffine(),
                JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(17)).toAffine()
        };
    }

    private static byte[] buildSyntheticZkey(
            AffineG1 delta1, AffineG2 delta2, AffineG1[] lPoints, AffineG1[] hPoints, byte[] customSec10)
            throws IOException {
        int nPublic = 1;
        int nVars = nPublic + 1 + lPoints.length;
        int domainSize = hPoints.length;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        // File header: magic "zkey", version 1, 10 sections
        writeU32(out, 0x79656b7a);
        writeU32(out, 1);
        writeU32(out, 10);

        // Section 1: protocol = 1 (groth16)
        writeSection(out, 1, u32Bytes(1));

        // Section 2: header (964 bytes)
        ByteArrayOutputStream hdr = new ByteArrayOutputStream();
        writeU32(hdr, 48);
        writeUnsignedLE(hdr, P, 48);
        writeU32(hdr, 32);
        writeUnsignedLE(hdr, R, 32);
        writeU32(hdr, nVars);
        writeU32(hdr, nPublic);
        writeU32(hdr, domainSize);
        hdr.write(g1Lem(G1));     // alpha1
        hdr.write(g1Lem(G1));     // beta1
        hdr.write(g2Lem(G2));     // beta2
        hdr.write(g2Lem(G2));     // gamma2
        hdr.write(g1Lem(delta1)); // delta1
        hdr.write(g2Lem(delta2)); // delta2
        assertEquals(964, hdr.size());
        writeSection(out, 2, hdr.toByteArray());

        // Section 3: IC (nPublic + 1 G1 points)
        ByteArrayOutputStream s3 = new ByteArrayOutputStream();
        for (int i = 0; i <= nPublic; i++) s3.write(g1Lem(G1));
        writeSection(out, 3, s3.toByteArray());

        // Section 4: coeffs (0 entries)
        writeSection(out, 4, u32Bytes(0));

        // Section 5 (A), 6 (B1), 7 (B2)
        ByteArrayOutputStream s5 = new ByteArrayOutputStream();
        ByteArrayOutputStream s6 = new ByteArrayOutputStream();
        ByteArrayOutputStream s7 = new ByteArrayOutputStream();
        for (int i = 0; i < nVars; i++) {
            s5.write(g1Lem(G1));
            s6.write(g1Lem(G1));
            s7.write(g2Lem(G2));
        }
        writeSection(out, 5, s5.toByteArray());
        writeSection(out, 6, s6.toByteArray());
        writeSection(out, 7, s7.toByteArray());

        // Section 8 (L)
        ByteArrayOutputStream s8 = new ByteArrayOutputStream();
        for (AffineG1 p : lPoints) s8.write(g1Lem(p));
        writeSection(out, 8, s8.toByteArray());

        // Section 9 (H)
        ByteArrayOutputStream s9 = new ByteArrayOutputStream();
        for (AffineG1 p : hPoints) s9.write(g1Lem(p));
        writeSection(out, 9, s9.toByteArray());

        // Section 10 (contributions)
        if (customSec10 != null) {
            writeSection(out, 10, customSec10);
        } else {
            ByteArrayOutputStream s10 = new ByteArrayOutputStream();
            byte[] csHash = new byte[64];
            for (int i = 0; i < 64; i++) csHash[i] = (byte) (i + 1);
            s10.write(csHash);
            writeU32(s10, 0);
            writeSection(out, 10, s10.toByteArray());
        }

        return out.toByteArray();
    }

    private static byte[] mutateSectionSize(byte[] valid, int targetSection, int extraBytes) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(valid, 0, 12);
        int pos = 12;
        ByteBuffer buf = ByteBuffer.wrap(valid).order(ByteOrder.LITTLE_ENDIAN);
        while (pos < valid.length) {
            int type = buf.getInt(pos);
            long size = buf.getLong(pos + 4);
            long newSize = type == targetSection ? size + extraBytes : size;
            writeU32(out, type);
            writeU64(out, newSize);
            out.write(valid, pos + 12, (int) size);
            if (type == targetSection) {
                out.write(new byte[extraBytes], 0, extraBytes);
            }
            pos += 12 + (int) size;
        }
        return out.toByteArray();
    }

    private static int findSectionHeaderOffset(byte[] zkey, int targetType) {
        ByteBuffer buf = ByteBuffer.wrap(zkey).order(ByteOrder.LITTLE_ENDIAN);
        int pos = 12;
        while (pos < zkey.length) {
            int type = buf.getInt(pos);
            long size = buf.getLong(pos + 4);
            if (type == targetType) return pos;
            pos += 12 + (int) size;
        }
        throw new IllegalArgumentException("Section not found: " + targetType);
    }

    private static long findSectionOffset(byte[] zkey, int targetType) {
        return findSectionHeaderOffset(zkey, targetType) + 12L;
    }

    private static AffineG2 buildSmallSubgroupG2() {
        // Find smallest integer x >= 0 where y^2 = x^3 + 4(1+u) has a root in Fp2 not in the r-subgroup.
        Fp2 bTwist = Fp2.of(Fp.of(4), Fp.of(4));
        for (int xi = 0; xi < 100; xi++) {
            Fp2 x = Fp2.of(Fp.of(xi), Fp.ZERO);
            Fp2 rhs = x.square().mul(x).add(bTwist);
            var yOpt = rhs.sqrt();
            if (yOpt.isPresent()) {
                Fp2 y = yOpt.get();
                AffineG2 candidate = new AffineG2(
                        MontFp2_381.of(x.c0().value(), x.c1().value()),
                        MontFp2_381.of(y.c0().value(), y.c1().value()));
                if (candidate.isOnCurve()
                        && !JacobianG2BLS381.fromAffine(candidate.x(), candidate.y()).scalarMul(R).isInfinity()) {
                    return candidate;
                }
            }
        }
        throw new AssertionError("Failed to find non-subgroup G2 point");
    }

    private static AffineG1 readG1(byte[] b, int off) {
        MontFp381 x = readMontFp(b, off);
        MontFp381 y = readMontFp(b, off + 48);
        return (x.isZero() && y.isZero()) ? AffineG1.INFINITY : new AffineG1(x, y);
    }

    private static AffineG2 readG2(byte[] b, int off) {
        MontFp381 x0 = readMontFp(b, off);
        MontFp381 x1 = readMontFp(b, off + 48);
        MontFp381 y0 = readMontFp(b, off + 96);
        MontFp381 y1 = readMontFp(b, off + 144);
        if (x0.isZero() && x1.isZero() && y0.isZero() && y1.isZero()) return AffineG2.INFINITY;
        return new AffineG2(MontFp2_381.of(x0, x1), MontFp2_381.of(y0, y1));
    }

    private static MontFp381 readMontFp(byte[] b, int off) {
        ByteBuffer bb = ByteBuffer.wrap(b, off, 48).order(ByteOrder.LITTLE_ENDIAN);
        return MontFp381.fromMontLimbs(
                bb.getLong(), bb.getLong(), bb.getLong(), bb.getLong(), bb.getLong(), bb.getLong());
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

    private static void putUnsignedLE(byte[] out, int off, BigInteger v, int len) {
        byte[] be = v.toByteArray();
        Arrays.fill(out, off, off + len, (byte) 0);
        int start = Math.max(0, be.length - len);
        int count = be.length - start;
        for (int i = 0; i < count; i++) {
            out[off + i] = be[be.length - 1 - i];
        }
    }

    private static void writeUnsignedLE(ByteArrayOutputStream out, BigInteger v, int len) {
        byte[] buf = new byte[len];
        putUnsignedLE(buf, 0, v, len);
        out.write(buf, 0, len);
    }

    private static void writeSection(ByteArrayOutputStream out, int type, byte[] data) throws IOException {
        writeU32(out, type);
        writeU64(out, data.length);
        out.write(data);
    }

    private static void writeU32(ByteArrayOutputStream out, int v) {
        out.write(v);
        out.write(v >>> 8);
        out.write(v >>> 16);
        out.write(v >>> 24);
    }

    private static void writeU64(ByteArrayOutputStream out, long v) {
        for (int i = 0; i < 8; i++) out.write((int) (v >>> (8 * i)));
    }

    private static byte[] u32Bytes(int v) {
        return new byte[]{(byte) v, (byte) (v >>> 8), (byte) (v >>> 16), (byte) (v >>> 24)};
    }

    private static void putU32(byte[] b, int off, int v) {
        b[off] = (byte) v;
        b[off + 1] = (byte) (v >>> 8);
        b[off + 2] = (byte) (v >>> 16);
        b[off + 3] = (byte) (v >>> 24);
    }

    private static void putU64(byte[] b, int off, long v) {
        for (int i = 0; i < 8; i++) b[off + i] = (byte) (v >>> (8 * i));
    }

    private static G1Point toG1(AffineG1 p) {
        return p.isInfinity() ? G1Point.INFINITY : new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
