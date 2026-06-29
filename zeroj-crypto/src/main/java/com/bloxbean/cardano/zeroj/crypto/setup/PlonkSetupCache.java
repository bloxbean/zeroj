package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PtauImporterBLS381;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Binary cache for BLS12-381 PlonK setup artifacts.
 *
 * <p>PlonK uses a common BLS12-381 Powers of Tau / KZG SRS that can be reused
 * across compatible circuits up to the SRS size. Each circuit still has
 * circuit-specific proving-key material, but generating that material does not
 * require a new trusted ceremony if the universal SRS is already trusted.</p>
 *
 * <p>If the circuit gates, public-input profile, domain size, or SRS identity
 * changes, generate a new PlonK proving key instead of reusing the old cache
 * entry.</p>
 */
public final class PlonkSetupCache {
    private PlonkSetupCache() {
    }

    /**
     * Save a BLS12-381 Powers of Tau / KZG SRS artifact for PlonK reuse.
     */
    public static void saveBls12381Srs(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        SrsCache.saveBls12381Srs(srs, path);
    }

    /**
     * Save a development-only SRS cache that includes the toxic tau scalar.
     */
    public static void saveBls12381InsecureDevSrsWithTau(PtauImporterBLS381.SRS srs, Path path) throws IOException {
        SrsCache.saveBls12381InsecureDevSrsWithTau(srs, path);
    }

    /**
     * Load a BLS12-381 Powers of Tau / KZG SRS artifact for PlonK reuse.
     */
    public static PtauImporterBLS381.SRS loadBls12381Srs(Path path) throws IOException {
        return SrsCache.loadBls12381Srs(path);
    }

    /**
     * Save a BLS12-381 PlonK circuit-specific proving key.
     */
    public static void saveBls12381ProvingKey(PlonKProvingKeyBLS381 pk, Path path) throws IOException {
        validatePlonkProvingKey(pk);
        SetupCacheIO.writeCacheFile(path, SetupCacheIO.TYPE_PLONK_BLS12381_PROVING_KEY, out -> {
            out.writeInt(pk.domainSize());
            out.writeInt(pk.nPublic());
            out.writeInt(pk.nConstraints());
            SetupCacheIO.writeScalar(out, pk.k1(), "k1");
            SetupCacheIO.writeScalar(out, pk.k2(), "k2");
            SetupCacheIO.writeFr(out, pk.omega());

            SetupCacheIO.writeFrArray(out, pk.ql());
            SetupCacheIO.writeFrArray(out, pk.qr());
            SetupCacheIO.writeFrArray(out, pk.qm());
            SetupCacheIO.writeFrArray(out, pk.qo());
            SetupCacheIO.writeFrArray(out, pk.qc());
            SetupCacheIO.writeFrArray(out, pk.s1());
            SetupCacheIO.writeFrArray(out, pk.s2());
            SetupCacheIO.writeFrArray(out, pk.s3());

            SetupCacheIO.writeG1Array(out, pk.srsG1());
            SetupCacheIO.writeG1Array(out, pk.srsG1Lagrange());
            SetupCacheIO.writeG2(out, pk.x2());

            SetupCacheIO.writeG1(out, pk.qmCommit());
            SetupCacheIO.writeG1(out, pk.qlCommit());
            SetupCacheIO.writeG1(out, pk.qrCommit());
            SetupCacheIO.writeG1(out, pk.qoCommit());
            SetupCacheIO.writeG1(out, pk.qcCommit());
            SetupCacheIO.writeG1(out, pk.s1Commit());
            SetupCacheIO.writeG1(out, pk.s2Commit());
            SetupCacheIO.writeG1(out, pk.s3Commit());
        });
    }

    /**
     * Load a BLS12-381 PlonK circuit-specific proving key.
     */
    public static PlonKProvingKeyBLS381 loadBls12381ProvingKey(Path path) throws IOException {
        return SetupCacheIO.readCacheFile(path, SetupCacheIO.TYPE_PLONK_BLS12381_PROVING_KEY, in -> {
            int domainSize = in.readInt();
            int nPublic = in.readInt();
            int nConstraints = in.readInt();
            var k1 = SetupCacheIO.readScalar(in, "k1");
            var k2 = SetupCacheIO.readScalar(in, "k2");
            MontFr381 omega = SetupCacheIO.readFr(in);

            MontFr381[] ql = SetupCacheIO.readFrArray(in);
            MontFr381[] qr = SetupCacheIO.readFrArray(in);
            MontFr381[] qm = SetupCacheIO.readFrArray(in);
            MontFr381[] qo = SetupCacheIO.readFrArray(in);
            MontFr381[] qc = SetupCacheIO.readFrArray(in);
            MontFr381[] s1 = SetupCacheIO.readFrArray(in);
            MontFr381[] s2 = SetupCacheIO.readFrArray(in);
            MontFr381[] s3 = SetupCacheIO.readFrArray(in);

            AffineG1[] srsG1 = SetupCacheIO.readG1Array(in);
            AffineG1[] srsG1Lagrange = SetupCacheIO.readG1Array(in);
            var x2 = SetupCacheIO.readG2(in);

            var qmCommit = SetupCacheIO.readG1(in);
            var qlCommit = SetupCacheIO.readG1(in);
            var qrCommit = SetupCacheIO.readG1(in);
            var qoCommit = SetupCacheIO.readG1(in);
            var qcCommit = SetupCacheIO.readG1(in);
            var s1Commit = SetupCacheIO.readG1(in);
            var s2Commit = SetupCacheIO.readG1(in);
            var s3Commit = SetupCacheIO.readG1(in);

            validatePlonkProvingKeyShape(domainSize, nPublic, nConstraints,
                    ql, qr, qm, qo, qc, s1, s2, s3, srsG1, srsG1Lagrange);
            validatePlonkProvingKeyPoints(srsG1, srsG1Lagrange, x2,
                    qmCommit, qlCommit, qrCommit, qoCommit, qcCommit,
                    s1Commit, s2Commit, s3Commit);

            return new PlonKProvingKeyBLS381(
                    domainSize, nPublic, nConstraints, k1, k2, omega,
                    ql, qr, qm, qo, qc, s1, s2, s3,
                    srsG1, srsG1Lagrange, x2,
                    qmCommit, qlCommit, qrCommit, qoCommit, qcCommit,
                    s1Commit, s2Commit, s3Commit);
        });
    }

    private static void validatePlonkProvingKey(PlonKProvingKeyBLS381 pk) throws IOException {
        if (pk == null) {
            throw new IOException("PlonK proving key must not be null");
        }
        validatePlonkProvingKeyShape(pk.domainSize(), pk.nPublic(), pk.nConstraints(),
                pk.ql(), pk.qr(), pk.qm(), pk.qo(), pk.qc(), pk.s1(), pk.s2(), pk.s3(),
                pk.srsG1(), pk.srsG1Lagrange());
        validatePlonkProvingKeyPoints(pk.srsG1(), pk.srsG1Lagrange(), pk.x2(),
                pk.qmCommit(), pk.qlCommit(), pk.qrCommit(), pk.qoCommit(), pk.qcCommit(),
                pk.s1Commit(), pk.s2Commit(), pk.s3Commit());
    }

    private static void validatePlonkProvingKeyShape(
            int domainSize,
            int nPublic,
            int nConstraints,
            MontFr381[] ql,
            MontFr381[] qr,
            MontFr381[] qm,
            MontFr381[] qo,
            MontFr381[] qc,
            MontFr381[] s1,
            MontFr381[] s2,
            MontFr381[] s3,
            AffineG1[] srsG1,
            AffineG1[] srsG1Lagrange) throws IOException {
        if (domainSize <= 0 || Integer.bitCount(domainSize) != 1) {
            throw new IOException("Invalid PlonK domain size: " + domainSize);
        }
        if (domainSize > SetupCacheIO.MAX_PLONK_DOMAIN_SIZE) {
            throw new IOException("PlonK domain size exceeds supported cache limit: " + domainSize);
        }
        if (nPublic < 0 || nPublic > nConstraints) {
            throw new IOException("Invalid PlonK public input count: " + nPublic);
        }
        if (nConstraints <= 0 || nConstraints > domainSize) {
            throw new IOException("Invalid PlonK constraint count: " + nConstraints);
        }
        requireFrArrayLength("ql", ql, domainSize);
        requireFrArrayLength("qr", qr, domainSize);
        requireFrArrayLength("qm", qm, domainSize);
        requireFrArrayLength("qo", qo, domainSize);
        requireFrArrayLength("qc", qc, domainSize);
        requireFrArrayLength("s1", s1, domainSize);
        requireFrArrayLength("s2", s2, domainSize);
        requireFrArrayLength("s3", s3, domainSize);
        if (srsG1.length < 2 * domainSize || srsG1Lagrange.length < domainSize) {
            throw new IOException("PlonK proving key SRS is too small for domain size " + domainSize);
        }
    }

    private static void requireFrArrayLength(String label, MontFr381[] arr, int expected) throws IOException {
        if (arr.length != expected) {
            throw new IOException("Invalid PlonK " + label + " length: expected " + expected + ", got " + arr.length);
        }
    }

    private static void validatePlonkProvingKeyPoints(
            AffineG1[] srsG1,
            AffineG1[] srsG1Lagrange,
            com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2 x2,
            AffineG1 qmCommit,
            AffineG1 qlCommit,
            AffineG1 qrCommit,
            AffineG1 qoCommit,
            AffineG1 qcCommit,
            AffineG1 s1Commit,
            AffineG1 s2Commit,
            AffineG1 s3Commit) throws IOException {
        SetupCacheIO.validateG1Array(srsG1, false, "PlonK SRS G1");
        SetupCacheIO.validateG1Array(srsG1Lagrange, true, "PlonK Lagrange SRS G1");
        SetupCacheIO.validateG2(x2, false, "PlonK X_2");
        SetupCacheIO.validateG1(qmCommit, true, "PlonK Qm commitment");
        SetupCacheIO.validateG1(qlCommit, true, "PlonK Ql commitment");
        SetupCacheIO.validateG1(qrCommit, true, "PlonK Qr commitment");
        SetupCacheIO.validateG1(qoCommit, true, "PlonK Qo commitment");
        SetupCacheIO.validateG1(qcCommit, true, "PlonK Qc commitment");
        SetupCacheIO.validateG1(s1Commit, false, "PlonK S1 commitment");
        SetupCacheIO.validateG1(s2Commit, false, "PlonK S2 commitment");
        SetupCacheIO.validateG1(s3Commit, false, "PlonK S3 commitment");
    }
}
