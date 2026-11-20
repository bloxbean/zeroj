package org.zeroj.crypto.plonk;

import java.io.IOException;
import java.io.InputStream;

/**
 * Placeholder entry point for snarkjs BLS12-381 PlonK {@code .zkey} import (ADR-0066).
 *
 * <p><b>Unsupported:</b> snarkjs 0.7.6 PlonK {@code .zkey} import is currently unsupported and
 * intentionally fails fast with {@link UnsupportedOperationException}. snarkjs PlonK {@code .zkey}
 * files store circuit-specific wire-addition/permutation maps (sections 3–6), selector polynomials
 * ordered {@code Qm, Ql, Qr, Qo, Qc} with extended evaluations (sections 7–11), and Fr Lagrange
 * polynomials (section 13) that require a dedicated format rework before ZeroJ can safely prove
 * snarkjs-arithmetized PlonK circuits.</p>
 *
 * <p>For BLS12-381 PlonK with a public ceremony SRS, import the universal {@code .ptau} file via
 * {@link PtauImporterBLS381#importPtau(InputStream, int, byte[])} and run
 * {@link PlonKSetupBLS381#setup}. For Groth16 {@code .zkey} import, use
 * {@link org.zeroj.crypto.groth16.ZkeyImporterBLS381} or
 * {@link org.zeroj.crypto.groth16.ZkeyPkStoreImporter}.</p>
 */
public final class PlonKZkeyImporterBLS381 {

    private static final String UNSUPPORTED_MESSAGE =
            "snarkjs BLS12-381 PlonK .zkey import is not supported (ADR-0066: requires full snarkjs 0.7.6 "
                    + "PlonK section-layout and wire-map rework). Import a BLS12-381 .ptau SRS via "
                    + "PtauImporterBLS381.importPtau(...) and run PlonKSetupBLS381.setup(...) instead.";

    private PlonKZkeyImporterBLS381() {}

    /**
     * Unsupported; always throws {@link UnsupportedOperationException} (see class Javadoc and ADR-0066).
     */
    public static PlonKProvingKeyBLS381 importZkey(InputStream input) throws IOException {
        throw new UnsupportedOperationException(UNSUPPORTED_MESSAGE);
    }

    /**
     * Unsupported; always throws {@link UnsupportedOperationException} (see class Javadoc and ADR-0066).
     */
    public static PlonKProvingKeyBLS381 importZkey(InputStream input, byte[] expectedSha256) throws IOException {
        throw new UnsupportedOperationException(UNSUPPORTED_MESSAGE);
    }
}
