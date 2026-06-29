package com.bloxbean.cardano.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;

class Groth16BLS381ImporterHardeningTest {

    @Test
    void zkeyImporterRejectsNullInput() {
        assertThrows(IOException.class, () -> ZkeyImporterBLS381.importZkey(null));
    }

    @Test
    void zkeyImporterRejectsTruncatedInput() {
        assertThrows(IOException.class, () ->
                ZkeyImporterBLS381.importZkey(new ByteArrayInputStream(new byte[]{'z', 'k'})));
    }

    @Test
    void zkeyImporterRejectsHashMismatch() {
        assertThrows(IOException.class, () ->
                ZkeyImporterBLS381.importZkey(
                        new ByteArrayInputStream(new byte[]{'z', 'k', 'e', 'y', 1, 0, 0, 0}),
                        new byte[32]));
    }

    @Test
    void witnessImporterRejectsTruncatedInput() {
        assertThrows(IOException.class, () ->
                ZkeyImporterBLS381.importWtns(new ByteArrayInputStream(new byte[]{'w', 't'})));
    }
}
