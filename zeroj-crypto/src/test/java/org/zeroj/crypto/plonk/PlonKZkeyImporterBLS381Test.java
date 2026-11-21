package org.zeroj.crypto.plonk;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PlonKZkeyImporterBLS381Test {

    @Test
    void importZkey_singleArg_failsExplicitlyWithUnsupportedOperationException() {
        UnsupportedOperationException ex = assertThrows(
                UnsupportedOperationException.class,
                () -> PlonKZkeyImporterBLS381.importZkey(new ByteArrayInputStream(new byte[]{'z', 'k', 'e', 'y'})));
        assertTrue(ex.getMessage().contains("ADR-0066"), ex.getMessage());
        assertTrue(ex.getMessage().contains("PtauImporterBLS381"), ex.getMessage());
    }

    @Test
    void importZkey_pinnedArg_failsExplicitlyWithUnsupportedOperationException() {
        UnsupportedOperationException ex = assertThrows(
                UnsupportedOperationException.class,
                () -> PlonKZkeyImporterBLS381.importZkey(
                        new ByteArrayInputStream(new byte[]{'z', 'k', 'e', 'y'}), new byte[32]));
        assertTrue(ex.getMessage().contains("ADR-0066"), ex.getMessage());
        assertTrue(ex.getMessage().contains("PtauImporterBLS381"), ex.getMessage());
    }

    @Test
    void importZkey_nullInput_failsExplicitlyWithUnsupportedOperationException() {
        assertThrows(UnsupportedOperationException.class, () -> PlonKZkeyImporterBLS381.importZkey(null));
        assertThrows(UnsupportedOperationException.class, () -> PlonKZkeyImporterBLS381.importZkey(null, null));
    }
}
