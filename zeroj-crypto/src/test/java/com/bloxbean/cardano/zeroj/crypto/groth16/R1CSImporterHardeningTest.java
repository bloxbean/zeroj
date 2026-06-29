package com.bloxbean.cardano.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertThrows;

class R1CSImporterHardeningTest {

    @Test
    void rejectsNullInput() {
        assertThrows(IOException.class, () -> R1CSImporter.importR1CS(null));
    }

    @Test
    void rejectsTruncatedHeader() {
        assertThrows(IOException.class, () ->
                R1CSImporter.importR1CS(new ByteArrayInputStream(new byte[]{'r', '1'})));
    }

    @Test
    void rejectsInvalidMagic() {
        byte[] data = new byte[12];
        data[0] = 'x';
        data[4] = 1;
        data[8] = 1;

        assertThrows(IOException.class, () ->
                R1CSImporter.importR1CS(new ByteArrayInputStream(data)));
    }
}
