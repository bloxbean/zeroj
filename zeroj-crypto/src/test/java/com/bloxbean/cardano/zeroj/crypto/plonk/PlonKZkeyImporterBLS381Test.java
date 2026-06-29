package com.bloxbean.cardano.zeroj.crypto.plonk;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.jupiter.api.Assertions.assertThrows;

class PlonKZkeyImporterBLS381Test {

    @Test
    void importZkey_rejectsNullInput() {
        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(null));
    }

    @Test
    void importZkey_rejectsTruncatedHeader() {
        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(
                new ByteArrayInputStream(new byte[]{'z', 'k', 'e', 'y'})));
    }

    @Test
    void importZkey_rejectsExpectedHashLengthMismatch() {
        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(
                new ByteArrayInputStream(new byte[]{'z', 'k', 'e', 'y'}), new byte[31]));
    }

    @Test
    void importZkey_rejectsExpectedHashMismatchBeforeParsing() {
        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(
                new ByteArrayInputStream(new byte[]{'z', 'k', 'e', 'y'}), new byte[32]));
    }

    @Test
    void importZkey_rejectsDuplicateSections() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'z', 'k', 'e', 'y'});
        out.write(leInt(1));
        out.write(leInt(2));
        writeSection(out, 1, new byte[0]);
        writeSection(out, 1, new byte[0]);

        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(
                new ByteArrayInputStream(out.toByteArray())));
    }

    @Test
    void importZkey_rejectsMissingRequiredSections() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'z', 'k', 'e', 'y'});
        out.write(leInt(1));
        out.write(leInt(1));
        writeSection(out, 1, leInt(2));

        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(
                new ByteArrayInputStream(out.toByteArray())));
    }

    @Test
    void importZkey_rejectsWrongProtocol() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'z', 'k', 'e', 'y'});
        out.write(leInt(1));
        out.write(leInt(10));
        writeSection(out, 1, leInt(1));
        for (int sectionId : new int[]{2, 7, 8, 9, 10, 11, 12, 13, 14}) {
            writeSection(out, sectionId, new byte[0]);
        }

        assertThrows(IOException.class, () -> PlonKZkeyImporterBLS381.importZkey(
                new ByteArrayInputStream(out.toByteArray())));
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
