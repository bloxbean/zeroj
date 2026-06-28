package com.bloxbean.cardano.zeroj.crypto.plonk;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.jupiter.api.Assertions.assertThrows;

class PtauImporterBLS381Test {

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
    void importPtau_rejectsExpectedHashMismatchBeforeParsing() {
        assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(
                new ByteArrayInputStream(new byte[]{'p', 't', 'a', 'u'}), 1, new byte[32]));
    }

    @Test
    void importPtau_rejectsDuplicateSections() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{'p', 't', 'a', 'u'});
        out.write(leInt(1));
        out.write(leInt(2));
        writeSection(out, 1, new byte[0]);
        writeSection(out, 1, new byte[0]);

        assertThrows(IOException.class, () -> PtauImporterBLS381.importPtau(
                new ByteArrayInputStream(out.toByteArray()), 1));
    }

    @Test
    void importPtau_rejectsWrongBaseFieldPrime() throws IOException {
        ByteArrayOutputStream header = new ByteArrayOutputStream();
        header.write(leInt(48));
        header.write(new byte[48]);
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
