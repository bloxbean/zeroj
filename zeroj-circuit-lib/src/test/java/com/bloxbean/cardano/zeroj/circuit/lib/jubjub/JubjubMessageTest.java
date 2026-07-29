package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JubjubMessageTest {

    @Test
    @DisplayName("canonical message factory pins length, byte order, and field boundary")
    void canonicalFactory() {
        for (BigInteger value : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE,
                JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE)}) {
            byte[] encoded = fixed32(value);
            JubjubMessage message = JubjubMessage.fromCanonicalFieldBytes(encoded);
            assertArrayEquals(encoded, message.toCanonicalFieldBytes());
            assertEquals(value, message.toPublicFieldElement());
        }
        assertThrows(IllegalArgumentException.class,
                () -> JubjubMessage.fromCanonicalFieldBytes(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> JubjubMessage.fromCanonicalFieldBytes(new byte[33]));
        assertThrows(IllegalArgumentException.class,
                () -> JubjubMessage.fromCanonicalFieldBytes(
                        fixed32(JubjubCurve.BASE_FIELD_PRIME)));
    }

    @Test
    @DisplayName("canonical message defensively copies inputs and outputs")
    void defensiveCopies() {
        byte[] source = fixed32(BigInteger.valueOf(42));
        JubjubMessage message = JubjubMessage.fromCanonicalFieldBytes(source);
        source[31] = 7;
        assertEquals(BigInteger.valueOf(42), message.toPublicFieldElement());

        byte[] output = message.toCanonicalFieldBytes();
        output[31] = 9;
        assertEquals(BigInteger.valueOf(42), message.toPublicFieldElement());
    }

    @Test
    @DisplayName("typed hash-to-field matches independent vectors at framing boundaries")
    void hashToFieldVectors() {
        assertEquals(new BigInteger(
                        "6a482f890fb3b183bcf9dcc92882f5e73db111459d830b2d3f306b44c6a0ce5d",
                        16),
                JubjubMessage.hashToField(new byte[0]).toPublicFieldElement());
        assertEquals(new BigInteger(
                        "54fb4aff307c5e8e14317ab691f43f93b453d7acc444cbe49f4246ad9c1d422c",
                        16),
                JubjubMessage.hashToField("a".getBytes(StandardCharsets.UTF_8))
                        .toPublicFieldElement());
        assertEquals(new BigInteger(
                        "304275eedabef9c974cb80beab9264e2ecdfd644da7221cccabd8364e3501f60",
                        16),
                JubjubMessage.hashToField(
                                "the quick brown fox".getBytes(StandardCharsets.UTF_8))
                        .toPublicFieldElement());

        int[] lengths = {0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 300};
        String[] expectedHex = {
                "6a482f890fb3b183bcf9dcc92882f5e73db111459d830b2d3f306b44c6a0ce5d",
                "0293a98dda20b8939ae6969fd6924f2e62d734d6bf2f82083a8529f867cb4587",
                "15e5483d0f6a7b94192e00973d45df09755114e17a9eecf418a831963bd36fc7",
                "1808f9604aec382c9ecaef4519cc212c78d8067f888b5441c2ce843e1d446f6d",
                "4f3ca97b3de8a866f13b1ab70115ea946f1486d2d4333575ec3d37699cedb7e4",
                "50ac794e90f37be3b734b8f3c2822840d5dd9f87b8a7b21381a5158aa36e55ff",
                "357e6daa6e06ecdaf68bbe665eb6295820dc6a52f49468b07eaa26221f9fb159",
                "40843c8be00ad540e7b5fc65adaada926609ee6779bb853801bdf4bfa3aa6d9c",
                "2171cf3048f1ab6eadb8a418b6fc14d973d8cc8e2b5d91ab210cd4b68ec52140",
                "6ce801c199d962736a0de9e4dffe7b3bbf669b601d174c13a64821aaa81813fe",
                "4c323a1425a554d765c58476f402bbc6b4f8c3528b7d61518cb456a53971b133",
                "67924a486c1a188f2403fa1f279d16d30d640e22fc5c295195f486faf24a458d"
        };
        for (int vector = 0; vector < lengths.length; vector++) {
            int length = lengths[vector];
            byte[] input = new byte[length];
            Arrays.fill(input, (byte) length);
            JubjubMessage typed = JubjubMessage.hashToField(input);
            assertEquals(new BigInteger(expectedHex[vector], 16),
                    typed.toPublicFieldElement(), "length=" + length);
            assertEquals(EdDSAJubjub.hashToField(input), typed.toPublicFieldElement(),
                    "compatibility adapter length=" + length);
        }
    }

    @Test
    @DisplayName("typed signer and verifier bind the same field element without implicit hashing")
    void typedSignAndVerify() {
        BigInteger sk = BigInteger.valueOf(1234567);
        EdDSAJubjub.Keypair keypair = EdDSAJubjub.keypairFromSecret(sk);
        JubjubMessage field = JubjubMessage.fromCanonicalFieldBytes(fixed32(BigInteger.ONE));
        JubjubMessage hashed = JubjubMessage.hashToField(new byte[]{1});

        EdDSAJubjub.Signature signature =
                EdDSAJubjub.signCompatibilityOffline(keypair, field);
        assertTrue(EdDSAJubjub.verify(keypair.pk(), field, signature));
        assertTrue(EdDSAJubjub.verify(keypair.pk(), BigInteger.ONE, signature));
        assertFalse(EdDSAJubjub.verify(keypair.pk(), hashed, signature));

        // The deprecated generic name remains a source/binary-compatible adapter only.
        assertEquals(signature, EdDSAJubjub.sign(keypair, field));
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length == 33 && raw[0] == 0 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }
}
