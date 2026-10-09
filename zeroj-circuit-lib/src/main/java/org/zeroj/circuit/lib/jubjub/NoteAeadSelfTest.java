package org.zeroj.circuit.lib.jubjub;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * A known-answer self-test of the platform's ChaCha20-Poly1305 on exactly the call
 * {@code confidential-note-jubjub-v1} makes: a 32-byte key, the all-zero nonce and empty
 * associated data (ADR-0055 D5, D9).
 *
 * <p>The provider is the only platform-dependent primitive of the profile: BLAKE2b and the
 * Jubjub arithmetic are ZeroJ's own code. A provider that is missing, faulty or not conformant
 * would make every delivery look like "not mine", so {@link NoteScanner} and
 * {@link ConfidentialNotes#seal} run this test first and fail closed (as ADR-0054's
 * implementation note 7 does for its transport).
 *
 * <p>The values are the {@code k_enc}, {@code p_enc} and {@code c_enc} of the first vector in
 * zcash/zcash-test-vectors {@code sapling_note_encryption.json} at commit
 * {@code 78321beacb0e0477e33cd002b56585a107c2708c} (public test values, vendored in
 * {@code src/test/resources/standard-vectors/}).
 */
final class NoteAeadSelfTest {

    private NoteAeadSelfTest() {
    }

    private static final String KEY =
            "e5bf8ab2f941e9b9d2c74ace2df6b33c3c3229fa0b9126f9dddb432966100069";
    private static final String PLAINTEXT =
            "01f19d9b797e39f33744583900e1f5050000000039176dac39ace4980ecc8d778e89860255ec36150600000000000000"
            + "00000000f600000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            + "000000000000000000000000000000000000000000000000000000000000000000000000";
    private static final String CIPHERTEXT =
            "8d6b27e7eff59bfba01d6588badd366ce59b4d5b0ef93bebcbf211417c56ae700ae18244bac2fb6437db01f83dc149e2"
            + "786ec4ec32c11b054a4c0e2bdbe343788bb9c33ff42fae99323213e0963e6f976d6fffb8c9fcf5219574c7a94c0e72f6"
            + "093aedafe380621b3ba815d2b97240f677d390f5fc5d45eeff16688e40b9eee8ee1d393b009750cb73df7a47fd07a281"
            + "41db49bd9ccab1f18d0b6a55ed101ca16f7345bcb0beaf7cd79a3d2bf288f1d88ebb1e4b742199d330c30a9fee1b44c6"
            + "86a1ff5cc33d4627f83d61ce34d6f1344e2b11a5f7172442296075919005434a574ed4e4c98e238edd5367e8f57524b6"
            + "38dd2d5830e83f7f32080d2d51a08ae84e37429c8438faae1540867b12ac2cf6a77da780d92cfa500c195a071ce8ae3f"
            + "102ce09501ecdac08a7952a08d53f362d37b64948c9915cbfc9f2d3c4e8222d39a348421447fabe4d5f087809a79e849"
            + "b28dffbc97fbbf647ff34f79ff64e737ebf03d8add44c154325f2bff14c6e9e90b0f9889f325a926a3685641a7a219ec"
            + "e6fb2b4deebf3109d7ee0f039dac427444993485848444ccafda5ea328740666dd75c323ce7b920ee0f3dc3abce6bd09"
            + "c13c957c5ea8952827116bb5bd0e5c27f820f2cf72a5105d9555be1e1e5e68fffb7133dc3900194e3b731c7d391170ad"
            + "6d4af13a78a06c25cfbb0d0991d5a883cff51cb6f591c792d99dcc559cde9b7b39c4f54a6bfb29f1f85e135d1733b49d"
            + "5dd67018e62e8c1ab0c19a25418726ccf2f5e88b97692112924bda2fde7348bad7295241729db4f38711c7ea98c5d419"
            + "7c66fd23";

    /**
     * Encrypts and decrypts the known answer.
     *
     * @throws IllegalStateException if either direction fails or differs
     */
    static void run() {
        HexFormat hex = HexFormat.of();
        byte[] key = hex.parseHex(KEY);
        byte[] plaintext = hex.parseHex(PLAINTEXT);
        byte[] ciphertext = hex.parseHex(CIPHERTEXT);
        byte[] sealed = SaplingNoteCrypto.encrypt(key, plaintext);
        if (!Arrays.equals(ciphertext, sealed)) {
            throw new IllegalStateException("ChaCha20-Poly1305 self-test: encryption differs from the known answer");
        }
        byte[] opened = SaplingNoteCrypto.decrypt(key, ciphertext);
        if (opened == null || !Arrays.equals(plaintext, opened)) {
            throw new IllegalStateException("ChaCha20-Poly1305 self-test: decryption differs from the known answer");
        }
    }
}
