package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

/**
 * Loads the unchanged CFRG {@code -03} vector files from {@code zeroj-test-vectors}
 * ({@code test-vectors/cfrg-drafts-03/}) and checks each against the SHA-256 pinned in spec §10, so a
 * modified copy fails loudly instead of silently changing the evidence.
 */
final class CfrgVectors {

    static final String CODEC = "fiatShamirCodecVectors.json";
    static final String SHAKE128 = "fiatShamirShake128Vectors.json";
    static final String SIGMA = "sigma-proofs_Shake128_BLS12381.json";
    static final String SIGMA_INVALID = "sigma-proofs-invalid_Shake128_BLS12381.json";

    private static final Map<String, String> PINNED_SHA256 = Map.of(
            CODEC, "97d85f96e252111fd01e4147d9ebc48c80203e5783fef1eea2204211d847c821",
            SHAKE128, "f04cdf455b60239d20392813ffd5dd8d079fb1c0d5b0e07de3e50899bd6f6502",
            SIGMA, "e9f942c2d76f2086793b771fbb32cc8452e51dcf274cf163258d36b8d9906e94",
            SIGMA_INVALID, "1da51dc890c0d9fe550d14c9f0f71c5175c5c5b6c6a698ef53074bb4c58bc740");

    private CfrgVectors() {
    }

    static JsonNode load(String name) {
        String path = "/test-vectors/cfrg-drafts-03/" + name;
        try (InputStream in = CfrgVectors.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException(path + " is not on the test classpath");
            }
            byte[] bytes = in.readAllBytes();
            String sha = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
            if (!sha.equals(PINNED_SHA256.get(name))) {
                throw new IllegalStateException(name + " does not match its pinned SHA-256: " + sha);
            }
            return new ObjectMapper().readTree(bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
