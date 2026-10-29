package org.zeroj.bls12381.pedersen;

import org.zeroj.bls12381.ec.G1Point;

import java.util.HexFormat;

/**
 * The basis set {@code pedersen-bls12-381-g1-basis-v1} ({@code pedersen-bls12-381-g1-v1} §2):
 * {@code G = hash_to_curve("G", DST_B)} and {@code H = hash_to_curve("H", DST_B)} under the RFC 9380
 * suite {@code BLS12381G1_XMD:SHA-256_SSWU_RO_}.
 *
 * <p>The bases are the pinned encodings of spec §2.2, decoded once with the strict decoder; nothing
 * is hashed at run time (spec §2.3 rule 2). {@code PedersenG1ReproductionTest} recomputes them from
 * the tag. Both are random-oracle outputs, so no one knows {@code log_H(G)}.
 */
final class G1PedersenBases {

    /** The basis tag, 68 ASCII octets (spec §2.1). */
    static final String DST_B = "ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_";

    /** Compressed encoding of {@code G} (spec §2.2). */
    static final String G_HEX =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";

    /** Compressed encoding of {@code H} (spec §2.2). */
    static final String H_HEX =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";

    /** The value base. */
    static final G1Point G = G1PedersenStrict.decodePoint(HexFormat.of().parseHex(G_HEX));

    /** The blinding base. */
    static final G1Point H = G1PedersenStrict.decodePoint(HexFormat.of().parseHex(H_HEX));

    static {
        // Spec §2.3 rule 1. The strict decoder has already established curve and subgroup membership.
        if (G.isInfinity() || H.isInfinity() || G.equals(H) || G.equals(H.negate())) {
            throw new IllegalStateException("pedersen-bls12-381-g1-basis-v1 is invalid");
        }
    }

    private G1PedersenBases() {
    }
}
