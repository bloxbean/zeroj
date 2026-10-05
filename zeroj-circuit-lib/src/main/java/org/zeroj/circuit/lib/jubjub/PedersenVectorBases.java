package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Pinned bases of the {@code pedersen-jubjub-vector-v1} profile
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md} §2, ADR-0051 D5).
 *
 * <p>{@code G_i = FindGroupHash("ZeroJ_PV", LE32(i))} for {@code i = 0..15} and
 * {@code H_V = FindGroupHash("ZeroJ_PV", "r")}, where {@code FindGroupHash} is the Zcash Sapling
 * group hash into Jubjub (Zcash Protocol Specification §5.4.9.5, {@code sapling-crypto} 0.9.0).
 * The derivation needs BLAKE2s, so the library ships its results as constants and re-runs the
 * derivation only in tests, against the Zcash known answers and an independent reproduction.
 *
 * <p>Every base is checked at class initialisation to be a prime-order subgroup point that is not
 * the identity; the tests additionally pin pairwise distinctness and the exact derivation.
 */
public final class PedersenVectorBases {

    /** Maximum dimension of a vector commitment in this profile. */
    public static final int MAX_DIMENSION = 16;

    /** BLAKE2s personalisation used to derive every base. */
    public static final String PERSONALIZATION = "ZeroJ_PV";

    private static final List<JubjubPoint> VALUE_BASES = List.of(
            point("205bd2fbee3a4c6ce5d86e1920570e03bc56a7022824b699f52c1c995bc219cd",
                    "198d9863b0bca88ca66fdb18401979acfbe41fb895fba4b1651aa01899814063"),
            point("4e02f0535dc84503f2188554692a83c5153081b0b3c28b5c2375783d3ad0b476",
                    "18afa800d969a6c757412d84d3284cfbe86990f6e4ac160271500dc908dcb31c"),
            point("2ade969eb6c2c98e405c91cbe90cbc8fbf1864c8ead95251b5d21ddf3e46ed2c",
                    "0e716ed2cf186aa591aa9331ae9bec5fbed8f030d5cd22d73327fc256e1b3495"),
            point("2ce6d5b335f6cdd1fdd6be89fbf1ab0d95a61fa9563e19bc617df9b9b70fcccc",
                    "44d41301a7fa84fea9b7aea46982062abf0afb636196eb22a9c37915809c66b0"),
            point("3dd1f3a1f9f3218b7c49b8f469b605ae4bb58856df54477fbf0f3b85e482096a",
                    "3f7b9652faee7c79b1e4abebd1b398a5742af0dc41b073aaeeae25656fc7b272"),
            point("41cca7be1d0decf9af9659d8d20a5564345859c3aa991c0d4cbb45105cb851e4",
                    "13901ab53c6dab65341a6f592923de467f32e70d70a76cbec9ac3b93edee3e2c"),
            point("3923fbc5240948f5efa9bf0b57ceba7da7ba30e004ed820db7f12dfe86bfadb4",
                    "0da742aecc54316b7b1dbd6deaff5148a3962e3c4099ac5781fe26a9490b430f"),
            point("3b40a4262c7d1b97a3a72bbcbda882ffb7a529e2145e7139a8de2791b955a72c",
                    "25dc303cf8713eec63506ed2601122297224d9c342ece2686c10ea01ee86241a"),
            point("6e18437fdfc7340f81e71c9d19e59a44827ade01e54aba3c0a14f68618a07d95",
                    "3fb405b55b3f2d600a6bfc2f88a92af6c425173d0d7cf329abaee3a32c514643"),
            point("3c653e6b470268a5c5024c6afd3668fef4387469c086e54073e981956bf67f6b",
                    "141919c7c72c1a39ee95e665a314bf0f51f9d240e67a04cf44855565f3eb2b2d"),
            point("1edcbd164e09b7a1a29cb90f892eb41ae2f3047197bb896c55b17524b6c56ca0",
                    "453e79a85942dc545aa75647b7679d9eed80a249bcb8d27d212b7ae29fb58ecb"),
            point("46217b4002cdc01ef2bfd29604c5ca3ff99f891c2f0e92a36e964eb2b9d2d490",
                    "0d85850a30916e2724ea60f51e136635bea94286507523b9e820f2497f699871"),
            point("3a10cd28295ec714214c39bc4c67c91c594e7dcba8f2889f27964ff3c595ed01",
                    "63b66ec90ce4ed01a85ec01d80ed14cf54e03feaf8efa010ec93cc28206bb77b"),
            point("126f5e93926d05326023e31f332a85a5440337af361d486da32629ef756659c6",
                    "602458f2c4708bd3f3a311aa243bd35ae9d3266bfb669d43d712a701ca64bc76"),
            point("0b8a62a6d1ab30aa503eaccfffe8886185699a8efcabc02f1cd60f69def66358",
                    "184dba5d05a379b5c133004a6c97d8831381eaa871e99bd3f2015f1d80665d57"),
            point("1dace0af9586ea8eeae2ab9ba2ff30a562e8339726708e4a7b630a54603e2412",
                    "1d6c1121e30cf03f24e0459083bc4ea8b11da6ee2f6f224d8b298db9aeab169f"));

    private static final JubjubPoint BLINDING_BASE = point(
            "55dcba07bdee766192d665cb67368bed334b2a598e9f16cf56a95c75f862d553",
            "3bae3b23568241df571d423838dc54b23ec96650db57f4ad64f3bce1f5481c75");

    private PedersenVectorBases() {}

    /** {@code G_index}, for {@code 0 ≤ index < }{@value #MAX_DIMENSION}. */
    public static JubjubPoint valueBase(int index) {
        Objects.checkIndex(index, MAX_DIMENSION);
        return VALUE_BASES.get(index);
    }

    /** {@code H_V}. */
    public static JubjubPoint blindingBase() {
        return BLINDING_BASE;
    }

    private static JubjubPoint point(String uHex, String vHex) {
        JubjubPoint p = JubjubPoint.fromAffine(new BigInteger(uHex, 16), new BigInteger(vHex, 16));
        if (p.isIdentity() || !p.isInSubgroup()) {
            throw new IllegalStateException("pinned vector base is not a non-identity subgroup point");
        }
        return p;
    }
}
