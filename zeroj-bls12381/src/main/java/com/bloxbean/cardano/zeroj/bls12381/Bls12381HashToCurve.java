package com.bloxbean.cardano.zeroj.bls12381;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;

import java.math.BigInteger;
import java.util.Objects;

/**
 * RFC 9380 BLS12-381 hash-to-curve support.
 */
final class Bls12381HashToCurve {
    private static final BigInteger G1_H_EFF = new BigInteger("d201000000010001", 16);
    private static final BigInteger G2_H_EFF = new BigInteger(
            "bc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551", 16);

    private static final Fp G1_Z = Fp.of(11);
    private static final Fp G1_A = fp("144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d");
    private static final Fp G1_B = fp("12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0");

    private static final Fp2 G2_Z = Fp2.of(Fp.of(BigInteger.valueOf(-2)), Fp.of(BigInteger.valueOf(-1)));
    private static final Fp2 G2_A = Fp2.of(Fp.ZERO, Fp.of(240));
    private static final Fp2 G2_B = Fp2.of(Fp.of(1012), Fp.of(1012));

    private static final Fp[] G1_X_NUM = fpArray(
            "11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
            "17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
            "0d54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0",
            "1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861",
            "0e99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9",
            "1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983",
            "0d6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84",
            "17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
            "080d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317",
            "169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e",
            "10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b",
            "06e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229");
    private static final Fp[] G1_X_DEN = fpArray(
            "08ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c",
            "12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff",
            "0b2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
            "03425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8",
            "13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e",
            "0e7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5",
            "0772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a",
            "14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
            "0a10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641",
            "095fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a");
    private static final Fp[] G1_Y_NUM = fpArray(
            "090d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33",
            "134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696",
            "0cc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6",
            "01f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb",
            "08cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb",
            "16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0",
            "04ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2",
            "0987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29",
            "09fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587",
            "0e1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
            "19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132",
            "18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e",
            "0b182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8",
            "0245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133",
            "05c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b",
            "15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604");
    private static final Fp[] G1_Y_DEN = fpArray(
            "16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1",
            "1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d",
            "058df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2",
            "16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416",
            "0be0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d",
            "08d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
            "166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c",
            "16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9",
            "1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
            "167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
            "04d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8",
            "0accbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092",
            "0ad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc",
            "02660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7",
            "0e0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f");

    private static final Fp2[] G2_X_NUM = fp2Array(
            fp2("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6", "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"),
            fp2("0", "11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"),
            fp2("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e", "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"),
            fp2("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1", "0"));
    private static final Fp2[] G2_X_DEN = fp2Array(
            fp2("0", "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"),
            fp2("0c", "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f"));
    private static final Fp2[] G2_Y_NUM = fp2Array(
            fp2("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706", "1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"),
            fp2("0", "5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"),
            fp2("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c", "8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"),
            fp2("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10", "0"));
    private static final Fp2[] G2_Y_DEN = fp2Array(
            fp2("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb", "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"),
            fp2("0", "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"),
            fp2("12", "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"));

    private Bls12381HashToCurve() {}

    static G1Point hashToG1(byte[] message, byte[] dst) {
        BigInteger[] u = Bls12381Hash.hashToFp(message, dst, 2);
        return clearG1(isoMapG1(simpleSwuG1(Fp.of(u[0]))).add(isoMapG1(simpleSwuG1(Fp.of(u[1])))));
    }

    static G1Point encodeToG1(byte[] message, byte[] dst) {
        BigInteger[] u = Bls12381Hash.hashToFp(message, dst, 1);
        return clearG1(isoMapG1(simpleSwuG1(Fp.of(u[0]))));
    }

    static G1Point hashToG1XofShake256(byte[] message, byte[] dst) {
        BigInteger[] u = Bls12381Hash.hashToFpXofShake256(message, dst, 2);
        return clearG1(isoMapG1(simpleSwuG1(Fp.of(u[0]))).add(isoMapG1(simpleSwuG1(Fp.of(u[1])))));
    }

    static G1Point encodeToG1XofShake256(byte[] message, byte[] dst) {
        BigInteger[] u = Bls12381Hash.hashToFpXofShake256(message, dst, 1);
        return clearG1(isoMapG1(simpleSwuG1(Fp.of(u[0]))));
    }

    static G2Point hashToG2(byte[] message, byte[] dst) {
        BigInteger[][] u = Bls12381Hash.hashToFp2(message, dst, 2);
        var u0 = Fp2.of(Fp.of(u[0][0]), Fp.of(u[0][1]));
        var u1 = Fp2.of(Fp.of(u[1][0]), Fp.of(u[1][1]));
        return clearG2(isoMapG2(simpleSwuG2(u0)).add(isoMapG2(simpleSwuG2(u1))));
    }

    static G2Point encodeToG2(byte[] message, byte[] dst) {
        BigInteger[][] u = Bls12381Hash.hashToFp2(message, dst, 1);
        var u0 = Fp2.of(Fp.of(u[0][0]), Fp.of(u[0][1]));
        return clearG2(isoMapG2(simpleSwuG2(u0)));
    }

    static G2Point hashToG2XofShake256(byte[] message, byte[] dst) {
        BigInteger[][] u = Bls12381Hash.hashToFp2XofShake256(message, dst, 2);
        var u0 = Fp2.of(Fp.of(u[0][0]), Fp.of(u[0][1]));
        var u1 = Fp2.of(Fp.of(u[1][0]), Fp.of(u[1][1]));
        return clearG2(isoMapG2(simpleSwuG2(u0)).add(isoMapG2(simpleSwuG2(u1))));
    }

    static G2Point encodeToG2XofShake256(byte[] message, byte[] dst) {
        BigInteger[][] u = Bls12381Hash.hashToFp2XofShake256(message, dst, 1);
        var u0 = Fp2.of(Fp.of(u[0][0]), Fp.of(u[0][1]));
        return clearG2(isoMapG2(simpleSwuG2(u0)));
    }

    private static G1Point clearG1(G1Point point) {
        return Bls12381Codecs.requireValid(point.scalarMul(G1_H_EFF));
    }

    private static G2Point clearG2(G2Point point) {
        return Bls12381Codecs.requireValid(point.scalarMul(G2_H_EFF));
    }

    private static FpPoint simpleSwuG1(Fp u) {
        var tv1 = G1_Z.mul(u.square());
        var tv2 = tv1.square().add(tv1);
        var tv3 = G1_B.mul(tv2.add(Fp.ONE));
        var tv4 = (tv2.isZero() ? G1_Z : tv2.neg()).mul(G1_A);
        var tv6 = tv4.square();
        tv2 = tv3.square().add(G1_A.mul(tv6));
        tv2 = tv2.mul(tv3);
        tv6 = tv6.mul(tv4);
        tv2 = tv2.add(G1_B.mul(tv6));
        var x = tv1.mul(tv3);
        var sqrtRatio = sqrtRatio(tv2, tv6, G1_Z);
        var y = tv1.mul(u).mul(sqrtRatio.value());
        if (sqrtRatio.wasSquare()) {
            x = tv3;
            y = sqrtRatio.value();
        }
        if (u.sgn0() != y.sgn0()) {
            y = y.neg();
        }
        x = x.div(tv4);
        return new FpPoint(x, y);
    }

    private static Fp2Point simpleSwuG2(Fp2 u) {
        var tv1 = G2_Z.mul(u.square());
        var tv2 = tv1.square().add(tv1);
        var tv3 = G2_B.mul(tv2.add(Fp2.ONE));
        var tv4 = (tv2.isZero() ? G2_Z : tv2.neg()).mul(G2_A);
        var tv6 = tv4.square();
        tv2 = tv3.square().add(G2_A.mul(tv6));
        tv2 = tv2.mul(tv3);
        tv6 = tv6.mul(tv4);
        tv2 = tv2.add(G2_B.mul(tv6));
        var x = tv1.mul(tv3);
        var sqrtRatio = sqrtRatio(tv2, tv6, G2_Z);
        var y = tv1.mul(u).mul(sqrtRatio.value());
        if (sqrtRatio.wasSquare()) {
            x = tv3;
            y = sqrtRatio.value();
        }
        if (u.sgn0() != y.sgn0()) {
            y = y.neg();
        }
        x = x.div(tv4);
        return new Fp2Point(x, y);
    }

    private static G1Point isoMapG1(FpPoint point) {
        var x = point.x();
        var xNum = eval(G1_X_NUM, x);
        var xDen = evalWithLeadingOne(G1_X_DEN, x);
        var yNum = eval(G1_Y_NUM, x);
        var yDen = evalWithLeadingOne(G1_Y_DEN, x);
        if (xDen.isZero() || yDen.isZero()) {
            return G1Point.INFINITY;
        }
        return new G1Point(xNum.div(xDen), point.y().mul(yNum).div(yDen));
    }

    private static G2Point isoMapG2(Fp2Point point) {
        var x = point.x();
        var xNum = eval(G2_X_NUM, x);
        var xDen = evalWithLeadingOne(G2_X_DEN, x);
        var yNum = eval(G2_Y_NUM, x);
        var yDen = evalWithLeadingOne(G2_Y_DEN, x);
        if (xDen.isZero() || yDen.isZero()) {
            return G2Point.INFINITY;
        }
        return new G2Point(xNum.div(xDen), point.y().mul(yNum).div(yDen));
    }

    private static SqrtRatioFp sqrtRatio(Fp u, Fp v, Fp z) {
        var direct = u.div(v).sqrt();
        if (direct.isPresent()) {
            return new SqrtRatioFp(true, direct.get());
        }
        return new SqrtRatioFp(false, z.mul(u).div(v).sqrt()
                .orElseThrow(() -> new IllegalStateException("sqrt_ratio failed")));
    }

    private static SqrtRatioFp2 sqrtRatio(Fp2 u, Fp2 v, Fp2 z) {
        var direct = u.div(v).sqrt();
        if (direct.isPresent()) {
            return new SqrtRatioFp2(true, direct.get());
        }
        return new SqrtRatioFp2(false, z.mul(u).div(v).sqrt()
                .orElseThrow(() -> new IllegalStateException("sqrt_ratio failed")));
    }

    private static Fp eval(Fp[] coeffs, Fp x) {
        var result = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 2; i >= 0; i--) {
            result = result.mul(x).add(coeffs[i]);
        }
        return result;
    }

    private static Fp evalWithLeadingOne(Fp[] coeffs, Fp x) {
        var result = Fp.ONE;
        for (int i = coeffs.length - 1; i >= 0; i--) {
            result = result.mul(x).add(coeffs[i]);
        }
        return result;
    }

    private static Fp2 eval(Fp2[] coeffs, Fp2 x) {
        var result = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 2; i >= 0; i--) {
            result = result.mul(x).add(coeffs[i]);
        }
        return result;
    }

    private static Fp2 evalWithLeadingOne(Fp2[] coeffs, Fp2 x) {
        var result = Fp2.ONE;
        for (int i = coeffs.length - 1; i >= 0; i--) {
            result = result.mul(x).add(coeffs[i]);
        }
        return result;
    }

    private static Fp fp(String hex) {
        Objects.requireNonNull(hex, "hex required");
        return Fp.of(new BigInteger(hex, 16));
    }

    private static Fp[] fpArray(String... hexValues) {
        var out = new Fp[hexValues.length];
        for (int i = 0; i < hexValues.length; i++) {
            out[i] = fp(hexValues[i]);
        }
        return out;
    }

    private static Fp2 fp2(String c0Hex, String c1Hex) {
        return Fp2.of(fp(c0Hex), fp(c1Hex));
    }

    private static Fp2[] fp2Array(Fp2... values) {
        return values;
    }

    private record FpPoint(Fp x, Fp y) {}
    private record Fp2Point(Fp2 x, Fp2 y) {}
    private record SqrtRatioFp(boolean wasSquare, Fp value) {}
    private record SqrtRatioFp2(boolean wasSquare, Fp2 value) {}
}
