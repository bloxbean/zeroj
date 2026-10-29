pragma circom 2.2.3;
include "../build/vendor/circomlib/circuits/bitify.circom";
include "../build/vendor/circomlib/circuits/sha256/sha256.circom";

// Complete standard digest, bound as two consecutive big-endian 128-bit limbs.
template Sha256Preimage(N) {
    signal input message[N];
    signal input digest[2];
    component bytes[N];
    component hash = Sha256(N * 8);
    for (var i = 0; i < N; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== message[i];
        for (var j = 0; j < 8; j++) hash.in[i*8+j] <== bytes[i].out[7-j];
    }
    for (var limb = 0; limb < 2; limb++) {
        var packed = 0;
        for (var j = 0; j < 128; j++) packed += hash.out[limb*128+j] * (2 ** (127-j));
        digest[limb] === packed;
    }
}
