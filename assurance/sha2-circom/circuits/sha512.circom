pragma circom 2.2.3;
include "../build/vendor/circomlib/circuits/bitify.circom";
include "../build/vendor/circomlib/circuits/binsum.circom";
include "../build/vendor/sha512/circuits/sha512/sha512.circom";

// Complete standard digest, bound as four consecutive big-endian 128-bit limbs.
template Sha512Preimage(N) {
    signal input message[N];
    signal input digest[4];
    component bytes[N];
    component hash = Sha512(N * 8);
    for (var i = 0; i < N; i++) {
        bytes[i] = Num2Bits(8);
        bytes[i].in <== message[i];
        for (var j = 0; j < 8; j++) hash.in[i*8+j] <== bytes[i].out[7-j];
    }
    for (var limb = 0; limb < 4; limb++) {
        var packed = 0;
        for (var j = 0; j < 128; j++) packed += hash.out[limb*128+j] * (2 ** (127-j));
        digest[limb] === packed;
    }
}
