package com.bloxbean.cardano.zeroj.bls12381.wasm;

import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.spi.Bls12381Provider;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BLS12-381 provider backed by zkcrypto/bls12_381 compiled to WASM and executed by Chicory.
 */
public final class WasmBls12381Provider implements Bls12381Provider {
    private final Bls12381WasmClient client;

    public WasmBls12381Provider(Bls12381WasmClient client) {
        this.client = Objects.requireNonNull(client, "client required");
    }

    public static WasmBls12381Provider createDefault() {
        return new WasmBls12381Provider(Bls12381WasmClient.createDefault());
    }

    @Override
    public String id() {
        return "zeroj-bls12381-wasm-zkcrypto";
    }

    @Override
    public G1Point g1Generator() {
        return client.g1Generator();
    }

    @Override
    public G2Point g2Generator() {
        return client.g2Generator();
    }

    @Override
    public G1Point g1ScalarMul(G1Point point, BigInteger scalar) {
        return client.g1ScalarMul(point, scalar);
    }

    @Override
    public G2Point g2ScalarMul(G2Point point, BigInteger scalar) {
        return client.g2ScalarMul(point, scalar);
    }

    @Override
    public G1Point g1SecretScalarMul(G1Point point, BigInteger scalar) {
        return client.g1ScalarMul(point, scalar);
    }

    @Override
    public G2Point g2SecretScalarMul(G2Point point, BigInteger scalar) {
        return client.g2ScalarMul(point, scalar);
    }

    @Override
    public boolean pairingProductIsIdentity(G1Point[] g1Points, G2Point[] g2Points) {
        return client.pairingProductIsIdentity(g1Points, g2Points);
    }
}
