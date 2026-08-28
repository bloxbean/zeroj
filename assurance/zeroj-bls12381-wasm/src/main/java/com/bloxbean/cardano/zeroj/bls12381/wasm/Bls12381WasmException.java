package com.bloxbean.cardano.zeroj.bls12381.wasm;

/**
 * Runtime exception raised by the Chicory-backed BLS12-381 provider.
 */
public class Bls12381WasmException extends RuntimeException {
    public Bls12381WasmException(String message) {
        super(message);
    }

    public Bls12381WasmException(String message, Throwable cause) {
        super(message, cause);
    }
}
