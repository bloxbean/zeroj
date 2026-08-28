package com.bloxbean.cardano.zeroj.bbs.wasm;

/**
 * Runtime exception raised by the Chicory-backed CFRG BBS WASM provider.
 */
public class Bbs12381WasmException extends RuntimeException {
    public Bbs12381WasmException(String message) {
        super(message);
    }

    public Bbs12381WasmException(String message, Throwable cause) {
        super(message, cause);
    }
}
