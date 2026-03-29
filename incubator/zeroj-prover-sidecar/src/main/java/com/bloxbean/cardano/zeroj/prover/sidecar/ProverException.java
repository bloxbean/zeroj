package com.bloxbean.cardano.zeroj.prover.sidecar;

/**
 * Exception thrown when proof generation via the sidecar fails.
 */
public class ProverException extends RuntimeException {

    private final ErrorCode errorCode;

    public ProverException(ErrorCode errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public ProverException(ErrorCode errorCode, String message, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public ErrorCode errorCode() {
        return errorCode;
    }

    public enum ErrorCode {
        /** Sidecar is unreachable. */
        CONNECTION_FAILED,
        /** Sidecar returned an error response. */
        PROVING_FAILED,
        /** Request timed out. */
        TIMEOUT,
        /** All retry attempts exhausted. */
        RETRIES_EXHAUSTED,
        /** Circuit not found in sidecar. */
        CIRCUIT_NOT_FOUND,
        /** Invalid witness / input. */
        INVALID_INPUT,
        /** Unexpected response format. */
        INVALID_RESPONSE
    }
}
