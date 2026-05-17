package com.bloxbean.cardano.zeroj.prover.spi;

/**
 * Exception thrown when proof generation fails.
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
        /** Proving backend is unreachable or failed to initialize. */
        CONNECTION_FAILED,
        /** Proving backend returned an error response. */
        PROVING_FAILED,
        /** Request timed out. */
        TIMEOUT,
        /** All retry attempts exhausted. */
        RETRIES_EXHAUSTED,
        /** Circuit not found by the backend. */
        CIRCUIT_NOT_FOUND,
        /** Invalid witness or input. */
        INVALID_INPUT,
        /** Unexpected response format. */
        INVALID_RESPONSE
    }
}
