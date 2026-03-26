package com.bloxbean.cardano.zeroj.codec;

/**
 * Exception thrown when proof serialization or deserialization fails.
 */
public class CodecException extends RuntimeException {

    public CodecException(String message) {
        super(message);
    }

    public CodecException(String message, Throwable cause) {
        super(message, cause);
    }
}
