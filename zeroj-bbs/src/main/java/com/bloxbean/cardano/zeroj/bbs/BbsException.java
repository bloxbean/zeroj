package com.bloxbean.cardano.zeroj.bbs;

/**
 * Runtime exception raised by CFRG BBS operations.
 */
public class BbsException extends RuntimeException {
    public BbsException(String message) {
        super(message);
    }

    public BbsException(String message, Throwable cause) {
        super(message, cause);
    }
}
