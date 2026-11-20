package org.zeroj.bindings.common;

/** Stable host-facing error. Never contains request values or Java exception text. */
public final class BindingException extends RuntimeException {
    private final String code;
    public BindingException(String code) { super(code); this.code = code; }
    public String code() { return code; }
}
