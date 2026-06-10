package com.finso.usermanagement.exception;

public class AccessDeniedException extends RuntimeException {

    public AccessDeniedException() {
        super("Access denied: insufficient permissions");
    }

    public AccessDeniedException(String message) {
        super(message);
    }
}
