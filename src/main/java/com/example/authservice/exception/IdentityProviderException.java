package com.example.authservice.exception;

public class IdentityProviderException extends RuntimeException {

  public IdentityProviderException(Throwable cause) {
    super("Identity provider is unavailable", cause);
  }
}
