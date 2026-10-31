package com.example.authservice.client.representation;

public record KeycloakCredential(String type, String value, boolean temporary) {

  public static KeycloakCredential password(String value) {
    return new KeycloakCredential("password", value, false);
  }
}
