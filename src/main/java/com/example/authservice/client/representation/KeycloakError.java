package com.example.authservice.client.representation;

import com.fasterxml.jackson.annotation.JsonProperty;

public record KeycloakError(
    String error,
    @JsonProperty("error_description") String errorDescription,
    String errorMessage) {

  public String message() {
    if (errorDescription != null) {
      return errorDescription;
    }
    return errorMessage != null ? errorMessage : "Request rejected by identity provider";
  }
}
