package com.example.authservice.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("app.keycloak")
public record KeycloakProperties(
    @NotBlank String serverUrl,
    @NotBlank String realm,
    @NotBlank String clientId,
    @NotBlank String clientSecret) {

  public String realmUrl() {
    return serverUrl + "/realms/" + realm;
  }

  public String adminUrl() {
    return serverUrl + "/admin/realms/" + realm;
  }
}
