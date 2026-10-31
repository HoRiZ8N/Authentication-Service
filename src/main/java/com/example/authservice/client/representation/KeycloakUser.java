package com.example.authservice.client.representation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import java.util.List;
import java.util.Map;

@JsonInclude(Include.NON_NULL)
public record KeycloakUser(
    String id,
    String username,
    Boolean enabled,
    Map<String, List<String>> attributes,
    List<KeycloakCredential> credentials) {

  public static final String USER_ID_ATTRIBUTE = "userId";

  public static KeycloakUser of(String username, Long userId, String password) {
    return new KeycloakUser(
        null,
        username,
        true,
        Map.of(USER_ID_ATTRIBUTE, List.of(String.valueOf(userId))),
        List.of(KeycloakCredential.password(password)));
  }
}
