package com.example.authservice.client;

import com.example.authservice.client.representation.KeycloakError;
import com.example.authservice.client.representation.KeycloakRole;
import com.example.authservice.client.representation.KeycloakUser;
import com.example.authservice.exception.DuplicateResourceException;
import com.example.authservice.exception.IdentityProviderException;
import com.example.authservice.exception.InvalidRequestException;
import java.net.URI;
import java.util.List;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class KeycloakAdminClient {

  private static final ParameterizedTypeReference<List<KeycloakUser>> USERS =
      new ParameterizedTypeReference<>() {
      };

  private final RestClient restClient;

  public KeycloakAdminClient(@Qualifier("keycloakAdminRestClient") RestClient restClient) {
    this.restClient = restClient;
  }

  public boolean existsByUserId(Long userId) {
    List<KeycloakUser> users = call(() -> restClient.get()
        .uri(b -> b.path("/users")
            .queryParam("q", KeycloakUser.USER_ID_ATTRIBUTE + ":" + userId)
            .queryParam("exact", true)
            .queryParam("briefRepresentation", true)
            .build())
        .retrieve()
        .body(USERS));
    return users != null && !users.isEmpty();
  }

  public KeycloakRole getRealmRole(String name) {
    return call(() -> restClient.get()
        .uri("/roles/{name}", name)
        .retrieve()
        .body(KeycloakRole.class));
  }

  public String createUser(KeycloakUser user) {
    URI location = call(() -> restClient.post()
        .uri("/users")
        .body(user)
        .retrieve()
        .toBodilessEntity()
        .getHeaders()
        .getLocation());
    if (location == null) {
      throw new IdentityProviderException(null);
    }
    String path = location.getPath();
    return path.substring(path.lastIndexOf('/') + 1);
  }

  public void assignRealmRole(String id, KeycloakRole role) {
    call(() -> restClient.post()
        .uri("/users/{id}/role-mappings/realm", id)
        .body(List.of(role))
        .retrieve()
        .toBodilessEntity());
  }

  public void deleteUser(String id) {
    call(() -> restClient.delete()
        .uri("/users/{id}", id)
        .retrieve()
        .toBodilessEntity());
  }

  private <T> T call(Supplier<T> request) {
    try {
      return request.get();
    } catch (HttpClientErrorException.Conflict ex) {
      throw new DuplicateResourceException("Credentials", "login");
    } catch (HttpClientErrorException.BadRequest ex) {
      KeycloakError error = ex.getResponseBodyAs(KeycloakError.class);
      throw new InvalidRequestException(
          error != null ? error.message() : "Request rejected by identity provider");
    } catch (RestClientException ex) {
      throw new IdentityProviderException(ex);
    }
  }
}
