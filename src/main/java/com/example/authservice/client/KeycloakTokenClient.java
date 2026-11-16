package com.example.authservice.client;

import com.example.authservice.client.representation.KeycloakError;
import com.example.authservice.client.representation.KeycloakTokenResponse;
import com.example.authservice.exception.IdentityProviderException;
import com.example.authservice.exception.InvalidCredentialsException;
import com.example.authservice.exception.InvalidTokenException;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class KeycloakTokenClient {

  private static final String TOKEN_PATH = "/token";
  private static final String INVALID_GRANT = "invalid_grant";
  public static final String INVALID_REFRESH_TOKEN = "Refresh token is invalid or expired";

  private final RestClient restClient;

  public KeycloakTokenClient(@Qualifier("keycloakTokenRestClient") RestClient restClient) {
    this.restClient = restClient;
  }

  public KeycloakTokenResponse passwordGrant(String login, String password) {
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "password");
    form.add("username", login);
    form.add("password", password);
    return requestToken(form, InvalidCredentialsException::new);
  }

  public KeycloakTokenResponse refreshGrant(String refreshToken) {
    MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.add("grant_type", "refresh_token");
    form.add("refresh_token", refreshToken);
    return requestToken(form, () -> new InvalidTokenException(INVALID_REFRESH_TOKEN));
  }

  private KeycloakTokenResponse requestToken(
      MultiValueMap<String, String> form, Supplier<RuntimeException> invalidGrant) {
    try {
      return restClient.post()
          .uri(TOKEN_PATH)
          .contentType(MediaType.APPLICATION_FORM_URLENCODED)
          .body(form)
          .retrieve()
          .body(KeycloakTokenResponse.class);
    } catch (HttpClientErrorException.BadRequest ex) {
      KeycloakError error = ex.getResponseBodyAs(KeycloakError.class);
      if (error != null && INVALID_GRANT.equals(error.error())) {
        throw invalidGrant.get();
      }
      throw new IdentityProviderException(ex);
    } catch (RestClientException ex) {
      throw new IdentityProviderException(ex);
    }
  }
}
