package com.example.authservice.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class AccessTokenValidatorTest {

  private final AccessTokenValidator validator = new AccessTokenValidator();

  @Test
  void acceptsUserAccessToken() {
    assertThat(validator.validate(jwt(b -> {
    })).hasErrors()).isFalse();
  }

  @Test
  void acceptsServiceTokenWithoutUserId() {
    assertThat(validator.validate(jwt(b -> b
        .claim(JwtClaims.REALM_ACCESS, Map.of(JwtClaims.ROLES, List.of("SERVICE")))
        .claims(c -> c.remove(JwtClaims.USER_ID)))).hasErrors()).isFalse();
  }

  @Test
  void rejectsRefreshToken() {
    assertThat(validator.validate(jwt(b -> b.claim(JwtClaims.TYPE, "Refresh"))).hasErrors())
        .isTrue();
  }

  @Test
  void rejectsTokenWithoutKnownRole() {
    assertThat(validator.validate(jwt(b -> b
        .claim(JwtClaims.REALM_ACCESS, Map.of(JwtClaims.ROLES, List.of("offline_access")))))
        .hasErrors()).isTrue();
  }

  @Test
  void rejectsUserTokenWithoutUserId() {
    assertThat(validator.validate(jwt(b -> b.claims(c -> c.remove(JwtClaims.USER_ID))))
        .hasErrors()).isTrue();
  }

  private static Jwt jwt(Consumer<Jwt.Builder> customizer) {
    Jwt.Builder builder = Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .claim(JwtClaims.TYPE, JwtClaims.ACCESS_TYPE)
        .claim(JwtClaims.REALM_ACCESS, Map.of(JwtClaims.ROLES, List.of("USER")))
        .claim(JwtClaims.USER_ID, 1L)
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(900));
    customizer.accept(builder);
    return builder.build();
  }
}
