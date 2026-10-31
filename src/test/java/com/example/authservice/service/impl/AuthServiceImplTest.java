package com.example.authservice.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.example.authservice.client.KeycloakTokenClient;
import com.example.authservice.client.representation.KeycloakTokenResponse;
import com.example.authservice.dto.LoginRequestDto;
import com.example.authservice.dto.RefreshTokenRequestDto;
import com.example.authservice.dto.TokenResponseDto;
import com.example.authservice.dto.TokenValidationDto;
import com.example.authservice.dto.ValidateTokenRequestDto;
import com.example.authservice.exception.IdentityProviderException;
import com.example.authservice.exception.InvalidCredentialsException;
import com.example.authservice.exception.InvalidTokenException;
import com.example.authservice.security.Role;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

  private static final String TOKEN = "token";

  @Mock
  private KeycloakTokenClient tokenClient;

  @Mock
  private JwtDecoder jwtDecoder;

  @InjectMocks
  private AuthServiceImpl authService;

  @Test
  void loginReturnsKeycloakTokens() {
    when(tokenClient.passwordGrant("john", "Password1")).thenReturn(keycloakTokens());

    TokenResponseDto result = authService.login(new LoginRequestDto("john", "Password1"));

    assertThat(result).isEqualTo(new TokenResponseDto("access", "refresh", "Bearer", 900, 3600));
  }

  @Test
  void loginPropagatesInvalidCredentials() {
    when(tokenClient.passwordGrant("john", "wrong")).thenThrow(new InvalidCredentialsException());

    assertThatThrownBy(() -> authService.login(new LoginRequestDto("john", "wrong")))
        .isInstanceOf(InvalidCredentialsException.class);
  }

  @Test
  void refreshReturnsNewTokens() {
    when(tokenClient.refreshGrant("refresh")).thenReturn(keycloakTokens());

    TokenResponseDto result = authService.refresh(new RefreshTokenRequestDto("refresh"));

    assertThat(result.accessToken()).isEqualTo("access");
  }

  @Test
  void validateReturnsUserIdAndHighestRole() {
    Instant expiresAt = Instant.now().plusSeconds(600);
    when(jwtDecoder.decode(TOKEN)).thenReturn(jwt(List.of("USER", "ADMIN"), 7L, expiresAt));

    TokenValidationDto result = authService.validate(new ValidateTokenRequestDto(TOKEN));

    assertThat(result).isEqualTo(new TokenValidationDto(7L, Role.ADMIN, expiresAt));
  }

  @Test
  void validateRejectsBadToken() {
    when(jwtDecoder.decode(TOKEN)).thenThrow(new BadJwtException("expired"));

    assertThatThrownBy(() -> authService.validate(new ValidateTokenRequestDto(TOKEN)))
        .isInstanceOf(InvalidTokenException.class)
        .hasMessage(AuthServiceImpl.INVALID_ACCESS_TOKEN);
  }

  @Test
  void validateReportsUnavailableKeySet() {
    when(jwtDecoder.decode(TOKEN)).thenThrow(new JwtException("JWK set unavailable"));

    assertThatThrownBy(() -> authService.validate(new ValidateTokenRequestDto(TOKEN)))
        .isInstanceOf(IdentityProviderException.class);
  }

  private static KeycloakTokenResponse keycloakTokens() {
    return new KeycloakTokenResponse("access", "refresh", "Bearer", 900, 3600);
  }

  private static Jwt jwt(List<String> roles, Long userId, Instant expiresAt) {
    return Jwt.withTokenValue(TOKEN)
        .header("alg", "RS256")
        .claim("realm_access", Map.of("roles", roles))
        .claim("userId", userId)
        .issuedAt(expiresAt.minusSeconds(900))
        .expiresAt(expiresAt)
        .build();
  }
}
