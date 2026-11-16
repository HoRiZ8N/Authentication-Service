package com.example.authservice.service.impl;

import com.example.authservice.client.KeycloakTokenClient;
import com.example.authservice.client.representation.KeycloakTokenResponse;
import com.example.authservice.dto.LoginRequestDto;
import com.example.authservice.dto.RefreshTokenRequestDto;
import com.example.authservice.dto.TokenResponseDto;
import com.example.authservice.dto.TokenValidationDto;
import com.example.authservice.dto.ValidateTokenRequestDto;
import com.example.authservice.exception.IdentityProviderException;
import com.example.authservice.exception.InvalidTokenException;
import com.example.authservice.security.JwtClaims;
import com.example.authservice.security.Role;
import com.example.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

  public static final String INVALID_ACCESS_TOKEN = "Access token is invalid or expired";

  private final KeycloakTokenClient tokenClient;
  private final JwtDecoder jwtDecoder;

  @Override
  public TokenResponseDto login(LoginRequestDto request) {
    return toDto(tokenClient.passwordGrant(request.login(), request.password()));
  }

  @Override
  public TokenResponseDto refresh(RefreshTokenRequestDto request) {
    return toDto(tokenClient.refreshGrant(request.refreshToken()));
  }

  @Override
  public TokenValidationDto validate(ValidateTokenRequestDto request) {
    Jwt jwt = decode(request.token());
    Role role = Role.highestOf(JwtClaims.realmRoles(jwt))
        .orElseThrow(() -> new InvalidTokenException(INVALID_ACCESS_TOKEN));
    return new TokenValidationDto(JwtClaims.userId(jwt), role, jwt.getExpiresAt());
  }

  private Jwt decode(String token) {
    try {
      return jwtDecoder.decode(token);
    } catch (BadJwtException ex) {
      throw new InvalidTokenException(INVALID_ACCESS_TOKEN);
    } catch (JwtException ex) {
      throw new IdentityProviderException(ex);
    }
  }

  private static TokenResponseDto toDto(KeycloakTokenResponse response) {
    return new TokenResponseDto(
        response.accessToken(),
        response.refreshToken(),
        response.tokenType(),
        response.expiresIn(),
        response.refreshExpiresIn());
  }
}
