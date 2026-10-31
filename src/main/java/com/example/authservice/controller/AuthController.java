package com.example.authservice.controller;

import com.example.authservice.dto.CredentialsRequestDto;
import com.example.authservice.dto.CredentialsResponseDto;
import com.example.authservice.dto.LoginRequestDto;
import com.example.authservice.dto.RefreshTokenRequestDto;
import com.example.authservice.dto.TokenResponseDto;
import com.example.authservice.dto.TokenValidationDto;
import com.example.authservice.dto.ValidateTokenRequestDto;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.CredentialService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthService authService;
  private final CredentialService credentialService;

  @PostMapping("/login")
  public ResponseEntity<TokenResponseDto> login(@Valid @RequestBody LoginRequestDto request) {
    return tokens(authService.login(request));
  }

  @PostMapping("/refresh")
  public ResponseEntity<TokenResponseDto> refresh(
      @Valid @RequestBody RefreshTokenRequestDto request) {
    return tokens(authService.refresh(request));
  }

  @PostMapping("/validate")
  public ResponseEntity<TokenValidationDto> validate(
      @Valid @RequestBody ValidateTokenRequestDto request) {
    return ResponseEntity.ok(authService.validate(request));
  }

  @PostMapping("/credentials")
  @PreAuthorize("hasRole('ADMIN') or (hasRole('SERVICE') and #request.role().name() == 'USER')")
  public ResponseEntity<CredentialsResponseDto> saveCredentials(
      @Valid @RequestBody CredentialsRequestDto request) {
    return ResponseEntity.status(HttpStatus.CREATED).body(credentialService.save(request));
  }

  private static ResponseEntity<TokenResponseDto> tokens(TokenResponseDto body) {
    return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
  }
}
