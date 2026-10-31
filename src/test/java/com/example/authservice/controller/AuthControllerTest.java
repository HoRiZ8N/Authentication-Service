package com.example.authservice.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.example.authservice.config.SecurityConfig;
import com.example.authservice.dto.CredentialsResponseDto;
import com.example.authservice.dto.TokenResponseDto;
import com.example.authservice.exception.IdentityProviderException;
import com.example.authservice.exception.InvalidCredentialsException;
import com.example.authservice.security.Role;
import com.example.authservice.security.SecurityErrorHandler;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.CredentialService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, SecurityErrorHandler.class})
class AuthControllerTest {

  private static final String CREDENTIALS = "/api/v1/auth/credentials";
  private static final String USER_CREDENTIALS =
      "{\"userId\":5,\"login\":\"john\",\"password\":\"Password1\",\"role\":\"USER\"}";
  private static final String ADMIN_CREDENTIALS =
      "{\"userId\":6,\"login\":\"boss\",\"password\":\"Password1\",\"role\":\"ADMIN\"}";

  @Autowired
  private MockMvc mockMvc;

  @MockitoBean
  private AuthService authService;

  @MockitoBean
  private CredentialService credentialService;

  @MockitoBean
  private JwtDecoder jwtDecoder;

  @Test
  void loginIsPublicAndNotCached() throws Exception {
    when(authService.login(any()))
        .thenReturn(new TokenResponseDto("access", "refresh", "Bearer", 900, 3600));

    mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"login\":\"john\",\"password\":\"Password1\"}"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
        .andExpect(jsonPath("$.accessToken").value("access"))
        .andExpect(jsonPath("$.refreshToken").value("refresh"));
  }

  @Test
  void loginWithWrongPasswordReturnsUnauthorized() throws Exception {
    when(authService.login(any())).thenThrow(new InvalidCredentialsException());

    mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"login\":\"john\",\"password\":\"wrong\"}"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value("Invalid login or password"));
  }

  @Test
  void loginValidatesBody() throws Exception {
    mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"login\":\"\"}"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.errors.login").exists())
        .andExpect(jsonPath("$.errors.password").exists());
  }

  @Test
  void unavailableKeycloakReturnsServiceUnavailable() throws Exception {
    when(authService.login(any())).thenThrow(new IdentityProviderException(null));

    mockMvc.perform(post("/api/v1/auth/login")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"login\":\"john\",\"password\":\"Password1\"}"))
        .andExpect(status().isServiceUnavailable());
  }

  @Test
  void credentialsRequireAuthentication() throws Exception {
    mockMvc.perform(post(CREDENTIALS)
            .contentType(MediaType.APPLICATION_JSON)
            .content(USER_CREDENTIALS))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.message").value(SecurityErrorHandler.AUTHENTICATION_REQUIRED));
    verifyNoInteractions(credentialService);
  }

  @Test
  void userCannotSaveCredentials() throws Exception {
    mockMvc.perform(post(CREDENTIALS)
            .with(as(Role.USER))
            .contentType(MediaType.APPLICATION_JSON)
            .content(USER_CREDENTIALS))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.message").value(SecurityErrorHandler.ACCESS_DENIED));
    verifyNoInteractions(credentialService);
  }

  @Test
  void adminSavesAdminCredentials() throws Exception {
    when(credentialService.save(any()))
        .thenReturn(new CredentialsResponseDto(6L, "boss", Role.ADMIN));

    mockMvc.perform(post(CREDENTIALS)
            .with(as(Role.ADMIN))
            .contentType(MediaType.APPLICATION_JSON)
            .content(ADMIN_CREDENTIALS))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.role").value("ADMIN"));
  }

  @Test
  void serviceSavesOnlyUserCredentials() throws Exception {
    when(credentialService.save(any()))
        .thenReturn(new CredentialsResponseDto(5L, "john", Role.USER));

    mockMvc.perform(post(CREDENTIALS)
            .with(as(Role.SERVICE))
            .contentType(MediaType.APPLICATION_JSON)
            .content(USER_CREDENTIALS))
        .andExpect(status().isCreated());
    mockMvc.perform(post(CREDENTIALS)
            .with(as(Role.SERVICE))
            .contentType(MediaType.APPLICATION_JSON)
            .content(ADMIN_CREDENTIALS))
        .andExpect(status().isForbidden());
  }

  private static RequestPostProcessor as(Role role) {
    return jwt().authorities(new SimpleGrantedAuthority("ROLE_" + role.name()));
  }
}
