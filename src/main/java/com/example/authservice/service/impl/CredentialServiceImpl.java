package com.example.authservice.service.impl;

import com.example.authservice.client.KeycloakAdminClient;
import com.example.authservice.client.representation.KeycloakRole;
import com.example.authservice.client.representation.KeycloakUser;
import com.example.authservice.dto.CredentialsRequestDto;
import com.example.authservice.dto.CredentialsResponseDto;
import com.example.authservice.exception.DuplicateResourceException;
import com.example.authservice.exception.InvalidRequestException;
import com.example.authservice.security.Role;
import com.example.authservice.service.CredentialService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CredentialServiceImpl implements CredentialService {

  public static final String SERVICE_ROLE_FORBIDDEN = "Role SERVICE cannot be assigned to a user";

  private final KeycloakAdminClient adminClient;

  @Override
  public CredentialsResponseDto save(CredentialsRequestDto request) {
    if (request.role() == Role.SERVICE) {
      throw new InvalidRequestException(SERVICE_ROLE_FORBIDDEN);
    }
    if (adminClient.existsByUserId(request.userId())) {
      throw new DuplicateResourceException("Credentials", "user id");
    }
    KeycloakRole role = adminClient.getRealmRole(request.role().name());
    String id = adminClient.createUser(
        KeycloakUser.of(request.login(), request.userId(), request.password()));
    try {
      adminClient.assignRealmRole(id, role);
    } catch (RuntimeException ex) {
      adminClient.deleteUser(id);
      throw ex;
    }
    return new CredentialsResponseDto(request.userId(), request.login(), request.role());
  }
}
