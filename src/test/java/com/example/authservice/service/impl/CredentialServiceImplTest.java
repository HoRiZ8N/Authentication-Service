package com.example.authservice.service.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.example.authservice.client.KeycloakAdminClient;
import com.example.authservice.client.representation.KeycloakRole;
import com.example.authservice.client.representation.KeycloakUser;
import com.example.authservice.dto.CredentialsRequestDto;
import com.example.authservice.dto.CredentialsResponseDto;
import com.example.authservice.exception.DuplicateResourceException;
import com.example.authservice.exception.IdentityProviderException;
import com.example.authservice.exception.InvalidRequestException;
import com.example.authservice.security.Role;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CredentialServiceImplTest {

  private static final Long USER_ID = 5L;
  private static final String KEYCLOAK_ID = "kc-id";
  private static final KeycloakRole USER_ROLE = new KeycloakRole("role-id", "USER");

  @Mock
  private KeycloakAdminClient adminClient;

  @InjectMocks
  private CredentialServiceImpl credentialService;

  @Test
  void saveCreatesKeycloakUserWithUserIdAndRole() {
    when(adminClient.existsByUserId(USER_ID)).thenReturn(false);
    when(adminClient.getRealmRole("USER")).thenReturn(USER_ROLE);
    when(adminClient.createUser(any())).thenReturn(KEYCLOAK_ID);

    CredentialsResponseDto result = credentialService.save(request(Role.USER));

    ArgumentCaptor<KeycloakUser> user = ArgumentCaptor.forClass(KeycloakUser.class);
    verify(adminClient).createUser(user.capture());
    assertThat(user.getValue().username()).isEqualTo("john");
    assertThat(user.getValue().attributes()).containsEntry("userId", List.of("5"));
    assertThat(user.getValue().credentials().getFirst().value()).isEqualTo("Password1");
    verify(adminClient).assignRealmRole(KEYCLOAK_ID, USER_ROLE);
    assertThat(result).isEqualTo(new CredentialsResponseDto(USER_ID, "john", Role.USER));
  }

  @Test
  void saveRejectsServiceRole() {
    assertThatThrownBy(() -> credentialService.save(request(Role.SERVICE)))
        .isInstanceOf(InvalidRequestException.class)
        .hasMessage(CredentialServiceImpl.SERVICE_ROLE_FORBIDDEN);
    verifyNoInteractions(adminClient);
  }

  @Test
  void saveRejectsTakenUserId() {
    when(adminClient.existsByUserId(USER_ID)).thenReturn(true);

    assertThatThrownBy(() -> credentialService.save(request(Role.USER)))
        .isInstanceOf(DuplicateResourceException.class);
    verify(adminClient, never()).createUser(any());
  }

  @Test
  void saveRemovesUserWhenRoleAssignmentFails() {
    when(adminClient.existsByUserId(USER_ID)).thenReturn(false);
    when(adminClient.getRealmRole("USER")).thenReturn(USER_ROLE);
    when(adminClient.createUser(any())).thenReturn(KEYCLOAK_ID);
    doThrow(new IdentityProviderException(null))
        .when(adminClient).assignRealmRole(KEYCLOAK_ID, USER_ROLE);

    assertThatThrownBy(() -> credentialService.save(request(Role.USER)))
        .isInstanceOf(IdentityProviderException.class);
    verify(adminClient).deleteUser(KEYCLOAK_ID);
  }

  private static CredentialsRequestDto request(Role role) {
    return new CredentialsRequestDto(USER_ID, "john", "Password1", role);
  }
}
