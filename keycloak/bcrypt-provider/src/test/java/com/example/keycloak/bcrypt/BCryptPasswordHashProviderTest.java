package com.example.keycloak.bcrypt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

class BCryptPasswordHashProviderTest {

  private final BCryptPasswordHashProvider provider =
      new BCryptPasswordHashProvider(BCryptPasswordHashProviderFactory.ID);

  @Test
  void hashesWithBcryptAndVerifies() {
    PasswordCredentialModel credential = provider.encodedCredential("s3cret-Pass", 4);

    assertEquals("bcrypt", credential.getPasswordCredentialData().getAlgorithm());
    assertEquals(4, credential.getPasswordCredentialData().getHashIterations());
    assertTrue(credential.getPasswordSecretData().getValue().startsWith("$2a$04$"));
    assertTrue(provider.verify("s3cret-Pass", credential));
    assertFalse(provider.verify("wrong", credential));
  }

  @Test
  void usesUniqueSaltForEachHash() {
    String first = provider.encode("same-password", 4);
    String second = provider.encode("same-password", 4);

    assertNotEquals(first, second);
  }

  @Test
  void fallsBackToDefaultCostWhenPolicyHasNoIterations() {
    assertEquals(BCryptPasswordHashProvider.DEFAULT_COST, BCryptPasswordHashProvider.cost(-1));
    assertEquals(BCryptPasswordHashProvider.DEFAULT_COST, BCryptPasswordHashProvider.cost(27500));
    assertEquals(10, BCryptPasswordHashProvider.cost(10));
  }
}
