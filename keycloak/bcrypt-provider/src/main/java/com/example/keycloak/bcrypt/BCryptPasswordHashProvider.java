package com.example.keycloak.bcrypt;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.mindrot.jbcrypt.BCrypt;

public class BCryptPasswordHashProvider implements PasswordHashProvider {

  static final int DEFAULT_COST = 12;
  private static final int MIN_COST = 4;
  private static final int MAX_COST = 31;
  private static final byte[] NO_SALT = new byte[0];

  private final String providerId;

  public BCryptPasswordHashProvider(String providerId) {
    this.providerId = providerId;
  }

  @Override
  public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
    return providerId.equals(credential.getPasswordCredentialData().getAlgorithm())
        && credential.getPasswordCredentialData().getHashIterations()
        == cost(policy.getHashIterations());
  }

  @Override
  public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
    int cost = cost(iterations);
    return PasswordCredentialModel.createFromValues(
        providerId, NO_SALT, cost, encode(rawPassword, cost));
  }

  @Override
  public String encode(String rawPassword, int iterations) {
    return BCrypt.hashpw(rawPassword, BCrypt.gensalt(cost(iterations)));
  }

  @Override
  public boolean verify(String rawPassword, PasswordCredentialModel credential) {
    String hash = credential.getPasswordSecretData().getValue();
    return hash != null && BCrypt.checkpw(rawPassword, hash);
  }

  @Override
  public void close() {
  }

  static int cost(int iterations) {
    return iterations >= MIN_COST && iterations <= MAX_COST ? iterations : DEFAULT_COST;
  }
}
