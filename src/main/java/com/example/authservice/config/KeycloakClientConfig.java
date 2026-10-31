package com.example.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;

@Configuration
public class KeycloakClientConfig {

  public static final String ADMIN_REGISTRATION = "keycloak-admin";

  @Bean
  public RestClient keycloakTokenRestClient(
      RestClient.Builder builder, KeycloakProperties properties) {
    return builder.clone()
        .baseUrl(properties.realmUrl() + "/protocol/openid-connect")
        .defaultHeaders(h -> h.setBasicAuth(properties.clientId(), properties.clientSecret()))
        .build();
  }

  @Bean
  public RestClient keycloakAdminRestClient(
      RestClient.Builder builder,
      KeycloakProperties properties,
      ClientRegistrationRepository registrations,
      OAuth2AuthorizedClientService authorizedClients) {
    OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(
        new AuthorizedClientServiceOAuth2AuthorizedClientManager(registrations, authorizedClients));
    interceptor.setClientRegistrationIdResolver(request -> ADMIN_REGISTRATION);
    interceptor.setPrincipalResolver(request -> new AnonymousAuthenticationToken(
        ADMIN_REGISTRATION, ADMIN_REGISTRATION, AuthorityUtils.createAuthorityList("ROLE_SYSTEM")));
    return builder.clone()
        .baseUrl(properties.adminUrl())
        .requestInterceptor(interceptor)
        .build();
  }
}
