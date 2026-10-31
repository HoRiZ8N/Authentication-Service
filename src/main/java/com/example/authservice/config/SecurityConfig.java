package com.example.authservice.config;

import com.example.authservice.security.AccessTokenValidator;
import com.example.authservice.security.JwtClaims;
import com.example.authservice.security.RealmRoleConverter;
import com.example.authservice.security.SecurityErrorHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity http, SecurityErrorHandler errorHandler) throws Exception {
    return http
        .csrf(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(a -> a
            .requestMatchers(HttpMethod.POST,
                "/api/v1/auth/login", "/api/v1/auth/refresh", "/api/v1/auth/validate")
            .permitAll()
            .requestMatchers("/error").permitAll()
            .anyRequest().authenticated())
        .oauth2ResourceServer(o -> o
            .jwt(j -> j.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            .authenticationEntryPoint(errorHandler)
            .accessDeniedHandler(errorHandler))
        .exceptionHandling(e -> e
            .authenticationEntryPoint(errorHandler)
            .accessDeniedHandler(errorHandler))
        .build();
  }

  @Bean
  public JwtDecoder jwtDecoder(
      @Value("${app.security.jwt.jwk-set-uri}") String jwkSetUri,
      @Value("${app.security.jwt.issuer}") String issuer) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
        .jwsAlgorithm(SignatureAlgorithm.RS256)
        .build();
    decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefaultWithIssuer(issuer), new AccessTokenValidator()));
    return decoder;
  }

  @Bean
  public JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(new RealmRoleConverter());
    converter.setPrincipalClaimName(JwtClaims.USER_ID);
    return converter;
  }
}
