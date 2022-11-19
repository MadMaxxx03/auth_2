package com.example.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;

import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
          .clientId("application-client")
          .clientSecret("${app.jwtSecret}")
          .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
          .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
          .redirectUri("http://localhost:8090")
          .scope(OidcScopes.OPENID)
          .scope("application.read")
          .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
          .issuer("http://auth-server:9000")
          .build();
    }
}