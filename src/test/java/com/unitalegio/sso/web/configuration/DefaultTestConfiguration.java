package com.unitalegio.sso.web.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.junit.jupiter.api.Order;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Order(Ordered.LOWEST_PRECEDENCE) // For rewriting beans;
@TestConfiguration
public class DefaultTestConfiguration {
    public static final String USERNAME_1 = "user1";
    public static final String PASSWORD_1 = "password1";
    public static final String ROLE_1 = "role1";
    public static final String ISSUER = "http://localhost:8080";



    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().issuer(ISSUER).build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        List<UserDetails> testUsers = new ArrayList<>();

        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username(USERNAME_1)
                .password(PASSWORD_1)
                .roles(ROLE_1)
                .build();
        testUsers.add(user1);

        return new InMemoryUserDetailsManager(testUsers);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient testNoneConsentRegisteredClient = RegisteredClient
                .withId("testId")
                .clientId("test-client")
                .clientSecret("{noop}testSecret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/test-client-oids")
//                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("test.test1")
                .scope("test.test2")
                .scope("client.create")
                .scope("client.read")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
        RegisteredClient opaqueNoneConsentRegisteredClient = RegisteredClient
                .withId("opaqueTestId")
                .clientId("opaque-test-client")
                .clientSecret("{noop}opaqueTestSecret")
                .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/opaque-test-client-oids")
//                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("test.test1")
                .scope("test.test2")
                .scope("client.create")
                .scope("client.read")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
        RegisteredClient testConsentRegisteredClient = RegisteredClient
                .withId("testConsentId")
                .clientId("test-consent-client")
                .clientSecret("{noop}testConsentSecret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/test-consent-client-oids")
//                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("test.test1")
                .scope("test.test2")
                .scope("client.create")
                .scope("client.read")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        RegisteredClient registeringRC = RegisteredClient
                .withId("registeringId")
                .clientId("test-registering-client")
                .clientSecret("{noop}testRegisteringClient")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/test-consent-client-oids")
//                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope("client.create")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();

        return new InMemoryRegisteredClientRepository(
                opaqueNoneConsentRegisteredClient,
                testNoneConsentRegisteredClient,
                testConsentRegisteredClient,
                registeringRC
        );
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    public JwtDecoder jwtDecoder(ProviderSettings providerSettings) {
        return NimbusJwtDecoder
                .withJwkSetUri("http://127.0.0.1:8080" + providerSettings.getJwkSetEndpoint())
                .jwsAlgorithm(SignatureAlgorithm.RS256) // Default in JwtEncoder
                .build();
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Something went wrong while generating RSA KeyPair \n" + e.getMessage());
        }
        return keyPair;
    }

}
