package com.unitalegio.sso.web.configuration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.unitalegio.sso.web.config.SecurityConfig;
import org.junit.jupiter.api.Order;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.PropertySource;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
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
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.UUID;

@Order(Ordered.LOWEST_PRECEDENCE) // For rewriting beans;
@TestConfiguration
public class DefaultTestConfiguration implements WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> {
    public static final String USERNAME_1 = "user1";
    public static final String PASSWORD_1 = "password1";
    public static final String ROLE_1 = "role1";
    public static final String ISSUER = "http://localhost:%d";

    @Bean
    public AuthorizationServerSettings providerSettings(@Value("${server.port}") int serverPort) {
        AuthorizationServerSettings serverSettings = AuthorizationServerSettings.builder()
                .issuer(String.format(ISSUER, serverPort))
                .build();
        String ingot = """
                Authorization endpoint -> %s
                Token endpoint -> %s
                Jwk set endpoint -> %s
                Oidc client registration endpoint -> %s
                Oidc user info endpoint -> %s
                Token introspection endpoint -> %s
                Token revocation endpoint -> %s%n
                Issuer -> %s
                OpenId configuration -> %s""";
        System.out.printf(ingot,
                serverSettings.getAuthorizationEndpoint(),
                serverSettings.getTokenEndpoint(),
                serverSettings.getJwkSetEndpoint(),
                serverSettings.getOidcClientRegistrationEndpoint(),
                serverSettings.getOidcUserInfoEndpoint(),
                serverSettings.getTokenIntrospectionEndpoint(),
                serverSettings.getTokenRevocationEndpoint(),
                serverSettings.getIssuer(),
                SecurityConfig.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI);
        return serverSettings;
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
    public RegisteredClientRepository registeredClientRepository(@Value("${server.port}") int serverPort) {
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
                .redirectUri(String.format("http://localhost:%d/login/oauth2/code/test-client-oids", serverPort))
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
                .redirectUri(String.format("http://localhost:%d/login/oauth2/code/opaque-test-client-oids", serverPort))
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
                .redirectUri(String.format("http://localhost:%d/login/oauth2/code/test-consent-client-oids", serverPort))
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
                .redirectUri(String.format("http://localhost:%d/login/oauth2/code/test-consent-client-oids", serverPort))
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

    @Autowired
    private ConfigurableEnvironment configurableEnvironment;

    @Override
    public void customize(ConfigurableServletWebServerFactory factory) {
        int startPort = Integer.parseInt(portRange.split("-")[0]);
        int endPort = Integer.parseInt(portRange.split("-")[1]);

        int randomPort = startPort + new Random().nextInt(endPort - startPort + 1);
        configurableEnvironment.getPropertySources().addFirst(new PropertySource<>("customPort") {
            @Override
            public Object getProperty(String name) {
                if ("server.port".equals(name)) {
                    return randomPort;
                }
                return null;
            }
        });
        factory.setPort(randomPort);
    }

    @Bean
    public JwtDecoder jwtDecoder(AuthorizationServerSettings providerSettings, @Value("${server.port}") int serverPort) {

        return NimbusJwtDecoder
                .withJwkSetUri(String.format("http://localhost:%d", serverPort) + providerSettings.getJwkSetEndpoint())
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
    @Value("${server.port-range:8000-9999}")
    private String portRange;

/*    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }*/
}
