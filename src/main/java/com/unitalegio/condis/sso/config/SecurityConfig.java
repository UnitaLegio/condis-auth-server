package com.unitalegio.condis.sso.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    private static final String AUTHORITIES_CLAIM = "authorities";
    public static final String DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI = "/.well-known/openid-configuration";

    @Value("${ul.issuer}")
    private String issuer;

    @Order(Ordered.HIGHEST_PRECEDENCE)
    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class);

        authorizationServerConfigurer.oidc(oidc -> oidc.clientRegistrationEndpoint(Customizer.withDefaults()));

        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        httpSecurity
                .securityMatcher(endpointsMatcher).exceptionHandling(
                        // Redirect to the login page when not authenticated from the
                        // authorization endpoint
                        (exceptions) ->
                                exceptions.authenticationEntryPoint(
                                        new LoginUrlAuthenticationEntryPoint("/login")))
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer(httpSecurityOAuth2ResourceServerConfigurer ->
                        httpSecurityOAuth2ResourceServerConfigurer.jwt(Customizer.withDefaults()))
                .apply(authorizationServerConfigurer);

        return httpSecurity.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .requestMatchers("/css/**", "/js/**", "/img/**", "/lib/**", "/favicon.ico");
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // TODO: Create RegisteredClientRepository within DB #3;

        RegisteredClient tempRegisteredClient = RegisteredClient.withId("tempId")
                .clientId("tempClientId")
                .clientSecret("{noop}tempSecret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID).scope("temp.temp1")
                .scope("temp.temp2")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(tempRegisteredClient);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            Authentication principal = context.getPrincipal();
            Set<String> authorities = new HashSet<>();
            for (GrantedAuthority authority : principal.getAuthorities()) {
                authorities.add(authority.getAuthority());
            }
            context.getClaims().claim(AUTHORITIES_CLAIM, authorities);

        };
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
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

    @Bean
    public AuthorizationServerSettings providerSettings() {
        AuthorizationServerSettings providerSettings = AuthorizationServerSettings.builder().issuer(issuer).build();
        // TODO: Create functional allowing to see these endpoints online.
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
                providerSettings.getAuthorizationEndpoint(),
                providerSettings.getTokenEndpoint(),
                providerSettings.getJwkSetEndpoint(),
                providerSettings.getOidcClientRegistrationEndpoint(),
                providerSettings.getOidcUserInfoEndpoint(),
                providerSettings.getTokenIntrospectionEndpoint(),
                providerSettings.getTokenRevocationEndpoint(),
                providerSettings.getIssuer(),
                DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI);
        return providerSettings;
    }
}
