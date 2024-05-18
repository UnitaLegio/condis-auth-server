package net.unitalegio.condis.sso.web.endpoint;

import net.unitalegio.condis.sso.web.AbstractOAuth2IntegrationTest;
import net.unitalegio.condis.sso.config.SecurityConfig;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.security.Principal;

/**
 * @author massenzio-p
 * @since 01.2023
 * <p>
 * Tests for OpenID operations.
 * <p>
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2OidcIntegrationTest extends AbstractOAuth2IntegrationTest {

    /**
     * This test checks that the user info endpoint return valid issuer url.
     *
     * @throws Exception - libs err.
     */
    @Test
    public void requestWhenConfigurationRequestAndIssuerSetThenReturnConfigurationResponse() throws Exception {

        this.mvc.perform(MockMvcRequestBuilders.get(SecurityConfig.DEFAULT_OIDC_PROVIDER_CONFIGURATION_ENDPOINT_URI))
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.jsonPath("issuer").value(authServerSettings.getIssuer()));
    }

    /**
     * This test asserts that the grand token has the same authorities as the access token.
     *
     * @throws Exception - libs errors.
     */
    @Test
    public void requestWhenAuthenticationRequestThenTokenResponseIncludesIdToken() throws Exception {
        RegisteredClient registeredClientWithOpenIDScope = getNonConsentRegisteredClient();
        OAuth2Authorization clientAuth = authorizeNonConsentClient(
                registeredClientWithOpenIDScope,
                authServerSettings.getAuthorizationEndpoint());
        OAuth2Authorization tokenAuth = authorizeUserAndGetAccessToken(
                registeredClientWithOpenIDScope,
                clientAuth,
                authServerSettings.getTokenEndpoint()
        );
        // Assert user authorities was propagated as claim in ID Token
        UsernamePasswordAuthenticationToken tokenAuthPrincipal = tokenAuth.getAttribute(Principal.class.getName());
        UsernamePasswordAuthenticationToken clientAuthPrincipal = clientAuth.getAttribute(Principal.class.getName());
        org.junit.jupiter.api.Assertions.assertNotNull(tokenAuthPrincipal);
        org.junit.jupiter.api.Assertions.assertNotNull(clientAuthPrincipal);
        Assertions.assertThat(clientAuthPrincipal.getAuthorities())
                .containsExactlyInAnyOrderElementsOf(tokenAuthPrincipal.getAuthorities());
    }

}
