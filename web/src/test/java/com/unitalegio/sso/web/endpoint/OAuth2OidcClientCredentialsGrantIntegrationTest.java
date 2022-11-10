package com.unitalegio.sso.web.endpoint;

import com.unitalegio.sso.web.AbstractOAuth2IntegrationTest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import static org.mockito.ArgumentMatchers.any;

/**
 * @author Max Pestov, massenzio-p
 * @since 12.2022
 *
 * Tests authentication with client credentials
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2OidcClientCredentialsGrantIntegrationTest extends AbstractOAuth2IntegrationTest {

    @MockBean
    private OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer;

    /**
     * Test if redirects after not authenticated token request.
     *
     * @throws Exception - mvc errs;
     */
    @Test
    public void requestWhenTokenRequestNotAuthenticatedThenRedirect() throws Exception {
        super.mvc.perform(MockMvcRequestBuilders.post(super.providerSettings.getTokenEndpoint())
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue()))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection());
    }

    /**
     *  Test token response if registered client authenticated with its credentials in header.
     *
     * @throws Exception - libs errs.
     */
    @Test
    public void requestWhenTokenRequestValidThenTokenResponse() throws Exception {

        RegisteredClient registeredClient = getNonConsentRegisteredClient();
        String scopes = getRegisteredClientScopesString(registeredClient);

        this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getTokenEndpoint())
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                        .param(OAuth2ParameterNames.SCOPE, scopes)
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
                                registeredClient.getClientId(),
                                registeredClient.getClientSecret().replace("{noop}", ""))))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope")
                        .value(scopes));

        Mockito.verify(jwtCustomizer).customize(any());
    }

    /**
     * Gets registered client scopes string.
     * @param registeredClient - registered client;

     * @return scopes string
     */
    private String getRegisteredClientScopesString(RegisteredClient registeredClient) {
        return registeredClient
                .getScopes()
                .stream()
                .reduce("", (s, s2) -> (s.length() > 0) ? s + " " + s2 : s + s2);
    }

    /**
     *  Test token response if registered client authenticated with its credentials in post body.

     * @throws Exception - libs errs.
     */
    @Test
    public void requestWhenTokenRequestPostsClientCredentialsThenTokenResponse() throws Exception {
        RegisteredClient registeredClient = getNonConsentRegisteredClient();
        String scopes = getRegisteredClientScopesString(registeredClient);

        this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getTokenEndpoint())
                        .param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                        .param(OAuth2ParameterNames.SCOPE, scopes)
                        .param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
                        .param(OAuth2ParameterNames.CLIENT_SECRET,
                                registeredClient.getClientSecret().replace("{noop}", "")))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope").value(scopes));
        Mockito.verify(jwtCustomizer).customize(any());
    }

}
