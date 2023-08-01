package com.unitalegio.sso.web.endpoint;

import com.unitalegio.sso.web.AbstractOAuth2IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

/**
 * @author massenzio-p
 * @since 01.2023
 * <p>
 * Tests for user info endpoint.
 * <p>
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OidcUserInfoIntegrationTest extends AbstractOAuth2IntegrationTest {

    /**
     * This test checks if user info response contains "sub": "testStub" for GET method
     *
     * @throws Exception - lib errors;
     */
    @Test
    public void requestWhenUserInfoRequestGetThenUserInfoResponse() throws Exception {
        testUserInfo(MockMvcRequestBuilders.get(authServerSettings.getOidcUserInfoEndpoint()));
    }

    /**
     * This test checks if user info response contains "sub": "testStub" for POST method
     * @throws Exception - lib errors;
     */
    @Test
    public void requestWhenUserInfoRequestPostThenUserInfoResponse() throws Exception {
        testUserInfo(MockMvcRequestBuilders.post(authServerSettings.getOidcUserInfoEndpoint()));
    }

    /**
     * Perform user info endpoint test with htt method customization.
     *
     * @param method - MockHttpServletRequestBuilder (http mvc method)
     * @throws Exception - lib errors;
     */
    private void testUserInfo(MockHttpServletRequestBuilder method) throws Exception {
        OAuth2AccessToken accessToken = getAccessToken();
        this.mvc.perform(method.header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken.getTokenValue()))
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.jsonPath("sub").value("testStub"));
    }

    /**
     * This method performs entire authentication.
     *
     * @return access token.
     * @throws Exception - lib errors;
     */
    private OAuth2AccessToken getAccessToken() throws Exception {
        RegisteredClient registeredClient = getNonConsentRegisteredClient();
        OAuth2Authorization authorization = authorizeNonConsentClient(
                registeredClient,
                authServerSettings.getAuthorizationEndpoint()
        );
        authorization = authorizeUserAndGetAccessToken(
                registeredClient,
                authorization,
                authServerSettings.getTokenEndpoint()
        );
        return authorization.getAccessToken().getToken();
    }

}
