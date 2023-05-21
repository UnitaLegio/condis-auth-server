package com.unitalegio.sso.web.endpoint;

import com.unitalegio.sso.web.AbstractOAuth2IntegrationTest;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

/**
 * @author Max Pestov, massenzio-p
 * @since 12.2022
 *
 * Tests token revocation.
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2TokenRevocationIntegrationIntegrationTest extends AbstractOAuth2IntegrationTest {

    /**
     * Tests if revoked refresh token is invalidated.
     *
     * @throws Exception - libs errs.
     */
    @Test
    public void requestWhenRevokeRefreshTokenThenRevoked() throws Exception {
        RegisteredClient registeredClient = super.getNonConsentRegisteredClient();

        OAuth2Authorization authorization = super.authorizeNonConsentClient(
                registeredClient,
                providerSettings.getAuthorizationEndpoint()
        );
        authorization = authorizeUserAndGetAccessToken(
                registeredClient,
                authorization,
                providerSettings.getTokenEndpoint()
        );

        OAuth2RefreshToken token = authorization.getRefreshToken().getToken();
        OAuth2TokenType tokenType = OAuth2TokenType.REFRESH_TOKEN;

        this.mvc.perform(MockMvcRequestBuilders
                        .post(providerSettings.getTokenRevocationEndpoint())
                        .params(getTokenRevocationRequestParameters(token, tokenType))
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Basic " + encodeBasicAuth(
                                        registeredClient.getClientId(),
                                        registeredClient.getClientSecret().replace("{noop}", "")))
                )
                .andExpect(MockMvcResultMatchers.status().isOk());

        OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
        Assertions.assertThat(refreshToken.isInvalidated()).isTrue();
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
        Assertions.assertThat(accessToken.isInvalidated()).isTrue();
    }

    /**
     * Tests if revoked access token is invalidated.
     *
     * @throws Exception - lib errs.
     */
    @Test
    public void requestWhenRevokeAccessTokenThenRevoked() throws Exception {

        RegisteredClient registeredClient = getNonConsentRegisteredClient();

        OAuth2Authorization authorization = authorizeNonConsentClient(registeredClient, providerSettings.getAuthorizationEndpoint());
        authorization = authorizeUserAndGetAccessToken(
                registeredClient,
                authorization,
                providerSettings.getTokenEndpoint()
        );
        OAuth2AccessToken token = authorization.getAccessToken().getToken();
        OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;
        this.authorizationService.save(authorization);

        this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getTokenRevocationEndpoint())
                        .params(getTokenRevocationRequestParameters(token, tokenType))
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
                                registeredClient.getClientId(),
                                registeredClient.getClientSecret().replace("{noop}", "")))
                )
                .andExpect(MockMvcResultMatchers.status().isOk());

        OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
        Assertions.assertThat(accessToken.isInvalidated()).isTrue();
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = updatedAuthorization.getRefreshToken();
        Assertions.assertThat(refreshToken.isInvalidated()).isFalse();
    }

}
