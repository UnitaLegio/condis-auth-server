package com.unitalegio.sso.web.endpoint;

import com.unitalegio.sso.web.AbstractOAuth2IntegrationTest;
import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author Max Pestov, massenzio-p
 * @since 12.2022
 *
 * Tests token refreshing.
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2RefreshTokenGrantIntegrationTest extends AbstractOAuth2IntegrationTest {

    /**
     * Tests if token refreshes successfully.
     *
     * @throws Exception - libs errs.
     */
    @Test
    public void requestWhenRefreshTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
        RegisteredClient registeredClient = super.getNonConsentRegisteredClient();

        OAuth2Authorization authorization = super.authorizeNonConsentClient(
                registeredClient,
                super.providerSettings.getAuthorizationEndpoint());
        authorization = super.authorizeUserAndGetAccessToken(
                registeredClient,
                authorization,
                super.providerSettings.getTokenEndpoint()
        );

        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders.post(super.providerSettings.getTokenEndpoint())
                        .params(getRefreshTokenRequestParameters(authorization))
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
                                registeredClient.getClientId(),
                                registeredClient.getClientSecret().replace("{noop}", ""))))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header()
                        .string(HttpHeaders.CACHE_CONTROL, CoreMatchers.containsString("no-store")))
                .andExpect(MockMvcResultMatchers.header()
                        .string(HttpHeaders.PRAGMA, CoreMatchers.containsString("no-cache")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.token_type").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope").isNotEmpty())
                .andReturn();

        MockHttpServletResponse servletResponse = mvcResult.getResponse();
        MockClientHttpResponse httpResponse = new MockClientHttpResponse(
                servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
        OAuth2AccessTokenResponse accessTokenResponse = accessTokenHttpResponseConverter.read(
                OAuth2AccessTokenResponse.class, httpResponse);

        // Assert user authorities was propagated as claim in JWT
        Jwt jwt = jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
        List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
        Authentication principal = authorization.getAttribute(Principal.class.getName());
        Set<String> userAuthorities = new HashSet<>();
        for (GrantedAuthority authority : principal.getAuthorities()) {
            userAuthorities.add(authority.getAuthority());
        }
        Assertions.assertThat(authoritiesClaim).containsExactlyInAnyOrderElementsOf(userAuthorities);
    }

    /**
     * Retrieves parameters for request with refresh token.
     *
     * @param authorization - authorization containing refresh token;
     * @return request parameters map.
     */
    private static MultiValueMap<String, String> getRefreshTokenRequestParameters(OAuth2Authorization authorization) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.REFRESH_TOKEN.getValue());
        parameters.set(OAuth2ParameterNames.REFRESH_TOKEN, authorization.getRefreshToken().getToken().getTokenValue());
        return parameters;
    }

    /**
     * Tests revoked (access) token update. Revoked access token must be valid after reauthorization with refresh
     * token.
     * @throws Exception - libs errs;
     */
    @Test
    public void requestWhenRevokeAndRefreshThenAccessTokenActive() throws Exception {
        RegisteredClient registeredClient = getNonConsentRegisteredClient();
        OAuth2Authorization authorization = authorizeNonConsentClient(registeredClient, providerSettings.getAuthorizationEndpoint());
        authorization = authorizeUserAndGetAccessToken(
                registeredClient,
                authorization,
                providerSettings.getTokenEndpoint());
        OAuth2AccessToken token = authorization.getAccessToken().getToken();
        OAuth2TokenType tokenType = OAuth2TokenType.ACCESS_TOKEN;

        this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getTokenRevocationEndpoint())
                        .params(getTokenRevocationRequestParameters(token, tokenType))
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
                                registeredClient.getClientId(),
                                registeredClient.getClientSecret().replace("{noop}", ""))
                        ))
                .andExpect(MockMvcResultMatchers.status().isOk());

        this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getTokenEndpoint())
                        .params(getRefreshTokenRequestParameters(authorization))
                        .header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
                                registeredClient.getClientId(),
                                registeredClient.getClientSecret().replace("{noop}", ""))
                        ))
                .andExpect(MockMvcResultMatchers.status().isOk());

        OAuth2Authorization updatedAuthorization = this.authorizationService.findById(authorization.getId());
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken = updatedAuthorization.getAccessToken();
        Assertions.assertThat(accessToken.isActive()).isTrue();
    }

}
