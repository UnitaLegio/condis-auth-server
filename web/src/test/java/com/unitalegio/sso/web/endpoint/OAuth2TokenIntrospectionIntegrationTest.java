package com.unitalegio.sso.web.endpoint;

import com.unitalegio.sso.web.AbstractOAuth2IntegrationTest;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2TokenIntrospectionHttpMessageConverter;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.ArrayList;
import java.util.List;

/**
 * @author Max Pestov, massenzio-p
 * @since 12.2022
 * <p>
 * Tests for token introspection.
 * <p>
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2TokenIntrospectionIntegrationTest extends AbstractOAuth2IntegrationTest {

    @LocalServerPort
    private int serverPort;

    private static final HttpMessageConverter<OAuth2TokenIntrospection> tokenIntrospectionHttpResponseConverter =
            new OAuth2TokenIntrospectionHttpMessageConverter();

    @MockBean
    private OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer;

    /**
     * It tests that introspection after request with valid access token positive response with valid data fields
     * returned.
     *
     * @throws Exception - lib errs.
     */
    @Test
    public void requestWhenIntrospectValidAccessTokenThenActive() throws Exception {
        RegisteredClient introspectRegisteredClient = registerAdditionalRegisteredClient(
                1,
                this.serverPort);
        RegisteredClient authorizedRegisteredClient = getNonConsentRegisteredClient();

        OAuth2Authorization authorization = authorizeNonConsentClient(
                authorizedRegisteredClient,
                providerSettings.getAuthorizationEndpoint()
        );
        authorization = authorizeUserAndGetAccessToken(
                authorizedRegisteredClient,
                authorization,
                providerSettings.getTokenEndpoint()
        );

        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
        // @formatter:off
        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders
                        .post(providerSettings.getTokenIntrospectionEndpoint())
                        .params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                        .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        // @formatter:on
        OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);
        OAuth2TokenClaimsSet.Builder claimsSetBuilder = OAuth2TokenClaimsSet.builder();
        authorization.getAccessToken().getClaims().forEach(claimsSetBuilder::claim);
        OAuth2TokenClaimsSet accessTokenClaims = claimsSetBuilder.build();

        Assertions.assertThat(tokenIntrospectionResponse.isActive()).isTrue();
        Assertions.assertThat(tokenIntrospectionResponse.getClientId())
                .isEqualTo(authorizedRegisteredClient.getClientId());
        Assertions.assertThat(tokenIntrospectionResponse.getUsername()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(
                accessTokenClaims.getIssuedAt().minusSeconds(1), accessTokenClaims.getIssuedAt().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
                accessTokenClaims.getExpiresAt().minusSeconds(1), accessTokenClaims.getExpiresAt().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getScopes())
                .containsExactlyInAnyOrderElementsOf(accessToken.getScopes());
        Assertions.assertThat(tokenIntrospectionResponse.getTokenType())
                .isEqualTo(accessToken.getTokenType().getValue());
        Assertions.assertThat(tokenIntrospectionResponse.getNotBefore()).isBetween(
                accessTokenClaims.getNotBefore().minusSeconds(1), accessTokenClaims.getNotBefore().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo(accessTokenClaims.getSubject());
        Assertions.assertThat(tokenIntrospectionResponse.getAudience())
                .containsExactlyInAnyOrderElementsOf(accessTokenClaims.getAudience());
        Assertions.assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(accessTokenClaims.getIssuer());
        Assertions.assertThat(tokenIntrospectionResponse.getId()).isEqualTo(accessTokenClaims.getId());
    }

    /**
     * It tests that introspection after request with valid refresh token positive response with valid data fields
     * returned.
     *
     * @throws Exception - lib errs.
     */
    @Test
    public void requestWhenIntrospectValidRefreshTokenThenActive() throws Exception {
        registerAdditionalRegisteredClient(1, this.serverPort);
        RegisteredClient introspectRegisteredClient = getAdditionalNonConsentRegisteredClient(1);
        RegisteredClient authorizedRegisteredClient = getNonConsentRegisteredClient();
        OAuth2Authorization authorization = authorizeNonConsentClient(
                authorizedRegisteredClient,
                providerSettings.getAuthorizationEndpoint()
        );
        authorization = authorizeUserAndGetAccessToken(
                authorizedRegisteredClient,
                authorization,
                providerSettings.getTokenEndpoint()
        );
        OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();

        // @formatter:off
        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getTokenIntrospectionEndpoint())
                        .params(getTokenIntrospectionRequestParameters(refreshToken, OAuth2TokenType.REFRESH_TOKEN))
                        .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        // @formatter:on

        OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);
        Assertions.assertThat(tokenIntrospectionResponse.isActive()).isTrue();
        Assertions.assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
        Assertions.assertThat(tokenIntrospectionResponse.getUsername()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(
                refreshToken.getIssuedAt().minusSeconds(1), refreshToken.getIssuedAt().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
                refreshToken.getExpiresAt().minusSeconds(1), refreshToken.getExpiresAt().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getScopes()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getTokenType()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getNotBefore()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getSubject()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getAudience()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getIssuer()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getId()).isNull();
    }

    /**
     * It tests token introspection, when clients allowed only for reference token (opaque).
     *
     * @throws Exception - lib errs.
     */
    @Test
    public void requestWhenObtainReferenceAccessTokenAndIntrospectThenActive() throws Exception {

        RegisteredClient authorizedRegisteredClient = getNonConsentRegisteredClientWorkingWithOpaqueToken();
        OAuth2Authorization regClientAuthorization = authorizeNonConsentClient(
                authorizedRegisteredClient,
                providerSettings.getAuthorizationEndpoint()
        );
        OAuth2AccessTokenResponse authorization = getValidOpaqueAccessTokenResponse(
                authorizedRegisteredClient,
                regClientAuthorization,
                providerSettings.getTokenEndpoint()
        );

        registerAdditionalRegisteredClient(1, this.serverPort);
        RegisteredClient introspectRegisteredClient = getAdditionalNonConsentRegisteredClient(1);
        OAuth2AccessToken accessToken = authorization.getAccessToken();
        // @formatter:off
        MvcResult mvcResult = this.mvc.perform(
                MockMvcRequestBuilders.post(providerSettings.getTokenIntrospectionEndpoint())
                        .params(getTokenIntrospectionRequestParameters(accessToken, OAuth2TokenType.ACCESS_TOKEN))
                        .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(introspectRegisteredClient)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();
        // @formatter:on

        OAuth2TokenIntrospection tokenIntrospectionResponse = readTokenIntrospectionResponse(mvcResult);

        ArgumentCaptor<OAuth2TokenClaimsContext> accessTokenClaimsContextCaptor =
                ArgumentCaptor.forClass(OAuth2TokenClaimsContext.class);

        Mockito.verify(accessTokenCustomizer).customize(accessTokenClaimsContextCaptor.capture());

        OAuth2TokenClaimsContext accessTokenClaimsContext = accessTokenClaimsContextCaptor.getValue();
        OAuth2TokenClaimsSet accessTokenClaims = accessTokenClaimsContext.getClaims().build();

        Assertions.assertThat(tokenIntrospectionResponse.isActive()).isTrue();
        Assertions.assertThat(tokenIntrospectionResponse.getClientId()).isEqualTo(authorizedRegisteredClient.getClientId());
        Assertions.assertThat(tokenIntrospectionResponse.getUsername()).isNull();
        Assertions.assertThat(tokenIntrospectionResponse.getIssuedAt()).isBetween(
                accessTokenClaims.getIssuedAt().minusSeconds(1), accessTokenClaims.getIssuedAt().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getExpiresAt()).isBetween(
                accessTokenClaims.getExpiresAt().minusSeconds(1), accessTokenClaims.getExpiresAt().plusSeconds(1));
        List<String> scopes = new ArrayList<>(accessTokenClaims.getClaim(OAuth2ParameterNames.SCOPE));
        Assertions.assertThat(tokenIntrospectionResponse.getScopes()).containsExactlyInAnyOrderElementsOf(scopes);
        Assertions.assertThat(tokenIntrospectionResponse.getTokenType()).isEqualTo(accessToken.getTokenType().getValue());
        Assertions.assertThat(tokenIntrospectionResponse.getNotBefore()).isBetween(
                accessTokenClaims.getNotBefore().minusSeconds(1), accessTokenClaims.getNotBefore().plusSeconds(1));
        Assertions.assertThat(tokenIntrospectionResponse.getSubject()).isEqualTo(accessTokenClaims.getSubject());
        Assertions.assertThat(tokenIntrospectionResponse.getAudience()).containsExactlyInAnyOrderElementsOf(accessTokenClaims.getAudience());
        Assertions.assertThat(tokenIntrospectionResponse.getIssuer()).isEqualTo(accessTokenClaims.getIssuer());
        Assertions.assertThat(tokenIntrospectionResponse.getId()).isEqualTo(accessTokenClaims.getId());
    }

    /**
     * Retrieves parameters for token introspection request.
     *
     * @param token     - token;
     * @param tokenType - token type;
     * @return request parameters map.
     */
    private static MultiValueMap<String, String> getTokenIntrospectionRequestParameters(AbstractOAuth2Token token,
                                                                                        OAuth2TokenType tokenType) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.TOKEN, token.getTokenValue());
        parameters.set(OAuth2ParameterNames.TOKEN_TYPE_HINT, tokenType.getValue());
        return parameters;
    }

    /**
     * Convert mvc response object to OAuth2 token introspection object.
     *
     * @param mvcResult - http mvc result;
     * @return token introspection object;
     * @throws Exception - libs errs.
     */
    private static OAuth2TokenIntrospection readTokenIntrospectionResponse(MvcResult mvcResult) throws Exception {
        MockHttpServletResponse servletResponse = mvcResult.getResponse();
        MockClientHttpResponse httpResponse = new MockClientHttpResponse(
                servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
        return tokenIntrospectionHttpResponseConverter.read(OAuth2TokenIntrospection.class, httpResponse);
    }

}
