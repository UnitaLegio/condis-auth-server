package com.unitalegio.sso.web;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.unitalegio.condis.sso.CondisSsoServer;
import com.unitalegio.sso.web.configuration.DefaultTestConfiguration;
import org.hamcrest.Matchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * @author massenzio-p
 * @since 12.2022
 * <p>
 * Abstract test class with common fields and methods.
 * </p>
 */
@ContextConfiguration(classes = {
        CondisSsoServer.class,
        DefaultTestConfiguration.class})
@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public abstract class AbstractOAuth2IntegrationTest {

    protected static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
    protected static final OAuth2TokenType ACCESS_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.ACCESS_TOKEN);
    protected static final String AUTHORITIES_CLAIM = "authorities";
    protected static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    protected MockMvc mvc;

    @Autowired
    protected RegisteredClientRepository registeredClientRepository;

    @Autowired
    protected AuthorizationServerSettings authServerSettings;

    @Autowired
    protected JwtDecoder jwtDecoder;

    @Autowired
    protected OAuth2AuthorizationService authorizationService;

    /**
     * Gets registered client defined in configuration;
     *
     * @return registered client;
     */
    protected RegisteredClient getNonConsentRegisteredClient() {
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("test-client");
        assertNotNull(registeredClient);
        return registeredClient;
    }

    /**
     * Gets registered working with opaque token;
     *
     * @return registered client;
     */
    protected RegisteredClient getNonConsentRegisteredClientWorkingWithOpaqueToken() {
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("opaque-test-client");
        assertNotNull(registeredClient);
        return registeredClient;
    }

    /**
     * Register additional registered client/
     *
     * @param clientNumber - number of new client.
     * @return persisted registered client.
     */
    protected RegisteredClient registerAdditionalRegisteredClient(int clientNumber) {
        RegisteredClient additionalClient = RegisteredClient
                .withId(String.format("additional%dId", clientNumber))
                .clientId(String.format("add%d-test-client", clientNumber))
                .clientSecret(String.format("{noop}testSecret%d", clientNumber))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.JWT_BEARER)
                .redirectUri(String.format("http://127.0.0.1:8080/login/oauth2/code/add-%d-client-oids", clientNumber))
                .scope(OidcScopes.OPENID)
                .scope("test.test1")
                .scope("test.test2")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
        try {
            this.registeredClientRepository.save(additionalClient);
        } catch (IllegalArgumentException e) {
            return getAdditionalNonConsentRegisteredClient(clientNumber);
        }
        return additionalClient;
    }

    /**
     * Gets additional registered client defined in configuration (for example for token introspection);
     *
     * @return additional registered client;
     */
    protected RegisteredClient getAdditionalNonConsentRegisteredClient(int clientNumber) {
        RegisteredClient registeredClient = this.registeredClientRepository
                .findByClientId(String.format("add%d-test-client", clientNumber));
        assertNotNull(registeredClient);
        return registeredClient;
    }

    /**
     * Finds registered client requiring consent page during authorizaiton;
     *
     * @return registered client;
     */
    protected RegisteredClient getConsentRegisteredClient() {
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("test-consent-client");
        assertNotNull(registeredClient);
        return registeredClient;
    }

    /**
     * Authenticate with registered client not requiring consent.
     *
     * @param registeredClient      - registered client;
     * @param authorizationEndpoint - authorization endpoint;
     * @return oauth2 authorization object;
     * @throws Exception - libs errs.
     */
    protected OAuth2Authorization authorizeNonConsentClient(RegisteredClient registeredClient,
                                                            String authorizationEndpoint) throws Exception {
        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders.get(authorizationEndpoint)
                        .params(getAuthorizationRequestParameters(registeredClient))
                        .with(SecurityMockMvcRequestPostProcessors.user("testStub")))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andReturn();

        String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
        assert redirectedUrl != null;
        assertTrue(
                redirectedUrl.matches(
                        registeredClient.getRedirectUris().iterator().next() + "\\?code=.{128,}&state=dummyState")
        );

        String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
        return getAuthorizationByToken(authorizationCode, AUTHORIZATION_CODE_TOKEN_TYPE);
    }

    /**
     * This method gets registered client intended for only registration other clients.
     * @return registering client.
     */
    protected RegisteredClient getRegisteringRegisteredClient() {
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("test-registering-client");
        assertNotNull(registeredClient);
        return registeredClient;
    }

    /**
     * Finds authorization by token
     *
     * @param token    - token;
     * @param codeType - type of token;
     * @return found authorization;
     */
    protected OAuth2Authorization getAuthorizationByToken(String token, OAuth2TokenType codeType) {
        return this.authorizationService.findByToken(token, codeType);
    }

    /**
     * Generates parameters for authorization http request;
     *
     * @param registeredClient - some registered client to get some parameters from;
     * @return map of parameters;
     */
    protected MultiValueMap<String, String> getAuthorizationRequestParameters(RegisteredClient registeredClient) {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
        params.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
        params.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
        params.set(OAuth2ParameterNames.SCOPE,
                StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " ")
        );
        params.set(OAuth2ParameterNames.STATE, "dummyState");

        return params;
    }

    /**
     * Extracts uri parameter value.
     *
     * @param redirectedUri - uri;
     * @param parameter     - parameter name;
     * @return parameter value;
     * @throws UnsupportedEncodingException - uri decoder error;
     */
    private String extractParameterFromRedirectUri(String redirectedUri,
                                                   String parameter) throws UnsupportedEncodingException {
        String locationHeader = URLDecoder.decode(redirectedUri, StandardCharsets.UTF_8.name());
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
        return uriComponents.getQueryParams().getFirst(parameter);
    }

    /**
     * Authenticates with regigestered client, which requires consent.
     *
     * @param registeredClient      - registered client (with consent option);
     * @param authorizationEndpoint - authorization endpoint;
     * @return oauth2 authorization object;
     * @throws Exception - libs;
     */
    protected OAuth2Authorization authorizeWithConsent(RegisteredClient registeredClient,
                                                       String authorizationEndpoint) throws Exception {

        assert registeredClient.getClientSettings().isRequireAuthorizationConsent();

        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders.get(authorizationEndpoint)
                        .params(getAuthorizationRequestParameters(registeredClient))
                        .with(SecurityMockMvcRequestPostProcessors.user("testStub")))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        HtmlPage consentPage = new WebClient()
                .loadHtmlCodeIntoCurrentWindow(mvcResult.getResponse().getContentAsString());
        HtmlInput stateInput = consentPage.querySelector("input[name=\"state\"]");

        MvcResult mvcConsentResult = this.mvc.perform(post(authorizationEndpoint)
                        .param(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId())
                        .param(OAuth2ParameterNames.SCOPE, "test.test1")
                        .param(OAuth2ParameterNames.SCOPE, "test.test2")
                        .param(OAuth2ParameterNames.STATE, stateInput.getValue())
                        .with(SecurityMockMvcRequestPostProcessors.user("testStub")))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andReturn();

        String redirectedUrl = mvcConsentResult.getResponse().getRedirectedUrl();
        assert redirectedUrl != null;
        assertTrue(
                redirectedUrl.matches(
                        registeredClient.getRedirectUris().iterator().next() + "\\?code=.{128,}&state=dummyState")
        );

        String authorizationCode = extractParameterFromRedirectUri(redirectedUrl, "code");
        return this.authorizationService.findByToken(authorizationCode, AUTHORIZATION_CODE_TOKEN_TYPE);
    }

    /**
     * Get basic encoded authorization string.
     *
     * @param clientId - client id;
     * @param secret   - client secret;
     * @return basic string;
     * @throws Exception - libs errs.
     */
    protected static String encodeBasicAuth(String clientId, String secret) throws Exception {
        clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
        secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
        String credentialsString = clientId + ":" + secret;
        byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
        return new String(encodedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Assert if token request successful returns jwt.
     *
     * @param registeredClient - authorized registered client;
     * @param authorization    - authorization of registered client;
     * @param tokenEndpointUri - endpoint of receiving jwt;
     * @return - converted token response;
     * @throws Exception - mvc errors;
     */
    protected OAuth2AccessTokenResponse getValidAccessTokenResponse(RegisteredClient registeredClient,
                                                                    OAuth2Authorization authorization,
                                                                    String tokenEndpointUri) throws Exception {
        MvcResult mvcResult = this.mvc.perform(post(tokenEndpointUri)
                        .params(getTokenRequestParameters(registeredClient, authorization))
                        .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string(
                        HttpHeaders.CACHE_CONTROL, Matchers.containsString("no-store")))
                .andExpect(MockMvcResultMatchers.header().string(
                        HttpHeaders.PRAGMA, Matchers.containsString("no-cache")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.token_type").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope").isNotEmpty())
                .andReturn();

        OAuth2Authorization accessTokenAuthorization = this.authorizationService.findById(authorization.getId());
        assertNotNull(accessTokenAuthorization);
        assertNotNull(accessTokenAuthorization.getAccessToken());
        assertNotNull(accessTokenAuthorization.getRefreshToken());

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken =
                accessTokenAuthorization.getToken(OAuth2AuthorizationCode.class);
        assertNotNull(authorizationCodeToken);
        assertEquals(true,
                authorizationCodeToken.getMetadata().get(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME));

        MockHttpServletResponse servletResponse = mvcResult.getResponse();
        MockClientHttpResponse httpResponse = new MockClientHttpResponse(
                servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
        return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
    }

    /**
     * It gets the opaque token.
     *
     * @param registeredClient - the authorized registered client;
     * @param authorization    - the authorization of registered client;
     * @param tokenEndpointUri - the endpoint of receiving jwt;
     * @return - converted token response;
     * @throws Exception - mvc errors;
     */
    protected OAuth2AccessTokenResponse getValidOpaqueAccessTokenResponse(RegisteredClient registeredClient,
                                                                    OAuth2Authorization authorization,
                                                                    String tokenEndpointUri) throws Exception {
        MvcResult mvcResult = this.mvc.perform(post(tokenEndpointUri)
                        .params(getTokenRequestParameters(registeredClient, authorization))
                        .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andReturn();

        MockHttpServletResponse servletResponse = mvcResult.getResponse();
        MockClientHttpResponse httpResponse = new MockClientHttpResponse(
                servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
        return accessTokenHttpResponseConverter.read(OAuth2AccessTokenResponse.class, httpResponse);
    }

    /**
     * Assert if token request successful returns jwt.
     *
     * @param registeredClient - authorized registered client;
     * @param authorization    - authorization of registered client;
     * @param tokenEndpointUri - endpoint of receiving jwt;
     * @return - Authorization with all necessary tokens and attributes;
     * @throws Exception - mvc errors;
     */
    protected OAuth2Authorization authorizeUserAndGetAccessToken(RegisteredClient registeredClient,
                                                                 OAuth2Authorization authorization,
                                                                 String tokenEndpointUri) throws Exception {
        OAuth2AccessTokenResponse response = getValidAccessTokenResponse(
                registeredClient,
                authorization,
                tokenEndpointUri);
        return getAuthorizationByToken(response.getAccessToken().getTokenValue(), ACCESS_TOKEN_TYPE);
    }

    /**
     * Generate map of token request parameters.
     *
     * @param registeredClient - registered client;
     * @param authorization    - oauth2 authorization object;
     * @return map with parameters.
     */
    protected static MultiValueMap<String, String> getTokenRequestParameters(RegisteredClient registeredClient,
                                                                             OAuth2Authorization authorization) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        parameters.set(OAuth2ParameterNames.CODE, authorization.getToken(OAuth2AuthorizationCode.class)
                .getToken().getTokenValue());
        parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
        return parameters;
    }

    /**
     * Create string Authorization header (content part) wiht credentials in basic format;
     *
     * @param registeredClient - registered client;
     * @return authorization header in string format;
     * @throws Exception - url encoder errors;
     */
    protected static String getAuthorizationHeader(RegisteredClient registeredClient) throws Exception {
        String clientId = registeredClient.getClientId();
        String clientSecret = registeredClient.getClientSecret().replace("{noop}", "");
        clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
        clientSecret = URLEncoder.encode(clientSecret, StandardCharsets.UTF_8.name());
        String credentialsString = clientId + ":" + clientSecret;
        byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
        return "Basic " + new String(encodedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Collect parameters for token revocation request.
     *
     * @param token     - token;
     * @param tokenType - type of token;
     * @return request parameters map.
     */
    protected static MultiValueMap<String, String> getTokenRevocationRequestParameters(OAuth2Token token,
                                                                                       OAuth2TokenType tokenType) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.TOKEN, token.getTokenValue());
        parameters.set(OAuth2ParameterNames.TOKEN_TYPE_HINT, tokenType.getValue());
        return parameters;
    }
}
