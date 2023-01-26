package com.unitalegio.sso.web.endpoint;

import com.unitalegio.sso.web.AbstractOAuth2IntegrationTest;
import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.core.oidc.http.converter.OidcClientRegistrationHttpMessageConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

/**
 * @author Max Pestov, massenzio
 * @since 01.2023
 *
 * This tests oAuth2 client registration endpoint;
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2TokenRegistrationIntegrationTest extends AbstractOAuth2IntegrationTest {

    @Autowired
    private JwtEncoder jwtClientAssertionEncoder;
    private static final HttpMessageConverter<OidcClientRegistration> clientRegistrationHttpMessageConverter =
            new OidcClientRegistrationHttpMessageConverter();

    /**
     * This test validates process of registering new client.
     *
     * @throws Exception - libs errors.
     */
    @Test
    public void requestWhenClientRegistrationRequestAuthorizedThenClientRegistrationResponse() throws Exception {

        OidcClientRegistration newClientRegistration = OidcClientRegistration.builder()
                .clientName("client-name")
                .redirectUri("http://127.0.0.1:8080/registered")
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .scope("scope1")
                .scope("scope2")
                .build();

        OidcClientRegistration clientRegistrationResponse = registerClient(newClientRegistration);

        Assertions.assertThat(clientRegistrationResponse.getClientId()).isNotNull();
        Assertions.assertThat(clientRegistrationResponse.getClientIdIssuedAt()).isNotNull();
        Assertions.assertThat(clientRegistrationResponse.getClientSecret()).isNotNull();
        Assertions.assertThat(clientRegistrationResponse.getClientSecretExpiresAt()).isNull();
        Assertions.assertThat(clientRegistrationResponse.getClientName()).isEqualTo(newClientRegistration.getClientName());
        Assertions.assertThat(clientRegistrationResponse.getRedirectUris())
                .containsExactlyInAnyOrderElementsOf(newClientRegistration.getRedirectUris());
        Assertions.assertThat(clientRegistrationResponse.getGrantTypes())
                .containsExactlyInAnyOrderElementsOf(newClientRegistration.getGrantTypes());
        Assertions.assertThat(clientRegistrationResponse.getResponseTypes())
                .containsExactly(OAuth2AuthorizationResponseType.CODE.getValue());
        Assertions.assertThat(clientRegistrationResponse.getScopes())
                .containsExactlyInAnyOrderElementsOf(newClientRegistration.getScopes());
        Assertions.assertThat(clientRegistrationResponse.getTokenEndpointAuthenticationMethod())
                .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
        Assertions.assertThat(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm())
                .isEqualTo(SignatureAlgorithm.RS256.getName());
        Assertions.assertThat(clientRegistrationResponse.getRegistrationClientUrl()).isNotNull();
        Assertions.assertThat(clientRegistrationResponse.getRegistrationAccessToken()).isNotEmpty();
    }

    /**
     * This test validates process of registering new client and then, checks if new registered client is equal that
     * which was supposed to be registered.
     *
     * @throws Exception - libs errors.
     */
    @Test
    public void requestWhenClientConfigurationRequestAuthorizedThenClientRegistrationResponse() throws Exception {

        OidcClientRegistration newClientRegistration = OidcClientRegistration.builder()
                .clientName("client-name")
                .redirectUri("https://client.example.com")
                .grantType(AuthorizationGrantType.AUTHORIZATION_CODE.getValue())
                .grantType(AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
                .scope("scope1")
                .scope("scope2")
                .build();


        OidcClientRegistration clientRegistrationResponse = registerClient(newClientRegistration);

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(clientRegistrationResponse.getRegistrationAccessToken());

        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders.get(clientRegistrationResponse.getRegistrationClientUrl().toURI())
                        .headers(httpHeaders))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.CACHE_CONTROL, CoreMatchers.containsString("no-store")))
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.PRAGMA, CoreMatchers.containsString("no-cache")))
                .andReturn();

        OidcClientRegistration clientConfigurationResponse = readClientRegistrationResponse(mvcResult.getResponse());

        Assertions.assertThat(clientConfigurationResponse.getClientId()).isEqualTo(clientRegistrationResponse.getClientId());
        Assertions.assertThat(clientConfigurationResponse.getClientIdIssuedAt()).isEqualTo(clientRegistrationResponse.getClientIdIssuedAt());
        Assertions.assertThat(clientConfigurationResponse.getClientSecret()).isEqualTo(clientRegistrationResponse.getClientSecret());
        Assertions.assertThat(clientConfigurationResponse.getClientSecretExpiresAt()).isEqualTo(clientRegistrationResponse.getClientSecretExpiresAt());
        Assertions.assertThat(clientConfigurationResponse.getClientName()).isEqualTo(clientRegistrationResponse.getClientName());
        Assertions.assertThat(clientConfigurationResponse.getRedirectUris())
                .containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getRedirectUris());
        Assertions.assertThat(clientConfigurationResponse.getGrantTypes())
                .containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getGrantTypes());
        Assertions.assertThat(clientConfigurationResponse.getResponseTypes())
                .containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getResponseTypes());
        Assertions.assertThat(clientConfigurationResponse.getScopes())
                .containsExactlyInAnyOrderElementsOf(clientRegistrationResponse.getScopes());
        Assertions.assertThat(clientConfigurationResponse.getTokenEndpointAuthenticationMethod())
                .isEqualTo(clientRegistrationResponse.getTokenEndpointAuthenticationMethod());
        Assertions.assertThat(clientConfigurationResponse.getIdTokenSignedResponseAlgorithm())
                .isEqualTo(clientRegistrationResponse.getIdTokenSignedResponseAlgorithm());
        Assertions.assertThat(clientConfigurationResponse.getRegistrationClientUrl())
                .isEqualTo(clientRegistrationResponse.getRegistrationClientUrl());
        Assertions.assertThat(clientConfigurationResponse.getRegistrationAccessToken()).isNull();
    }

    /**
     * Commit a procedure of registration of new client by a mock registering client.
     *
     * @param clientRegistration - the client to register.
     * @return a new registered client.
     * @throws Exception - libs errors.
     */
    private OidcClientRegistration registerClient(OidcClientRegistration clientRegistration) throws Exception {
        // ***** (1) Obtain the "initial" access token used for registering the client

        RegisteredClient clientRegistrar = getRegisteringRegisteredClient();
        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();

        /*JwtClaimsSet jwtClaimsSet = jwtClientAssertionClaims(clientRegistrar).build();
        JwtEncoderParameters jwtEncoderParameters = JwtEncoderParameters.from(jwsHeader, jwtClaimsSet);
        Jwt jwtAssertion = jwtClientAssertionEncoder.encode(jwtEncoderParameters);*/

        OAuth2Authorization authorization = authorizeNonConsentClient(clientRegistrar, providerSettings.getAuthorizationEndpoint());
        authorization = authorizeUserAndGetAccessToken(clientRegistrar, authorization, providerSettings.getTokenEndpoint());
        OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();

        // ***** (2) Register the client

        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.setBearerAuth(accessToken.getTokenValue());

        // Register the client
        MvcResult mvcResult = this.mvc.perform(MockMvcRequestBuilders.post(providerSettings.getOidcClientRegistrationEndpoint())
                        .headers(httpHeaders)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(getClientRegistrationRequestContent(clientRegistration)))
                .andExpect(MockMvcResultMatchers.status().isCreated())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.CACHE_CONTROL, CoreMatchers.containsString("no-store")))
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.PRAGMA, CoreMatchers.containsString("no-cache")))
                .andReturn();

        return readClientRegistrationResponse(mvcResult.getResponse());
    }

    /**
     * The method create http body with content of a client registration.

     * @param clientRegistration - the client to register.
     * @return an array of bytes, which can be wrapped into a string or just directed in a raw view to the target.
     * @throws Exception - libs errors.
     */
    private static byte[] getClientRegistrationRequestContent(OidcClientRegistration clientRegistration) throws Exception {
        MockHttpOutputMessage httpRequest = new MockHttpOutputMessage();
        clientRegistrationHttpMessageConverter.write(clientRegistration, null, httpRequest);
        return httpRequest.getBodyAsBytes();
    }

    /**
     * This wraps mock servlet into mock http response, and then uses converter to get it into appropriate format.

     * @param response - response on new client registration.
     * @return particular object of client registration.
     * @throws Exception - libs errors.
     */
    private static OidcClientRegistration readClientRegistrationResponse(MockHttpServletResponse response) throws Exception {
        MockClientHttpResponse httpResponse = new MockClientHttpResponse(
                response.getContentAsByteArray(), HttpStatus.valueOf(response.getStatus()));
        return clientRegistrationHttpMessageConverter.read(OidcClientRegistration.class, httpResponse);
    }

}
