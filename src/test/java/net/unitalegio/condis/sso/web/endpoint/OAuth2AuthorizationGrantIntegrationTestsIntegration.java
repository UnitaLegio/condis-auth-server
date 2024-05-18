package net.unitalegio.condis.sso.web.endpoint;

import net.unitalegio.condis.sso.web.AbstractOAuth2IntegrationTest;
import org.assertj.core.api.Assertions;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import java.security.Principal;
import java.text.MessageFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * @author massenzio-p
 * @since 12.2022
 *
 * Tests for authorization function of getting authorization code and access token.
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2AuthorizationGrantIntegrationTestsIntegration extends AbstractOAuth2IntegrationTest {

    /**
     * Authorization request.
     * Tests if not authenticated API users get 401 status code;
     *
     * @throws Exception - mvc error;
     */
    @Test
    public void requestWhenAuthorizationRequestNotAuthenticatedThenUnauthorized() throws Exception {
        this.mvc.perform(MockMvcRequestBuilders.get(authServerSettings.getAuthorizationEndpoint())
                        .params(super.getAuthorizationRequestParameters(super.getNonConsentRegisteredClient())))
                /* TODO: #7. Fix this within issue. Status must be unauthorized for api client */
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
//                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andReturn();
    }

    /**
     * Authorization request.
     * Tests if not registered client gets 400 status code;
     *
     * @throws Exception - mvc error;
     */
    @Test
    public void requestWhenRegisteredClientMissingThenBadRequest() throws Exception {
        RegisteredClient missingRegisteredClient = RegisteredClient.from(super.getNonConsentRegisteredClient())
                .clientId("missing-client")
                .build();
        this.mvc.perform(MockMvcRequestBuilders.get(authServerSettings.getAuthorizationEndpoint())
                        .params(super.getAuthorizationRequestParameters(missingRegisteredClient)))
                .andExpect(MockMvcResultMatchers.status().isBadRequest())
                .andReturn();
    }

    /**
     * Asserts redirection to client;
     *
     * @param authorizationEndpoint - authorization endpoint url;
     * @throws Exception - mvc, urlDecoder errors;
     */
    private void assertAuthorizationRequestRedirectsToClient(String authorizationEndpoint) throws Exception {
        OAuth2Authorization oAuth2Authorization = super.authorizeNonConsentClient(super.getNonConsentRegisteredClient(), authorizationEndpoint);

        assertNotNull(oAuth2Authorization);
        assertEquals(
                AuthorizationGrantType.AUTHORIZATION_CODE,
                oAuth2Authorization.getAuthorizationGrantType());
    }

    /**
     * Authorization request.
     * Tests if successful authentication redirects to client back;
     *
     * @throws Exception - mvc errors;
     */
    @Test
    public void requestWhenAuthorizationRequestAuthenticatedThenRedirectToClient() throws Exception {
        assertAuthorizationRequestRedirectsToClient(authServerSettings.getAuthorizationEndpoint());
    }

    /**
     * Tests if jwt response is valid for authorized client
     *
     * @throws Exception - mvc, url encoder and so on;
     */
    @Test
    public void requestWhenTokenRequestValidThenReturnAccessTokenResponse() throws Exception {
        RegisteredClient registeredClient = super.getNonConsentRegisteredClient();

        OAuth2Authorization authorization = super.authorizeNonConsentClient(registeredClient, authServerSettings.getAuthorizationEndpoint());

        OAuth2AccessTokenResponse accessTokenResponse = getValidAccessTokenResponse(
                registeredClient, authorization, authServerSettings.getTokenEndpoint());

        // Assert user authorities was propagated as claim in JWT
        Jwt jwt = this.jwtDecoder.decode(accessTokenResponse.getAccessToken().getTokenValue());
        List<String> authoritiesClaim = jwt.getClaim(AUTHORITIES_CLAIM);
        Authentication principal = authorization.getAttribute(Principal.class.getName());
        Set<String> userAuthorities = new HashSet<>();
        for (GrantedAuthority authority : principal.getAuthorities()) {
            userAuthorities.add(authority.getAuthority());
        }
        assertThat(authoritiesClaim).containsExactlyElementsOf(userAuthorities);
    }

    /**
     * Test if consent page displays during authentication with special registered client requiring that;
     * @throws Exception - libs err.
     */
    @Test
    public void requestWhenRequiresConsentThenDisplaysConsentPage() throws Exception {
        RegisteredClient registeredClient = super.getConsentRegisteredClient();

        String consentPage = this.mvc.perform(MockMvcRequestBuilders.get(authServerSettings.getAuthorizationEndpoint())
                        .params(super.getAuthorizationRequestParameters(registeredClient))
                        .with(SecurityMockMvcRequestPostProcessors.user("user")))
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andReturn()
                .getResponse()
                .getContentAsString();

        Assertions.assertThat(consentPage).contains("Consent required");
        Assertions.assertThat(consentPage).contains(scopeCheckbox("test.test1"));
        Assertions.assertThat(consentPage).contains(scopeCheckbox("test.test2"));
    }

    /**
     * Creates html input consent checkbox string for particular scope.
     *
     * @param scope - oauth2 scope;
     * @return html input element as string;
     */
    private CharSequence scopeCheckbox(String scope) {
        return MessageFormat.format(
                "<input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"{0}\" id=\"{0}\">",
                scope
        );
    }

    /**
     * Test if access token is returned after consent page proceed;
     *
     * @throws Exception - libs errs;
     */
    @Test
    public void requestWhenConsentRequestThenReturnAccessTokenResponse() throws Exception {

        RegisteredClient registeredClient = super.getConsentRegisteredClient();

        OAuth2Authorization authorization = super.authorizeWithConsent(
                registeredClient, authServerSettings.getAuthorizationEndpoint());

        this.mvc.perform(post(authServerSettings.getTokenEndpoint())
                        .params(getTokenRequestParameters(registeredClient, authorization))
                        .header(HttpHeaders.AUTHORIZATION, getAuthorizationHeader(registeredClient)))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers
                        .header().string(HttpHeaders.CACHE_CONTROL, CoreMatchers.containsString("no-store")))
                .andExpect(MockMvcResultMatchers
                        .header().string(HttpHeaders.PRAGMA, CoreMatchers.containsString("no-cache")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.token_type").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope").isNotEmpty())
                .andReturn();
    }

}
