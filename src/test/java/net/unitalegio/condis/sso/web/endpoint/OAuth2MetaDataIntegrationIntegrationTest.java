package net.unitalegio.condis.sso.web.endpoint;

import net.unitalegio.condis.sso.web.AbstractOAuth2IntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;


/**
 * @since 12.2022
 *
 * Tests for server metadata endpoint.
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2MetaDataIntegrationIntegrationTest extends AbstractOAuth2IntegrationTest {
    private static final String DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI =
            "/.well-known/oauth-authorization-server";

    /**
     * Tests if metadata endpoint successful returns data with particular issuer
     * @throws Exception - mvc errs;
     */
    @Test
    public void requestWhenAuthorizationServerMetadataRequestAndIssuerSetThenReturnMetadataResponse() throws Exception {
        super.mvc.perform(MockMvcRequestBuilders.get(DEFAULT_OAUTH2_AUTHORIZATION_SERVER_METADATA_ENDPOINT_URI))
                .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
                .andExpect(MockMvcResultMatchers.jsonPath("issuer").value(authServerSettings.getIssuer()))
                .andReturn();
    }

}
