package net.unitalegio.condis.sso.web.endpoint;

import net.unitalegio.condis.sso.web.AbstractOAuth2IntegrationTest;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

/**
 * @author massenzio-p
 * @since 12.2022
 *
 * Tests for jwk set endpoint.
 *
 * Based on Spring OAuth2 Authorization Server tests, and adapted.
 */
public class OAuth2JwkSetIntegrationIntegrationTest extends AbstractOAuth2IntegrationTest {

    private static final String DEFAULT_JWK_SET_ENDPOINT_URI = "/oauth2/jwks";
    private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

    /**
     * Asserts that jwkSet endpoint successfully responds with necessary keys.
     *
     * @throws Exception - mvc error;
     */
    @Test
    public void testJwkSet() throws Exception {
        super.mvc.perform(MockMvcRequestBuilders.get(authServerSettings.getJwkSetEndpoint()))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header()
                        .string(HttpHeaders.CACHE_CONTROL,
                                CoreMatchers.containsString("no-store")))
                .andExpect(MockMvcResultMatchers.header()
                        .string(HttpHeaders.PRAGMA,
                                CoreMatchers.containsString("no-cache")))
                .andExpect(MockMvcResultMatchers.jsonPath("$.keys").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.keys").isArray());
    }
}
