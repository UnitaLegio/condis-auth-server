package com.unitalegio.sso.web;

import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.HtmlButton;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.unitalegio.sso.web.configuration.DefaultTestConfiguration;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * @since 12.2022
 * <p>
 * Default user authentication behaviour tests.
 * Largely copied from spring-authorization-server samples tests, and adopted.
 */
public class DefaultAuthorizationIntegrationTests extends AbstractOAuth2IntegrationTest {

    private final int serverPort;

    private final String REDIRECT_URI;

    //    private final String REDIRECT_URI;

    private final String AUTHORIZATION_REQUEST;

    public DefaultAuthorizationIntegrationTests(@LocalServerPort int serverPort) {
        this.serverPort = serverPort;
        REDIRECT_URI = String.format(
                "http://localhost:%d/login/oauth2/code/test-client-oids",
                this.serverPort);
        AUTHORIZATION_REQUEST = UriComponentsBuilder
                .fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", "test-client")
                .queryParam("scope", "openid")
                .queryParam("state", "some-state")
                .queryParam("redirect_uri", REDIRECT_URI)
                .toUriString();
    }

    @Autowired
    private WebClient webClient;

    @BeforeEach
    public void setUp() {
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(true);
        this.webClient.getOptions().setRedirectEnabled(true);
        // Logout before
        this.webClient.getCookieManager().clearCookies();
    }

    /**
     * Tests if 404 returns correctly after successful user's login action.
     * It is needed, because there is not some index page at this sso server;
     *
     * @throws IOException, when occurs something about dark magic in HtmlUnit library or in its dependencies;
     */
    @Test
    public void whenLoginSuccessfulThenDisplayNotFoundError() throws IOException {
        HtmlPage page = this.webClient.getPage("/login");
        assertLoginPage(page);

        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        WebResponse singInResponse =
                signIn(page, DefaultTestConfiguration.USERNAME_1, DefaultTestConfiguration.PASSWORD_1)
                        .getWebResponse();
        Assertions.assertEquals(HttpStatus.NOT_FOUND.value(), singInResponse.getStatusCode());

    }

    /**
     * Tests if it gets error of 'Bad credentials' when credentials are wrong;
     *
     * @throws IOException, when occurs something about dark magic in HtmlUnit library or in its dependencies;
     */
    @Test
    public void whenLoginFailsThenDisplayBadCredentials() throws IOException {
        HtmlPage loginPage = this.webClient.getPage("/login");

        HtmlPage loginErrorPage = signIn(loginPage, DefaultTestConfiguration.USERNAME_1, "wrongPassword");

        HtmlElement alert = loginErrorPage.querySelector("div[role=\"alert\"]");

        Assertions.assertNotNull(alert);
        Assertions.assertEquals("Bad credentials", alert.getTextContent());
    }

    /**
     * Tests redirecting to login page when requesting token without authentication;
     *
     * @throws IOException, when occurs something about dark magic in HtmlUnit library or in its dependencies;
     */
    @Test
    public void whenNotLoggedInAndRequestingTokenThenRedirectsToLogin() throws IOException {
        HtmlPage page = this.webClient.getPage(String.format(AUTHORIZATION_REQUEST, this.serverPort));
        assertLoginPage(page);
    }

    /**
     * Tests redirecting to client application with code after successful login;
     *
     * @throws IOException, when occurs something about dark magic in HtmlUnit library or in its dependencies;
     */
    @Test
    public void whenNotLoggedInAndRequestingTokenThenRedirectsToClientApplication() throws IOException {
        this.webClient.getOptions().setThrowExceptionOnFailingStatusCode(false);
        this.webClient.getOptions().setRedirectEnabled(false);

        signIn(this.webClient.getPage("/login"),
                DefaultTestConfiguration.USERNAME_1,
                DefaultTestConfiguration.PASSWORD_1
        );

        // Request token
        WebResponse response = this.webClient
                .getPage(AUTHORIZATION_REQUEST)
                .getWebResponse();

        Assertions.assertEquals(HttpStatus.MOVED_PERMANENTLY.value(), response.getStatusCode());
        String location = response.getResponseHeaderValue("location");
        Assertions.assertTrue(location.startsWith(REDIRECT_URI));
        Assertions.assertTrue(location.contains("code="));
    }

    /**
     * Proceed user authentication via login form;
     */
    @SuppressWarnings("SameParameterValue")
    private static <P extends Page> P signIn(HtmlPage page, String username, String password) throws IOException {
        HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
        HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
        HtmlButton signInButton = page.querySelector("button");

        usernameInput.type(username);
        passwordInput.type(password);

        return signInButton.click();
    }

    /**
     * Asserts that page is really login page;
     */
    private void assertLoginPage(HtmlPage page) {
        Assertions.assertTrue(page.getUrl().toString().endsWith("/login"));

        HtmlInput usernameInput = page.querySelector("input[name=\"username\"]");
        HtmlInput passwordInput = page.querySelector("input[name=\"password\"]");
        HtmlButton signInButton = page.querySelector("button");

        Assertions.assertNotNull(usernameInput);
        Assertions.assertNotNull(passwordInput);
        Assertions.assertEquals("Sign in", signInButton.getTextContent());
    }
}
