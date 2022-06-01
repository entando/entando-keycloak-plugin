package org.entando.entando.aps.servlet.security;

import static com.jayway.jsonpath.matchers.JsonPathMatchers.hasJsonPath;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.xml.HasXPath.hasXPath;

import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import java.io.ByteArrayInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilderFactory;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.w3c.dom.Element;

@ExtendWith(MockitoExtension.class)
class KeycloakLegacyApiAuthenticationFilterTest {

    @Mock
    private KeycloakConfiguration configuration;
    @Mock
    private IUserManager userManager;
    @Mock
    private OpenIDConnectService oidcService;
    @Mock
    private IAuthenticationProviderManager authenticationProviderManager;
    @Mock
    private KeycloakAuthorizationManager keycloakGroupManager;
    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private KeycloakLegacyApiAuthenticationFilter keycloakLegacyApiAuthenticationFilter;

    @Test
    void testLegacyApiAuthenticationFailureXml() throws Exception {

        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException exception = new NonceExpiredException("Invalid or expired token");

        keycloakLegacyApiAuthenticationFilter.onAuthenticationFailure(request, response, exception);

        String content = response.getContentAsString();
        Assertions.assertTrue(content.contains("<?xml version='1.0' encoding='UTF-8'?>"));

        Element xml =  DocumentBuilderFactory
                .newInstance()
                .newDocumentBuilder()
                .parse(new ByteArrayInputStream(response.getContentAsByteArray()))
                .getDocumentElement();

        assertThat(xml, hasXPath("/response/result", is("FAILURE")));
        assertThat(xml, hasXPath("/response/errors/error/code", is("API_AUTHORIZATION_REQUIRED")));
        assertThat(xml, hasXPath("/response/errors/error/message", is("Invalid or expired token")));
        assertThat(xml, hasXPath("/response/errors/error/status", is("UNAUTHORIZED")));
    }

    @Test
    void testLegacyApiAuthenticationFailureJson() throws Exception {

        Mockito.when(request.getHeader("Accept")).thenReturn("application/json");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException exception = new NonceExpiredException("Invalid or expired token");

        keycloakLegacyApiAuthenticationFilter.onAuthenticationFailure(request, response, exception);

        String content = response.getContentAsString();

        assertThat(content, hasJsonPath("$.response.result", is("FAILURE")));
        assertThat(content, hasJsonPath("$.response.errors.error.code", is("API_AUTHORIZATION_REQUIRED")));
        assertThat(content, hasJsonPath("$.response.errors.error.message", is("Invalid or expired token")));
        assertThat(content, hasJsonPath("$.response.errors.error.status", is("UNAUTHORIZED")));
    }
}
