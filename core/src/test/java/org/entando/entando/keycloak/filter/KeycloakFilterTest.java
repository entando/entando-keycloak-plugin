package org.entando.entando.keycloak.filter;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.entando.entando.web.common.exceptions.EntandoTokenException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class KeycloakFilterTest {

    @Mock private KeycloakConfiguration configuration;
    @Mock private OpenIDConnectService oidcService;
    @Mock private IAuthenticationProviderManager providerManager;
    @Mock private KeycloakAuthorizationManager keycloakGroupManager;
    @Mock private IUserManager userManager;

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession session;
    @Mock private FilterChain filterChain;

    @Mock private ResponseEntity<AccessToken> accessTokenResponse;
    @Mock private ResponseEntity<AuthResponse> authResponse;
    @Mock private ResponseEntity<AuthResponse> refreshResponse;
    @Mock private UserDetails userDetails;

    @Mock private AccessToken accessToken;
    @Mock private AuthResponse auth;
    @Mock private AuthResponse refreshAuth;

    private KeycloakFilter keycloakFilter;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);

        when(configuration.getAuthUrl()).thenReturn("https://dev.entando.org/auth");
        when(configuration.getRealm()).thenReturn("entando");
        when(configuration.getClientId()).thenReturn("entando-app");
        when(configuration.getPublicClientId()).thenReturn("entando-web");
        when(configuration.getClientSecret()).thenReturn("a76d5398-fc2f-4859-bf57-f043a89eea70");

        keycloakFilter = new KeycloakFilter(configuration, oidcService, providerManager, keycloakGroupManager, userManager);
        when(request.getSession()).thenReturn(session);
    }

    @Test
    public void testConfigurationDisabled() throws IOException, ServletException {
        when(configuration.isEnabled()).thenReturn(false);
        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void testAuthenticationFlow() throws IOException, ServletException, ApsSystemException {
        final String requestRedirect = "https://dev.entando.org/entando-app/main.html";
        final String loginEndpoint = "https://dev.entando.org/entando-app/do/login";

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn("/do/login");
        when(request.getRequestURL()).thenReturn(new StringBuffer(loginEndpoint));
        when(request.getParameter(eq("redirectTo"))).thenReturn(requestRedirect);

        final String redirect = "http://dev.entando.org/auth/realms/entando/protocol/openid-connect/auth";
        when(oidcService.getRedirectUrl(any(), any())).thenReturn(redirect);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(0)).doFilter(any(), any());
        verify(response, times(1)).sendRedirect(redirect);
        verify(oidcService, times(1)).getRedirectUrl(eq(loginEndpoint), anyString());
        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_REDIRECT), eq("/main.html"));
        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_STATE), anyString());

        reset(session, oidcService, filterChain, response, request);

        final String state = "0ca97afd-f0b0-4860-820a-b7cd1414f69c";
        final String authorizationCode = "the-authorization-code-from-keycloak";

        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_STATE))).thenReturn(state);
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_REDIRECT))).thenReturn("/main.html");

        when(request.getServletPath()).thenReturn("/do/login");
        when(request.getParameter(eq("code"))).thenReturn(authorizationCode);
        when(request.getParameter(eq("state"))).thenReturn(state);
        when(request.getRequestURL()).thenReturn(new StringBuffer(loginEndpoint));
        when(request.getContextPath()).thenReturn("https://dev.entando.org/entando-app");

        when(oidcService.requestToken(anyString(), anyString())).thenReturn(authResponse);
        when(authResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(authResponse.getBody()).thenReturn(auth);
        when(auth.getAccessToken()).thenReturn("access-token-over-here");
        when(auth.getRefreshToken()).thenReturn("refresh-token-over-here");

        when(oidcService.validateToken(anyString())).thenReturn(accessTokenResponse);
        when(accessTokenResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessTokenResponse.getBody()).thenReturn(accessToken);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(providerManager.getUser(anyString())).thenReturn(userDetails);

        keycloakFilter.doFilter(request, response, filterChain);

        verify(oidcService, times(1)).requestToken(eq(authorizationCode), eq(loginEndpoint));
        verify(oidcService, times(1)).validateToken(eq("access-token-over-here"));
        verify(keycloakGroupManager, times(1)).processNewUser(same(userDetails));

        verify(session, times(1)).setAttribute(eq("user"), same(userDetails));
        verify(session, times(1)).setAttribute(eq(SystemConstants.SESSIONPARAM_CURRENT_USER), same(userDetails));
        verify(response, times(1)).sendRedirect(eq("https://dev.entando.org/entando-app/main.html"));
        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_REDIRECT), isNull());
    }

    @Test(expected = EntandoTokenException.class)
    public void testAuthenticationFlowWithError() throws IOException, ServletException {
        final String loginEndpoint = "https://dev.entando.org/entando-app/do/login";
        final String state = "0ca97afd-f0b0-4860-820a-b7cd1414f69c";
        final String authorizationCode = "the-authorization-code-from-keycloak";

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_STATE))).thenReturn(state);
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_REDIRECT))).thenReturn("/main.html");

        // error provided by keycloak
        when(request.getParameter(eq("error"))).thenReturn("invalid_code");
        when(request.getParameter(eq("error_description"))).thenReturn("Any description provided by keycloak");

        when(request.getServletPath()).thenReturn("/do/login");
        when(request.getParameter(eq("code"))).thenReturn(authorizationCode);
        when(request.getParameter(eq("state"))).thenReturn(state);
        when(request.getRequestURL()).thenReturn(new StringBuffer(loginEndpoint));
        when(request.getContextPath()).thenReturn("https://dev.entando.org/entando-app");

        when(oidcService.requestToken(anyString(), anyString())).thenReturn(authResponse);
        when(authResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(authResponse.getBody()).thenReturn(auth);
        when(auth.getAccessToken()).thenReturn("access-token-over-here");
        when(auth.getRefreshToken()).thenReturn("refresh-token-over-here");

        keycloakFilter.doFilter(request, response, filterChain);
    }

    @Test
    public void testAuthenticationWithInvalidAuthCode() throws IOException, ServletException {
        final String loginEndpoint = "https://dev.entando.org/entando-app/do/login";
        final String state = "0ca97afd-f0b0-4860-820a-b7cd1414f69c";
        final String authorizationCode = "the-authorization-code-from-keycloak";

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getSession()).thenReturn(session);
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_STATE))).thenReturn(state);
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_REDIRECT))).thenReturn("/main.html");

        when(request.getServletPath()).thenReturn("/do/login");
        when(request.getParameter(eq("code"))).thenReturn(authorizationCode);
        when(request.getParameter(eq("state"))).thenReturn(state);
        when(request.getRequestURL()).thenReturn(new StringBuffer(loginEndpoint));
        when(request.getContextPath()).thenReturn("https://dev.entando.org/entando-app");

        final HttpClientErrorException exception = Mockito.mock(HttpClientErrorException.class);
        when(exception.getResponseBodyAsString()).thenReturn("{ \"error\": \"invalid_grant\", \"error_description\": \"Refresh token expired\" }");
        when(exception.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);

        when(oidcService.requestToken(anyString(), anyString())).thenThrow(exception);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(response, times(1)).sendRedirect(eq("https://dev.entando.org/entando-app/main.html"));
    }

    @Test(expected = EntandoTokenException.class)
    public void testAuthenticationWithInvalidRedirectURL() throws IOException, ServletException {
        final String requestRedirect = "https://not.authorized.url";
        final String loginEndpoint = "https://dev.entando.org/entando-app/do/login";

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn("/do/login");
        when(request.getRequestURL()).thenReturn(new StringBuffer(loginEndpoint));
        when(request.getParameter(eq("redirectTo"))).thenReturn(requestRedirect);

        final String redirect = "http://dev.entando.org/auth/realms/entando/protocol/openid-connect/auth";
        when(oidcService.getRedirectUrl(any(), any())).thenReturn(redirect);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(0)).doFilter(any(), any());
        verify(response, times(1)).sendRedirect(redirect);
    }

    @Test
    public void testLogout() throws IOException, ServletException {
        final String loginEndpoint = "https://dev.entando.org/entando-app/do/logout.action";

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn("/do/logout.action");
        when(request.getRequestURL()).thenReturn(new StringBuffer(loginEndpoint));

        final String redirect = "http://dev.entando.org/auth/realms/entando/protocol/openid-connect/logout";
        when(oidcService.getLogoutUrl(any())).thenReturn(redirect);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(0)).doFilter(any(), any());
        verify(response, times(1)).sendRedirect(redirect);
        verify(session, times(1)).invalidate();
    }

    @Test
    public void testNormalFlow() throws IOException, ServletException {
        final String endpoint = "https://dev.entando.org/entando-app/do/main";

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn("/do/main");
        when(request.getRequestURL()).thenReturn(new StringBuffer(endpoint));

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(1)).doFilter(any(), any());
    }

    @Test
    public void testTokenValidation() throws IOException, ServletException {
        final String path = "/do/main";
        final String endpoint = "https://dev.entando.org/entando-app" + path;

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn(path);
        when(request.getRequestURL()).thenReturn(new StringBuffer(endpoint));

        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_ACCESS_TOKEN))).thenReturn("access-token-over-here");
        when(oidcService.validateToken(anyString())).thenReturn(accessTokenResponse);
        when(accessTokenResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessTokenResponse.getBody()).thenReturn(accessToken);
        when(accessToken.isActive()).thenReturn(false);

        when(userManager.getGuestUser()).thenReturn(userDetails);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(1)).doFilter(any(), any());
        verify(userManager, times(1)).getGuestUser();
        verify(session, times(1)).setAttribute(eq("user"), same(userDetails));
        verify(session, times(1)).setAttribute(eq(SystemConstants.SESSIONPARAM_CURRENT_USER), same(userDetails));
        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_ACCESS_TOKEN), isNull());
    }

    @Test
    public void testTokenValidationAndRefreshToken() throws IOException, ServletException {
        final String path = "/do/main";
        final String endpoint = "https://dev.entando.org/entando-app" + path;

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn(path);
        when(request.getRequestURL()).thenReturn(new StringBuffer(endpoint));

        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_ACCESS_TOKEN))).thenReturn("access-token-over-here");
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_REFRESH_TOKEN))).thenReturn("refresh-token-over-here");

        when(oidcService.validateToken(anyString())).thenReturn(accessTokenResponse);
        when(accessTokenResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessTokenResponse.getBody()).thenReturn(accessToken);
        when(accessToken.isActive()).thenReturn(false);

        final String newAccessToken = "a-new-access-token-over-here";
        final String newRefreshToken = "a-new-refresh-token-over-here";

        when(oidcService.refreshToken(anyString())).thenReturn(refreshResponse);
        when(refreshResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(refreshResponse.getBody()).thenReturn(refreshAuth);
        when(refreshAuth.getAccessToken()).thenReturn(newAccessToken);
        when(refreshAuth.getRefreshToken()).thenReturn(newRefreshToken);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(1)).doFilter(any(), any());

        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_ACCESS_TOKEN), eq(newAccessToken));
        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_REFRESH_TOKEN), eq(newRefreshToken));
    }

    @Test
    public void testTokenValidationWithTokenAndRefreshExpired() throws IOException, ServletException {
        final String path = "/do/main";
        final String endpoint = "https://dev.entando.org/entando-app" + path;

        when(configuration.isEnabled()).thenReturn(true);
        when(request.getServletPath()).thenReturn(path);
        when(request.getRequestURL()).thenReturn(new StringBuffer(endpoint));

        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_ACCESS_TOKEN))).thenReturn("access-token-over-here");
        when(session.getAttribute(eq(KeycloakFilter.SESSION_PARAM_REFRESH_TOKEN))).thenReturn("refresh-token-over-here");
        when(oidcService.validateToken(anyString())).thenReturn(accessTokenResponse);
        when(accessTokenResponse.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessTokenResponse.getBody()).thenReturn(accessToken);
        when(accessToken.isActive()).thenReturn(false);

        final HttpClientErrorException exception = Mockito.mock(HttpClientErrorException.class);
        when(exception.getResponseBodyAsString()).thenReturn("{ \"error\": \"invalid_grant\", \"error_description\": \"Refresh token expired\" }");
        when(exception.getStatusCode()).thenReturn(HttpStatus.BAD_REQUEST);
        when(oidcService.refreshToken(anyString())).thenThrow(exception);

        when(userManager.getGuestUser()).thenReturn(userDetails);

        keycloakFilter.doFilter(request, response, filterChain);
        verify(filterChain, times(1)).doFilter(any(), any());
        verify(userManager, times(1)).getGuestUser();
        verify(session, times(1)).setAttribute(eq("user"), same(userDetails));
        verify(session, times(1)).setAttribute(eq(SystemConstants.SESSIONPARAM_CURRENT_USER), same(userDetails));
        verify(session, times(1)).setAttribute(eq(KeycloakFilter.SESSION_PARAM_ACCESS_TOKEN), isNull());
    }

}
