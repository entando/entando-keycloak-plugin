package org.entando.entando.keycloak.interceptor;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectorService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.web.common.annotation.RestAccessControl;
import org.entando.entando.web.common.exceptions.EntandoAuthorizationException;
import org.entando.entando.web.common.exceptions.EntandoTokenException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class KeycloakOauth2InterceptorTest {

    private static final String PERMISSION = "my-permission";

    @Mock private OpenIDConnectorService oidcService;
    @Mock private IAuthenticationProviderManager authenticationProviderManager;
    @Mock private IAuthorizationManager authorizationManager;

    @Mock private HttpServletRequest request;
    @Mock private HttpServletResponse response;
    @Mock private HttpSession session;
    @Mock private HandlerMethod method;
    @Mock private RestAccessControl accessControl;

    @Mock private ResponseEntity<AccessToken> resp;
    @Mock private AccessToken accessToken;
    @Mock private UserDetails userDetails;

    private KeycloakOauth2Interceptor interceptor;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        interceptor = new KeycloakOauth2Interceptor();
        interceptor.setOidcService(oidcService);
        interceptor.setAuthenticationProviderManager(authenticationProviderManager);
        interceptor.setAuthorizationManager(authorizationManager);

        when(resp.getBody()).thenReturn(accessToken);
        when(request.getSession()).thenReturn(session);
    }

    @Test
    public void testInterceptorOkWhenNoPermissionAnnotation() {
        when(method.getMethodAnnotation(same(RestAccessControl.class))).thenReturn(null);
        final boolean allowed = interceptor.preHandle(request, response, method);
        assertThat(allowed).isTrue();
    }

    @Test(expected = EntandoTokenException.class)
    public void testWithoutAuthorizationHeader() {
        mockAccessControl();
        when(request.getHeader(anyString())).thenReturn(null);
        interceptor.preHandle(request, response, method);

        verify(request, times(1)).getHeader(eq("Authorization"));
    }

    @Test(expected = EntandoTokenException.class)
    public void testWithInvalidAuthorizationHeader() {
        mockAccessControl();
        when(request.getHeader(eq("Authorization"))).thenReturn("I'm an invalid bearer token");
        interceptor.preHandle(request, response, method);

        verify(request, times(1)).getHeader(eq("Authorization"));
    }

    @Test
    public void testSuccess() throws ApsSystemException {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authenticationProviderManager.getUser(anyString())).thenReturn(userDetails);
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(true);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        when(oidcService.validateToken(eq("VALIDTOKEN"))).thenReturn(resp);

        final boolean allowed = interceptor.preHandle(request, response, method);
        assertThat(allowed).isTrue();

        verify(request, times(1)).getHeader(eq("Authorization"));
        verify(authenticationProviderManager, times(1)).getUser(eq("admin"));
        verify(authorizationManager, times(1)).isAuthOnPermission(same(userDetails), eq(PERMISSION));
        verify(session, times(1)).setAttribute(eq("user"), same(userDetails));
    }

    @Test(expected = EntandoAuthorizationException.class)
    public void testWithoutPermission() throws ApsSystemException {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authenticationProviderManager.getUser(anyString())).thenReturn(userDetails);
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(false);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        when(oidcService.validateToken(eq("VALIDTOKEN"))).thenReturn(resp);

        interceptor.preHandle(request, response, method);
    }

    @Test(expected = EntandoTokenException.class)
    public void testUserNotFound() throws ApsSystemException {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authenticationProviderManager.getUser(anyString())).thenThrow(new ApsSystemException(PERMISSION));
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(false);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        when(oidcService.validateToken(eq("VALIDTOKEN"))).thenReturn(resp);

        interceptor.preHandle(request, response, method);
    }

    @Test(expected = EntandoTokenException.class)
    public void testUnauthorizedValidation() {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.UNAUTHORIZED);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        when(oidcService.validateToken(eq("VALIDTOKEN"))).thenReturn(resp);

        interceptor.preHandle(request, response, method);
    }

    @Test(expected = EntandoTokenException.class)
    public void testInactiveToken() throws ApsSystemException {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(false);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authenticationProviderManager.getUser(anyString())).thenReturn(userDetails);
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(true);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        when(oidcService.validateToken(eq("VALIDTOKEN"))).thenReturn(resp);

        interceptor.preHandle(request, response, method);
    }

    private void mockAccessControl() {
        when(accessControl.permission()).thenReturn(PERMISSION);
        when(method.getMethodAnnotation(same(RestAccessControl.class))).thenReturn(accessControl);
    }

}
