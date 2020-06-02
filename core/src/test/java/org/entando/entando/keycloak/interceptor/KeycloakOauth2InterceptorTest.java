package org.entando.entando.keycloak.interceptor;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.servlet.security.UserAuthentication;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.web.common.annotation.RestAccessControl;
import org.entando.entando.web.common.exceptions.EntandoAuthorizationException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class KeycloakOauth2InterceptorTest {

    private static final String[] PERMISSION = {"my-permission"};

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

    @Test(expected = EntandoAuthorizationException.class)
    public void testWithoutAuthorizationHeader() {
        mockAccessControl();
        when(request.getHeader(anyString())).thenReturn(null);
        interceptor.preHandle(request, response, method);

        verify(request, times(1)).getHeader(eq("Authorization"));
    }

    @Test(expected = EntandoAuthorizationException.class)
    public void testWithInvalidAuthorizationHeader() {
        mockAccessControl();
        when(request.getHeader(eq("Authorization"))).thenReturn("I'm an invalid bearer token");
        interceptor.preHandle(request, response, method);

        verify(request, times(1)).getHeader(eq("Authorization"));
    }

    @Test
    public void testSuccess() {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(new UserAuthentication(userDetails));

        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");

        final boolean allowed = interceptor.preHandle(request, response, method);
        assertThat(allowed).isTrue();

        verify(authorizationManager, times(1)).isAuthOnPermission(same(userDetails), eq(PERMISSION[0]));

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Test(expected = EntandoAuthorizationException.class)
    public void testWithoutPermission() {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(false);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");

        interceptor.preHandle(request, response, method);
    }

    @Test(expected = EntandoAuthorizationException.class)
    public void testUserNotFound() {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(false);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");

        interceptor.preHandle(request, response, method);
    }

    @Test(expected = EntandoAuthorizationException.class)
    public void testUnauthorizedValidation() {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.UNAUTHORIZED);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");

        interceptor.preHandle(request, response, method);
    }

    @Test(expected = EntandoAuthorizationException.class)
    public void testInactiveToken() {
        mockAccessControl();
        when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        when(accessToken.isActive()).thenReturn(false);
        when(accessToken.getUsername()).thenReturn("admin");
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(true);
        when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");

        interceptor.preHandle(request, response, method);
    }

    private void mockAccessControl() {
        when(accessControl.permission()).thenReturn(PERMISSION);
        when(method.getMethodAnnotation(same(RestAccessControl.class))).thenReturn(accessControl);
    }

}
