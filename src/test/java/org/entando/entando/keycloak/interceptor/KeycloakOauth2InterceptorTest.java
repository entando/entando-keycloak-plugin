package org.entando.entando.keycloak.interceptor;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.servlet.security.UserAuthentication;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.web.common.annotation.RestAccessControl;
import org.entando.entando.web.common.exceptions.EntandoAuthorizationException;
import org.mockito.Mock;
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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
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

    @BeforeEach
    public void setUp() {
        interceptor = new KeycloakOauth2Interceptor();
        interceptor.setAuthorizationManager(authorizationManager);
        SecurityContextHolder.getContext().setAuthentication(null);
        Mockito.lenient().when(resp.getBody()).thenReturn(accessToken);
        Mockito.lenient().when(request.getSession()).thenReturn(session);
    }

    @Test
    public void testInterceptorOkWhenNoPermissionAnnotation() {
        when(method.getMethodAnnotation(same(RestAccessControl.class))).thenReturn(null);
        final boolean allowed = interceptor.preHandle(request, response, method);
        assertThat(allowed).isTrue();
    }

    @Test
    public void testWithoutAuthorizationHeader() {
        mockAccessControl();
        when(request.getHeader(anyString())).thenReturn(null);
        Assertions.assertThrows(EntandoAuthorizationException.class, () -> {
            interceptor.preHandle(request, response, method);
        });
        verify(request, times(1)).getHeader(eq("Authorization"));
    }

    @Test
    public void testWithInvalidAuthorizationHeader() {
        mockAccessControl();
        when(request.getHeader(eq("Authorization"))).thenReturn("I'm an invalid bearer token");
        Assertions.assertThrows(EntandoAuthorizationException.class, () -> {
            interceptor.preHandle(request, response, method);
        });
        verify(request, times(1)).getHeader(eq("Authorization"));
    }

    @Test
    public void testSuccess() {
        mockAccessControl();
        Mockito.lenient().when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        Mockito.lenient().when(accessToken.isActive()).thenReturn(true);
        Mockito.lenient().when(accessToken.getUsername()).thenReturn("admin");
        when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(true);
        SecurityContextHolder.getContext().setAuthentication(new UserAuthentication(userDetails));

        Mockito.lenient().when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");

        final boolean allowed = interceptor.preHandle(request, response, method);
        assertThat(allowed).isTrue();

        verify(authorizationManager, times(1)).isAuthOnPermission(same(userDetails), eq(PERMISSION[0]));

        SecurityContextHolder.getContext().setAuthentication(null);
    }

    @Test
    public void testWithoutPermission() {
        mockAccessControl();
        Mockito.lenient().when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        Mockito.lenient().when(accessToken.isActive()).thenReturn(true);
        Mockito.lenient().when(accessToken.getUsername()).thenReturn("admin");
        Mockito.lenient().when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(false);
        Mockito.lenient().when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        Assertions.assertThrows(EntandoAuthorizationException.class, () -> {
            interceptor.preHandle(request, response, method);
        });
    }

    @Test
    public void testUserNotFound() {
        mockAccessControl();
        Mockito.lenient().when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        Mockito.lenient().when(accessToken.isActive()).thenReturn(true);
        Mockito.lenient().when(accessToken.getUsername()).thenReturn("admin");
        Mockito.lenient().when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(false);
        Mockito.lenient().when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        Assertions.assertThrows(EntandoAuthorizationException.class, () -> {
            interceptor.preHandle(request, response, method);
        });
    }

    @Test
    public void testUnauthorizedValidation() {
        mockAccessControl();
        Mockito.lenient().when(resp.getStatusCode()).thenReturn(HttpStatus.UNAUTHORIZED);
        Mockito.lenient().when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        Assertions.assertThrows(EntandoAuthorizationException.class, () -> {
            interceptor.preHandle(request, response, method);
        });
    }

    @Test
    public void testInactiveToken() {
        mockAccessControl();
        Mockito.lenient().when(resp.getStatusCode()).thenReturn(HttpStatus.OK);
        Mockito.lenient().when(accessToken.isActive()).thenReturn(false);
        Mockito.lenient().when(accessToken.getUsername()).thenReturn("admin");
        Mockito.lenient().when(authorizationManager.isAuthOnPermission(any(UserDetails.class), anyString())).thenReturn(true);
        Mockito.lenient().when(request.getHeader(eq("Authorization"))).thenReturn("Bearer VALIDTOKEN");
        Assertions.assertThrows(EntandoAuthorizationException.class, () -> {
            interceptor.preHandle(request, response, method);
        });
    }

    private void mockAccessControl() {
        when(accessControl.permission()).thenReturn(PERMISSION);
        when(method.getMethodAnnotation(same(RestAccessControl.class))).thenReturn(accessControl);
    }

}
