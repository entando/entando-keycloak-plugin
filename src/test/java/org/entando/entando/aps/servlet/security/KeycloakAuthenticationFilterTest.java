package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.services.role.Permission;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.User;
import org.entando.entando.assertionHelper.KeycloakAuthenticationFilterAssertionHelper;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.TokenRoles;
import org.entando.entando.mockhelper.UserMockHelper;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;

public class KeycloakAuthenticationFilterTest {

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
    private AccessToken accessToken;
    @Mock
    private HttpServletRequest request;
    @Mock
    private HttpServletResponse response;
    @Mock
    private HttpSession session;
    @Mock
    private Map<String, TokenRoles> resourceAccess;
    @Mock
    private TokenRoles tokenRoles;

    @InjectMocks
    private KeycloakAuthenticationFilter keycloakAuthenticationFilter;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void attemptAuthenticationWithSuperuserPermissionShouldAddKeycloakAuthentication() throws Exception {

        List<String> expected = Collections.singletonList(Permission.SUPERUSER);

        // multiple permissions
        this.mockForAttemptAuthenticationTest();
        List<String> permissionList = Arrays.asList(Permission.ENTER_BACKEND, Permission.SUPERUSER);
        when(tokenRoles.getRoles()).thenReturn(permissionList);
        User actual = (User) keycloakAuthenticationFilter.attemptAuthentication(request, response).getPrincipal();
        KeycloakAuthenticationFilterAssertionHelper.assertKeycloakAuthorization(actual.getAuthorizations().get(0), expected);

        // single permission
        this.mockForAttemptAuthenticationTest();
        permissionList = Collections.singletonList(Permission.SUPERUSER);
        when(tokenRoles.getRoles()).thenReturn(permissionList);
        actual = (User) keycloakAuthenticationFilter.attemptAuthentication(request, response).getPrincipal();
        KeycloakAuthenticationFilterAssertionHelper.assertKeycloakAuthorization(actual.getAuthorizations().get(0), expected);
    }


    @Test
    public void attemptAuthenticationWithoutKeycloakPermissionShouldReturnEmptyAuthorizationList() throws Exception {

        this.mockForAttemptAuthenticationTest();

        List<String> permissionList = Collections.singletonList(Permission.ENTER_BACKEND);
        when(tokenRoles.getRoles()).thenReturn(permissionList);
        User actual = (User) keycloakAuthenticationFilter.attemptAuthentication(request, response).getPrincipal();

        assertEquals(0, actual.getAuthorizations().size());
    }


    @Test
    public void attemptAuthenticationWithEmptyOrNullPermissionListShouldReturnEmptyAuthorizationList() throws Exception {

        this.mockForAttemptAuthenticationTest();

        when(tokenRoles.getRoles()).thenReturn(null);
        User actual = (User) keycloakAuthenticationFilter.attemptAuthentication(request, response).getPrincipal();
        assertEquals(0, actual.getAuthorizations().size());

        when(tokenRoles.getRoles()).thenReturn(new ArrayList<>());
        actual = (User) keycloakAuthenticationFilter.attemptAuthentication(request, response).getPrincipal();
        assertEquals(0, actual.getAuthorizations().size());
    }



    private void mockForAttemptAuthenticationTest() throws Exception {

        when(request.getHeader("Authorization")).thenReturn("Bearer jwt");
        when(request.getSession()).thenReturn(session);
        doNothing().when(session).setAttribute(anyString(), any());
        when(oidcService.validateToken(anyString())).thenReturn(new ResponseEntity<>(accessToken, HttpStatus.OK));
        when(accessToken.isActive()).thenReturn(true);
        when(accessToken.getUsername()).thenReturn(UserMockHelper.USERNAME);
        when(authenticationProviderManager.getUser(anyString())).thenReturn(UserMockHelper.mockUser());
        when(accessToken.getResourceAccess()).thenReturn(resourceAccess);
        when(configuration.getClientId()).thenReturn("clientId");
        when(resourceAccess.get(anyString())).thenReturn(tokenRoles);
    }
}