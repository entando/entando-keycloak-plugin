package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.group.Group;
import com.agiletec.aps.system.services.role.Role;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.system.exception.RestServerError;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.aps.system.services.user.model.UserAuthorityDto;
import org.entando.entando.aps.system.services.user.model.UserDto;
import org.entando.entando.keycloak.KeycloakTestConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectorService;
import org.entando.entando.web.common.model.PagedMetadata;
import org.entando.entando.web.common.model.RestListRequest;
import org.entando.entando.web.user.model.UserAuthoritiesRequest;
import org.entando.entando.web.user.model.UserAuthority;
import org.entando.entando.web.user.model.UserPasswordRequest;
import org.entando.entando.web.user.model.UserRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.*;

public class UserServiceIntegratedTest {

    private static final String USERNAME = "aredfarear";

    @Mock private IAuthorizationManager authorizationManager;

    private UserService userService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        final KeycloakConfiguration configuration = KeycloakTestConfiguration.getConfiguration();
        final KeycloakService keycloakService = new KeycloakService(configuration);
        final OpenIDConnectorService oidcService = new OpenIDConnectorService(configuration);
        userService = new UserService(authorizationManager, keycloakService, oidcService);

        KeycloakTestConfiguration.deleteUsers();
    }

    @Test
    public void testUsers() {
        assertThat(userService.getUsers()).isEmpty();

        userService.addUser(activeUser());

        List<UserDetails> users = userService.getUsers();
        assertThat(users).hasSize(1);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("username", USERNAME);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("disabled", false);

        assertThat(userService.getUsernames()).hasSize(1).contains(USERNAME);
        assertThat(userService.searchUsernames(USERNAME)).hasSize(1).contains(USERNAME);
        assertThat(userService.searchUsernames("")).hasSize(1).contains(USERNAME);
        assertThat(userService.searchUsernames(null)).hasSize(1).contains(USERNAME);
        assertThat(userService.searchUsernames("aa")).isEmpty();

        users = userService.searchUsers(USERNAME);
        assertThat(users).hasSize(1);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("username", USERNAME);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("disabled", false);

        users = userService.searchUsers("");
        assertThat(users).hasSize(1);

        assertThat(userService.searchUsers("aa")).isEmpty();

        userService.removeUser(USERNAME);
        assertThat(userService.getUsers()).isEmpty();
        assertThat(userService.getUsernames()).isEmpty();
        assertThat(userService.searchUsers(USERNAME)).isEmpty();
        assertThat(userService.searchUsernames(USERNAME)).isEmpty();
    }

    @Test
    public void testGetUser() {
        userService.addUser(activeUser());
        final UserDto user = userService.getUser(USERNAME);
        assertThat(user).hasFieldOrPropertyWithValue("username", USERNAME)
                .hasFieldOrPropertyWithValue("status", IUserService.STATUS_ACTIVE)
                .hasFieldOrPropertyWithValue("accountNotExpired", true)
                .hasFieldOrPropertyWithValue("credentialsNotExpired", false);
    }

    @Test
    public void testGetUserAuthorities() throws ApsSystemException {
        userService.addUser(activeUser());
        when(authorizationManager.getUserAuthorizations(anyString())).thenReturn(authorizations());

        final List<UserAuthorityDto> authorities = userService.getUserAuthorities(USERNAME);
        assertThat(authorities).hasSize(1);
        assertThat(authorities.get(0)).hasFieldOrPropertyWithValue("group", "administrators");
        assertThat(authorities.get(0)).hasFieldOrPropertyWithValue("role", "admin");

        verify(authorizationManager, times(1)).getUserAuthorizations(eq(USERNAME));
    }

    @Test
    public void testGetUsers() {
        userService.addUser(activeUser());
        final RestListRequest request = new RestListRequest();
        final PagedMetadata<UserDto> users = userService.getUsers(request, null);
        assertThat(users.getBody()).hasSize(1);
        assertThat(users.getBody().get(0)).hasFieldOrPropertyWithValue("username", USERNAME)
                .hasFieldOrPropertyWithValue("status", IUserService.STATUS_ACTIVE)
                .hasFieldOrPropertyWithValue("accountNotExpired", true)
                .hasFieldOrPropertyWithValue("credentialsNotExpired", false);
    }

    @Test
    public void testAddUserAndAuthenticate() {
        userService.addUser(activeUser());

        UserDetails user = userService.getUser(USERNAME, "qwer1234");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isFalse();

        assertThat(userService.getUser(USERNAME, "1234qwer")).isNull();

        userService.updateUserPassword(USERNAME, "4321rewq");
        user = userService.getUser(USERNAME, "4321rewq");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isTrue();
    }

    @Test
    public void testUserUpdatePassword() {
        userService.addUser(activeUser());

        UserDetails user = userService.getUser(USERNAME, "qwer1234");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isFalse();

        final UserPasswordRequest request = new UserPasswordRequest();
        request.setOldPassword("qwer1234");
        request.setNewPassword("1234qwer");
        request.setUsername(USERNAME);
        userService.updateUserPassword(request);

        user = userService.getUser(USERNAME, "1234qwer");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isTrue();
    }

    @Test
    public void testUserUpdate() {
        final UserRequest request = activeUser();
        userService.addUser(request);
        assertThat(userService.getUser(USERNAME, "qwer1234")).isNotNull();

        request.setPassword("1234qwer");
        userService.updateUser(request);
        assertThat(userService.getUser(USERNAME, "1234qwer")).isNotNull();

        request.setStatus(IUserService.STATUS_DISABLED);
        userService.updateUser(request);
        assertThat(userService.getUser(USERNAME, "1234qwer")).isNull();
    }

    @Test
    public void testAddUserAuthorizations() throws ApsSystemException {
        userService.addUser(activeUser());

        final String group = "administrators";
        final String role = "admin";
        final UserAuthority authority = authority(group, role);
        final UserAuthoritiesRequest request = authorities(authority);
        when(authorizationManager.isAuthOnGroupAndRole(isA(UserDetails.class), anyString(), anyString(), isA(Boolean.class))).thenReturn(false);
        userService.addUserAuthorities(USERNAME, request);

        verify(authorizationManager, times(1)).isAuthOnGroupAndRole(isA(UserDetails.class), eq(group), eq(role), eq(true));
        verify(authorizationManager, times(1)).addUserAuthorization(eq(USERNAME), eq(group), eq(role));
    }

    @Test
    public void testUpdateUserAuthorizations() throws ApsSystemException {
        userService.addUser(activeUser());

        final String group = "administrators";
        final String role = "admin";
        final UserAuthority authority = authority(group, role);
        final UserAuthoritiesRequest request = authorities(authority);
        when(authorizationManager.isAuthOnGroupAndRole(isA(UserDetails.class), anyString(), anyString(), isA(Boolean.class))).thenReturn(false);
        userService.updateUserAuthorities(USERNAME, request);

        verify(authorizationManager, times(1)).deleteUserAuthorizations(eq(USERNAME));
        verify(authorizationManager, times(1)).isAuthOnGroupAndRole(isA(UserDetails.class), eq(group), eq(role), eq(true));
        verify(authorizationManager, times(1)).addUserAuthorization(eq(USERNAME), eq(group), eq(role));
    }

    @Test
    public void testDeleteUserAuthorizations() throws ApsSystemException {
        userService.addUser(activeUser());

        when(authorizationManager.isAuthOnGroupAndRole(isA(UserDetails.class), anyString(), anyString(), isA(Boolean.class))).thenReturn(false);
        userService.deleteUserAuthorities(USERNAME);

        verify(authorizationManager, times(1)).deleteUserAuthorizations(eq(USERNAME));
    }

    @Test
    public void testAddDisabledUserAndAuthenticate() {
        userService.addUser(disabledUser());
        assertThat(userService.getUser(USERNAME, "qwer1234")).isNull();
    }

    @Test(expected = RestServerError.class)
    public void testDeleteUserAuthorizationsException() throws ApsSystemException {
        userService.addUser(activeUser());
        doThrow(new ApsSystemException(USERNAME)).when(authorizationManager).deleteUserAuthorizations(anyString());
        userService.deleteUserAuthorities(USERNAME);
    }

    @Test(expected = RestServerError.class)
    public void testAddUserAuthorizationsException() throws ApsSystemException {
        userService.addUser(activeUser());
        when(authorizationManager.isAuthOnGroupAndRole(isA(UserDetails.class), anyString(), anyString(), isA(Boolean.class)))
                .thenReturn(false);
        doThrow(new ApsSystemException(USERNAME)).when(authorizationManager).addUserAuthorization(anyString(), anyString(), anyString());
        userService.addUserAuthorities(USERNAME, authorities(authority("group", "role")));
    }

    @Test(expected = RestServerError.class)
    public void testGetUserDetailsException() throws ApsSystemException {
        userService.addUser(activeUser());
        doThrow(new ApsSystemException(USERNAME)).when(authorizationManager).getUserAuthorizations(anyString());
        userService.getUserDetails(USERNAME);
    }

    private UserAuthoritiesRequest authorities(final UserAuthority ... authorities) {
        final UserAuthoritiesRequest request = new UserAuthoritiesRequest();
        request.addAll(Arrays.asList(authorities));
        return request;
    }

    private UserAuthority authority(final String group, final String role) {
        final UserAuthority authority = new UserAuthority();
        authority.setGroup(group);
        authority.setRole(role);
        return authority;
    }

    private UserRequest activeUser() {
        final UserRequest request = new UserRequest();
        request.setStatus(IUserService.STATUS_ACTIVE);
        request.setUsername(USERNAME);
        request.setPassword("qwer1234");
        request.setReset(false);
        return request;
    }

    private UserRequest disabledUser() {
        final UserRequest request = activeUser();
        request.setStatus(IUserService.STATUS_DISABLED);
        return request;
    }

    private List<Authorization> authorizations() {
        final Group group = new Group();
        group.setName("administrators");
        final Role role = new Role();
        role.setName("admin");
        final Authorization authorization = new Authorization(group, role);
        return Collections.singletonList(authorization);
    }
}
