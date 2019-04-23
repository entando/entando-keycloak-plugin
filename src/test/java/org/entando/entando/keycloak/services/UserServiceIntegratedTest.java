package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.keycloak.KeycloakTestConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectorService;
import org.entando.entando.web.user.model.UserPasswordRequest;
import org.entando.entando.web.user.model.UserRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

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
    public void testAddDisabledUserAndAuthenticate() {
        userService.addUser(disabledUser());
        assertThat(userService.getUser(USERNAME, "qwer1234")).isNull();
    }

    @Test public void testGetUserAuthorities() {}
    @Test public void testAddUserAuthorities() {}
    @Test public void testUpdateUserAuthorities() {}
    @Test public void testDeleteUserAuthorities() {}
    @Test public void testGetUsers() {}
    @Test public void testGetUser() {}
    @Test public void testUpdateUser() {}
    @Test public void testAddUser() {}
    @Test public void testRemoveUser() {}
    @Test public void testUpdateUserPassword() {}


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
}
