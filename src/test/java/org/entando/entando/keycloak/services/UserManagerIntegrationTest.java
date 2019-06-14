package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.system.exception.RestServerError;
import org.entando.entando.keycloak.KeycloakTestConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.web.user.model.UserPasswordRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;

public class UserManagerIntegrationTest {

    private static final String USERNAME = "marine";

    @Mock private IAuthorizationManager authorizationManager;

    private KeycloakUserManager userManager;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        final KeycloakConfiguration configuration = KeycloakTestConfiguration.getConfiguration();
        final KeycloakService keycloakService = new KeycloakService(configuration);
        final OpenIDConnectService oidcService = new OpenIDConnectService(configuration);
        userManager = new KeycloakUserManager(authorizationManager, keycloakService, oidcService);

        KeycloakTestConfiguration.deleteUsers();
    }

    @Test
    public void testUsers() {
        assertThat(userManager.getUsers()).isEmpty();

        userManager.addUser(activeUser());

        List<UserDetails> users = userManager.getUsers();
        assertThat(users).hasSize(1);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("username", USERNAME);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("disabled", false);

        assertThat(userManager.getUsernames()).hasSize(1).contains(USERNAME);
        assertThat(userManager.searchUsernames(USERNAME)).hasSize(1).contains(USERNAME);
        assertThat(userManager.searchUsernames("")).hasSize(1).contains(USERNAME);
        assertThat(userManager.searchUsernames(null)).hasSize(1).contains(USERNAME);
        assertThat(userManager.searchUsernames("aa")).isEmpty();

        users = userManager.searchUsers(USERNAME);
        assertThat(users).hasSize(1);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("username", USERNAME);
        assertThat(users.get(0)).hasFieldOrPropertyWithValue("disabled", false);

        users = userManager.searchUsers("");
        assertThat(users).hasSize(1);

        assertThat(userManager.searchUsers("aa")).isEmpty();

        userManager.removeUser(USERNAME);
        assertThat(userManager.getUsers()).isEmpty();
        assertThat(userManager.getUsernames()).isEmpty();
        assertThat(userManager.searchUsers(USERNAME)).isEmpty();
        assertThat(userManager.searchUsernames(USERNAME)).isEmpty();
    }

    @Test
    public void testGetUser() {
        userManager.addUser(activeUser());
        final UserDetails user = userManager.getUser(USERNAME);
        assertThat(user).hasFieldOrPropertyWithValue("username", USERNAME)
                .hasFieldOrPropertyWithValue("disabled", false)
                .hasFieldOrPropertyWithValue("accountNotExpired", true)
                .hasFieldOrPropertyWithValue("credentialsNotExpired", false);
    }

    @Test
    public void testGetUsers() {
        userManager.addUser(activeUser());
        userManager.addUser(activeUser("cop"));
        userManager.addUser(activeUser("doomguy"));

        final List<String> usernames = userManager.getUsernames();
        final List<String> searchUsernames = userManager.searchUsernames("mar");
        final List<String> noUsernames = userManager.searchUsernames("1010");

        assertThat(usernames).hasSize(3).contains(USERNAME, "cop", "doomguy");
        assertThat(searchUsernames).hasSize(1).contains(USERNAME);
        assertThat(noUsernames).isEmpty();
    }

    @Test
    public void testAddUserAndAuthenticate() {
        userManager.addUser(activeUser());

        UserDetails user = userManager.getUser(USERNAME, "qwer1234");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isFalse();

        assertThat(userManager.getUser(USERNAME, "1234qwer")).isNull();

        userManager.changePassword(USERNAME, "4321rewq");
        user = userManager.getUser(USERNAME, "4321rewq");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isTrue();
    }

    @Test
    public void testUserUpdatePassword() {
        userManager.addUser(activeUser());

        UserDetails user = userManager.getUser(USERNAME, "qwer1234");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isFalse();

        final UserPasswordRequest request = new UserPasswordRequest();
        request.setOldPassword("qwer1234");
        request.setNewPassword("1234qwer");
        request.setUsername(USERNAME);
        userManager.changePassword(USERNAME, "1234qwer");

        user = userManager.getUser(USERNAME, "1234qwer");
        assertThat(user).isNotNull();
        assertThat(user.isCredentialsNotExpired()).isTrue();
    }

    @Test
    public void testUserUpdate() {
        final User request = (User) activeUser();
        userManager.addUser(request);
        assertThat(userManager.getUser(USERNAME, "qwer1234")).isNotNull();

        request.setDisabled(true);
        userManager.updateUser(request);
        assertThat(userManager.getUser(USERNAME, "qwer1234")).isNull();
    }

    @Test
    public void testAddDisabledUserAndAuthenticate() {
        userManager.addUser(disabledUser());
        assertThat(userManager.getUser(USERNAME, "qwer1234")).isNull();
    }

    @Test(expected = RestServerError.class)
    public void testGetUserDetailsException() throws ApsSystemException {
        userManager.addUser(activeUser());
        doThrow(new ApsSystemException(USERNAME)).when(authorizationManager).getUserAuthorizations(anyString());
        userManager.getUser(USERNAME);
    }

    private static UserDetails activeUser() {
        return activeUser(USERNAME);
    }

    private static UserDetails activeUser(final String username) {
        return user(username, "qwer1234", true);
    }

    static UserDetails activeUser(final String username, final String password) {
        return user(username, password, true);
    }

    private static UserDetails user(final String username, final String password, final boolean enabled) {
        final User request = new User();
        request.setDisabled(!enabled);
        request.setUsername(username);
        request.setPassword(password);
        return request;
    }

    private static UserDetails disabledUser() {
        return user(USERNAME, "qwer1234", false);
    }

}
