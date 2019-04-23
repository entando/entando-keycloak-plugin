package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.web.user.model.UserRequest;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class UserManagerTest {

    private static final String USERNAME = "admin";
    private static final String PASSWORD = "password";

    @Mock private UserService userService;
    @Mock private UserDetails userDetails;

    private UserManager manager;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        manager = new UserManager();
        manager.setUserService(userService);
    }

    @Test
    public void testAddUser() {
        when(userDetails.getUsername()).thenReturn(USERNAME);
        when(userDetails.getPassword()).thenReturn(PASSWORD);
        when(userDetails.isDisabled()).thenReturn(false);
        manager.addUser(userDetails);

        final ArgumentCaptor<UserRequest> captor = ArgumentCaptor.forClass(UserRequest.class);
        verify(userService, times(1)).addUser(captor.capture());

        assertThat(captor.getValue()).hasFieldOrPropertyWithValue("password", PASSWORD)
                .hasFieldOrPropertyWithValue("username", USERNAME)
                .hasFieldOrPropertyWithValue("status", IUserService.STATUS_ACTIVE)
                .hasFieldOrPropertyWithValue("reset", true);
    }

    @Test
    public void testUpdateUser() {
        when(userDetails.getUsername()).thenReturn(USERNAME);
        when(userDetails.getPassword()).thenReturn(PASSWORD);
        when(userDetails.isDisabled()).thenReturn(false);
        manager.updateUser(userDetails);

        final ArgumentCaptor<UserRequest> captor = ArgumentCaptor.forClass(UserRequest.class);
        verify(userService, times(1)).updateUser(captor.capture());

        assertThat(captor.getValue()).hasFieldOrPropertyWithValue("password", PASSWORD)
                .hasFieldOrPropertyWithValue("username", USERNAME)
                .hasFieldOrPropertyWithValue("status", IUserService.STATUS_ACTIVE)
                .hasFieldOrPropertyWithValue("reset", true);
    }

    @Test
    public void testGetUserByUsernameAndPassword() {
        when(userService.getUser(anyString(), anyString())).thenReturn(userDetails);
        final UserDetails details = manager.getUser(USERNAME, PASSWORD);
        verify(userService, times(1)).getUser(eq(USERNAME), eq(PASSWORD));
        assertThat(details).isSameAs(userDetails);
    }

    @Test
    public void testGetUserByUsername() {
        when(userService.getUserDetails(anyString())).thenReturn(userDetails);
        final UserDetails details = manager.getUser(USERNAME);
        verify(userService, times(1)).getUserDetails(eq(USERNAME));
        assertThat(details).isSameAs(userDetails);
    }

    @Test
    public void testRemoveUser() {
        manager.removeUser(USERNAME);
        verify(userService, times(1)).removeUser(eq(USERNAME));
        reset(userService);

        when(userDetails.getUsername()).thenReturn(USERNAME);
        manager.removeUser(userDetails);
        verify(userService, times(1)).removeUser(eq(USERNAME));
    }

    @Test
    public void testListUsernames() {
        final List<String> userServiceReturn = Collections.singletonList(USERNAME);
        when(userService.getUsernames()).thenReturn(userServiceReturn);
        assertThat(manager.getUsernames()).isSameAs(userServiceReturn);
    }

    @Test
    public void testSearchUsernames() {
        final List<String> userServiceReturn = Collections.singletonList(USERNAME);
        when(userService.searchUsernames(anyString())).thenReturn(userServiceReturn);
        assertThat(manager.searchUsernames("admin")).isSameAs(userServiceReturn);
        verify(userService, times(1)).searchUsernames(eq("admin"));
    }

    @Test
    public void testListUsers() {
        final List<UserDetails> userServiceReturn = Collections.singletonList(userDetails);
        when(userService.getUsers()).thenReturn(userServiceReturn);
        assertThat(manager.getUsers()).isSameAs(userServiceReturn);
    }

    @Test
    public void testSearchUsers() {
        final List<UserDetails> userServiceReturn = Collections.singletonList(userDetails);
        when(userService.searchUsers(anyString())).thenReturn(userServiceReturn);
        assertThat(manager.searchUsers("admin")).isSameAs(userServiceReturn);
        verify(userService, times(1)).searchUsers(eq("admin"));
    }

    @Test
    public void testChangePassword() {
        manager.changePassword(USERNAME, PASSWORD);
        verify(userService, times(1)).updateUserPassword(eq(USERNAME), eq(PASSWORD));
    }

    @Test
    public void testGetGuestUser() {
        final UserDetails details = manager.getGuestUser();
        assertThat(details).hasFieldOrPropertyWithValue("username", "guest");
    }

    @Test
    public void testDeprecatedMethods() {
        assertThat(manager.isArgon2Encrypted("")).isFalse();
        assertThat(manager.encrypt("")).isNull();
        manager.updateLastAccess(null);
    }

}
