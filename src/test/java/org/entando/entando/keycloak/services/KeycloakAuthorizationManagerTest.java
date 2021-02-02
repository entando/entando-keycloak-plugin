package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.authorization.AuthorizationManager;
import com.agiletec.aps.system.services.group.Group;
import com.agiletec.aps.system.services.group.GroupManager;
import com.agiletec.aps.system.services.role.Role;
import com.agiletec.aps.system.services.role.RoleManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import java.util.ArrayList;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.entando.entando.ent.exception.EntException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class KeycloakAuthorizationManagerTest {

    @Mock private UserDetails userDetails;
    @Mock private KeycloakConfiguration configuration;
    @Mock private AuthorizationManager authorizationManager;
    @Mock private GroupManager groupManager;
    @Mock private RoleManager roleManager;

    private KeycloakAuthorizationManager manager;

    @BeforeEach
    public void setUp() {
        manager = new KeycloakAuthorizationManager(configuration, authorizationManager, groupManager, roleManager);
    }

    @Test
    void testGroupCreation() throws EntException {
        when(configuration.getDefaultAuthorizations()).thenReturn("readers");
        when(groupManager.getGroup(anyString())).thenReturn(null);
        when(userDetails.getAuthorizations()).thenReturn(new ArrayList<>());

        manager.processNewUser(userDetails);

        final ArgumentCaptor<Group> groupCaptor = ArgumentCaptor.forClass(Group.class);
        final ArgumentCaptor<Authorization> authorizationCaptor = ArgumentCaptor.forClass(Authorization.class);
        verify(roleManager, times(0)).getRole(anyString());
        verify(groupManager, times(1)).getGroup(eq("readers"));
        verify(groupManager, times(1)).addGroup(groupCaptor.capture());
        verify(userDetails, times(1)).addAuthorization(authorizationCaptor.capture());

        assertThat(groupCaptor.getValue().getName()).isEqualTo("readers");
        assertThat(groupCaptor.getValue().getDescription()).isEqualTo("readers");

        assertThat(authorizationCaptor.getValue().getGroup().getName()).isEqualTo("readers");
        assertThat(authorizationCaptor.getValue().getRole()).isNull();
    }

    @Test
    void testGroupAndRoleCreation() throws EntException {
        when(configuration.getDefaultAuthorizations()).thenReturn("readers:read-all");
        when(groupManager.getGroup(anyString())).thenReturn(null);
        when(roleManager.getRole(anyString())).thenReturn(null);
        when(userDetails.getAuthorizations()).thenReturn(new ArrayList<>());

        manager.processNewUser(userDetails);

        final ArgumentCaptor<Group> groupCaptor = ArgumentCaptor.forClass(Group.class);
        final ArgumentCaptor<Role> roleCaptor = ArgumentCaptor.forClass(Role.class);
        final ArgumentCaptor<Authorization> authorizationCaptor = ArgumentCaptor.forClass(Authorization.class);
        verify(roleManager, times(1)).getRole(eq("read-all"));
        verify(roleManager, times(1)).addRole(roleCaptor.capture());
        verify(groupManager, times(1)).getGroup(eq("readers"));
        verify(groupManager, times(1)).addGroup(groupCaptor.capture());
        verify(userDetails, times(1)).addAuthorization(authorizationCaptor.capture());

        assertThat(groupCaptor.getValue().getName()).isEqualTo("readers");
        assertThat(groupCaptor.getValue().getDescription()).isEqualTo("readers");

        assertThat(roleCaptor.getValue().getName()).isEqualTo("read-all");
        assertThat(roleCaptor.getValue().getDescription()).isEqualTo("read-all");

        assertThat(authorizationCaptor.getValue().getGroup().getName()).isEqualTo("readers");
        assertThat(authorizationCaptor.getValue().getRole().getName()).isEqualTo("read-all");
    }

    @Test
    void testVerification() {
        final Authorization readers = authorization("readers", "read-all");
        final Authorization writers = authorization("writers", "write-all");

        when(configuration.getDefaultAuthorizations()).thenReturn("readers:read-all,writers:write-all");
        when(userDetails.getAuthorizations()).thenReturn(Arrays.asList(readers, writers));

        manager.processNewUser(userDetails);

        verify(roleManager, times(0)).getRole(anyString());
        verify(groupManager, times(0)).getGroup(anyString());
        verify(userDetails, times(0)).addAuthorization(any());
    }

    private Authorization authorization(final String groupName, final String roleName) {
        final Group group = new Group();
        group.setName(groupName);
        final Role role = new Role();
        role.setName(roleName);
        return new Authorization(group, role);
    }

}
