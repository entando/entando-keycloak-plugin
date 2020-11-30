package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.UserDetails;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.entando.entando.ent.exception.EntException;

public class AuthenticationProviderManagerTest {

    @Mock private KeycloakUserManager userManager;
    @Mock private UserDetails userDetails;

    private KeycloakAuthenticationProviderManager manager;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        manager = new KeycloakAuthenticationProviderManager(userManager);
    }

    @Test
    public void testGetUser() throws EntException {
        when(userManager.getUser(anyString())).thenReturn(userDetails);
        final UserDetails user = manager.getUser("admin");
        verify(userManager, times(1)).getUser(eq("admin"));
        assertThat(user).isSameAs(userDetails);
    }

    @Test
    public void testGetUserWithPassword() throws EntException {
        when(userManager.getUser(anyString(), anyString())).thenReturn(userDetails);
        final UserDetails user = manager.getUser("admin", "password");
        verify(userManager, times(1)).getUser(eq("admin"), eq("password"));
        assertThat(user).isSameAs(userDetails);
    }

    @Test
    public void testAuthenticate() {
        assertThat(manager.authenticate(null)).isNull();
    }

    @Test
    public void testLoadUserByUsername() {
        assertThat(manager.loadUserByUsername("admin")).isNull();
    }

}
