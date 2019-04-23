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

public class AuthenticationProviderManagerTest {

    @Mock private UserManager userManager;
    @Mock private UserDetails userDetails;

    private AuthenticationProviderManager manager;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        manager = new AuthenticationProviderManager();
        manager.setUserManager(userManager);
    }

    @Test
    public void testGetUser() {
        when(userManager.getUser(anyString())).thenReturn(userDetails);
        final UserDetails user = manager.getUser("admin");
        verify(userManager, times(1)).getUser(eq("admin"));
        assertThat(user).isSameAs(userDetails);
    }

    @Test
    public void testGetUserWithPassword() {
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
