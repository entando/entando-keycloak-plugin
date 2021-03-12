package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.UserDetails;
import org.mockito.Mock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import org.entando.entando.ent.exception.EntException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class AuthenticationProviderManagerTest {

    @Mock private KeycloakUserManager userManager;
    @Mock private UserDetails userDetails;

    private KeycloakAuthenticationProviderManager manager;

    @BeforeEach
    public void setUp() {
        manager = new KeycloakAuthenticationProviderManager(userManager);
    }

    @Test
    void testGetUser() throws EntException {
        when(userManager.getUser(anyString())).thenReturn(userDetails);
        final UserDetails user = manager.getUser("admin");
        verify(userManager, times(1)).getUser(eq("admin"));
        assertThat(user).isSameAs(userDetails);
    }

    @Test
    void testGetUserWithPassword() throws EntException {
        when(userManager.getUser(anyString(), anyString())).thenReturn(userDetails);
        final UserDetails user = manager.getUser("admin", "password");
        verify(userManager, times(1)).getUser(eq("admin"), eq("password"));
        assertThat(user).isSameAs(userDetails);
    }

    @Test
    void testAuthenticate() {
        assertThat(manager.authenticate(null)).isNull();
    }

    @Test
    void testLoadUserByUsername() {
        assertThat(manager.loadUserByUsername("admin")).isNull();
    }

}
