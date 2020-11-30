package org.entando.entando.keycloak.adapter;

import com.agiletec.aps.system.services.user.AuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.keycloak.services.KeycloakAuthenticationProviderManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class AuthenticationProviderManagerAdapter extends AuthenticationProviderManager implements IAuthenticationProviderManager {

    private KeycloakAuthenticationProviderManager keycloak;

    public AuthenticationProviderManagerAdapter(final IUserManager userManager) {
        setUserManager(userManager);
        keycloak = new KeycloakAuthenticationProviderManager(userManager);
    }

    private boolean keycloakEnabled;

    @Override
    public UserDetails getUser(final String username) throws EntException {
        return keycloakEnabled
                ? keycloak.getUser(username)
                : super.getUser(username);
    }

    @Override
    public UserDetails getUser(final String username, final String password) throws EntException {
        return keycloakEnabled
                ? keycloak.getUser(username, password)
                : super.getUser(username, password);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        return keycloakEnabled
                ? keycloak.authenticate(authentication)
                : super.authenticate(authentication);
    }

    @Override
    public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(final String username) throws UsernameNotFoundException {
        return keycloakEnabled
                ? keycloak.loadUserByUsername(username)
                : super.loadUserByUsername(username);
    }

    public void setKeycloakEnabled(final boolean keycloakEnabled) {
         this.keycloakEnabled = keycloakEnabled;
    }
}
