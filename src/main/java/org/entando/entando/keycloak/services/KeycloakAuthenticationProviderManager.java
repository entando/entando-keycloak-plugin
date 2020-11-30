package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.ent.exception.EntException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.client.RestClientException;

public class KeycloakAuthenticationProviderManager implements IAuthenticationProviderManager {

    private final IUserManager userManager;

    public KeycloakAuthenticationProviderManager(final IUserManager userManager) {
        this.userManager = userManager;
    }

    @Override
    public UserDetails getUser(final String username) throws EntException {
        return userManager.getUser(username);
    }

    @Override
    public UserDetails getUser(final String username, final String password) throws EntException {
        return userManager.getUser(username, password);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        if (authentication != null) {
            try {
                userManager.getUser(authentication.getName());
            } catch (EntException e) {
                throw new RestClientException("Error detected during the authentication of the user " + authentication.getName());
            }
        }
        return authentication;
    }

    @Override // deprecated
    public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(final String s) throws UsernameNotFoundException {
        return null;
    }

}
