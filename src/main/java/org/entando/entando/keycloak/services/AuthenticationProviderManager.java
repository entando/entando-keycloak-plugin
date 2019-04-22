package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class AuthenticationProviderManager implements IAuthenticationProviderManager {

    @Autowired private UserManager userManager;

    @Override
    public UserDetails getUser(final String username) {
        return userManager.getUser(username);
    }

    @Override
    public UserDetails getUser(final String username, final String password) {
        return userManager.getUser(username, password);
    }

    @Override // deprecated
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        return null;
    }

    @Override // deprecated
    public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(final String s) throws UsernameNotFoundException {
        return null;
    }
}
