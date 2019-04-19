package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Primary
@Service
public class AuthenticationProviderManager implements IAuthenticationProviderManager {

    private final UserService userService;

    @Autowired
    public AuthenticationProviderManager(final UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails getUser(final String username) {
        return userService.getUserDetails(username);
    }

    @Override // deprecated
    public UserDetails getUser(final String username, final String password) {
        return getUser(username);
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
