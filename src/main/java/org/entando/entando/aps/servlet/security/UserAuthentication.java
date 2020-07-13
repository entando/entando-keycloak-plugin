package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.services.user.UserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class UserAuthentication implements Authentication {

    private UserDetails userDetails;

    public UserAuthentication(final UserDetails userDetails) {
        this.userDetails = userDetails;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return userDetails.getAuthorizations();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return userDetails;
    }

    @Override
    public Object getPrincipal() {
        return userDetails;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(final boolean b) throws IllegalArgumentException {
    }

    @Override
    public String getName() {
        return userDetails.getUsername();
    }
}
