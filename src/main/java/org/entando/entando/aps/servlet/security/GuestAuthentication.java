package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.services.user.UserDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class GuestAuthentication implements Authentication {

    private final UserDetails guestUser;

    public GuestAuthentication(final UserDetails guestUser) {
        this.guestUser = guestUser;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    @Override
    public Object getDetails() {
        return guestUser;
    }

    @Override
    public Object getPrincipal() {
        return guestUser;
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(final boolean b) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return "guest";
    }
}
