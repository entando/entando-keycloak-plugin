package org.entando.entando.keycloak.services.oidc.model;

import java.util.List;

public class TokenRoles {

    private List<String> roles;

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(final List<String> roles) {
        this.roles = roles;
    }
}
