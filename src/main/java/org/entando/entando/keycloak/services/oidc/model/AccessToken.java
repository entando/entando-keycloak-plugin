package org.entando.entando.keycloak.services.oidc.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public class AccessToken {

    private String name;
    private String username;
    private String email;

    @JsonProperty("resource_access")
    private Map<String, TokenRoles> resourceAccess;

    private boolean active;

    @Override
    public String toString() {
        return String.format("{name=%s, username=%s, email=%s, active=%s}", name, username, email, active);
    }

    public String getName() {
        return name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(final String email) {
        this.email = email;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(final boolean active) {
        this.active = active;
    }

    public Map<String, TokenRoles> getResourceAccess() {
        return resourceAccess;
    }

    public void setResourceAccess(final Map<String, TokenRoles> resourceAccess) {
        this.resourceAccess = resourceAccess;
    }
}
