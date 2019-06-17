package org.entando.entando.keycloak.services.oidc.model;

import java.util.List;

public class UserRepresentation {

    private String id;
    private long createdTimestamp;
    private String username;
    private boolean enabled;
    private boolean totp;
    private String emailVerified;
    private String firstName;
    private String lastName;
    private String email;
    private List<String> requiredActions;

    public String getId() {
        return id;
    }

    public void setId(final String id) {
        this.id = id;
    }

    public long getCreatedTimestamp() {
        return createdTimestamp;
    }

    public void setCreatedTimestamp(final long createdTimestamp) {
        this.createdTimestamp = createdTimestamp;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isTotp() {
        return totp;
    }

    public void setTotp(final boolean totp) {
        this.totp = totp;
    }

    public String getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(final String emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(final String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(final String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(final String email) {
        this.email = email;
    }

    public List<String> getRequiredActions() {
        return requiredActions;
    }

    public void setRequiredActions(final List<String> requiredActions) {
        this.requiredActions = requiredActions;
    }
}
