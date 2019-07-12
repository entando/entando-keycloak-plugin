package org.entando.entando.keycloak.services;

public class KeycloakConfiguration {

    private boolean enabled;
    private String authUrl;
    private String realm;
    private String clientId;
    private String clientSecret;
    private String secureUris;
    private String defaultAuthorizations;

    public String toString() {
        return String.format("{auth.url=%s, realm=%s, client.id=%s, client.secret=%s}", authUrl, realm, clientId, clientSecret);
    }

    public String getAuthUrl() {
        return authUrl;
    }

    public void setAuthUrl(final String authUrl) {
        this.authUrl = authUrl;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(final String realm) {
        this.realm = realm;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(final String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getSecureUris() {
        return secureUris;
    }

    public void setSecureUris(final String secureUris) {
        this.secureUris = secureUris;
    }

    public String getDefaultAuthorizations() {
        return defaultAuthorizations;
    }

    public void setDefaultAuthorizations(final String defaultAuthorizations) {
        this.defaultAuthorizations = defaultAuthorizations;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }
}
