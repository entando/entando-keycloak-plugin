package org.entando.entando.keycloak.services;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class KeycloakJson {

    @JsonProperty("realm") private final String realm;
    @JsonProperty("auth-server-url") private final String authServerUrl;
    @JsonProperty("ssl-required") private final String sslRequired;
    @JsonProperty("resource") private final String resource;
    @JsonProperty("public-client") private final boolean publicClient;

    public KeycloakJson(final KeycloakConfiguration configuration) {
        this.realm = configuration.getRealm();
        this.authServerUrl = configuration.getAuthUrl();
        this.sslRequired = "external";
        this.resource = configuration.getPublicClientId();
        this.publicClient = true;
    }

}
