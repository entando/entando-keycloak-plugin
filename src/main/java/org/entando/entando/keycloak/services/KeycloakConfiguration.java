package org.entando.entando.keycloak.services;

import lombok.Data;

@Data
public class KeycloakConfiguration {

    private boolean enabled;
    private String authUrl;
    private String realm;
    private String clientId;
    private String clientSecret;
    private String publicClientId;
    private String secureUris;
    private String defaultAuthorizations;

}
