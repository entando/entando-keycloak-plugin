package org.entando.entando.keycloak.services.keycloak;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class KeycloakService {

    private final RealmResource realmResource;
    private final KeycloakConfiguration configuration;

    @Autowired
    public KeycloakService(final KeycloakConfiguration configuration) {
        this.configuration = configuration;
        final Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(configuration.getAuthUrl())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .realm(configuration.getRealm())
                .clientId(configuration.getClientId())
                .clientSecret(configuration.getClientSecret())
                .build();
        this.realmResource = keycloak.realm(configuration.getRealm());
    }

    public RealmResource getRealmResource() {
        return realmResource;
    }

    public String getClientUUID() {
        return realmResource.clients()
                .findByClientId(configuration.getClientId()).get(0).getId();
    }
}
