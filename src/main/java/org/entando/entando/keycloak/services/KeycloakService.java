package org.entando.entando.keycloak.services;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class KeycloakService {

    private final RealmResource realmResource;

    @Autowired
    public KeycloakService(final KeycloakConfiguration configuration) {
        final Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(configuration.getAuthUrl())
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .realm(configuration.getRealm())
                .clientId(configuration.getClientId())
                .clientSecret(configuration.getClientSecret())
                .build();
        this.realmResource = keycloak.realm(configuration.getRealm());
    }

    RealmResource getRealmResource() {
        return realmResource;
    }

}
