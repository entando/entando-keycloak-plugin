package org.entando.entando.keycloak;

import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.KeycloakService;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import javax.ws.rs.core.Response;
import java.util.List;

import static java.util.Collections.singletonList;

public class KeycloakTestConfiguration {

    private static final String BASE_URL = "http://localhost:8081/auth";
    private static final String REALM_NAME = "entando-core-test";
    private static final String CLIENT_ID = "entando-core";

    private static KeycloakService keycloakService;
    private static KeycloakConfiguration configuration;

    public static KeycloakConfiguration getConfiguration() {
        if (configuration == null) create();
        return configuration;
    }

    public static void deleteUsers() {
        final UsersResource users = keycloakService.getRealmResource().users();
        users.list().forEach(user -> users.delete(user.getId()));
    }

    private static KeycloakService create() {
        final Keycloak keycloak = KeycloakBuilder.builder()
                .serverUrl(BASE_URL)
                .grantType(OAuth2Constants.PASSWORD)
                .realm("master")
                .clientId("admin-cli")
                .username("admin")
                .password("qwe123")
                .build();
        final String secret = getClientSecret(keycloak);
        configuration = new KeycloakConfiguration();
        configuration.setAuthUrl(BASE_URL);
        configuration.setClientId(CLIENT_ID);
        configuration.setRealm(REALM_NAME);
        configuration.setClientSecret(secret);

        keycloakService = new KeycloakService(configuration);
        return keycloakService;
    }

    private static void assignRoleRealmAdmin(final RealmResource resource, final ClientResource clientResource) {
        final String id = resource.clients().findByClientId("realm-management").get(0).getId();
        final RoleRepresentation role = resource.clients().get(id).roles().get("realm-admin").toRepresentation();
        resource.users().get(clientResource.getServiceAccountUser().getId()).roles().clientLevel(id).add(singletonList(role));
    }

    private static String getClientSecret(final Keycloak keycloak) {
        try {
            final RealmResource realm = keycloak.realm(REALM_NAME);
            realm.toRepresentation();
            final List<ClientRepresentation> id = realm.clients().findByClientId(CLIENT_ID);
            return realm.clients().get(id.get(0).getId()).getSecret().getValue();
        } catch (Exception e) {
            return createRealm(keycloak);
        }
    }

    private static String createRealm(final Keycloak masterKeycloak) {
        final RealmRepresentation newRealm = new RealmRepresentation();
        newRealm.setRealm(REALM_NAME);
        newRealm.setEnabled(true);
        newRealm.setDisplayName("Entando - Test");
        masterKeycloak.realms().create(newRealm);

        final ClientRepresentation client = new ClientRepresentation();
        client.setName("entando-core");
        client.setClientId(CLIENT_ID);
        client.setEnabled(true);
        client.setServiceAccountsEnabled(true);
        client.setStandardFlowEnabled(true);
        client.setImplicitFlowEnabled(false);
        client.setDirectAccessGrantsEnabled(true);
        client.setAuthorizationServicesEnabled(false);
        client.setRedirectUris(singletonList("http://localhost:8080/*"));

        final RealmResource resource = masterKeycloak.realm(REALM_NAME);
        final Response response = resource.clients().create(client);
        final String id = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        final ClientResource clientResource = resource.clients().get(id);
        final String secret = clientResource.generateNewSecret().getValue();

        assignRoleRealmAdmin(resource, clientResource);

        return secret;
    }

}
