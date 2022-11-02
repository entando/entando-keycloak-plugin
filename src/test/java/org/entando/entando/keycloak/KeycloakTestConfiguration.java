package org.entando.entando.keycloak;

import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.KeycloakService;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.UserRepresentation;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;

import static java.util.Collections.singletonList;
import static java.util.Optional.ofNullable;

public class KeycloakTestConfiguration {

    private static final String BASE_URL = ofNullable(System.getenv("KEYCLOAK_AUTH_URL")).orElse("http://localhost:8081/auth");
    private static final String REALM_NAME = "entando-development";
    private static final String CLIENT_ID = "entando-core";

    private static KeycloakService keycloakService;
    private static KeycloakConfiguration configuration;
    private static Keycloak keycloak;

    public static KeycloakConfiguration getConfiguration() {
        if (configuration == null) create();
        return configuration;
    }

    public static void deleteUsers() {
        keycloakService.listUsers().stream()
                .map(UserRepresentation::getId)
                .forEach(keycloakService::removeUser);
    }

    public static void logoutAllSessions() {
        keycloak.realms().realm(REALM_NAME).logoutAll();
    }

    private static void create() {
        keycloak = KeycloakBuilder.builder()
                .serverUrl(BASE_URL)
                .grantType(OAuth2Constants.PASSWORD)
                .realm("master")
                .clientId("admin-cli")
                .username("entando-admin")
                .password("qwe123")
                .build();

        final String secret = getClientSecret(keycloak);
        configuration = new KeycloakConfiguration();
        configuration.setAuthUrl(BASE_URL);
        configuration.setClientId(CLIENT_ID);
        configuration.setRealm(REALM_NAME);
        configuration.setClientSecret(secret);

        final OpenIDConnectService oidcService = new OpenIDConnectService(configuration);

        keycloakService = new KeycloakService(configuration, oidcService);
    }

    private static void assignRoleRealmAdmin(final RealmResource resource, final ClientResource clientResource) {
        final String id = resource.clients().findByClientId("realm-management").get(0).getId();
        RoleScopeResource rolesByClient = resource.users().get(clientResource.getServiceAccountUser().getId()).roles().clientLevel(id);
        if(rolesByClient.listAll().isEmpty()) {
            final RoleRepresentation role = resource.clients().get(id).roles().get("realm-admin").toRepresentation();
            rolesByClient.add(singletonList(role));
        }
    }

    private static String getClientSecret(final Keycloak keycloak) {
        try {
            final RealmResource realm = keycloak.realm(REALM_NAME);
            realm.toRepresentation();
            final List<ClientRepresentation> id = realm.clients().findByClientId(CLIENT_ID);
            ClientResource clientResource = realm.clients().get(id.get(0).getId());
            assignRoleRealmAdmin(realm, clientResource);
            return clientResource.getSecret().getValue();
        } catch (final NotFoundException e) {
            return createRealm(keycloak);
        }
    }

    private static String createRealm(final Keycloak masterKeycloak) {
        final RealmRepresentation newRealm = new RealmRepresentation();
        newRealm.setRealm(REALM_NAME);
        newRealm.setEnabled(true);
        newRealm.setDisplayName("Entando - Test");
        masterKeycloak.realms().create(newRealm);


        final RealmResource resource = masterKeycloak.realm(REALM_NAME);
        createEntandoWebClient(resource);
        final Response response = createEntandoCoreClient(resource);
        final String id = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        final ClientResource clientResource = resource.clients().get(id);
        final String secret = clientResource.generateNewSecret().getValue();

        assignRoleRealmAdmin(resource, clientResource);

        return secret;
    }

    private static Response createEntandoCoreClient(RealmResource resource) {
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
        return resource.clients().create(client);
    }

    private static void createEntandoWebClient(RealmResource realmResource) {
        ClientRepresentation client = new ClientRepresentation();
        client.setName("Entando WEB");
        client.setClientId("entando-web");
        client.setEnabled(true);
        client.setServiceAccountsEnabled(false);
        client.setStandardFlowEnabled(true);
        client.setImplicitFlowEnabled(true);
        client.setDirectAccessGrantsEnabled(false);
        client.setAuthorizationServicesEnabled(false);
        client.setRedirectUris(Collections.singletonList("*"));
        client.setPublicClient(true);
        client.setOrigin("*");
        client.setWebOrigins(Collections.singletonList("*"));
        realmResource.clients().create(client);
    }

}
