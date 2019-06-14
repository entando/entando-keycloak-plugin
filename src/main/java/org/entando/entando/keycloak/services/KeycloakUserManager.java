package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.entando.entando.KeycloakWiki;
import org.entando.entando.aps.system.exception.ResourceNotFoundException;
import org.entando.entando.aps.system.exception.RestServerError;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.exception.CredentialsExpiredException;
import org.entando.entando.keycloak.services.oidc.exception.OidcException;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import javax.ws.rs.ClientErrorException;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.entando.entando.KeycloakWiki.wiki;

public class KeycloakUserManager implements IUserManager {

    private static final String ERRCODE_USER_NOT_FOUND = "1";
    private static final Logger log = LoggerFactory.getLogger(KeycloakUserManager.class);

    private final IAuthorizationManager authorizationManager;
    private final KeycloakService keycloakService;
    private final OpenIDConnectService oidcService;

    public KeycloakUserManager(final IAuthorizationManager authorizationManager,
                               final KeycloakService keycloakService,
                               final OpenIDConnectService oidcService) {
        this.authorizationManager = authorizationManager;
        this.keycloakService = keycloakService;
        this.oidcService = oidcService;
    }

    @Override
    public List<String> getUsernames() {
        return keycloakService.getRealmResource().users().list().stream()
                .map(UserRepresentation::getUsername)
                .collect(Collectors.toList());
    }

    @Override
    public List<String> searchUsernames(final String text) {
        return list(text)
                .map(UserRepresentation::getUsername)
                .collect(Collectors.toList());
    }

    @Override
    public List<UserDetails> getUsers() {
        return keycloakService.getRealmResource().users().list().stream()
                .map(KeycloakMapper::convertUserDetails)
                .collect(Collectors.toList());
    }

    @Override
    public List<UserDetails> searchUsers(final String text) {
        return list(text)
                .map(KeycloakMapper::convertUserDetails)
                .collect(Collectors.toList());
    }

    @Override
    public void removeUser(final UserDetails user) {
        removeUser(user.getUsername());
    }

    @Override
    public void removeUser(final String username) {
        keycloakService.getRealmResource().users().get(getUserRepresentation(username).getId()).remove();
    }

    @Override
    public void updateUser(final UserDetails user) {
        final UserRepresentation userRep = getUserRepresentation(user.getUsername());
        userRep.setEnabled(!user.isDisabled());
        ofNullable(user.getPassword()).ifPresent(password -> updateUserPassword(userRep, password, true));
        keycloakService.getRealmResource().users().get(userRep.getId()).update(userRep);
    }

    @Override
    public void updateLastAccess(final UserDetails user) {
        // not necessary
    }

    @Override
    public void changePassword(final String username, final String password) {
        final UserRepresentation user = getUserRepresentation(username);
        updateUserPassword(user, password, false);
    }

    @Override
    public void addUser(final UserDetails user) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername(user.getUsername());
        userRep.setEnabled(!user.isDisabled());

        final Response response = keycloakService.getRealmResource().users().create(userRep);
        if (response.getStatus() == 201) {
            userRep.setId(response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1"));
            updateUserPassword(userRep, user.getPassword(), true);
        }
    }

    @Override
    public UserDetails getUser(final String username) {
        try {
            final User userDetails = KeycloakMapper.convertUserDetails(getUserRepresentation(username));
            final List<Authorization> authorizations = authorizationManager.getUserAuthorizations(username);

            userDetails.setAuthorizations(authorizations);
            return userDetails;
        } catch (ApsSystemException e) {
            log.error("Error in loading user {}", username, e);
            throw new RestServerError("Error in loading user", e);
        }
    }

    @Override
    public UserDetails getUser(final String username, final String password) {
        try {
            return ofNullable(oidcService.login(username, password))
                    .map(token -> getUser(username))
                    .orElse(null);
        } catch (CredentialsExpiredException e) {
            return getUser(username);
        } catch (OidcException e) {
            return null;
        }
    }

    @Override
    public UserDetails getGuestUser() {
        User user = new User();
        user.setUsername("guest");
        return user;
    }

    @Override// deprecated
    public String encrypt(final String text) {
        return null;
    }

    @Override// deprecated
    public boolean isArgon2Encrypted(final String encrypted) {
        return true;
    }

    private Stream<UserRepresentation> list(final String text) {
        final List<UserRepresentation> list = StringUtils.isEmpty(text)
                ? keycloakService.getRealmResource().users().list()
                : keycloakService.getRealmResource().users().search(text);
        // workaround to a bug on keycloak to not list Service Account Users
        return list.stream().filter(usr -> !usr.getUsername().startsWith("service-account-"));
    }

    private void updateUserPassword(final UserRepresentation user, final String password, final boolean temporary) {
        final CredentialRepresentation credentials = new CredentialRepresentation();
        credentials.setValue(password);
        credentials.setTemporary(temporary);
        credentials.setType("password");
        keycloakService.getRealmResource().users().get(user.getId()).resetPassword(credentials);

        if (!temporary) {
            user.setRequiredActions(emptyList());
            keycloakService.getRealmResource().users().get(user.getId()).update(user);
        }
    }

    private UserRepresentation getUserRepresentation(final String username) {
        try {
            return keycloakService.getRealmResource().users().search(username).stream()
                    .findFirst()
                    .map(usr -> keycloakService.getRealmResource().users().get(usr.getId()).toRepresentation())
                    .orElseThrow(() -> new ResourceNotFoundException(ERRCODE_USER_NOT_FOUND, "user", username));
        } catch (ClientErrorException e) {
            if (HttpStatus.FORBIDDEN.value() == e.getResponse().getStatus()
                    || HttpStatus.UNAUTHORIZED.value() == e.getResponse().getStatus()) {
                throw new RestServerError("There was an error while trying to load user because the " +
                        "client on Keycloak doesn't have permission to do that. " +
                        "The client needs to have Service Accounts enabled and the permission 'realm-admin' on client 'realm-management'. " +
                        "For more details, refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_FORBIDDEN), e);
            }
            throw e;
        }
    }

}
