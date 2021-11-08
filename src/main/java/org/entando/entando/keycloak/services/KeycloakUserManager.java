package org.entando.entando.keycloak.services;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;

import com.agiletec.aps.system.common.AbstractParameterizableService;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.entando.entando.aps.system.exception.ResourceNotFoundException;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.exception.CredentialsExpiredException;
import org.entando.entando.keycloak.services.oidc.exception.OidcException;
import org.entando.entando.keycloak.services.oidc.model.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeycloakUserManager extends AbstractParameterizableService implements IUserManager {

    private static final Logger log = LoggerFactory.getLogger(KeycloakUserManager.class);

    private static final String ERRCODE_USER_NOT_FOUND = "1";

    private final IAuthorizationManager authorizationManager;
    private final KeycloakService keycloakService;
    private final OpenIDConnectService oidcService;

    public transient List<String> parameterNames = new ArrayList<>();

    public KeycloakUserManager(final IAuthorizationManager authorizationManager,
            final KeycloakService keycloakService,
            final OpenIDConnectService oidcService) {
        this.authorizationManager = authorizationManager;
        this.keycloakService = keycloakService;
        this.oidcService = oidcService;
    }

    @Override
    public List<String> getUsernames() {
        return keycloakService.listUsers().stream()
                .map(org.entando.entando.keycloak.services.oidc.model.UserRepresentation::getUsername)
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
        return keycloakService.listUsers().stream()
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
        final UserRepresentation userRep = getUserRepresentation(username)
                .orElseThrow(() -> new ResourceNotFoundException(ERRCODE_USER_NOT_FOUND, "user", username));
        keycloakService.removeUser(userRep.getId());
    }

    @Override
    public void updateUser(final UserDetails user) {
        final UserRepresentation userRep = getUserRepresentation(user.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException(ERRCODE_USER_NOT_FOUND, "user", user.getUsername()));
        userRep.setEnabled(!user.isDisabled());
        ofNullable(user.getPassword()).ifPresent(password -> updateUserPassword(userRep, password, true));
        keycloakService.updateUser(userRep);
    }

    @Override
    public void updateLastAccess(final UserDetails user) {
        // not necessary
    }

    @Override
    public void changePassword(final String username, final String password) {
        final UserRepresentation user = getUserRepresentation(username)
                .orElseThrow(() -> new ResourceNotFoundException(ERRCODE_USER_NOT_FOUND, "user", username));
        updateUserPassword(user, password, false);
    }

    @Override
    public void addUser(final UserDetails user) {
        UserRepresentation userRep = new UserRepresentation();
        userRep.setUsername(user.getUsername());
        userRep.setEnabled(!user.isDisabled());
        userRep.setId(keycloakService.createUser(userRep));
        updateUserPassword(userRep, user.getPassword(), true);
    }

    @Override
    public UserDetails getUser(final String username) {
        return getUserRepresentation(username)
                .map(KeycloakMapper::convertUserDetails)
                .map(this::getAuthorizations)
                .orElse(null);
    }

    private UserDetails getAuthorizations(final User user) {
        try {
            user.setAuthorizations(authorizationManager.getUserAuthorizations(user.getUsername()));
            return user;
        } catch (EntException e) {
            throw new RuntimeException(e);
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

    private Stream<UserRepresentation> list(final String text) {
        final List<UserRepresentation> list = keycloakService.listUsers(text);
        // workaround to a bug on keycloak to not list Service Account Users
        return list.stream().filter(usr -> !usr.getUsername().startsWith("service-account-"));
    }

    private void updateUserPassword(final UserRepresentation user, final String password, final boolean temporary) {
        keycloakService.resetPassword(user.getId(), password, temporary);

        if (!temporary) {
            user.setRequiredActions(emptyList());
            keycloakService.updateUser(user);
        }
    }

    private Optional<UserRepresentation> getUserRepresentation(final String username) {
        return keycloakService.listUsers(username).stream().filter(f->f.getUsername().equals(username)).findFirst();
    }

    @Override
    protected List<String> getParameterNames() {
        return parameterNames;
    }

    @Override
    public void init() {
        log.debug("{} ready", this.getClass().getName());
    }
}
