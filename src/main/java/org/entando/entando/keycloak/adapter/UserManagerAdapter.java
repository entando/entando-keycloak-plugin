package org.entando.entando.keycloak.adapter;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import com.agiletec.aps.system.services.user.UserManager;
import org.entando.entando.keycloak.services.KeycloakService;
import org.entando.entando.keycloak.services.KeycloakUserManager;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;

import java.util.List;

public class UserManagerAdapter extends UserManager implements IUserManager {

    private final KeycloakUserManager keycloak;

    public UserManagerAdapter(final IAuthorizationManager authorizationManager,
                              final KeycloakService keycloakService,
                              final OpenIDConnectService oidcService) {
        keycloak = new KeycloakUserManager(authorizationManager, keycloakService, oidcService);
    }

    private boolean keycloakEnabled;

    @Override
    public List<String> getUsernames() throws ApsSystemException {
        return keycloakEnabled ? keycloak.getUsernames() : super.getUsernames();
    }

    @Override
    public List<String> searchUsernames(final String text) throws ApsSystemException {
        return keycloakEnabled ? keycloak.searchUsernames(text) : super.searchUsernames(text);
    }

    @Override
    public List<UserDetails> getUsers() throws ApsSystemException {
        return keycloakEnabled ? keycloak.getUsers() : super.getUsers();
    }

    @Override
    public List<UserDetails> searchUsers(final String text) throws ApsSystemException {
        return keycloakEnabled ? keycloak.searchUsers(text) : super.searchUsers(text);
    }

    @Override
    public void removeUser(final UserDetails userDetails) throws ApsSystemException {
        if (keycloakEnabled) keycloak.removeUser(userDetails);
        else super.removeUser(userDetails);
    }

    @Override
    public void removeUser(final String username) throws ApsSystemException {
        if (keycloakEnabled) keycloak.removeUser(username);
        else super.removeUser(username);
    }

    @Override
    public void updateUser(final UserDetails userDetails) throws ApsSystemException {
        if (keycloakEnabled) keycloak.updateUser(userDetails);
        else super.updateUser(userDetails);
    }

    @Override
    public void updateLastAccess(final UserDetails userDetails) throws ApsSystemException {
        if (keycloakEnabled) keycloak.updateLastAccess(userDetails);
        else super.updateLastAccess(userDetails);
    }

    @Override
    public void changePassword(final String username, final String password) throws ApsSystemException {
        if (keycloakEnabled) keycloak.changePassword(username, password);
        else super.changePassword(username, password);
    }

    @Override
    public void addUser(final UserDetails userDetails) throws ApsSystemException {
        if (keycloakEnabled) keycloak.addUser(userDetails);
        else super.addUser(userDetails);
    }

    @Override
    public UserDetails getUser(final String username) throws ApsSystemException {
        return keycloakEnabled ? keycloak.getUser(username) : super.getUser(username);
    }

    @Override
    public UserDetails getUser(final String username, final String password) throws ApsSystemException {
        return keycloakEnabled
                ? keycloak.getUser(username, password)
                : super.getUser(username, password);
    }

    @Override
    public UserDetails getGuestUser() {
        return keycloakEnabled ? keycloak.getGuestUser() : super.getGuestUser();
    }

    public String encrypt(final String password) throws ApsSystemException {
        return keycloakEnabled ? keycloak.encrypt(password) : super.encrypt(password);
    }

    public boolean isArgon2Encrypted(final String password) {
        return keycloakEnabled ? keycloak.isArgon2Encrypted(password) : super.isArgon2Encrypted(password);
    }

    public void setKeycloakEnabled(final boolean keycloakEnabled) {
        this.keycloakEnabled = keycloakEnabled;
    }
}
