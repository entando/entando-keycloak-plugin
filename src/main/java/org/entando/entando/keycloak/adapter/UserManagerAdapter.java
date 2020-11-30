package org.entando.entando.keycloak.adapter;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import com.agiletec.aps.system.services.user.UserManager;
import org.entando.entando.keycloak.services.KeycloakService;
import org.entando.entando.keycloak.services.KeycloakUserManager;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;

import java.util.List;
import org.entando.entando.ent.exception.EntException;

public class UserManagerAdapter extends UserManager implements IUserManager {

    private KeycloakUserManager keycloak;
    public UserManagerAdapter(){

    }
    public UserManagerAdapter(final IAuthorizationManager authorizationManager,
                              final KeycloakService keycloakService,
                              final OpenIDConnectService oidcService) {
        keycloak = new KeycloakUserManager(authorizationManager, keycloakService, oidcService);
    }

    private boolean keycloakEnabled;

    @Override
    public List<String> getUsernames() throws EntException {
        return keycloakEnabled ? keycloak.getUsernames() : super.getUsernames();
    }

    @Override
    public List<String> searchUsernames(final String text) throws EntException {
        return keycloakEnabled ? keycloak.searchUsernames(text) : super.searchUsernames(text);
    }

    @Override
    public List<UserDetails> getUsers() throws EntException {
        return keycloakEnabled ? keycloak.getUsers() : super.getUsers();
    }

    @Override
    public List<UserDetails> searchUsers(final String text) throws EntException {
        return keycloakEnabled ? keycloak.searchUsers(text) : super.searchUsers(text);
    }

    @Override
    public void removeUser(final UserDetails userDetails) throws EntException {
        if (keycloakEnabled) keycloak.removeUser(userDetails);
        else super.removeUser(userDetails);
    }

    @Override
    public void removeUser(final String username) throws EntException {
        if (keycloakEnabled) keycloak.removeUser(username);
        else super.removeUser(username);
    }

    @Override
    public void updateUser(final UserDetails userDetails) throws EntException {
        if (keycloakEnabled) keycloak.updateUser(userDetails);
        else super.updateUser(userDetails);
    }

    @Override
    public void updateLastAccess(final UserDetails userDetails) throws EntException {
        if (keycloakEnabled) keycloak.updateLastAccess(userDetails);
        else super.updateLastAccess(userDetails);
    }

    @Override
    public void changePassword(final String username, final String password) throws EntException {
        if (keycloakEnabled) keycloak.changePassword(username, password);
        else super.changePassword(username, password);
    }

    @Override
    public void addUser(final UserDetails userDetails) throws EntException {
        if (keycloakEnabled) keycloak.addUser(userDetails);
        else super.addUser(userDetails);
    }

    @Override
    public UserDetails getUser(final String username) throws EntException {
        return keycloakEnabled ? keycloak.getUser(username) : super.getUser(username);
    }

    @Override
    public UserDetails getUser(final String username, final String password) throws EntException {
        return keycloakEnabled
                ? keycloak.getUser(username, password)
                : super.getUser(username, password);
    }

    @Override
    public UserDetails getGuestUser() {
        return keycloakEnabled ? keycloak.getGuestUser() : super.getGuestUser();
    }
    
    public void setKeycloakEnabled(final boolean keycloakEnabled) {
        this.keycloakEnabled = keycloakEnabled;
    }
    
}
