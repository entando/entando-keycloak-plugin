package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.web.user.model.UserRequest;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class UserManager implements IUserManager {

    @Autowired private UserService userService;

    @Override
    public List<String> getUsernames() {
        return userService.getUsernames();
    }

    @Override
    public List<String> searchUsernames(final String text) {
        return userService.searchUsernames(text);
    }

    @Override
    public List<UserDetails> getUsers() {
        return userService.getUsers();
    }

    @Override
    public List<UserDetails> searchUsers(final String text) {
        return userService.searchUsers(text);
    }

    @Override
    public void removeUser(final UserDetails user) {
        userService.removeUser(user.getUsername());
    }

    @Override
    public void removeUser(final String username) {
        userService.removeUser(username);
    }

    @Override
    public void updateUser(final UserDetails user) {
        final UserRequest request = new UserRequest();
        request.setPassword(user.getPassword());
        request.setReset(true);
        request.setStatus(user.isDisabled() ? IUserService.STATUS_DISABLED: IUserService.STATUS_ACTIVE);
        request.setUsername(user.getUsername());
        userService.updateUser(request);
    }

    @Override
    public void updateLastAccess(final UserDetails user) {
        // not necessary
    }

    @Override
    public void changePassword(final String username, final String password) {
        userService.updateUserPassword(username, password);
    }

    @Override
    public void addUser(final UserDetails user) {
        final UserRequest request = new UserRequest();
        request.setPassword(user.getPassword());
        request.setReset(true);
        request.setStatus(user.isDisabled() ? IUserService.STATUS_DISABLED: IUserService.STATUS_ACTIVE);
        request.setUsername(user.getUsername());
        userService.addUser(request);
    }

    @Override
    public UserDetails getUser(final String username) {
        return userService.getUserDetails(username);
    }

    @Override
    public UserDetails getUser(final String username, final String password) {
        return userService.getUser(username, password);
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
        return false;
    }

    public void setUserService(final UserService userService) {
        this.userService = userService;
    }
}
