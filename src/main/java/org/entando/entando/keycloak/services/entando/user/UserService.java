package org.entando.entando.keycloak.services.entando.user;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import org.entando.entando.aps.system.exception.ResourceNotFoundException;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.aps.system.services.user.model.UserAuthorityDto;
import org.entando.entando.aps.system.services.user.model.UserDto;
import org.entando.entando.keycloak.services.keycloak.KeycloakConfiguration;
import org.entando.entando.keycloak.services.keycloak.KeycloakMapper;
import org.entando.entando.keycloak.services.keycloak.KeycloakService;
import org.entando.entando.web.common.model.PagedMetadata;
import org.entando.entando.web.common.model.RestListRequest;
import org.entando.entando.web.user.model.UserAuthoritiesRequest;
import org.entando.entando.web.user.model.UserAuthority;
import org.entando.entando.web.user.model.UserPasswordRequest;
import org.entando.entando.web.user.model.UserRequest;
import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.representations.idm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;

@Primary
@Service
public class UserService implements IUserService {

    private static final String ERRCODE_USER_NOT_FOUND = "1";

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final KeycloakService keycloakService;
    private final String clientId;

    @Autowired
    public UserService(final KeycloakConfiguration configuration, final KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
        this.clientId = configuration.getClientId();
    }

    @Override
    public List<UserAuthorityDto> getUserAuthorities(final String username) {
        try {
            final UserRepresentation user = getUserRepresentation(username);
            return keycloakService.getRealmResource()
                    .users().get(user.getId()).groups()
                    .stream().findFirst()
                    .map(this::getUserAuthorities)
                    .orElse(Collections.emptyList());
        } catch (Exception e) {
            log.error("Error while trying to execute getUserAuthorities", e);
            throw e;
        }
    }

    private List<UserAuthorityDto> getUserAuthorities(final GroupRepresentation group) {
        return keycloakService.getRealmResource().groups().group(group.getId()).roles()
                .clientLevel(keycloakService.getClientUUID()).listAll()
                .stream()
                .map(role -> new UserAuthorityDto(group.getName(), role.getName()))
                .collect(Collectors.toList());
    }

    @Override
    public List<UserAuthorityDto> addUserAuthorities(final String username, final UserAuthoritiesRequest request) {
        final ClientRepresentation client = keycloakService.getRealmResource().clients().findByClientId(clientId)
                .stream().findFirst().orElseThrow(RuntimeException::new);
        final UserRepresentation user = getUserRepresentation(username);
        final List<String> roles = user.getClientRoles().get(clientId);
        final List<RoleRepresentation> newRoles = request.stream()
                .map(UserAuthority::getRole)
                .filter(role -> !roles.contains(role))
                .map(keycloakService.getRealmResource().clients().get(clientId).roles()::get)
                .map(RoleResource::toRepresentation)
                .collect(Collectors.toList());

        keycloakService.getRealmResource().users().get(user.getId()).roles().clientLevel(client.getId()).add(newRoles);
        return getUserAuthorities(username);
    }

    @Override
    public List<UserAuthorityDto> updateUserAuthorities(final String username, final UserAuthoritiesRequest request) {
        deleteUserAuthorities(username);
        return addUserAuthorities(username, request);
    }

    @Override
    public void deleteUserAuthorities(final String username) {
        final UserRepresentation user = getUserRepresentation(username);
        final ClientRepresentation client = keycloakService.getRealmResource().clients().findByClientId(clientId)
                .stream().findFirst().orElseThrow(RuntimeException::new);
        final List<String> roles = user.getClientRoles().get(clientId);
        final List<RoleRepresentation> toRemoveRoles = roles.stream()
                .map(keycloakService.getRealmResource().clients().get(clientId).roles()::get)
                .map(RoleResource::toRepresentation)
                .collect(Collectors.toList());
        keycloakService.getRealmResource().users().get(user.getId()).roles().clientLevel(client.getId()).remove(toRemoveRoles);
    }

    @Override
    public PagedMetadata<UserDto> getUsers(final RestListRequest requestList, final String withProfile) {
       try {
           log.info("Listing Users");
           final int offset = (requestList.getPage() - 1) * requestList.getPageSize();
           final Integer count = keycloakService.getRealmResource().users().count();
           final List<UserDto> list = keycloakService.getRealmResource().users().list(offset, requestList.getPageSize()).stream()
                   .map(KeycloakMapper::convertUser)
                   .collect(Collectors.toList());
           return new PagedMetadata<>(requestList, list, count);
       } catch (Exception e) {
           log.error("Error while trying to execute getUsers", e);
           throw e;
       }
    }

    @Override
    public UserDto getUser(final String username) {
        return KeycloakMapper.convertUser(getUserRepresentation(username));
    }

    private UserRepresentation getUserRepresentation(final String username) {
        return keycloakService.getRealmResource().users().search(username).stream()
                .findFirst()
                .orElseThrow(() -> new ResourceNotFoundException(ERRCODE_USER_NOT_FOUND, "user", username));
    }

    @Override
    public UserDto updateUser(final UserRequest userRequest) {
        final UserRepresentation user = getUserRepresentation(userRequest.getUsername());
        ofNullable(userRequest.getStatus()).map(IUserService.STATUS_ACTIVE::equals).ifPresent(user::setEnabled);
        ofNullable(userRequest.getPassword())
                .ifPresent(password -> updateUserPassword(user.getId(), password, true));
        keycloakService.getRealmResource().users().get(user.getId()).update(user);
        return KeycloakMapper.convertUser(user);
    }

    @Override
    public UserDto addUser(final UserRequest userRequest) {
        try {
            UserRepresentation user = new UserRepresentation();
            user.setUsername(userRequest.getUsername());
            user.setEnabled(IUserService.STATUS_ACTIVE.equals(userRequest.getStatus()));

            final Response response = keycloakService.getRealmResource().users().create(user);
            final String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
            updateUserPassword(userId, userRequest.getPassword(), true);
            return KeycloakMapper.convertUser(user);
        } catch (Exception e) {
            log.error("Error while trying to execute addUser", e);
            throw e;
        }
    }

    @Override
    public void removeUser(final String username) {
        keycloakService.getRealmResource().users().get(getUserRepresentation(username).getId()).remove();
    }

    @Override
    public UserDto updateUserPassword(final UserPasswordRequest passwordRequest) {
        final UserRepresentation user = getUserRepresentation(passwordRequest.getUsername());
        // TODO validate user current password
        updateUserPassword(user.getId(), passwordRequest.getNewPassword(), false);
        return KeycloakMapper.convertUser(user);
    }

    private void updateUserPassword(final String userId, final String password, final boolean temporary) {
        final CredentialRepresentation credentials = new CredentialRepresentation();
        credentials.setValue(password);
        credentials.setTemporary(temporary);
        credentials.setType("password");
        keycloakService.getRealmResource().users().get(userId).resetPassword(credentials);
    }

    public void setAuthorizationManager(IAuthorizationManager authorizationManager) {}
    public void setAuthenticationProvider(IAuthenticationProviderManager authenticationProvider) {}

}
