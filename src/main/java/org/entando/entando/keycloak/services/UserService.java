package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import org.apache.commons.lang.StringUtils;
import org.entando.entando.KeycloakWiki;
import org.entando.entando.aps.system.exception.ResourceNotFoundException;
import org.entando.entando.aps.system.exception.RestServerError;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.aps.system.services.user.model.UserAuthorityDto;
import org.entando.entando.aps.system.services.user.model.UserDto;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.exception.CredentialsExpiredException;
import org.entando.entando.keycloak.services.oidc.exception.OidcException;
import org.entando.entando.web.common.model.PagedMetadata;
import org.entando.entando.web.common.model.RestListRequest;
import org.entando.entando.web.user.model.UserAuthoritiesRequest;
import org.entando.entando.web.user.model.UserPasswordRequest;
import org.entando.entando.web.user.model.UserRequest;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import javax.ws.rs.ClientErrorException;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.entando.entando.KeycloakWiki.wiki;

@Primary
@Service
public class UserService implements IUserService {

    private static final String ERRCODE_USER_NOT_FOUND = "1";

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final IAuthorizationManager authorizationManager;
    private final KeycloakService keycloakService;
    private final OpenIDConnectService oidcService;

    @Autowired
    public UserService(final IAuthorizationManager authorizationManager,
                       final KeycloakService keycloakService,
                       final OpenIDConnectService oidcService) {
        this.authorizationManager = authorizationManager;
        this.keycloakService = keycloakService;
        this.oidcService = oidcService;
    }

    @Override
    public List<UserAuthorityDto> getUserAuthorities(final String username) {
        return getUserDetails(username).getAuthorizations()
                .stream().map(UserAuthorityDto::new)
                .collect(Collectors.toList());
    }

    @Override
    public List<UserAuthorityDto> addUserAuthorities(final String username, final UserAuthoritiesRequest request) {
        final UserDetails user = getUserDetails(username);
        return request.stream().map(authorization -> {
            try {
                if (!authorizationManager.isAuthOnGroupAndRole(user, authorization.getGroup(), authorization.getRole(), true)) {
                    authorizationManager.addUserAuthorization(username, authorization.getGroup(), authorization.getRole());
                }
            } catch (ApsSystemException ex) {
                log.error("Error in add authorities for {}", username, ex);
                throw new RestServerError("Error in add authorities", ex);
            }
            return new UserAuthorityDto(authorization.getGroup(), authorization.getRole());
        }).collect(Collectors.toList());
    }

    @Override
    public List<UserAuthorityDto> updateUserAuthorities(final String username, final UserAuthoritiesRequest request) {
        deleteUserAuthorities(username);
        return addUserAuthorities(username, request);
    }

    @Override
    public void deleteUserAuthorities(final String username) {
        try {
            authorizationManager.deleteUserAuthorizations(username);
        } catch (ApsSystemException e) {
            log.error("Error in delete authorities for {}", username, e);
            throw new RestServerError("Error in delete authorities", e);
        }
    }

    @Override
    public PagedMetadata<UserDto> getUsers(final RestListRequest requestList, final String withProfile) {
       log.info("Listing Users");
       final int offset = (requestList.getPage() - 1) * requestList.getPageSize();
       final Integer count = keycloakService.getRealmResource().users().count();
       final List<UserDto> list = keycloakService.getRealmResource().users().list(offset, requestList.getPageSize()).stream()
               .map(KeycloakMapper::convertUser)
               .collect(Collectors.toList());
       return new PagedMetadata<>(requestList, list, count);
    }

    @Override
    public UserDto getUser(final String username) {
        return KeycloakMapper.convertUser(getUserRepresentation(username));
    }

    UserDetails getUserDetails(final String username) {
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

    @Override
    public UserDto updateUser(final UserRequest userRequest) {
        final UserRepresentation user = getUserRepresentation(userRequest.getUsername());
        ofNullable(userRequest.getStatus()).map(IUserService.STATUS_ACTIVE::equals).ifPresent(user::setEnabled);
        ofNullable(userRequest.getPassword())
                .ifPresent(password -> updateUserPassword(user, password, true));
        keycloakService.getRealmResource().users().get(user.getId()).update(user);
        return KeycloakMapper.convertUser(user);
    }

    @Override
    public UserDto addUser(final UserRequest userRequest) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(userRequest.getUsername());
        user.setEnabled(IUserService.STATUS_ACTIVE.equals(userRequest.getStatus()));

        final Response response = keycloakService.getRealmResource().users().create(user);
        if (response.getStatus() == 201) {
            user.setId(response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1"));
            updateUserPassword(user, userRequest.getPassword(), true);
            return KeycloakMapper.convertUser(user);
        }

        return null;
    }

    @Override
    public void removeUser(final String username) {
        keycloakService.getRealmResource().users().get(getUserRepresentation(username).getId()).remove();
    }

    @Override
    public UserDto updateUserPassword(final UserPasswordRequest request) {
        final UserRepresentation user = getUserRepresentation(request.getUsername());
        updateUserPassword(user, request.getNewPassword(), false);
        return KeycloakMapper.convertUser(user);
    }

    List<String> getUsernames() {
        return keycloakService.getRealmResource().users().list().stream()
                .map(UserRepresentation::getUsername)
                .collect(Collectors.toList());
    }

    private Stream<UserRepresentation> list(final String text) {
        final List<UserRepresentation> list = StringUtils.isEmpty(text)
                ? keycloakService.getRealmResource().users().list()
                : keycloakService.getRealmResource().users().search(text);
        // workaround to a bug on keycloak to not list Service Account Users
        return list.stream().filter(usr -> !usr.getUsername().startsWith("service-account-"));
    }

    List<String> searchUsernames(final String text) {
        return list(text)
                .map(UserRepresentation::getUsername)
                .collect(Collectors.toList());
    }

    void updateUserPassword(final String username, final String password) {
        final UserRepresentation user = getUserRepresentation(username);
        updateUserPassword(user, password, false);
    }

    List<UserDetails> getUsers() {
        return keycloakService.getRealmResource().users().list().stream()
                .map(KeycloakMapper::convertUserDetails)
                .collect(Collectors.toList());
    }

    List<UserDetails> searchUsers(final String text) {
        return list(text)
                .map(KeycloakMapper::convertUserDetails)
                .collect(Collectors.toList());
    }

    UserDetails getUser(final String username, final String password) {
        try {
            return ofNullable(oidcService.login(username, password))
                    .map(token -> getUserDetails(username))
                    .orElse(null);
        } catch (CredentialsExpiredException e) {
            return getUserDetails(username);
        } catch (OidcException e) {
            return null;
        }
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

}
