package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.User;
import org.entando.entando.aps.system.services.user.model.UserDto;
import org.keycloak.representations.idm.UserRepresentation;

class KeycloakMapper {

    static User convertUserDetails(final UserRepresentation userRepresentation) {
        final User user = new User();
        user.setDisabled(!userRepresentation.isEnabled());
        user.setUsername(userRepresentation.getUsername());
        return user;
    }

    static UserDto convertUser(final UserRepresentation userRepresentation) {
        return new UserDto(convertUserDetails(userRepresentation));
    }

}
