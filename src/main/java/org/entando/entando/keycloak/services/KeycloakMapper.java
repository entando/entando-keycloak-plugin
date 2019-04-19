package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.aps.system.services.group.model.GroupDto;
import org.entando.entando.aps.system.services.role.model.RoleDto;
import org.entando.entando.aps.system.services.user.model.UserDto;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public class KeycloakMapper {

    public static User convertUserDetails(final UserRepresentation userRepresentation) {
        final User user = new User();
        user.setDisabled(!userRepresentation.isEnabled());
        user.setUsername(userRepresentation.getUsername());
        return user;
    }

    public static UserDto convertUser(final UserRepresentation userRepresentation) {
        return new UserDto(convertUserDetails(userRepresentation));
    }

    public static GroupDto convertGroup(final GroupRepresentation groupRepresentation) {
        final GroupDto group = new GroupDto();
        group.setCode(groupRepresentation.getId());
        group.setName(groupRepresentation.getName());
        return group;
    }

    public static RoleDto convertRole(final GroupRepresentation groupRepresentation) {
        final RoleDto role = new RoleDto();
        role.setCode(groupRepresentation.getId());
        role.setName(groupRepresentation.getName());
        return role;
    }

}
