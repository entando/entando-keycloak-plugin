package org.entando.entando.keycloak.services.keycloak;

import com.agiletec.aps.system.services.user.User;
import org.entando.entando.aps.system.services.group.model.GroupDto;
import org.entando.entando.aps.system.services.role.model.RoleDto;
import org.entando.entando.aps.system.services.user.IUserService;
import org.entando.entando.aps.system.services.user.model.UserDto;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

public class KeycloakMapper {

    public static UserDto convertUser(final UserRepresentation userRepresentation) {
        final User user = new User();
        user.setDisabled(!userRepresentation.isEnabled());
        user.setUsername(userRepresentation.getUsername());
        return new UserDto(user);
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
