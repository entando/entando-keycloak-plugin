package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.authorization.AuthorizationManager;
import com.agiletec.aps.system.services.group.Group;
import com.agiletec.aps.system.services.group.GroupManager;
import com.agiletec.aps.system.services.role.Role;
import com.agiletec.aps.system.services.role.RoleManager;
import com.agiletec.aps.system.services.user.UserDetails;
import com.google.common.collect.Sets;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;

import org.entando.entando.ent.exception.EntException;

@Service
public class KeycloakAuthorizationManager {

    private final KeycloakConfiguration configuration;
    private final AuthorizationManager authorizationManager;
    private final GroupManager groupManager;
    private final RoleManager roleManager;

    private static final int GROUP_POSITION = 0;
    private static final int ROLE_POSITION = 1;

    @Autowired
    public KeycloakAuthorizationManager(final KeycloakConfiguration configuration,
                                        final AuthorizationManager authorizationManager,
                                        final GroupManager groupManager,
                                        final RoleManager roleManager) {
        this.configuration = configuration;
        this.authorizationManager = authorizationManager;
        this.groupManager = groupManager;
        this.roleManager = roleManager;
    }

    public void processNewUser(final UserDetails user) {
        if (StringUtils.isEmpty(configuration.getDefaultAuthorizations())) {
            return;
        }
        final Set<String> defaultAuthorizations = Sets.newHashSet(configuration.getDefaultAuthorizations().split(","));
        final Set<String> userAuthorizations = user.getAuthorizations().stream().map(authorization -> {
            final String group = ofNullable(authorization.getGroup()).map(Group::getName).orElse("");
            final String role = ofNullable(authorization.getRole()).map(Role::getName).orElse("");
            return StringUtils.isEmpty(role) ? group : group + ":" + role;
        }).collect(Collectors.toSet());

        defaultAuthorizations.stream()
                .filter(defaultGroup -> !userAuthorizations.contains(defaultGroup))
                .forEach(authorization -> this.assignGroupToUser(authorization, user));
    }

    private void assignGroupToUser(final String authorization, final UserDetails user) {
        final String[] split = authorization.split(":");
        String groupName = split.length > 0 ? split[GROUP_POSITION] : "";
        String roleName = split.length > 1 ? split[ROLE_POSITION] : "";
        try {
            final Group group = ofNullable(groupName).filter(StringUtils::isNotEmpty)
                    .map(this::findOrCreateGroup).orElse(null);
            final Role role = ofNullable(roleName).filter(StringUtils::isNotEmpty)
                    .map(this::findOrCreateRole).orElse(null);
            groupName = ofNullable(group).map(Group::getName).orElse(null); // null or "" ?
            roleName = ofNullable(role).map(Role::getName).orElse(null); // null or "" ?
            authorizationManager.addUserAuthorization(user.getUsername(), groupName, roleName);
            user.addAuthorization(new Authorization(group, role));
        } catch (EntException e) {
            throw new RuntimeException(e);
        }
    }

    private Group findOrCreateGroup(final String groupName) {
        try {
            Group group = groupManager.getGroup(groupName);
            if (group == null) {
                group = new Group();
                group.setName(groupName);
                group.setDescription(groupName);
                groupManager.addGroup(group);
            }
            return group;
        } catch (EntException e) {
            throw new RuntimeException(e);
        }
    }

    private Role findOrCreateRole(final String roleName) {
        try {
            Role role = roleManager.getRole(roleName);
            if (role == null) {
                role = new Role();
                role.setName(roleName);
                role.setDescription(roleName);
                roleManager.addRole(role);
            }
            return role;
        } catch (EntException e) {
            throw new RuntimeException(e);
        }
    }

}
