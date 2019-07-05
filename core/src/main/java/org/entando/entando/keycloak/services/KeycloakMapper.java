package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.user.User;
import org.entando.entando.keycloak.services.oidc.model.UserRepresentation;

import static java.util.Optional.ofNullable;

class KeycloakMapper {

    static User convertUserDetails(final UserRepresentation userRepresentation) {
        final boolean credentialsExpired = ofNullable(userRepresentation.getRequiredActions())
                .filter(actions -> actions.contains("UPDATE_PASSWORD")).isPresent();
        final User user = credentialsExpired ? newUserCredentialsExpired() : new User();
        user.setDisabled(!userRepresentation.isEnabled());
        user.setUsername(userRepresentation.getUsername());
        return user;
    }

    private static User newUserCredentialsExpired() {
        return new User() {
            {
                setMaxMonthsSinceLastAccess(-1);
                setMaxMonthsSinceLastPasswordChange(-1);
            }

            @Override
            public boolean isCredentialsNotExpired() {
                return false;
            }
        };
    }

}
