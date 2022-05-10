package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import javax.servlet.http.HttpServletRequest;
import org.entando.entando.aps.system.services.api.model.ApiException;
import org.entando.entando.aps.system.services.api.server.LegacyApiUserExtractor;
import org.entando.entando.aps.system.services.oauth2.IApiOAuth2TokenManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class KeycloakLegacyApiUserExtractor extends LegacyApiUserExtractor {

    private boolean keycloakEnabled;

    public KeycloakLegacyApiUserExtractor(IUserManager userManager,
            IAuthorizationManager authorizationManager,
            IApiOAuth2TokenManager tokenManager) {
        super(userManager, authorizationManager, tokenManager);
    }

    @Override
    public UserDetails getUser(HttpServletRequest request) throws ApiException {
        if (!keycloakEnabled) {
            return super.getUser(request);
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof UserAuthentication) {
            return (UserDetails) authentication.getDetails();
        }
        return  null;
    }

    public void setKeycloakEnabled(final boolean keycloakEnabled) {
        this.keycloakEnabled = keycloakEnabled;
    }
}
