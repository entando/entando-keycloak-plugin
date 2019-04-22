package org.entando.entando.keycloak.interceptor;

import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectorService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.web.common.annotation.RestAccessControl;
import org.entando.entando.web.common.exceptions.EntandoAuthorizationException;
import org.entando.entando.web.common.exceptions.EntandoTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeycloakOauth2Interceptor extends HandlerInterceptorAdapter {

    private static final Logger log = LoggerFactory.getLogger(KeycloakOauth2Interceptor.class);

    @Autowired private KeycloakConfiguration configuration;
    @Autowired private OpenIDConnectorService oidcService;
    @Autowired private IAuthenticationProviderManager authenticationProviderManager;
    @Autowired private IAuthorizationManager authorizationManager;

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) {
        if (handler instanceof HandlerMethod) {
            final HandlerMethod method = (HandlerMethod) handler;
            final RestAccessControl accessControl = method.getMethodAnnotation(RestAccessControl.class);
            if (accessControl != null) {
                final String permission = accessControl.permission();
                validateToken(request, permission);
            }
        }
        return true;
    }

    private void validateToken(final HttpServletRequest request, final String permission) {
        final String authorization = request.getHeader("Authorization");

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            log.warn("No bearer token provided");
            throw new EntandoTokenException("no token found", request, "guest");
        }

        final String bearerToken = authorization.substring("Bearer ".length());
        final ResponseEntity<AccessToken> resp = oidcService.validateToken(bearerToken);
        final AccessToken accessToken = resp.getBody();

        if (HttpStatus.NOT_FOUND.equals(resp.getStatusCode()) || HttpStatus.UNAUTHORIZED.equals(resp.getStatusCode())) {
            log.error("Invalid OAuth2 configuration: {}", configuration);
            throw new EntandoTokenException("Invalid OAuth configuration", request, "guest");
        }

        if (accessToken == null || !accessToken.isActive()) {
            throw new EntandoTokenException("invalid or expired token", request, "guest");
        }

        try {
            final UserDetails user = authenticationProviderManager.getUser(accessToken.getUsername());
            if (!authorizationManager.isAuthOnPermission(user, permission)) {
                log.warn("User {} is missing the required permission {}", accessToken.getUsername(), permission);
                throw new EntandoAuthorizationException(null, request, accessToken.getUsername());
            }

            request.getSession().setAttribute("user", user);

            log.info("User authenticated");
        } catch (ApsSystemException e) {
            log.error("System exception", e);
            throw new EntandoTokenException("error parsing OAuth parameters", request, accessToken.getUsername());
        }
    }

}
