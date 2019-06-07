package org.entando.entando.keycloak.interceptor;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.apache.commons.lang3.StringUtils;
import org.entando.entando.aps.servlet.security.UserAuthentication;
import org.entando.entando.web.common.annotation.RestAccessControl;
import org.entando.entando.web.common.exceptions.EntandoAuthorizationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class KeycloakOauth2Interceptor extends HandlerInterceptorAdapter {

    private static final Logger log = LoggerFactory.getLogger(KeycloakOauth2Interceptor.class);

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
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof UserAuthentication)) {
            throw new EntandoAuthorizationException("invalid authentication", request, "guest");
        }
        final UserDetails user = (UserDetails) authentication.getDetails();
        if (StringUtils.isNotEmpty(permission) && !authorizationManager.isAuthOnPermission(user, permission)) {
            log.warn("User {} is missing the required permission {}", user.getUsername(), permission);
            throw new EntandoAuthorizationException(null, request, user.getUsername());
        }
    }

    public void setAuthorizationManager(final IAuthorizationManager authorizationManager) {
        this.authorizationManager = authorizationManager;
    }
}
