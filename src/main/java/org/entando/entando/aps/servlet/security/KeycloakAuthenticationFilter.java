package org.entando.entando.aps.servlet.security;

import static java.util.Optional.ofNullable;
import static org.entando.entando.aps.servlet.security.KeycloakSecurityConfig.API_PATH;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.group.Group;
import com.agiletec.aps.system.services.role.Permission;
import com.agiletec.aps.system.services.role.Role;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.TokenRoles;
import org.entando.entando.web.common.model.RestError;
import org.entando.entando.web.common.model.RestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.stereotype.Service;

@Service
public class KeycloakAuthenticationFilter extends AbstractAuthenticationProcessingFilter implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    private final ObjectMapper objectMapper;
    private final KeycloakConfiguration configuration;
    private final IUserManager userManager;
    private final OpenIDConnectService oidcService;
    private final IAuthenticationProviderManager authenticationProviderManager;
    private final KeycloakAuthorizationManager keycloakGroupManager;

    @Autowired
    public KeycloakAuthenticationFilter(final KeycloakConfiguration configuration,
                                        final IUserManager userManager,
                                        final OpenIDConnectService oidcService,
                                        final IAuthenticationProviderManager authenticationProviderManager,
                                        final KeycloakAuthorizationManager keycloakGroupManager) {
        super("/api/**");
        this.objectMapper = new ObjectMapper();
        this.configuration = configuration;
        this.keycloakGroupManager = keycloakGroupManager;
        this.setAuthenticationManager(authenticationProviderManager);
        this.userManager = userManager;
        this.oidcService = oidcService;
        this.authenticationProviderManager = authenticationProviderManager;
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) throws AuthenticationException {
        final String authorization = request.getHeader("Authorization");

        if (authorization == null || !authorization.matches("^[Bb]earer .*")) {
            final UserDetails guestUser = userManager.getGuestUser();
            final GuestAuthentication guestAuthentication = new GuestAuthentication(guestUser);
            setUserOnContext(request, guestUser, guestAuthentication);
            return guestAuthentication;
        }

        final String bearerToken = authorization.substring("Bearer ".length());
        final ResponseEntity<AccessToken> resp = oidcService.validateToken(bearerToken);
        final AccessToken accessToken = resp.getBody();

        if (HttpStatus.NOT_FOUND.equals(resp.getStatusCode()) || HttpStatus.UNAUTHORIZED.equals(resp.getStatusCode())) {
            log.error("Invalid OAuth2 configuration");
            throw new BadCredentialsException("Invalid OAuth configuration");
        }

        if (accessToken == null || !accessToken.isActive()) {
            throw new NonceExpiredException("Invalid or expired token");
        }

        try {
            final UserDetails user = authenticationProviderManager.getUser(accessToken.getUsername());
            final UserAuthentication userAuthentication = new UserAuthentication(user);

            ofNullable(accessToken.getResourceAccess())
                    .map(access -> access.get(configuration.getClientId()))
                    .map(TokenRoles::getRoles)
                    .ifPresent(permissions -> addAuthorizations(permissions, user));

            setUserOnContext(request, user, userAuthentication);

            // TODO optimise to not check on every request
            keycloakGroupManager.processNewUser(user);

            return userAuthentication;
        } catch (EntException e) {
            log.error("System exception", e);
            throw new InsufficientAuthenticationException("error parsing OAuth parameters");
        }
    }

    private void addAuthorizations(final List<String> permissions, final UserDetails user) {

        permissions.stream()
                .filter(permission -> permission.equals(Permission.SUPERUSER))
                .findFirst()
                .ifPresent(permission -> {

                    final Role role = new Role();
                    role.setName("admin");
                    role.addPermission(Permission.SUPERUSER);

                    final Group group = new Group();
                    group.setName(Group.ADMINS_GROUP_NAME);

                    user.addAuthorization(new Authorization(group, role));
                });
    }

    private void setUserOnContext(HttpServletRequest request, UserDetails user, Authentication authentication) {
        if (API_PATH.equals(request.getServletPath())) {
            request.setAttribute("user", user);
        } else {
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.getSession().setAttribute("user", user);
            request.getSession().setAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER, user);
        }
    }

    @Override
    protected void successfulAuthentication(final HttpServletRequest request,
                                            final HttpServletResponse response,
                                            final FilterChain chain,
                                            final Authentication authResult) throws IOException, ServletException {
        chain.doFilter(request, response);
    }

    @Override
    protected void unsuccessfulAuthentication(final HttpServletRequest request,
                                              final HttpServletResponse response,
                                              final AuthenticationException failed) throws IOException {
        this.onAuthenticationFailure(request, response, failed);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        final RestResponse<Void, Void> restResponse = new RestResponse<>(null, null);
        restResponse.addError(new RestError(HttpStatus.UNAUTHORIZED.toString(), exception.getMessage()));

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.addHeader("Content-Type", "application/json");
        response.getOutputStream().println(objectMapper.writeValueAsString(restResponse));
    }
}