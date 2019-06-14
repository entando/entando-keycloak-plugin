package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.exception.ApsSystemException;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
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
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.stereotype.Service;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Service
public class KeycloakAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(KeycloakAuthenticationFilter.class);

    private final IUserManager userManager;
    private final OpenIDConnectService oidcService;
    private final IAuthenticationProviderManager authenticationProviderManager;
    private final KeycloakAuthorizationManager keycloakGroupManager;

    @Autowired
    public KeycloakAuthenticationFilter(final IUserManager userManager,
                                        final OpenIDConnectService oidcService,
                                        final IAuthenticationProviderManager authenticationProviderManager,
                                        final KeycloakAuthorizationManager keycloakGroupManager) {
        super("/api/**");
        this.keycloakGroupManager = keycloakGroupManager;
        this.setAuthenticationManager(authenticationProviderManager);
        this.userManager = userManager;
        this.oidcService = oidcService;
        this.authenticationProviderManager = authenticationProviderManager;
    }

    @Override
    public Authentication attemptAuthentication(final HttpServletRequest request, final HttpServletResponse response) throws AuthenticationException {
        final String authorization = request.getHeader("Authorization");

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            final UserDetails guestUser = userManager.getGuestUser();
            final GuestAuthentication guestAuthentication = new GuestAuthentication(guestUser);
            SecurityContextHolder.getContext().setAuthentication(guestAuthentication);
            saveUserOnSession(request, guestUser);
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

            SecurityContextHolder.getContext().setAuthentication(userAuthentication);
            saveUserOnSession(request, user);

            // TODO optimise to not check on every request
            keycloakGroupManager.processNewUser(user);

            return userAuthentication;
        } catch (ApsSystemException e) {
            log.error("System exception", e);
            throw new InsufficientAuthenticationException("error parsing OAuth parameters");
        }
    }

    private void saveUserOnSession(final HttpServletRequest request, final UserDetails guestUser) {
        request.getSession().setAttribute("user", guestUser);
        request.getSession().setAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER, guestUser);
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
                                              final AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }
}