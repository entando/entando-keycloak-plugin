package org.entando.entando.keycloak.filter;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.keycloak.services.AuthenticationProviderManager;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.entando.entando.web.common.exceptions.EntandoTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.UUID;

public class KeycloakFilter implements Filter {

    private final OpenIDConnectService oidcService;
    private final AuthenticationProviderManager providerManager;

    private static final Logger log = LoggerFactory.getLogger(KeycloakFilter.class);

    public KeycloakFilter(final OpenIDConnectService oidcService, final AuthenticationProviderManager providerManager) {
        this.oidcService = oidcService;
        this.providerManager = providerManager;
    }

    @Override
    public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain chain) throws IOException {
        log.info("performing action on filter");

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if ("/do/login".equals(request.getServletPath()) || "/do/login.action".equals(request.getServletPath())) {
            doLogin(request, response);
        } else if ("/do/logout.action".equals(request.getServletPath())) {
            doLogout(request, response);
        }
    }

    private void doLogout(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final HttpSession session = request.getSession();
        final String redirectUri = request.getRequestURL().toString().replace("/do/logout.action", "");
        session.invalidate();
        response.sendRedirect(oidcService.getLogoutUrl(redirectUri));
    }

    private void doLogin(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final HttpSession session = request.getSession();
        final String authorizationCode = request.getParameter("code");
        final String stateParameter = request.getParameter("state");
        final String redirectUri = request.getRequestURL().toString();

        if (authorizationCode != null) {
            if (stateParameter == null || !stateParameter.equals(session.getAttribute("state"))) {
                log.warn("State parameter not provided or different than generated");
            }

            try {
                final ResponseEntity<AuthResponse> responseEntity = oidcService.requestToken(authorizationCode, redirectUri);
                if (!HttpStatus.OK.equals(responseEntity.getStatusCode()) || responseEntity.getBody() == null) {
                    throw new EntandoTokenException("invalid or expired token", request, "guest");
                }

                final ResponseEntity<AccessToken> tokenResponse = oidcService.validateToken(responseEntity.getBody().getAccessToken());
                if (!HttpStatus.OK.equals(tokenResponse.getStatusCode())
                        || tokenResponse.getBody() == null || !tokenResponse.getBody().isActive()) {
                    throw new EntandoTokenException("invalid or expired token", request, "guest");
                }
                final UserDetails user = providerManager.getUser(tokenResponse.getBody().getUsername());
                session.setAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER, user);
                response.sendRedirect(request.getContextPath() + "/do/main");
                return;
            } catch (HttpClientErrorException e) {
                log.error("Error while trying to authenticate", e);
            }
        }

        final String state = UUID.randomUUID().toString();
        final String redirect = oidcService.getRedirectUrl(redirectUri, state);

        session.setAttribute("state", state);
        response.sendRedirect(redirect);
    }

    @Override public void init(final FilterConfig filterConfig) {}
    @Override public void destroy() {}
}
