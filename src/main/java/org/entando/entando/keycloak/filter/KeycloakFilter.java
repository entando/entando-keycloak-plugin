package org.entando.entando.keycloak.filter;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.user.UserDetails;
import org.entando.entando.KeycloakWiki;
import org.entando.entando.aps.system.exception.RestServerError;
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

import static org.entando.entando.KeycloakWiki.wiki;

public class KeycloakFilter implements Filter {

    private final OpenIDConnectService oidcService;
    private final AuthenticationProviderManager providerManager;

    private static final String SESSION_PARAM_REDIRECT = "redirectTo";
    private static final Logger log = LoggerFactory.getLogger(KeycloakFilter.class);

    public KeycloakFilter(final OpenIDConnectService oidcService, final AuthenticationProviderManager providerManager) {
        this.oidcService = oidcService;
        this.providerManager = providerManager;
    }

    @Override
    public void doFilter(final ServletRequest servletRequest,
                         final ServletResponse servletResponse,
                         final FilterChain chain) throws IOException, ServletException {
        log.info("performing action on filter");

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if ("/do/login".equals(request.getServletPath()) || "/do/login.action".equals(request.getServletPath())) {
            doLogin(request, response, chain);
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

    private void doLogin(final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain) throws IOException, ServletException {
        final HttpSession session = request.getSession();
        final String authorizationCode = request.getParameter("code");
        final String stateParameter = request.getParameter("state");
        final String redirectUri = request.getRequestURL().toString();
        final String redirectTo = request.getParameter("redirectTo");

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
            } catch (HttpClientErrorException e) {
                if (HttpStatus.FORBIDDEN.equals(e.getStatusCode())) {
                    throw new RestServerError("Unable to validate token because the Client doesn't have permission to do so. " +
                            "Please refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_PUBLIC), e);
                }
                if (HttpStatus.BAD_REQUEST.equals(e.getStatusCode())) {
                    throw new RestServerError("Unable to validate token because the Client credentials are invalid. " +
                            "Please refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_CREDENTIALS), e);
                }
                throw new RestServerError("Unable to validate token", e);
            }

            final String redirectPath = session.getAttribute(SESSION_PARAM_REDIRECT) != null
                    ? session.getAttribute("redirectTo").toString()
                    : "/do/main";
            session.setAttribute(SESSION_PARAM_REDIRECT, null);
            response.sendRedirect(request.getContextPath() + redirectPath);

            return;
        } else {
            final String path = request.getRequestURL().toString().replace(request.getServletPath(), "");
            if (redirectTo != null){
                final String redirect = redirectTo.replace(path, "");
                if (!redirect.startsWith("/")) {
                    throw new EntandoTokenException("Invalid redirect", request, "guest");
                }
                session.setAttribute(SESSION_PARAM_REDIRECT, redirect);
            }
        }

        final Object user = session.getAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER);

        if (user != null && !((UserDetails)user).getUsername().equals("guest")) {
            chain.doFilter(request, response);
        } else {
            final String state = UUID.randomUUID().toString();
            final String redirect = oidcService.getRedirectUrl(redirectUri, state);

            session.setAttribute("state", state);
            response.sendRedirect(redirect);
        }
    }

    @Override public void init(final FilterConfig filterConfig) {}
    @Override public void destroy() {}
}
