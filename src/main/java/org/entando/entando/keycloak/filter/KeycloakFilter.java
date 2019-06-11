package org.entando.entando.keycloak.filter;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.user.UserDetails;
import org.apache.commons.lang3.StringUtils;
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

    private static final String SESSION_PARAM_STATE = "keycloak-plugin-state";
    private static final String SESSION_PARAM_REDIRECT = "keycloak-plugin-redirectTo";
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
        final String error = request.getParameter("error");
        final String errorDescription = request.getParameter("error_description");

        if (StringUtils.isNotEmpty(error)) {
            if ("unsupported_response_type".equals(error)) {
                log.error(errorDescription + " Please refer to the wiki " + wiki(KeycloakWiki.EN_APP_STANDARD_FLOW_DISABLED));
            }
            throw new EntandoTokenException(errorDescription, request, "guest");
        }

        if (authorizationCode != null) {
            if (stateParameter == null) {
                log.warn("State parameter not provided");
            } else if (!stateParameter.equals(session.getAttribute(SESSION_PARAM_STATE))) {
                log.warn("State parameter '{}' is different than generated '{}'", stateParameter, session.getAttribute(SESSION_PARAM_STATE));
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
                saveUserOnSession(request, user);
                log.info("Sucessfuly authenticated user {}", user.getUsername());
            } catch (HttpClientErrorException e) {
                if (HttpStatus.FORBIDDEN.equals(e.getStatusCode())) {
                    throw new RestServerError("Unable to validate token because the Client doesn't have permission to do so. " +
                            "Please refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_PUBLIC), e);
                }
                if (HttpStatus.BAD_REQUEST.equals(e.getStatusCode())) {
                    if (isInvalidCredentials(e)) {
                        throw new RestServerError("Unable to validate token because the Client credentials are invalid. " +
                                "Please refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_CREDENTIALS), e);
                    } else if (isInvalidCode(e)) {
                        redirect(request, response, session);
                        return;
                    }
                }
                throw new RestServerError("Unable to validate token", e);
            }

            redirect(request, response, session);
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

            session.setAttribute(SESSION_PARAM_STATE, state);
            response.sendRedirect(redirect);
        }
    }

    private void saveUserOnSession(final HttpServletRequest request, final UserDetails guestUser) {
        request.getSession().setAttribute("user", guestUser);
        request.getSession().setAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER, guestUser);
    }

    private void redirect(final HttpServletRequest request, final HttpServletResponse response, final HttpSession session) throws IOException {
        final String redirectPath = session.getAttribute(SESSION_PARAM_REDIRECT) != null
                ? session.getAttribute(SESSION_PARAM_REDIRECT).toString()
                : "/do/main";
        log.info("Redirecting user to {}", (request.getContextPath() + redirectPath));
        session.setAttribute(SESSION_PARAM_REDIRECT, null);
        response.sendRedirect(request.getContextPath() + redirectPath);
    }

    private boolean isInvalidCredentials(final HttpClientErrorException exception) {
        return StringUtils.contains(exception.getResponseBodyAsString(), "unauthorized_client");
    }

    private boolean isInvalidCode(final HttpClientErrorException exception) {
        return StringUtils.contains(exception.getResponseBodyAsString(), "invalid_grant");
    }

    @Override public void init(final FilterConfig filterConfig) {}
    @Override public void destroy() {}
}
