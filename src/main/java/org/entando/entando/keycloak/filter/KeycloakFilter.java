package org.entando.entando.keycloak.filter;

import static org.entando.entando.KeycloakWiki.wiki;

import com.agiletec.aps.system.SystemConstants;
import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.agiletec.aps.system.services.user.UserDetails;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.UUID;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang3.StringUtils;
import org.entando.entando.KeycloakWiki;
import org.entando.entando.aps.servlet.security.GuestAuthentication;
import org.entando.entando.aps.system.exception.RestServerError;
import org.entando.entando.ent.exception.EntException;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.KeycloakJson;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.entando.entando.web.common.exceptions.EntandoTokenException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.client.HttpClientErrorException;

public class KeycloakFilter implements Filter {

    private final KeycloakConfiguration configuration;
    private final OpenIDConnectService oidcService;
    private final IAuthenticationProviderManager providerManager;
    private final KeycloakAuthorizationManager keycloakGroupManager;
    private final IUserManager userManager;
    private final ObjectMapper objectMapper;
    private final KeycloakJson keycloakJson;

    public static final String SESSION_PARAM_STATE = "keycloak-plugin-state";
    public static final String SESSION_PARAM_REDIRECT = "keycloak-plugin-redirectTo";
    public static final String SESSION_PARAM_ACCESS_TOKEN = "keycloak-plugin-access-token";
    public static final String SESSION_PARAM_REFRESH_TOKEN = "keycloak-plugin-refresh-token";

    private static final Logger log = LoggerFactory.getLogger(KeycloakFilter.class);

    public KeycloakFilter(final KeycloakConfiguration configuration,
                          final OpenIDConnectService oidcService,
                          final IAuthenticationProviderManager providerManager,
                          final KeycloakAuthorizationManager keycloakGroupManager,
                          final IUserManager userManager) {
        this.configuration = configuration;
        this.oidcService = oidcService;
        this.providerManager = providerManager;
        this.keycloakGroupManager = keycloakGroupManager;
        this.userManager = userManager;
        this.objectMapper = new ObjectMapper();
        this.keycloakJson = new KeycloakJson(configuration);
    }

    @Override
    public void doFilter(final ServletRequest servletRequest,
                         final ServletResponse servletResponse,
                         final FilterChain chain) throws IOException, ServletException {
        if (!configuration.isEnabled()) {
            chain.doFilter(servletRequest, servletResponse);
            return;
        }

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        if (!"/api".equals(request.getServletPath())) {
            final HttpSession session = request.getSession();
            final String accessToken = (String) session.getAttribute(SESSION_PARAM_ACCESS_TOKEN);

            if (accessToken != null && !isAccessTokenValid(accessToken) && !refreshToken(request)) {
                invalidateSession(request);
            }
        }

        switch (request.getServletPath()) {
            case "/do/login":
            case "/do/login.action":
                doLogin(request, response, chain);
                break;
            case "/do/logout":
            case "/do/logout.action":
                doLogout(request, response);
                break;
            case "/keycloak.json":
                returnKeycloakJson(response);
                break;
            default:
                HttpSession session = request.getSession(false);
                if (session != null) {
                    // Setting the current path as redirect parameter to ensure that a user is redirected back to the
                    // desired page after the authentication (in particular when using app-builder/admin-console integration)
                    session.setAttribute(SESSION_PARAM_REDIRECT, request.getRequestURI().substring(request.getContextPath().length()));
                }
                chain.doFilter(request, response);
        }
    }

    private void returnKeycloakJson(final HttpServletResponse response) throws IOException {
        response.setHeader("Content-Type", "application/json");
        objectMapper.writeValue(response.getOutputStream(), keycloakJson);
    }

    private boolean isAccessTokenValid(final String accessToken) {
        final ResponseEntity<AccessToken> tokenResponse = oidcService.validateToken(accessToken);
        return HttpStatus.OK.equals(tokenResponse.getStatusCode())
                && tokenResponse.getBody() != null
                && tokenResponse.getBody().isActive();
    }

    private boolean refreshToken(final HttpServletRequest request) {
        final HttpSession session = request.getSession();
        final String refreshToken = (String) session.getAttribute(SESSION_PARAM_REFRESH_TOKEN);

        if (refreshToken != null) {
            try {
                final ResponseEntity<AuthResponse> refreshResponse = oidcService.refreshToken(refreshToken);
                if (HttpStatus.OK.equals(refreshResponse.getStatusCode()) && refreshResponse.getBody() != null) {
                    session.setAttribute(SESSION_PARAM_ACCESS_TOKEN, refreshResponse.getBody().getAccessToken());
                    session.setAttribute(SESSION_PARAM_REFRESH_TOKEN, refreshResponse.getBody().getRefreshToken());
                    return true;
                }
            } catch (HttpClientErrorException e) {
                if (!HttpStatus.BAD_REQUEST.equals(e.getStatusCode())
                        || e.getResponseBodyAsString() == null
                        || !e.getResponseBodyAsString().contains("invalid_grant")) {
                    log.error("Something unexpected returned while trying to refresh token, the response was [{}] {}",
                            e.getStatusCode().toString(),
                            e.getResponseBodyAsString());
                }
            }
        }

        return false;
    }

    private void invalidateSession(final HttpServletRequest request) {
        final UserDetails guestUser = userManager.getGuestUser();
        final GuestAuthentication guestAuthentication = new GuestAuthentication(guestUser);
        SecurityContextHolder.getContext().setAuthentication(guestAuthentication);
        saveUserOnSession(request, guestUser);
        request.getSession().setAttribute(SESSION_PARAM_ACCESS_TOKEN, null);
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
                log.error("{}. For more details, refer to the wiki {}",
                        errorDescription,
                        wiki(KeycloakWiki.EN_APP_STANDARD_FLOW_DISABLED));
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
                session.setAttribute(SESSION_PARAM_ACCESS_TOKEN, responseEntity.getBody().getAccessToken());
                session.setAttribute(SESSION_PARAM_REFRESH_TOKEN, responseEntity.getBody().getRefreshToken());

                keycloakGroupManager.processNewUser(user);
                saveUserOnSession(request, user);
                log.info("Successfully authenticated user {}", user.getUsername());
            } catch (HttpClientErrorException e) {
                if (HttpStatus.FORBIDDEN.equals(e.getStatusCode())) {
                    throw new RestServerError("Unable to validate token because the Client in keycloak is configured as public. " +
                            "Please change the client on keycloak to confidential. " +
                            "For more details, refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_PUBLIC), e);
                }
                if (HttpStatus.BAD_REQUEST.equals(e.getStatusCode())) {
                    if (isInvalidCredentials(e)) {
                        throw new RestServerError("Unable to validate token because the Client credentials are invalid. " +
                                "Please make sure the credentials from keycloak is correctly set in the params or environment variable." +
                                "For more details, refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_CREDENTIALS), e);
                    } else if (isInvalidCode(e)) {
                        redirect(request, response, session);
                        return;
                    }
                }
                throw new RestServerError("Unable to validate token", e);
            } catch (EntException e) {
                throw new RestServerError("Unable to find user", e);
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

    private void saveUserOnSession(final HttpServletRequest request, final UserDetails user) {
        request.getSession().setAttribute("user", user);
        request.getSession().setAttribute(SystemConstants.SESSIONPARAM_CURRENT_USER, user);
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
