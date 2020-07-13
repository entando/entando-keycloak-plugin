package org.entando.entando.keycloak.services.oidc;

import org.entando.entando.KeycloakWiki;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.exception.AccountDisabledException;
import org.entando.entando.keycloak.services.oidc.exception.CredentialsExpiredException;
import org.entando.entando.keycloak.services.oidc.exception.InvalidCredentialsException;
import org.entando.entando.keycloak.services.oidc.exception.OidcException;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Base64;

import static org.entando.entando.KeycloakWiki.wiki;

@Service("oidcService")
public class OpenIDConnectService {

    private static final Logger log = LoggerFactory.getLogger(OpenIDConnectService.class);

    private final KeycloakConfiguration configuration;
    private final String authToken;

    @Autowired
    public OpenIDConnectService(final KeycloakConfiguration configuration) {
        this.configuration = configuration;

        final String authData = configuration.getClientId() + ":" + configuration.getClientSecret();
        authToken = Base64.getEncoder().encodeToString(authData.getBytes());
    }

    public AuthResponse login(final String username, final String password) throws OidcException {
        try {
            final ResponseEntity<AuthResponse> response = request(username, password);
            return HttpStatus.OK.equals(response.getStatusCode()) ? response.getBody() : null;
        } catch (HttpClientErrorException e) {
            if (HttpStatus.BAD_REQUEST.equals(e.getStatusCode())) {
                if (e.getResponseBodyAsString().contains("Account is not fully set up")) {
                    throw new CredentialsExpiredException(e);
                }
                if (e.getResponseBodyAsString().contains("Account disabled")) {
                    throw new AccountDisabledException(e);
                }
                log.error("There was an error while trying to authenticate, " +
                        "this might indicate a misconfiguration on Keycloak {}",
                        e.getResponseBodyAsString(), e);
            }
            if (HttpStatus.UNAUTHORIZED.equals(e.getStatusCode())) {
                throw new InvalidCredentialsException(e);
            }
            throw new OidcException(e);
        }
    }

    public AuthResponse authenticateAPI() throws OidcException {
        try {
            final ResponseEntity<AuthResponse> response = requestClient();
            return HttpStatus.OK.equals(response.getStatusCode()) ? response.getBody() : null;
        } catch (HttpClientErrorException e) {
            if (HttpStatus.BAD_REQUEST.equals(e.getStatusCode()) && e.getResponseBodyAsString().contains("unauthorized_client")) {
                log.error("Unable to validate token because the Client credentials are invalid. " +
                          "Please make sure the credentials from keycloak is correctly set in the params or environment variable." +
                          "For more details, refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_CREDENTIALS), e);
                throw new InvalidCredentialsException(e);
            }
            if (HttpStatus.UNAUTHORIZED.equals(e.getStatusCode())) {
                log.error("There was an error while trying to load user because the " +
                        "client on Keycloak doesn't have permission to do that. " +
                        "The client needs to have Service Accounts enabled and the permission 'realm-admin' on client 'realm-management'. " +
                        "For more details, refer to the wiki " + wiki(KeycloakWiki.EN_APP_CLIENT_FORBIDDEN), e);
                throw new OidcException(e);
            }
            log.error("There was an error while trying to authenticate, " +
                            "this might indicate a misconfiguration on Keycloak {}",
                    e.getResponseBodyAsString(), e);
            throw new OidcException(e);
        }
    }

    public String getRedirectUrl(final String redirectUri, final String state) throws UnsupportedEncodingException {
        return new StringBuilder(configuration.getAuthUrl())
                .append("/realms/").append(configuration.getRealm())
                .append("/protocol/openid-connect/auth")
                .append("?response_type=code")
                .append("&client_id=").append(configuration.getClientId())
                .append("&redirect_uri=").append(URLEncoder.encode(redirectUri, "UTF-8"))
                .append("&state=").append(state)
                .append("&login=true")
                .append("&scope=openid")
                .toString();
    }

    private ResponseEntity<AuthResponse> request(final String username, final String password) {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createLoginRequest(username, password);
        final String url = String.format("%s/realms/%s/protocol/openid-connect/token", configuration.getAuthUrl(), configuration.getRealm());
        return restTemplate.postForEntity(url, req, AuthResponse.class);
    }

    private ResponseEntity<AuthResponse> requestClient() {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createApiAuthenticationRequest();
        final String url = String.format("%s/realms/%s/protocol/openid-connect/token", configuration.getAuthUrl(), configuration.getRealm());
        return restTemplate.postForEntity(url, req, AuthResponse.class);
    }

    private HttpEntity<MultiValueMap<String, String>> createLoginRequest(final String username, final String password) {
        final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("username", username);
        body.add("password", password);
        body.add("grant_type", "password");

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + authToken);
        return new HttpEntity<>(body, headers);
    }

    private HttpEntity<MultiValueMap<String, String>> createRefreshTokenRequest(final String refreshToken) {
        final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + authToken);
        return new HttpEntity<>(body, headers);
    }

    private HttpEntity<MultiValueMap<String, String>> createApiAuthenticationRequest() {
        final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "client_credentials");

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + authToken);
        return new HttpEntity<>(body, headers);
    }

    public ResponseEntity<AccessToken> validateToken(final String bearerToken) {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createValidationRequest(bearerToken);
        final String url = String.format("%s/realms/%s/protocol/openid-connect/token/introspect", configuration.getAuthUrl(), configuration.getRealm());
        return restTemplate.postForEntity(url, req, AccessToken.class);
    }

    public ResponseEntity<AuthResponse> refreshToken(final String refreshToken) {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createRefreshTokenRequest(refreshToken);
        final String url = String.format("%s/realms/%s/protocol/openid-connect/token", configuration.getAuthUrl(), configuration.getRealm());
        return restTemplate.postForEntity(url, req, AuthResponse.class);
    }

    public ResponseEntity<AuthResponse> requestToken(final String code, final String redirectUri) {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createAuthorizationCodeRequest(code, redirectUri);
        final String url = String.format("%s/realms/%s/protocol/openid-connect/token", configuration.getAuthUrl(), configuration.getRealm());
        return restTemplate.postForEntity(url, req, AuthResponse.class);
    }

    private HttpEntity<MultiValueMap<String, String>> createAuthorizationCodeRequest(final String code, final String redirectUri) {
        final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("grant_type", "authorization_code");

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", "Basic " + authToken);
        return new HttpEntity<>(body, headers);
    }

    private HttpEntity<MultiValueMap<String, String>> createValidationRequest(final String bearerToken) {
        final MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("token", bearerToken);
        body.add("client_id", configuration.getClientId());
        body.add("client_secret", configuration.getClientSecret());

        final HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        return new HttpEntity<>(body, headers);
    }

    public String getLogoutUrl(final String redirectUri) throws UnsupportedEncodingException {
        return new StringBuilder(configuration.getAuthUrl())
                .append("/realms/").append(configuration.getRealm())
                .append("/protocol/openid-connect/logout")
                .append("?redirect_uri=").append(URLEncoder.encode(redirectUri, "UTF-8"))
                .toString();
    }
}
