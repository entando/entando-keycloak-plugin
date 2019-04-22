package org.entando.entando.keycloak.services.oidc;

import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;

@Service
public class OpenIDConnectorService {

    private static final Logger log = LoggerFactory.getLogger(OpenIDConnectorService.class);

    private final KeycloakConfiguration configuration;
    private final String authToken;

    @Autowired
    public OpenIDConnectorService(final KeycloakConfiguration configuration) {
        this.configuration = configuration;

        final String authData = configuration.getClientId() + ":" + configuration.getClientSecret();
        authToken = Base64.getEncoder().encodeToString(authData.getBytes());
    }

    public AuthResponse login(final String username, final String password) {
        try {
            final ResponseEntity<AuthResponse> response = request(username, password);
            return HttpStatus.OK.equals(response.getStatusCode()) ? response.getBody() : null;
        } catch (HttpClientErrorException e) {
            if (HttpStatus.BAD_REQUEST.equals(e.getStatusCode())) {
                log.error("There was an error while trying to authenticate, " +
                        "this might indicate a misconfiguration on Keycloak {}",
                        e.getResponseBodyAsString(), e);
                throw e;
            }
            if (HttpStatus.UNAUTHORIZED.equals(e.getStatusCode())) {
                // invalid credentials
                return null;
            }
            throw e;
        }
    }

    private ResponseEntity<AuthResponse> request(final String username, final String password) {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createLoginRequest(username, password);
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

    public ResponseEntity<AccessToken> validateToken(final String bearerToken) {
        final RestTemplate restTemplate = new RestTemplate();
        final HttpEntity<MultiValueMap<String, String>> req = createValidationRequest(bearerToken);
        final String url = String.format("%s/realms/%s/protocol/openid-connect/token/introspect", configuration.getAuthUrl(), configuration.getRealm());
        return restTemplate.postForEntity(url, req, AccessToken.class);
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

}
