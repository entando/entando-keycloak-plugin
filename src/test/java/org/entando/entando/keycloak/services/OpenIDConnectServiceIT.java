package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import org.entando.entando.keycloak.KeycloakTestConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.entando.entando.keycloak.services.oidc.exception.CredentialsExpiredException;
import org.entando.entando.keycloak.services.oidc.exception.InvalidCredentialsException;
import org.entando.entando.keycloak.services.oidc.exception.OidcException;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.mockito.Mock;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.entando.entando.keycloak.services.UserManagerIT.activeUser;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OpenIDConnectServiceIT {

    private static final String USERNAME = "iddqd";
    private static final String PASSWORD = "idkfa";

    @Mock
    private IAuthorizationManager authorizationManager;

    private OpenIDConnectService oidcService;
    private KeycloakUserManager userManager;

    @BeforeEach
    void setUp() {
        final KeycloakConfiguration configuration = KeycloakTestConfiguration.getConfiguration();
        oidcService = new OpenIDConnectService(configuration);
        final KeycloakService keycloakService = new KeycloakService(configuration, oidcService);
        userManager = new KeycloakUserManager(authorizationManager, keycloakService, oidcService);

        KeycloakTestConfiguration.deleteUsers();
    }

    @Test
    void testLoginWithExpiredCredentials() throws OidcException {
        userManager.addUser(activeUser(USERNAME, PASSWORD));
        Assertions.assertThrows(CredentialsExpiredException.class, () -> {
            oidcService.login(USERNAME, PASSWORD);
        });
    }

    @Test
    void testLoginWithInvalidCredentials() throws OidcException {
        userManager.addUser(activeUser(USERNAME, PASSWORD));
        Assertions.assertThrows(InvalidCredentialsException.class, () -> {
            oidcService.login(USERNAME, "woodstock");
        });
    }

    @Test
    void testLoginSuccessfulAndTokenValidation() throws OidcException {
        userManager.addUser(activeUser(USERNAME, "woodstock"));
        userManager.changePassword(USERNAME, PASSWORD);
        final AuthResponse response = oidcService.login(USERNAME, PASSWORD);
        assertThat(response.getAccessToken()).isNotEmpty();

        final ResponseEntity<AccessToken> validationResponse = oidcService.validateToken(response.getAccessToken());
        assertThat(validationResponse.getStatusCode()).isEqualTo(HttpStatus.OK);

        final ResponseEntity<AuthResponse> refreshTokenResponse = oidcService.refreshToken(response.getRefreshToken());
        assertThat(refreshTokenResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshTokenResponse.getBody()).isNotNull();
        assertThat(refreshTokenResponse.getBody().getAccessToken()).isNotEmpty();
    }

    @Test
    void testLoginSuccessfulAndTokenRevoked() throws OidcException {
        userManager.addUser(activeUser(USERNAME, "woodstock"));
        userManager.changePassword(USERNAME, PASSWORD);

        final AuthResponse response = oidcService.login(USERNAME, PASSWORD);
        assertThat(response.getAccessToken()).isNotEmpty();

        KeycloakTestConfiguration.logoutAllSessions();

        final ResponseEntity<AccessToken> validationResponse = oidcService.validateToken(response.getAccessToken());
        assertThat(validationResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(validationResponse.getBody()).isNotNull();
        assertThat(validationResponse.getBody().isActive()).isFalse();

        final CompletableFuture<Void> future = CompletableFuture
                .runAsync(() -> oidcService.refreshToken(response.getRefreshToken()));
        while(!future.isDone());
        assertThat(future)
                .hasFailedWithThrowableThat()
                .isInstanceOf(HttpClientErrorException.class)
                .withFailMessage("400 Bad Request");
    }

}
