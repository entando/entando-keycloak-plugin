package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import org.entando.entando.keycloak.KeycloakTestConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectorService;
import org.entando.entando.keycloak.services.oidc.exception.CredentialsExpiredException;
import org.entando.entando.keycloak.services.oidc.exception.InvalidCredentialsException;
import org.entando.entando.keycloak.services.oidc.exception.OidcException;
import org.entando.entando.keycloak.services.oidc.model.AccessToken;
import org.entando.entando.keycloak.services.oidc.model.AuthResponse;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.entando.entando.keycloak.services.UserServiceIntegrationTest.activeUser;

public class OpenIDConnectorServiceIntegrationTest {

    private static final String USERNAME = "iddqd";
    private static final String PASSWORD = "idkfa";

    @Mock
    private IAuthorizationManager authorizationManager;

    private OpenIDConnectorService oidcService;
    private UserService userService;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        final KeycloakConfiguration configuration = KeycloakTestConfiguration.getConfiguration();
        final KeycloakService keycloakService = new KeycloakService(configuration);
        oidcService = new OpenIDConnectorService(configuration);
        userService = new UserService(authorizationManager, keycloakService, oidcService);

        KeycloakTestConfiguration.deleteUsers();
    }

    @Test(expected = CredentialsExpiredException.class)
    public void testLoginWithExpiredCredentials() throws OidcException {
        userService.addUser(activeUser(USERNAME, PASSWORD));
        oidcService.login(USERNAME, PASSWORD);
    }

    @Test(expected = InvalidCredentialsException.class)
    public void testLoginWithInvalidCredentials() throws OidcException {
        userService.addUser(activeUser(USERNAME, PASSWORD));
        oidcService.login(USERNAME, "woodstock");
    }

    @Test
    public void testLoginSuccessfulAndTokenValidation() throws OidcException {
        userService.addUser(activeUser(USERNAME, "woodstock"));
        userService.updateUserPassword(USERNAME, PASSWORD);
        final AuthResponse response = oidcService.login(USERNAME, PASSWORD);
        assertThat(response.getAccessToken()).isNotEmpty();

        final ResponseEntity<AccessToken> validationResponse = oidcService.validateToken(response.getAccessToken());
        assertThat(validationResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

}
