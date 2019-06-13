package org.entando.entando.keycloak.services;

import com.agiletec.aps.system.services.authorization.IAuthorizationManager;
import org.entando.entando.keycloak.KeycloakTestConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
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
import static org.entando.entando.keycloak.services.UserManagerIntegrationTest.activeUser;

public class OpenIDConnectServiceIntegrationTest {

    private static final String USERNAME = "iddqd";
    private static final String PASSWORD = "idkfa";

    @Mock
    private IAuthorizationManager authorizationManager;

    private OpenIDConnectService oidcService;
    private UserManager userManager;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        final KeycloakConfiguration configuration = KeycloakTestConfiguration.getConfiguration();
        final KeycloakService keycloakService = new KeycloakService(configuration);
        oidcService = new OpenIDConnectService(configuration);
        userManager = new UserManager(authorizationManager, keycloakService, oidcService);

        KeycloakTestConfiguration.deleteUsers();
    }

    @Test(expected = CredentialsExpiredException.class)
    public void testLoginWithExpiredCredentials() throws OidcException {
        userManager.addUser(activeUser(USERNAME, PASSWORD));
        oidcService.login(USERNAME, PASSWORD);
    }

    @Test(expected = InvalidCredentialsException.class)
    public void testLoginWithInvalidCredentials() throws OidcException {
        userManager.addUser(activeUser(USERNAME, PASSWORD));
        oidcService.login(USERNAME, "woodstock");
    }

    @Test
    public void testLoginSuccessfulAndTokenValidation() throws OidcException {
        userManager.addUser(activeUser(USERNAME, "woodstock"));
        userManager.changePassword(USERNAME, PASSWORD);
        final AuthResponse response = oidcService.login(USERNAME, PASSWORD);
        assertThat(response.getAccessToken()).isNotEmpty();

        final ResponseEntity<AccessToken> validationResponse = oidcService.validateToken(response.getAccessToken());
        assertThat(validationResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

}
