package org.entando.entando.keycloak;

import org.entando.entando.aps.servlet.security.KeycloakAuthenticationFilterTest;
import org.entando.entando.keycloak.interceptor.KeycloakOauth2InterceptorTest;
import org.entando.entando.keycloak.services.AuthenticationProviderManagerTest;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManagerTest;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@Suite.SuiteClasses({KeycloakAuthenticationFilterTest.class, KeycloakOauth2InterceptorTest.class, AuthenticationProviderManagerTest.class, KeycloakAuthorizationManagerTest.class})
@RunWith(Suite.class)
public class AllTests {
}
