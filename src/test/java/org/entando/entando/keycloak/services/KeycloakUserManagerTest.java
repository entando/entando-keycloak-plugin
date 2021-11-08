package org.entando.entando.keycloak.services;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class KeycloakUserManagerTest {

    private KeycloakUserManager userManager = new KeycloakUserManager(null, null, null);

    @Test
    void initTest() {
        try {
            userManager.init();
        } catch (Exception e) {
            Assertions.fail();
        }
    }

    @Test
    void getParameterNamesTest() {
        assertThat(userManager.getParameterNames().isEmpty()).isTrue();
    }

}
