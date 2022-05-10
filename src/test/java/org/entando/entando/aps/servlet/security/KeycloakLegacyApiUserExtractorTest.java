package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.services.user.User;
import com.agiletec.aps.system.services.user.UserDetails;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import org.entando.entando.aps.system.services.oauth2.IApiOAuth2TokenManager;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.context.SecurityContextHolder;

@ExtendWith(MockitoExtension.class)
class KeycloakLegacyApiUserExtractorTest {

    @Mock
    private IApiOAuth2TokenManager tokenManager;

    @Mock
    private HttpServletRequest request;

    @InjectMocks
    private KeycloakLegacyApiUserExtractor userExtractor;

    @Test
    void getUser_keycloakEnabledAndAuthenticationSet_shouldReturnUser() throws Exception {

        User user = new User();
        user.setUsername("admin");
        UserAuthentication userAuthentication = new UserAuthentication(user);

        SecurityContextHolder.getContext().setAuthentication(userAuthentication);

        userExtractor.setKeycloakEnabled(true);
        UserDetails userDetails = userExtractor.getUser(request);

        Assertions.assertEquals("admin", userDetails.getUsername());
    }

    @Test
    void getUser_keycloakEnabledAndAuthenticationNotSet_shouldReturnNull() throws Exception {
        userExtractor.setKeycloakEnabled(true);
        UserDetails userDetails = userExtractor.getUser(request);
        Assertions.assertNull(userDetails);
    }

    @Test
    void getUser_keycloakDisabledAndInvalidToken_shouldReturnNull() throws Exception {
        Mockito.when(request.getHeaders("Authorization")).thenReturn(Collections.enumeration(List.of("Bearer <bearer>")));
        userExtractor.setKeycloakEnabled(false);
        UserDetails userDetails = userExtractor.getUser(request);
        Assertions.assertNull(userDetails);
    }
}
