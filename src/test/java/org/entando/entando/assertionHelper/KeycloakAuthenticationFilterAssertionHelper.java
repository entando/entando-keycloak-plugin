package org.entando.entando.assertionHelper;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.agiletec.aps.system.services.authorization.Authorization;
import com.agiletec.aps.system.services.group.Group;

import java.util.List;

public class KeycloakAuthenticationFilterAssertionHelper {

    /**
     *
     * @param authorization
     * @param permissionList
     */
    public static void assertKeycloakAuthorization(Authorization authorization, List<String> permissionList) {

        assertEquals(Group.ADMINS_GROUP_NAME, authorization.getGroup().getName());
        assertEquals("admin", authorization.getRole().getName());
        assertArrayEquals(permissionList.toArray(), authorization.getRole().getPermissions().toArray());
    }
}
