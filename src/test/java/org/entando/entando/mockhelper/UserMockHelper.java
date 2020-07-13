package org.entando.entando.mockhelper;

import com.agiletec.aps.system.services.user.User;

public class UserMockHelper {

    public static final String USERNAME = "JohnLackland";


    /**
     * @return
     */
    public static User mockUser() {

        User user = new User();
        user.setUsername(USERNAME);
        return user;
    }
}
