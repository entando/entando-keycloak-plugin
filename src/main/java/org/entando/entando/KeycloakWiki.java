package org.entando.entando;

public class KeycloakWiki {

    private static final String WIKI_URL = "https://github.com/entando/entando-keycloak-plugin/wiki/Keycloak-common-issues";

    public static final String EN_APP_CLIENT_PUBLIC = "entando-app-client-is-public";
    public static final String EN_APP_STANDARD_FLOW_DISABLED = "standard-flow-disabled";
    public static final String EN_APP_CLIENT_CREDENTIALS = "invalid-client-credentials";
    public static final String EN_APP_CLIENT_FORBIDDEN = "entando-app-client-doesnt-have-roles-to-manage-users";

    public static String wiki(final String section) {
        return WIKI_URL + "#" + section;
    }

}
