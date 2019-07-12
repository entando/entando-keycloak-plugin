package org.entando.entando.keycloak.services.oidc.exception;

public class CredentialsExpiredException extends OidcException {

    public CredentialsExpiredException(final Throwable throwable) {
        super(throwable);
    }

}
