package org.entando.entando.keycloak.services.oidc.exception;

public class InvalidCredentialsException extends OidcException {

    public InvalidCredentialsException(final Throwable throwable) {
        super(throwable);
    }
}
