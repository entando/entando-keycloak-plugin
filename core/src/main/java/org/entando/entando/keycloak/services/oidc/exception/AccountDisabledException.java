package org.entando.entando.keycloak.services.oidc.exception;

public class AccountDisabledException extends OidcException {

    public AccountDisabledException(final Throwable throwable) {
        super(throwable);
    }
}
