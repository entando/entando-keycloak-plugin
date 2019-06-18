package org.entando.entando.keycloak.adapter;

import org.entando.entando.keycloak.interceptor.KeycloakOauth2Interceptor;
import org.entando.entando.web.common.interceptor.EntandoOauth2Interceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.Nullable;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class EntandoOauth2InterceptorAdapter extends EntandoOauth2Interceptor {

    @Autowired
    private KeycloakOauth2Interceptor keycloak;

    private boolean keycloakEnabled;

    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        return keycloakEnabled
                ? keycloak.preHandle(request, response, handler)
                : super.preHandle(request, response, handler);
    }

    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable ModelAndView modelAndView) throws Exception {
        if (keycloakEnabled) keycloak.postHandle(request, response, handler, modelAndView);
        else super.postHandle(request, response, handler, modelAndView);
    }

    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, @Nullable Exception ex) throws Exception {
        if (keycloakEnabled) keycloak.afterCompletion(request, response, handler, ex);
        else super.afterCompletion(request, response, handler, ex);
    }

    public void afterConcurrentHandlingStarted(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        if (keycloakEnabled) keycloak.afterConcurrentHandlingStarted(request, response, handler);
        else super.afterConcurrentHandlingStarted(request, response, handler);
    }

    public void setKeycloakEnabled(final boolean keycloakEnabled) {
        this.keycloakEnabled = keycloakEnabled;
    }

}
