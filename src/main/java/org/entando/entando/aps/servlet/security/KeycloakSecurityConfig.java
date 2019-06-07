package org.entando.entando.aps.servlet.security;

import org.apache.commons.lang3.StringUtils;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Order(70)
@Configuration
@EnableWebSecurity
public class KeycloakSecurityConfig extends WebSecurityConfigurerAdapter {

    private final KeycloakAuthenticationFilter keycloakAuthenticationFilter;
    private final KeycloakConfiguration configuration;

    @Autowired
    public KeycloakSecurityConfig(final KeycloakAuthenticationFilter keycloakAuthenticationFilter, final KeycloakConfiguration configuration) {
        this.keycloakAuthenticationFilter = keycloakAuthenticationFilter;
        this.configuration = configuration;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        final HttpSecurity httpSecurity = http.addFilterBefore(keycloakAuthenticationFilter, BasicAuthenticationFilter.class)
                .csrf().disable();

        if (StringUtils.isNotEmpty(configuration.getSecureUris())) {
            final String[] urls = configuration.getSecureUris().split(",");
            ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry requests = httpSecurity.authorizeRequests();
            for (String url : urls) {
                if (StringUtils.isNotEmpty(url)) {
                    requests = requests.antMatchers(url).authenticated();
                }
            }
        }
    }

}