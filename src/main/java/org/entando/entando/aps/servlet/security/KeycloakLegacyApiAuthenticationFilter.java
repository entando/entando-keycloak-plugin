package org.entando.entando.aps.servlet.security;

import com.agiletec.aps.system.services.user.IAuthenticationProviderManager;
import com.agiletec.aps.system.services.user.IUserManager;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;
import com.fasterxml.jackson.dataformat.xml.ser.ToXmlGenerator;
import com.fasterxml.jackson.module.jaxb.JaxbAnnotationModule;
import java.io.IOException;
import java.util.List;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import org.entando.entando.aps.system.services.api.IApiErrorCodes;
import org.entando.entando.aps.system.services.api.model.ApiError;
import org.entando.entando.aps.system.services.api.model.StringApiResponse;
import org.entando.entando.aps.system.services.api.server.IResponseBuilder;
import org.entando.entando.keycloak.services.KeycloakAuthorizationManager;
import org.entando.entando.keycloak.services.KeycloakConfiguration;
import org.entando.entando.keycloak.services.oidc.OpenIDConnectService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class KeycloakLegacyApiAuthenticationFilter extends KeycloakAuthenticationFilter {

    private final XmlMapper xmlMapper;
    private final ObjectMapper objectMapper;

    @Autowired
    public KeycloakLegacyApiAuthenticationFilter(
            KeycloakConfiguration configuration,
            IUserManager userManager,
            OpenIDConnectService oidcService,
            IAuthenticationProviderManager authenticationProviderManager,
            KeycloakAuthorizationManager keycloakGroupManager) {
        super(configuration, userManager, oidcService, authenticationProviderManager, keycloakGroupManager);
        setFilterProcessesUrl("/legacyapi/**");

        this.xmlMapper = new XmlMapper();
        xmlMapper.registerModule(new JaxbAnnotationModule());
        xmlMapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        xmlMapper.configure(ToXmlGenerator.Feature.WRITE_XML_DECLARATION, true);

        this.objectMapper = new ObjectMapper();

        SimpleModule customErrorSerializer = new SimpleModule();
        customErrorSerializer.addSerializer(ApiError.class, new LegacyApiErrorJsonSerializer());
        objectMapper.registerModule(customErrorSerializer);

        objectMapper.registerModule(new JaxbAnnotationModule());
        objectMapper.configure(SerializationFeature.INDENT_OUTPUT, true);
        objectMapper.configure(SerializationFeature.WRAP_ROOT_VALUE, true);
        objectMapper.configure(MapperFeature.USE_WRAPPER_NAME_AS_PROPERTY_NAME, true);
        objectMapper.configure(SerializationFeature.WRITE_SINGLE_ELEM_ARRAYS_UNWRAPPED, true);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception) throws IOException {

        List<MediaType> acceptedMediaTypes = MediaType.parseMediaTypes(request.getHeader("Accept"));

        MediaType contentType = MediaType.APPLICATION_XML;
        if (acceptedMediaTypes.contains(MediaType.APPLICATION_JSON)) {
            contentType = MediaType.APPLICATION_JSON;
        }
        response.addHeader("Content-Type", contentType.toString());

        response.setStatus(HttpStatus.UNAUTHORIZED.value());

        StringApiResponse legacyApiResponse = new StringApiResponse();
        ApiError error = new ApiError(IApiErrorCodes.API_AUTHORIZATION_REQUIRED, exception.getMessage(), Response.Status.UNAUTHORIZED);
        legacyApiResponse.addError(error);
        legacyApiResponse.setResult(IResponseBuilder.FAILURE);

        response.getOutputStream().println(contentType == MediaType.APPLICATION_XML ?
                xmlMapper.writeValueAsString(legacyApiResponse) :
                objectMapper.writeValueAsString(legacyApiResponse));
    }
}
