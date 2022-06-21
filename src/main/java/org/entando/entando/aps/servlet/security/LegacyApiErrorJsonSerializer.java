package org.entando.entando.aps.servlet.security;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import org.entando.entando.aps.system.services.api.model.ApiError;

public class LegacyApiErrorJsonSerializer extends JsonSerializer<ApiError> {

    @Override
    public void serialize(ApiError apiError, JsonGenerator jsonGenerator, SerializerProvider serializerProvider)
            throws IOException {
        jsonGenerator.writeStartObject();
        jsonGenerator.writeObjectFieldStart("error");
        serializerProvider.defaultSerializeField("code", apiError.getCode(), jsonGenerator);
        serializerProvider.defaultSerializeField("message", apiError.getMessage(), jsonGenerator);
        serializerProvider.defaultSerializeField("status", apiError.getStatus(), jsonGenerator);
        jsonGenerator.writeEndObject();
        jsonGenerator.writeEndObject();
    }
}
