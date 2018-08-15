/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package fi.mpass.shibboleth.authn.principal.impl;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.Principal;
import java.util.regex.Pattern;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonString;
import javax.json.JsonStructure;
import javax.json.stream.JsonGenerator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Strings;

import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;
import net.shibboleth.idp.authn.principal.AbstractPrincipalSerializer;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Serializer for {@link SocialUserPrincipal}. Based on {@link GenericPrincipalSerializer}.
 */
public class SocialUserPrincipalSerializer extends AbstractPrincipalSerializer<String> {

    /** Field name of principal type. */
    @Nonnull
    @NotEmpty
    private static final String PRINCIPAL_TYPE_FIELD = "socialTyp";

    /** Field name of principal name. */
    @Nonnull
    @NotEmpty
    private static final String PRINCIPAL_NAME_FIELD = "socialNam";

    /** Pattern used to determine if input is supported. */
    @Nonnull
    private static final Pattern JSON_PATTERN = Pattern.compile("^\\{\"socialTyp\":.*,\"socialNam\":.*\\}$");

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SocialUserPrincipalSerializer.class);

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull final Principal principal) {
        return principal instanceof SocialUserPrincipal;
    }

    /** {@inheritDoc} */
    @Override
    @Nonnull
    @NotEmpty
    public String serialize(@Nonnull final Principal principal) throws IOException {
        log.trace("Attempting to serialize type={}, name={}", ((SocialUserPrincipal) principal).getType(),
                ((SocialUserPrincipal) principal).getName());
        final StringWriter sink = new StringWriter(32);
        final JsonGenerator gen = getJsonGenerator(sink);
        final String name = principal.getName() == null ? "" : principal.getName();
        gen.writeStartObject().write(PRINCIPAL_TYPE_FIELD, ((SocialUserPrincipal) principal).getType())
                .write(PRINCIPAL_NAME_FIELD, name).writeEnd();
        gen.close();
        log.trace("Successfully built serialized principal: {}", sink.toString());
        return sink.toString();
    }

    /** {@inheritDoc} */
    @Override
    public boolean supports(@Nonnull @NotEmpty final String value) {
        return JSON_PATTERN.matcher(value).matches();
    }

    /** {@inheritDoc} */
    @Override
    @Nullable
    public SocialUserPrincipal deserialize(@Nonnull @NotEmpty final String value) throws IOException {
        log.trace("Attempting to deserialize {}", value);
        final JsonReader reader = getJsonReader(new StringReader(value));
        JsonStructure st = null;
        try {
            log.debug("Reading the JSON structure");
            st = reader.read();
        } finally {
            reader.close();
        }
        if (!(st instanceof JsonObject)) {
            log.warn("Could not parse a JSON object from serialized value", value);
            throw new IOException("Found invalid data structure while parsing SocialUserPrincipal");
        }
        log.debug("JSON structure successfully read");
        final JsonString name = ((JsonObject) st).getJsonString(PRINCIPAL_NAME_FIELD);
        final JsonString type = ((JsonObject) st).getJsonString(PRINCIPAL_TYPE_FIELD);
        if (name != null && type != null) {
            final String socialType = type.getString();
            if (!Strings.isNullOrEmpty(socialType)) {
                return new SocialUserPrincipal(socialType, name.getString());
            }
        }
        return null;
    }

}
