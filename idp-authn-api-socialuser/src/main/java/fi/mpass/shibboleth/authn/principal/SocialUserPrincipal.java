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

package fi.mpass.shibboleth.authn.principal;

import java.security.Principal;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Social user principal implementation. */
public class SocialUserPrincipal implements Principal {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SocialUserPrincipal.class);

    /** Type of the principal. */
    public enum Types {
        /** Id for the social authentication provider e.g. 'facebook'. */
        providerId,
        /** UserId provided by the authentication provider. */
        userId,
        /** Email provided by the authentication provider. */
        email,
        /** First Name provided by the authentication provider. */
        firstName,
        /** Last Name provided by the authentication provider. */
        lastName,
        /** Dispay Name provided by the authentication provider. */
        displayName
    };

    /** The value. */
    @Nullable
    private String value;

    /** The Type. */
    @Nonnull
    private String type;

    /** The Type. */
    @Nullable
    private Types typesType;

    /**
     * Constructor.
     * 
     * @param suType SocialUserPrincipal type
     * @param suValue SocialUserPrincipal Value
     */
    public SocialUserPrincipal(@Nonnull String suType, String suValue) {
        log.trace("Entering");
        value = suValue;
        type = suType;
        try {
            typesType = Types.valueOf(type);
        } catch (IllegalArgumentException | NullPointerException e) {
            // This is normal operation, custom principal type
        }
        log.trace("Entering");

    }

    /**
     * Constructor.
     * 
     * @param suType SocialUserPrincipal type
     * @param suValue SocialUserPrincipal Value
     */
    public SocialUserPrincipal(@Nonnull Types suType, String suValue) {
        log.trace("Entering");
        value = suValue;
        type = suType.name();
        typesType = suType;
        log.trace("Leaving");
    }

    @Override
    public String getName() {
        log.trace("Entering & Leaving");
        return value;
    }

    /**
     * Type of the principal.
     * 
     * @return String Type as string
     */
    public String getType() {
        log.trace("Entering & Leaving");
        return type;
    }

    /**
     * Type of the principal.
     * 
     * @return enum Type
     */
    public Types getTypesType() {
        log.trace("Entering & Leaving");
        return typesType;
    }

    /**
     * Value of the principal.
     * 
     * @return String Value
     */
    public String getValue() {
        log.trace("Entering & Leaving");
        return value;
    }
}
