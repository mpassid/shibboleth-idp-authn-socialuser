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

package fi.mpass.shibboleth.authn.impl;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.SocialAuthenticationRequest;

/**
 * This class extracts request parameters from http request attributes set by shibboleth idp 3.
 */
public class ShibServletSocialAuthenticationRequestImpl implements SocialAuthenticationRequest {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ShibServletSocialAuthenticationRequestImpl.class);

    /** passive attribute name. */
    @Nonnull
    private String passiveAttribute;

    /** forcedauth attribute name. */
    @Nonnull
    private String forcedAuthAttribute;

    /** profileRequestContext attribute name. */
    @Nonnull
    private String profileRequestContextAttribute;

    /**
     * Setter for passive attribute name.
     * 
     * @param passive name for passive attribute
     */
    public void setPassiveAttribute(String passive) {
        log.trace("Entering & Leaving");
        this.passiveAttribute = passive;
    }

    /**
     * Setter for passive attribute name.
     * 
     * @param forcedAuth name for forcedAuth attribute
     */
    public void setForcedAuthAttribute(String forcedAuth) {
        log.trace("Entering & Leaving");
        this.forcedAuthAttribute = forcedAuth;
    }

    /**
     * Setter for context attribute name.
     * 
     * @param context name for context attribute
     */
    public void setProfileRequestContextAttribute(String context) {
        log.trace("Entering & Leaving");
        this.profileRequestContextAttribute = context;
    }

    /**
     * If request requires passive authentication.
     * 
     * @param httpRequest the request
     *
     * @return true if passive is required, otherwise false
     */
    @Override
    public boolean isPassive(HttpServletRequest httpRequest) {
        log.trace("Entering");
        Boolean isPassive = (Boolean) httpRequest.getAttribute(passiveAttribute);
        if (isPassive != null && isPassive) {
            log.trace("Leaving");
            return true;
        }
        log.trace("Leaving");
        return false;
    }

    /**
     * If request requires passive authentication.
     * 
     * @param httpRequest the request
     *
     * @return true if passive is required, otherwise false
     */
    @Override
    public boolean isForcedAuth(HttpServletRequest httpRequest) {
        log.trace("Entering");
        Boolean isForcedAuth = (Boolean) httpRequest.getAttribute(forcedAuthAttribute);
        if (isForcedAuth != null && isForcedAuth) {
            log.trace("Leaving");
            return true;
        }
        log.trace("Leaving");
        return false;
    }

    /**
     * request login hint if that exists.
     * 
     * @param httpRequest the request
     *
     * @return login hint if that exists, otherwise null
     */
    @Override
    public String getLoginHint(HttpServletRequest httpRequest) {
        log.trace("Entering");
        @SuppressWarnings("rawtypes") ProfileRequestContext profileRequestContext =
                (ProfileRequestContext) httpRequest.getAttribute(profileRequestContextAttribute);
        if (profileRequestContext == null) {
            log.trace("Leaving");
            return null;
        }
        AuthenticationContext authenticationContext =
                (AuthenticationContext) profileRequestContext.getSubcontext(AuthenticationContext.class);
        if (authenticationContext == null) {
            log.trace("Leaving");
            return null;
        }
        log.trace("Leaving");
        return authenticationContext.getHintedName();
    }

}
