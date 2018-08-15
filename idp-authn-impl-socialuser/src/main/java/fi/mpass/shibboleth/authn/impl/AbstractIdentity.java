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
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.principal.UsernamePrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.social.connect.ConnectionKey;
import org.springframework.social.connect.UserProfile;

import fi.mpass.shibboleth.authn.SocialAuthenticationRequest;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal.Types;

/** Implements methods common to all social user identity methods. */
public abstract class AbstractIdentity {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractIdentity.class);

    /** Authentication request. */
    private SocialAuthenticationRequest socialAuthenticationRequest;

    /**
     * Setter for authentication request.
     * 
     * @param authRequest Authentication request
     */
    public void setAuthenticationRequest(SocialAuthenticationRequest authRequest) {
        log.trace("Entering & Leaving");
        this.socialAuthenticationRequest = authRequest;
    }

    /**
     * Getter for authentication request.
     * 
     * @return Authentication request
     */
    protected SocialAuthenticationRequest getAuthenticationRequest() {
        log.trace("Entering & Leaving");
        return this.socialAuthenticationRequest;
    }

    /**
     * Returns user Subject based on key and profile.
     * 
     * @param key Connection Key of the user
     * @param profile Profile of the user
     * @return User Subject
     */
    public Subject getSubject(ConnectionKey key, UserProfile profile) {
        log.trace("Entering");
        Subject subject = new Subject();
        String userId = key.getProviderUserId();
        subject.getPrincipals().add(new UsernamePrincipal(userId));
        subject.getPrincipals().add(new SocialUserPrincipal(Types.userId, userId));
        subject.getPrincipals().add(new SocialUserPrincipal(Types.providerId, key.getProviderId()));
        subject.getPrincipals().add(new SocialUserPrincipal(Types.email, profile.getEmail()));
        subject.getPrincipals().add(new SocialUserPrincipal(Types.firstName, profile.getFirstName()));
        subject.getPrincipals().add(new SocialUserPrincipal(Types.lastName, profile.getLastName()));
        log.trace("Leaving");
        return subject;

    }

}
