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
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.social.connect.Connection;
import org.springframework.social.google.api.Google;
import org.springframework.social.google.connect.GoogleConnectionFactory;
import org.springframework.social.oauth2.AccessGrant;

import fi.mpass.shibboleth.authn.SocialRedirectAuthenticator;
import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;

/** Implements Google authentication. */
public class GoogleIdentity extends AbstractSpringSocialOAuth2Identity implements SocialRedirectAuthenticator {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(GoogleIdentity.class);

    /** Google Connection factory. */
    private GoogleConnectionFactory connectionFactory;

    /*
     * (non-Javadoc)
     * 
     * @see fi.csc.idp.authn.impl.SocialRedirectAuthenticator#init()
     */
    @Override
    public synchronized void init() {
        log.trace("Entering");
        if (connectionFactory == null) {
            connectionFactory = new GoogleConnectionFactory(getAppId(), getAppSecret());
            setOauthOperations(connectionFactory.getOAuthOperations());
        }
        log.trace("Leaving");
    }

    /*
     * (non-Javadoc)
     * 
     * @see fi.csc.idp.authn.impl.SocialRedirectAuthenticator#getSubject()
     */
    @Override
    public Subject getSubject(HttpServletRequest httpRequest) throws SocialUserAuthenticationException {
        log.trace("Entering");
        AccessGrant accessGrant = null;
        accessGrant = getAccessGrant(httpRequest);
        if (accessGrant == null) {
            // not authenticated
            log.trace("Leaving");
            return null;
        }
        Connection<Google> connection = connectionFactory.createConnection(accessGrant);
        log.trace("Leaving");
        return getSubject(connection.getKey(), connection.fetchUserProfile());
    }

}
