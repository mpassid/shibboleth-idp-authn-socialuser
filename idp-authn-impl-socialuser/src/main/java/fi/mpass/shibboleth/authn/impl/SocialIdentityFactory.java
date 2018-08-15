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

import java.util.Map;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.SocialRedirectAuthenticator;

/** Returns correct SocialRedirectAuthenticator implementation. */
public class SocialIdentityFactory {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SocialIdentityFactory.class);

    /** map of supported implementations. */
    @Nonnull
    private Map<String, Object> socialImplBeans;

    /**
     * Sets map of supported implementations.
     * 
     * @param suSocialImplBeans map of supported implementations
     */
    public void setSocialImplBeans(Map<String, Object> suSocialImplBeans) {
        this.socialImplBeans = suSocialImplBeans;
    }

    /**
     * Returns correct Authenticator based on request.
     * 
     * @param httpRequest request
     * @return SocialRedirectAuthenticator implementation
     */
    public SocialRedirectAuthenticator getAuthenticator(final HttpServletRequest httpRequest) {
        if (socialImplBeans.containsKey(httpRequest.getRequestURI())) {
            SocialRedirectAuthenticator sra =
                    (SocialRedirectAuthenticator) socialImplBeans.get(httpRequest.getRequestURI());
            sra.init();
            return sra;
        }
        return null;
    }

}
