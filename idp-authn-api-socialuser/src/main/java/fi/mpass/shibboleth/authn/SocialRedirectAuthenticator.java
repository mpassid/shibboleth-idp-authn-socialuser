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

package fi.mpass.shibboleth.authn;

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

/** Interface for performing social authentication. */
public interface SocialRedirectAuthenticator {

    /**
     * Module initialization, must be called first.
     * 
     */
    public void init();

    /**
     * If user is not authenticated, user must be redirected to returned url.
     * 
     * @param httpRequest the request
     *
     * @return The url to redirect the user to.
     */
    public abstract String getRedirectUrl(HttpServletRequest httpRequest);

    /**
     * Method return user as Subject.
     *
     * @param httpRequest the request
     * 
     * @return The user subject. If null, user is not authenticated.
     * @throws SocialUserAuthenticationException if authentication sequence is not successful
     */
    public abstract Subject getSubject(HttpServletRequest httpRequest) throws SocialUserAuthenticationException;

}
