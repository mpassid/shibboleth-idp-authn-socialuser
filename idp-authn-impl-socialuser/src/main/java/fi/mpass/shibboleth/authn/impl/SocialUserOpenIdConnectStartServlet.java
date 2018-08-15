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

import java.io.IOException;

import javax.servlet.annotation.WebServlet;
import javax.annotation.Nonnull;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Extracts Social identity and places it in a request attribute to be used by the IdP's external authentication
 * interface.
 */
@WebServlet(name = "SocialUserOpenIdConnectStartServlet", urlPatterns = {"/Authn/SocialUserOpenIdConnectStart"})
public class SocialUserOpenIdConnectStartServlet extends HttpServlet {

    /** Prefix for the session attribute ids. */
    public static final String SESSION_ATTR_PREFIX =
            "fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectStartServlet.";

    /** Session attribute id for flow conversation key. */
    public static final String SESSION_ATTR_FLOWKEY = SESSION_ATTR_PREFIX + "key";

    /** Session attribute id for {@link SocialUserOpenIdConnectContext}. */
    public static final String SESSION_ATTR_SUCTX = SESSION_ATTR_PREFIX + "socialUserOpenIdConnectContext";

    /** Serial UID. */
    private static final long serialVersionUID = -3162157736238514852L;

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SocialUserOpenIdConnectStartServlet.class);

    /** Constructor. */
    public SocialUserOpenIdConnectStartServlet() {
    }

    /** {@inheritDoc} */
    @Override
    public void init(final ServletConfig config) throws ServletException {
        super.init(config);
    }

    /** {@inheritDoc} */
    @Override
    protected void service(final HttpServletRequest httpRequest, final HttpServletResponse httpResponse)
            throws ServletException, IOException {
        log.trace("Entering");
        try {
            final String key = ExternalAuthentication.startExternalAuthentication(httpRequest);
            httpRequest.getSession().setAttribute(SESSION_ATTR_FLOWKEY, key);

            @SuppressWarnings("rawtypes") final ProfileRequestContext profileRequestContext =
                    (ProfileRequestContext) httpRequest.getAttribute(ProfileRequestContext.BINDING_KEY);
            if (profileRequestContext == null) {
                throw new ExternalAuthenticationException("Could not access profileRequestContext from the request");
            }
            final AuthenticationContext authenticationContext =
                    (AuthenticationContext) profileRequestContext.getSubcontext(AuthenticationContext.class);
            if (authenticationContext == null) {
                throw new ExternalAuthenticationException("Could not find AuthenticationContext from the request");
            }
            final SocialUserOpenIdConnectContext socialUserOpenIdConnectContext =
                    (SocialUserOpenIdConnectContext) authenticationContext
                            .getSubcontext(SocialUserOpenIdConnectContext.class);
            if (socialUserOpenIdConnectContext == null) {
                throw new ExternalAuthenticationException(
                        "Could not find SocialUserOpenIdConnectContext from the request");
            }
            httpRequest.getSession().setAttribute(SESSION_ATTR_SUCTX, socialUserOpenIdConnectContext);
            log.debug("Redirecting user browser to {}", socialUserOpenIdConnectContext.getAuthenticationRequestURI());
            httpResponse.sendRedirect(socialUserOpenIdConnectContext.getAuthenticationRequestURI().toString());
        } catch (ExternalAuthenticationException e) {
            log.error("Error processing external authentication request", e);
            log.trace("Leaving");
            throw new ServletException("Error processing external authentication request", e);
        }
        log.trace("Leaving");
    }
}
