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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.SocialLoginHintCoder;

/**
 * An action that extracts a login hint from an HTTP form body or query string, and sets it to the
 * {@link AuthenticationContext}.
 * 
 */
@SuppressWarnings("rawtypes")
public class ExtractLoginHintFromFormRequest extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ExtractLoginHintFromFormRequest.class);

    /** Parameter name for login hint. */
    @Nonnull
    @NotEmpty
    private List<String> loginHintFieldNames;

    /** coder for coding login hint. */
    private SocialLoginHintCoder socialLoginHintCoder;

    /**
     * Set the login hint parameter names.
     * 
     * @param fieldNames the login hint field names
     */
    public void setLoginHintFieldName(@Nonnull @NotEmpty final List<String> fieldNames) {
        log.trace("Entering");
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        loginHintFieldNames = fieldNames;
        log.trace("Leaving");
    }

    /**
     * Set the login hint coder.
     * 
     * @param loginHintCoder the login hint coder
     */
    public void setLoginHintCoder(SocialLoginHintCoder loginHintCoder) {
        log.trace("Entering");
        this.socialLoginHintCoder = loginHintCoder;
        log.trace("Leaving");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        log.trace("Entering");
        authenticationContext.setHintedName(null);

        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        if (loginHintFieldNames == null || loginHintFieldNames.size() == 0) {
            log.warn("No login hint field names defined", getLogPrefix());
            log.trace("Leaving");
            return;
        }

        if (socialLoginHintCoder == null && loginHintFieldNames.size() > 1) {
            log.debug("Multiple login hints require encoder", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        Map<String, String> loginHints = new HashMap<String, String>();
        for (String loginHintFieldName : loginHintFieldNames) {
            final String loginHint = request.getParameter(loginHintFieldName);
            if (loginHint == null || loginHint.isEmpty()) {
                log.debug("{} No required login hint " + loginHint + " in request", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
            loginHints.put(loginHintFieldName, loginHint);
        }
        authenticationContext.setHintedName(getLoginHint(loginHints));
        log.trace("Leaving");

    }

    /**
     * Returns encoded login hint if encoder exists, otherwise it returns one noncoded value from the map (assumes there
     * is only one).
     * 
     * @param loginHints map
     * @return login hint string
     */
    private String getLoginHint(Map<String, String> loginHints) {
        log.trace("Entering");
        if (socialLoginHintCoder == null) {
            for (Map.Entry<String, String> entry : loginHints.entrySet()) {
                /* We return any value */
                log.trace("Leaving");
                return entry.getValue();

            }
        }
        log.trace("Leaving");
        return socialLoginHintCoder.encode(loginHints);
    }
}