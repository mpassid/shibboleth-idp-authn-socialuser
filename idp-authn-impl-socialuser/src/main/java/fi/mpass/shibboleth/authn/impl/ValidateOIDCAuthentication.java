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

import java.text.ParseException;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that sets username principal.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class ValidateOIDCAuthentication extends AbstractValidationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCAuthentication.class);

    /** Avoid creating multiple principals. */
    private boolean avoidMultiplePrincipal;

    /** the subject received from id token. */
    private String oidcSubject;

    /**
     * In MFA use case prior authentication may have created a usernameprincipal already with value not matching to MFA.
     * 
     * @param avoid true if additional principals should be avoided.
     */
    public void setAvoidMultiplePrincipal(boolean avoid) {
        this.avoidMultiplePrincipal = avoid;
    }

    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        log.trace("{}: Prerequisities fulfilled to start doPreExecute", getLogPrefix());

        final SocialUserOpenIdConnectContext suCtx =
                authenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class);
        if (suCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return false;
        }

        if (suCtx.getIDToken() == null) {
            log.error("{} No ID Token in response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return false;
        }
        try {
            oidcSubject = suCtx.getIDToken().getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            log.error("{} unable to parse ID Token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return false;
        }

        if (oidcSubject == null) {
            log.error("{} Subject is null in ID Token response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");
        buildAuthenticationResult(profileRequestContext, authenticationContext);
        log.trace("Leaving");
        return;
    }

    @Override
    protected Subject populateSubject(Subject subject) {
        log.trace("Entering");
        if (avoidMultiplePrincipal && subject.getPrincipals().size() > 0) {
            log.debug("{} Subject contains already principal, not populated", getLogPrefix());

        } else {
            log.debug("{} Setting usernameprincipal to {}", getLogPrefix(), oidcSubject);
            subject.getPrincipals().add(new UsernamePrincipal(oidcSubject));

        }
        log.trace("Leaving");
        return subject;
    }

}
