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

import java.util.Date;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that verifies Expiration Time of ID Token.
 * 
 *
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre
 * 
 *      <pre>
 *      AuthenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class, false) != null
 *      </pre>
 * 
 *      AND
 * 
 *      <pre>
 *      SocialUserOpenIdConnectContext.getOidcTokenResponse() != null
 *      </pre>
 */
@SuppressWarnings("rawtypes")
// TODO: Add preconditions to doc (suCtx.getOidcTokenResponse() etc)
public class ValidateOIDCIDTokenExpirationTime extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCIDTokenExpirationTime.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final SocialUserOpenIdConnectContext suCtx =
                authenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class);
        if (suCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        // Check time
        // The current time MUST be before the time represented by the exp
        Date currentDate = new Date();
        try {
            Date expDate = suCtx.getIDToken().getJWTClaimsSet().getExpirationTime();
            if (currentDate.after(expDate)) {
                log.error("{} Current date {} is past exp date {}", getLogPrefix(), currentDate, expDate);
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
        } catch (java.text.ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.trace("Leaving");
        return;
    }

}
