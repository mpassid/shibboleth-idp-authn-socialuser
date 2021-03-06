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
import java.util.Date;

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.annotation.Duration;
import net.shibboleth.utilities.java.support.annotation.constraint.NonNegative;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.joda.time.DateTime;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An action that verifies Authentication Time of ID Token.
 * 
 * @event {@link net.shibboleth.idp.authn.AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class ValidateOIDCIDTokenAuthenticationTime extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCIDTokenAuthenticationTime.class);

    /**
     * Clock skew - milliseconds before a lower time bound, or after an upper time bound, to consider still acceptable
     * Default value: 3 minutes.
     */
    @Duration
    @NonNegative
    private long clockSkew;

    /**
     * Amount of time in milliseconds for which a forced authentication is valid after it is issued. Default value: 30
     * seconds.
     */
    @Duration
    @NonNegative
    private long authnLifetime;

    /**
     * Constructor.
     */
    public ValidateOIDCIDTokenAuthenticationTime() {
        super();
        setClockSkew(60 * 3 * 1000);
        setAuthnLifetime(30 * 1000);
    }

    /**
     * Get the clock skew.
     * 
     * @return the clock skew
     */
    @NonNegative
    public long getClockSkew() {
        return clockSkew;
    }

    /**
     * Set the clock skew.
     * 
     * @param skew clock skew to set
     */
    public void setClockSkew(@Duration @NonNegative final long skew) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        clockSkew = Constraint.isGreaterThanOrEqual(0, skew, "Clock skew must be greater than or equal to 0");
    }

    /**
     * Gets the amount of time, in milliseconds, for which a forced authentication is valid.
     * 
     * @return amount of time, in milliseconds, for which a forced authentication is valid
     */
    @NonNegative
    public long getAuthnLifetime() {
        return authnLifetime;
    }

    /**
     * Sets the amount of time, in milliseconds, for which a forced authentication is valid.
     * 
     * @param lifetime amount of time, in milliseconds, for which a forced authentication is valid
     */
    public synchronized void setAuthnLifetime(@Duration @NonNegative final long lifetime) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        authnLifetime =
                Constraint.isGreaterThanOrEqual(0, lifetime, "Authn lifetime must be greater than or equal to 0");
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        if (!authenticationContext.isForceAuthn()) {
            log.trace("Leaving");
            return;
        }
        // If we have forced authentication, we will check for authentication age
        final SocialUserOpenIdConnectContext suCtx =
                authenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class);
        if (suCtx == null) {
            log.error("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        final Date authTimeDate;
        try {
            authTimeDate = suCtx.getIDToken().getJWTClaimsSet().getDateClaim("auth_time");
        } catch (ParseException e) {
            log.error("{} Error parsing id token", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (authTimeDate == null) {
            log.error("{} max age set but no auth_time received", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        final DateTime authTime = new DateTime(authTimeDate);
        final DateTime now = new DateTime();
        final DateTime latestValid = now.plus(getClockSkew());
        final DateTime expiration = authTime.plus(getClockSkew() + getAuthnLifetime());

        // Check authentication wasn't performed in the future
        // Based on org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler
        if (authTime.isAfter(latestValid)) {
            log.warn("{} Authentication time was not yet valid: time was {}, latest valid is: {}", getLogPrefix(),
                    authTime, latestValid);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        // Check authentication time has not expired
        if (expiration.isBefore(now)) {
            log.warn("{} Authentication time was expired: time was '{}', expired at: '{}', current time: '{}'",
                    getLogPrefix(), authTime, expiration, now);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.trace("Leaving");
    }

}