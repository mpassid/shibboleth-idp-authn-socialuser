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

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

/**
 * An action that creates a {@link SocialUserOpenIdConnectContext}, and attaches it to the
 * {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 */
@SuppressWarnings("rawtypes")
public class ValidateOIDCAuthenticationResponse extends AbstractExtractionAction {

    /*
     * A DRAFT PROTO CLASS!! NOT TO BE USED YET.
     * 
     * FINAL GOAL IS TO MOVE FROM CURRENT OIDC TO MORE WEBFLOW LIKE IMPLEMENTATION.
     */

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCAuthenticationResponse.class);

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("Entering");

        final SocialUserOpenIdConnectContext suCtx =
                authenticationContext.getSubcontext(SocialUserOpenIdConnectContext.class);
        if (suCtx == null) {
            log.info("{} Not able to find su oidc context", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }

        if (suCtx.getAuthenticationResponseURI() == null) {
            log.info("{} response uri not set", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.debug("Validating response {}", suCtx.getAuthenticationResponseURI().toString());
        AuthenticationResponse response = null;
        try {
            response = AuthenticationResponseParser.parse(suCtx.getAuthenticationResponseURI());
        } catch (ParseException e) {
            log.info("{} response parsing failed", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        if (!response.indicatesSuccess()) {
            log.trace("Leaving");
            AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) response;
            String error = errorResponse.getErrorObject().getCode();
            String errorDescription = errorResponse.getErrorObject().getDescription();
            if (StringSupport.trimOrNull(errorDescription) != null) {
                error += " : " + errorDescription;
            }
            log.trace("Leaving");
            log.info("{} response indicated error: {}", getLogPrefix(), error);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;
        // implicit and hybrid flows return id token in response.
        suCtx.setIDToken(successResponse.getIDToken());
        State state = suCtx.getState();
        if (state == null || !state.equals(successResponse.getState())) {
            log.info("{} state mismatch:", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
        }

        suCtx.setAuthenticationSuccessResponse(successResponse);
        log.trace("Leaving");
        return;
    }

}
