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

import javax.annotation.Nonnull;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;

/**
 * An action that calls the token endpoint and populates the information to {@link SocialUserOpenIdConnectContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event {@link AuthnEventIds#INVALID_AUTHN_CTX}
 */
@SuppressWarnings("rawtypes")
public class GetOIDCTokenResponse extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(GetOIDCTokenResponse.class);

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
        if (suCtx.getIDToken() != null) {
            log.debug("id token exists already, no need to fetch it from token endpoint");
            log.trace("Leaving");
            return;
        }
        final AuthenticationSuccessResponse response = suCtx.getAuthenticationSuccessResponse();
        if (response == null) {
            log.info("{} No oidc authentication success response", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        final AuthorizationCode code = response.getAuthorizationCode();
        final AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, suCtx.getRedirectURI());
        final ClientAuthentication clientAuth = new ClientSecretBasic(suCtx.getClientID(), suCtx.getClientSecret());
        log.debug("{} Using the following token endpoint URI: {}", getLogPrefix(),
                suCtx.getoIDCProviderMetadata().getTokenEndpointURI());
        final TokenRequest tokenRequest =
                new TokenRequest(suCtx.getoIDCProviderMetadata().getTokenEndpointURI(), clientAuth, codeGrant);
        final OIDCTokenResponse oidcTokenResponse;
        try {
            oidcTokenResponse = (OIDCTokenResponse) OIDCTokenResponseParser.parse(tokenRequest.toHTTPRequest().send());
            if (!oidcTokenResponse.indicatesSuccess()) {
                log.warn("{} Token response does not indicate success", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
                log.trace("Leaving");
                return;
            }

        } catch (SerializeException | IOException | ParseException e) {
            log.error("{} token response failed", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        log.debug("Storing oidc token response to context: {}", oidcTokenResponse.toJSONObject().toJSONString());
        log.trace("Leaving");
    }
}
