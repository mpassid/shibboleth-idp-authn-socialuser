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
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import fi.mpass.shibboleth.authn.SocialRedirectAuthenticator;
import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.SocialUserErrorIds;

/** Class for implementing OAuth2 authentication. */
public class OAuth2Identity extends AbstractOAuth2Identity implements SocialRedirectAuthenticator {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OAuth2Identity.class);

    @Override
    public void init() {
    }

    @Override
    public String getRedirectUrl(HttpServletRequest httpRequest) {
        log.trace("Entering");
        if (httpRequest == null) {
            log.trace("Leaving");
            return null;
        }
        State state = new State();
        httpRequest.getSession().setAttribute(SESSION_ATTR_STATE, state);
        String ret = null;
        try {
            AuthorizationRequest request =
                    new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), getClientId())
                            .scope(getScope()).state(state)
                            .redirectionURI(new URI(httpRequest.getRequestURL().toString()))
                            .endpointURI(getAuthorizationEndpoint()).build();
            ret = request.toURI().toString();
        } catch (URISyntaxException | SerializeException e) {
            log.error("Could not construct the redirect URL", e);
            log.trace("Leaving");
            return null;
        }
        log.trace("Leaving");
        return ret;

    }

    @Override
    public Subject getSubject(HttpServletRequest httpRequest) throws SocialUserAuthenticationException {
        log.trace("Entering");
        try {
            TokenRequest request = getTokenRequest(httpRequest);
            if (request == null) {
                log.debug("User is not authenticated yet");
                log.trace("Leaving");
                return null;
            }
            TokenResponse tokenResponse = TokenResponse.parse(request.toHTTPRequest().send());
            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                String error = errorResponse.getErrorObject().getCode();
                String errorDescription = errorResponse.getErrorObject().getDescription();
                if (errorDescription != null && !errorDescription.isEmpty()) {
                    error += " : " + errorDescription;
                }
                log.error("Error in the token response: {}", error);
                log.trace("Leaving");
                throw new SocialUserAuthenticationException(error, SocialUserErrorIds.EXCEPTION);
            }
            AccessTokenResponse tokenSuccessResponse = (AccessTokenResponse) tokenResponse;
            // Get the access token, the server may also return a refresh token
            AccessToken accessToken = tokenSuccessResponse.getTokens().getAccessToken();
            // try reading stuff from accesstoken
            Subject subject = new Subject();
            log.debug("claims from provider: {}", accessToken.toJSONString());
            parsePrincipalsFromClaims(subject, accessToken.toJSONObject());
            if (getUserinfoEndpoint() != null && !getUserinfoEndpoint().toString().isEmpty()) {
                // The protected resource / web API
                URL resourceURL = new URL(getUserinfoEndpoint().toString());
                // Open the connection and include the token
                URLConnection conn = resourceURL.openConnection();
                conn.setRequestProperty("Authorization", accessToken.toAuthorizationHeader());
                String userinfo = IOUtils.toString(conn.getInputStream());
                conn.getInputStream().close();
                try {
                    parsePrincipalsFromClaims(subject, JSONObjectUtils.parseJSONObject(userinfo));
                } catch (java.text.ParseException e) {
                    log.error("error parsing userinfo endpoint");
                    log.trace("Leaving");
                    throw new SocialUserAuthenticationException(e.getMessage(), SocialUserErrorIds.EXCEPTION);
                }
            }
            addDefaultPrincipals(subject);
            return subject;

        } catch (SerializeException | IOException | URISyntaxException | ParseException e) {
            log.error("Could not parse subject", e);
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(e.getMessage(), SocialUserErrorIds.EXCEPTION);
        }

    }

}
