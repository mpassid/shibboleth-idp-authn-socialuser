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
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.SerializeException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.token.AccessToken;

import fi.mpass.shibboleth.authn.SocialRedirectAuthenticator;
import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.SocialUserErrorIds;

/**
 * Class for implementing Yle authentication. This version has still some concerns anf will be changed
 */
public class YleIdentity extends OAuth2Identity implements SocialRedirectAuthenticator {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(YleIdentity.class);

    /** Yle app Id. */
    private String appId;

    /** Yle app Key. */
    private String appKey;

    @Override
    public void init() {
    }

    /**
     * Setter for Yle Application Id.
     * 
     * @param yleAppId Yle Application Id
     */
    public void setAppId(String yleAppId) {
        log.trace("Entering & Leaving");
        this.appId = yleAppId;
    }

    /**
     * Setter for Yle Application Key.
     * 
     * @param yleAppKey Yle Application Key
     */
    public void setAppKey(String yleAppKey) {
        log.trace("Entering & Leaving");
        this.appKey = yleAppKey;
    }

    @Override
    public String getRedirectUrl(HttpServletRequest httpRequest) {
        log.trace("Entering");
        String ret = super.getRedirectUrl(httpRequest);
        if (ret != null) {
            log.debug("Adding the gateway credentials trail to the URL");
            ret = ret + getYleGatewayCredentialsTrail();
        }
        log.trace("Leaving");
        return ret;

    }

    // Checkstyle: CyclomaticComplexity OFF
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
            HTTPRequest req = request.toHTTPRequest();
            req.setQuery(request.toHTTPRequest().getQuery() + getClientCredentialsTrail());
            TokenResponse tokenResponse = TokenResponse.parse(req.send());
            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                String error = "error in token fetch";
                if (errorResponse != null && errorResponse.getErrorObject() != null
                        && errorResponse.getErrorObject().getCode() != null) {
                    error = errorResponse.getErrorObject().getCode();
                    String errorDescription = errorResponse.getErrorObject().getDescription();
                    if (errorDescription != null && !errorDescription.isEmpty()) {
                        error += " : " + errorDescription;
                    }
                }
                log.error("Error when attempting to parse token response: {}", error);
                log.trace("Leaving");
                throw new SocialUserAuthenticationException(error, SocialUserErrorIds.EXCEPTION);
            }
            AccessTokenResponse tokenSuccessResponse = (AccessTokenResponse) tokenResponse;
            // Get the access token, the server may also return a refresh token
            AccessToken accessToken = tokenSuccessResponse.getTokens().getAccessToken();
            // try reading stuff from accesstoken
            Subject subject = new Subject();
            parsePrincipalsFromClaims(subject, accessToken.toJSONObject());
            if (getUserinfoEndpoint() != null && !getUserinfoEndpoint().toString().isEmpty()) {
                // The protected resource insists on having access token as
                // query parameter
                // access token should be in headers
                URL resourceURL = new URL(getUserinfoEndpoint().toString() + "&access_token=" + accessToken.getValue());
                URLConnection conn = resourceURL.openConnection();
                String userinfo = IOUtils.toString(conn.getInputStream());
                conn.getInputStream().close();
                try {
                    parsePrincipalsFromClaims(subject, JSONObjectUtils.parseJSONObject(userinfo));
                } catch (java.text.ParseException e) {
                    log.error("error parsing userinfo endpoint", e);
                    log.trace("Leaving");
                    throw new SocialUserAuthenticationException(e.getMessage(), SocialUserErrorIds.EXCEPTION);
                }
            }
            addDefaultPrincipals(subject);
            return subject;

        } catch (SerializeException | IOException | URISyntaxException | ParseException e) {
            log.error("Could not parse subject from the token response, ", e);
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(e.getMessage(), SocialUserErrorIds.EXCEPTION);
        }

    }

    // Checkstyle: CyclomaticComplexity ON

    /**
     * Yle authorize server is behind gateway requiring own set of keys as query parameters.
     * 
     * @return Yle specific addition to redirect url.
     * 
     */
    private String getYleGatewayCredentialsTrail() {
        return "&app_id=" + appId + "&app_key=" + appKey;
    }

    /**
     * Yle authorize server insists on having credentials as query parameters.
     * 
     * @return Yle specific addition to redirect url.
     */
    private String getClientCredentialsTrail() {
        return "&client_id=" + getClientId().getValue() + "&client_secret=" + getClientSecret().getValue();
    }

}
