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
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.social.oauth1.AuthorizedRequestToken;
import org.springframework.social.oauth1.OAuth1Operations;
import org.springframework.social.oauth1.OAuth1Parameters;
import org.springframework.social.oauth1.OAuthToken;

import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.SocialUserErrorIds;

/** Implements methods common to OAuth(1) types. */
public abstract class AbstractSpringSocialOAuthIdentity extends AbstractIdentity {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractSpringSocialOAuthIdentity.class);

    /** OAuth Application id. */
    @Nonnull
    private String consumerKey;

    /** OAuth Application secret. */
    @Nonnull
    private String consumerSecret;

    /** OAuth methods. */
    private OAuth1Operations oauthOperations;

    /**
     * Setter for OAuth operations.
     * 
     * @param operations OAuth operations
     */
    public void setOauthOperations(OAuth1Operations operations) {
        log.trace("Entering & Leaving");
        this.oauthOperations = operations;
    }

    /**
     * Setter for OAuth consumer key.
     * 
     * @param oauthConsumerKey OAuth consumer key
     */

    public void setConsumerKey(String oauthConsumerKey) {
        log.trace("Entering & Leaving");
        this.consumerKey = oauthConsumerKey;
    }

    /**
     * Setter for OAuth consumer secret.
     * 
     * @param oauthConsumerSecret OAuth consumer secret
     */

    public void setConsumerSecret(String oauthConsumerSecret) {
        log.trace("Entering & Leaving");
        this.consumerSecret = oauthConsumerSecret;
    }

    /**
     * Getter for OAuth consumer key.
     *
     * @return OAuth consumer key
     */

    protected String getConsumerKey() {
        log.trace("Entering & Leaving");
        return this.consumerKey;
    }

    /**
     * Getter for OAuth consumer secret.
     * 
     * @return OAuth consumer secret
     */

    String getConsumerSecret() {
        log.trace("Entering & Leaving");
        return this.consumerSecret;
    }

    /**
     * Returns redirect url for authentication.
     *
     * @param httpRequest the request
     * @return redirect url
     */

    public String getRedirectUrl(HttpServletRequest httpRequest) {
        log.trace("Entering");
        if (httpRequest == null) {
            log.trace("Leaving");
            return null;
        }
        OAuthToken requestToken = oauthOperations.fetchRequestToken(httpRequest.getRequestURL().toString(), null);
        httpRequest.getSession().setAttribute("ext_auth_request_token", requestToken);
        String authorizeUrl = oauthOperations.buildAuthorizeUrl(requestToken.getValue(), OAuth1Parameters.NONE);
        log.trace("Leaving");
        return authorizeUrl;
    }

    /**
     * Throws an error if user authentication has failed. Returns Authorization Code if such exists. Returns null if
     * authentication has not been performed yet.
     * 
     * @param httpRequest is the request.
     * 
     * @return request token or null.
     * @throws SocialUserAuthenticationException if user has canceled the operation.
     */
    private OAuthToken getRequestToken(HttpServletRequest httpRequest) throws SocialUserAuthenticationException {
        log.trace("Entering");
        // Is this twitter specific
        String denied = httpRequest.getParameter("denied");
        if (denied != null && !denied.isEmpty()) {
            log.trace("Leaving");
            throw new SocialUserAuthenticationException("user denied", SocialUserErrorIds.USER_CANCELED);
        }
        OAuthToken requestToken = (OAuthToken) httpRequest.getSession().getAttribute("ext_auth_request_token");
        log.trace("Leaving");
        return requestToken;
    }

    /**
     * Returns Access Token if user is known, otherwise null.
     * 
     * @param httpRequest the request
     * 
     * @return Access Token
     * @throws SocialUserAuthenticationException Id token fetch fails due to other reason than user not already having
     *             authorized.
     */
    public OAuthToken getAccessToken(HttpServletRequest httpRequest) throws SocialUserAuthenticationException {
        log.trace("Entering");
        OAuthToken accessToken = null;
        try {
            OAuthToken requestToken = getRequestToken(httpRequest);
            if (requestToken == null) {
                // not authenticated
                log.trace("Leaving");
                return null;
            }
            String oauthVerifier = httpRequest.getParameter("oauth_verifier");
            accessToken = oauthOperations
                    .exchangeForAccessToken(new AuthorizedRequestToken(requestToken, oauthVerifier), null);

        } catch (NullPointerException | IllegalStateException e) {
            // not authenticated
            log.trace("Leaving");
            return null;
        }
        log.trace("Leaving");
        return accessToken;
    }

}
