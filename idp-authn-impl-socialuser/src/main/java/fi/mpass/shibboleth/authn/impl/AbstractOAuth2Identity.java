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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.util.JSONArrayUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationErrorResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;

import fi.mpass.shibboleth.authn.SocialAuthenticationRequest;
import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.SocialUserErrorIds;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;

/** Implements OAuth2/OpenId basics for classes using Nimbus library. */
public abstract class AbstractOAuth2Identity {

    /** key for state parameter. */
    public static final String SESSION_ATTR_STATE = "fi.mpass.state";

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOAuth2Identity.class);

    /** Scope. */
    @Nonnull
    private Scope scope;

    /** Client Id. */
    @Nonnull
    private ClientID clientID;

    /** Client Secret. */
    @Nonnull
    private Secret clientSecret;

    /** Authorization Endpoint. */
    @Nonnull
    private URI authorizationEndpoint;

    /** Token Endpoint. */
    @Nonnull
    private URI tokenEndpoint;

    /** UserInfo Endpoint. */
    private URI userinfoEndpoint;

    /** Revocation Endpoint. */
    private URI revocationEndpoint;

    /** Redirect URI. */
    private URI redirectURI;

    /** Authentication request. */
    private SocialAuthenticationRequest socialAuthenticationRequest;

    /** map of claims to principals. */
    @Nonnull
    private Map<String, String> claimsPrincipals;

    /** map of principal default values. */
    @Nonnull
    private Map<String, String> principalsDefaults;

    /** map of custom claims types. */
    private Map<String, String> customClaimsTypes;

    /** custom claims type. */
    private final String customClaimTypeJsonArray = "jsonarray";

    /**
     * This information is used to decide how to interpret custom claim.
     * 
     * @param types map of custom claims types
     */
    public void setCustomClaimsTypes(Map<String, String> types) {
        log.trace("Entering");
        this.customClaimsTypes = types;
        log.trace("Leaving");
    }

    /**
     * This information is used to decide how to interpret custom claim.
     * 
     * @return map of custom claims types
     */
    public Map<String, String> getCustomClaimsTypes() {
        log.trace("Entering & Leaving");
        return this.customClaimsTypes;
    }

    /**
     * Setter for OAuth2 Scope values.
     * 
     * @param oauth2Scopes OAuth2 Scope values
     */
    public void setScope(List<String> oauth2Scopes) {
        log.trace("Entering");
        scope = new Scope();
        for (String oauth2Scope : oauth2Scopes) {
            scope.add(oauth2Scope);
        }
        log.trace("Leaving");
    }

    /**
     * Getter for OAuth2 Scope values.
     * 
     * @return OAuth2 Scope values
     */
    protected Scope getScope() {
        log.trace("Entering");
        if (scope == null) {
            scope = new Scope();
        }
        log.trace("Leaving");
        return scope;
    }

    /**
     * Getter for OAuth2 redirect uri for provider return to.
     * 
     * @return OAuth2 redirect uri
     */

    public URI getRedirectURI() {
        return redirectURI;
    }

    /**
     * Setter for OAuth2 redirect uri for provider to return to.
     * 
     * @param redirect OAuth2 redirect uri
     */

    public void setRedirectURI(URI redirect) {
        this.redirectURI = redirect;
    }

    /**
     * Sets map of principal defaults.
     * 
     * @param oauth2PrincipalsDefaults map of principal defaults
     */
    public void setPrincipalsDefaults(Map<String, String> oauth2PrincipalsDefaults) {
        log.trace("Entering");
        this.principalsDefaults = oauth2PrincipalsDefaults;
        log.trace("Leaving");
    }

    /**
     * Gets map of claims to principals.
     * 
     * @return map of claims to principals
     */
    protected Map<String, String> getPrincipalsDefaults() {
        log.trace("Entering & Leaving");
        return principalsDefaults;
    }

    /**
     * Sets map of claims to principals.
     * 
     * @param oauth2ClaimsPrincipals map of claims to principals
     */
    public void setClaimsPrincipals(Map<String, String> oauth2ClaimsPrincipals) {
        log.trace("Entering");
        this.claimsPrincipals = oauth2ClaimsPrincipals;
        log.trace("Leaving");
    }

    /**
     * Gets map of claims to principals.
     * 
     * @return map of claims to principals
     */
    protected Map<String, String> getClaimsPrincipals() {
        log.trace("Entering & Leaving");
        return claimsPrincipals;
    }

    /**
     * Setter for authorization endpoint.
     * 
     * @param endPoint AuthorizationEndpoint
     * @throws URISyntaxException If the endpoint is not valid.
     */
    public void setAuthorizationEndpoint(String endPoint) throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.authorizationEndpoint = new URI(endPoint);
    }

    /**
     * Getter for authorization endpoint.
     * 
     * @return AuthorizationEndpoint
     */
    protected URI getAuthorizationEndpoint() {
        log.trace("Entering & Leaving");
        return authorizationEndpoint;
    }

    /**
     * Setter for token endpoint.
     * 
     * @param endPoint TokenEndpoint
     * @throws URISyntaxException If the endpoint is not valid.
     */
    public void setTokenEndpoint(String endPoint) throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.tokenEndpoint = new URI(endPoint);
    }

    /**
     * Getter for token endpoint.
     * 
     * @return TokenEndpoint
     * @throws URISyntaxException If the endpoint is not valid.
     */
    public URI getTokenEndpoint() throws URISyntaxException {
        log.trace("Entering & Leaving");
        return tokenEndpoint;
    }

    /**
     * Setter for userinfo endpoint.
     * 
     * @param endPoint UserinfoEndpoint
     * @throws URISyntaxException If the endpoint is not valid.
     */
    public void setUserinfoEndpoint(String endPoint) throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.userinfoEndpoint = new URI(endPoint);
    }

    /**
     * Getter for userinfo endpoint.
     * 
     * @return UserinfoEndpoint
     * @throws URISyntaxException If the endpoint is not valid.
     */
    protected URI getUserinfoEndpoint() throws URISyntaxException {
        log.trace("Entering & Leaving");
        return userinfoEndpoint;
    }

    /**
     * Setter for revocation endpoint.
     * 
     * @param endPoint RevocationEndpoint
     * @throws URISyntaxException If the endpoint is not valid.
     */
    public void setRevocationEndpoint(String endPoint) throws URISyntaxException {
        log.trace("Entering & Leaving");
        this.revocationEndpoint = new URI(endPoint);
    }

    /**
     * Getter for revocation endpoint.
     * 
     * @return RevocationEndpoint
     */
    protected URI getRevocationEndpoint() {
        log.trace("Entering & Leaving");
        return revocationEndpoint;
    }

    /**
     * Setter for Oauth2 client id.
     * 
     * @param oauth2ClientId Oauth2 Client ID
     */
    public void setClientId(String oauth2ClientId) {
        log.trace("Entering & Leaving");
        this.clientID = new ClientID(oauth2ClientId);
    }

    /**
     * Getter for Oauth2 client id.
     * 
     * @return Oauth2 Client ID
     */
    public ClientID getClientId() {
        log.trace("Entering & Leaving");
        return clientID;
    }

    /**
     * Setter for Oauth2 Client secret.
     * 
     * @param oauth2ClientSecret Oauth2 Client Secret
     */
    public void setClientSecret(String oauth2ClientSecret) {
        log.trace("Entering & Leaving");
        this.clientSecret = new Secret(oauth2ClientSecret);
    }

    /**
     * Getter for Oauth2 Client secret.
     * 
     * @return Oauth2 Client Secret
     */
    public Secret getClientSecret() {
        log.trace("Entering & Leaving");
        return clientSecret;
    }

    /**
     * Setter for authentication request.
     * 
     * @param authRequest Authentication request
     */
    public void setAuthenticationRequest(SocialAuthenticationRequest authRequest) {
        log.trace("Entering & Leaving");
        this.socialAuthenticationRequest = authRequest;
    }

    /**
     * Getter for authentication request.
     * 
     * @return Authentication request
     */
    protected SocialAuthenticationRequest getAuthenticationRequest() {
        log.trace("Entering & Leaving");
        return this.socialAuthenticationRequest;
    }

    /**
     * This method forms Token request.
     * 
     * @param httpRequest the request formed by the oauth2 server
     * @return returns token request or null if the user has not authorized yet.
     * @throws SocialUserAuthenticationException If tokenrequest fails to other than non-authorization reason.
     */
    // Checkstyle: CyclomaticComplexity OFF
    protected TokenRequest getTokenRequest(HttpServletRequest httpRequest) throws SocialUserAuthenticationException {
        log.trace("Entering");
        try {
            AuthenticationResponse response = null;
            String temp = httpRequest.getRequestURL() + "?" + httpRequest.getQueryString();
            URI uri = new URI(temp);
            response = AuthenticationResponseParser.parse(uri);
            if (!response.indicatesSuccess()) {
                log.trace("Leaving");
                AuthenticationErrorResponse errorResponse = (AuthenticationErrorResponse) response;
                String error = errorResponse.getErrorObject().getCode();
                String errorDescription = errorResponse.getErrorObject().getDescription();
                if (errorDescription != null && !errorDescription.isEmpty()) {
                    error += " : " + errorDescription;
                }
                log.trace("Leaving");
                throw new SocialUserAuthenticationException(error, SocialUserErrorIds.EXCEPTION);
            }
            AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;
            AuthorizationCode code = successResponse.getAuthorizationCode();
            URI callback = new URI(httpRequest.getRequestURL().toString());
            AuthorizationGrant codeGrant = new AuthorizationCodeGrant(code, callback);
            ClientAuthentication clientAuth = new ClientSecretBasic(getClientId(), getClientSecret());
            TokenRequest request = new TokenRequest(getTokenEndpoint(), clientAuth, codeGrant);
            State state = (State) httpRequest.getSession().getAttribute(SESSION_ATTR_STATE);
            if (state == null || !state.equals(successResponse.getState())) {
                throw new SocialUserAuthenticationException("State parameter not satisfied",
                        SocialUserErrorIds.EXCEPTION);
            }
            return request;
        } catch (IllegalArgumentException e) {
            log.debug("User is not authenticated yet", e);
            log.trace("Leaving");
            return null;

        } catch (URISyntaxException | ParseException e) {
            log.error("Could not construct token request", e);
            log.trace("Leaving");
            throw new SocialUserAuthenticationException(e.getMessage(), SocialUserErrorIds.EXCEPTION);
        }
    }

    // Checkstyle: CyclomaticComplexity ON

    /**
     * This method sets default principal values to subject if such principal does not exist already.
     * 
     * @param subject The subject we add default principal values to
     */
    protected void addDefaultPrincipals(Subject subject) {
        log.trace("Entering");
        if (getPrincipalsDefaults() == null || getPrincipalsDefaults().isEmpty()) {
            log.trace("Leaving");
            return;
        }
        for (Map.Entry<String, String> entry : getPrincipalsDefaults().entrySet()) {
            String principal = entry.getKey().toString();
            boolean found = false;
            final Set<SocialUserPrincipal> principals = subject.getPrincipals(SocialUserPrincipal.class);
            for (SocialUserPrincipal sprin : principals) {
                if (principal.equals(sprin.getType())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                subject.getPrincipals().add(new SocialUserPrincipal(principal, entry.getValue()));
            }
        }
        log.trace("Leaving");

    }

    /**
     * This method parses principals from claim.
     * 
     * @param subject we add claims to
     * @param potClaims potential claims
     */
    // Checkstyle: CyclomaticComplexity OFF
    protected void parsePrincipalsFromClaims(Subject subject, JSONObject potClaims) {

        log.trace("Entering");
        boolean first = true;
        if (getClaimsPrincipals() == null || getClaimsPrincipals().isEmpty()) {
            log.trace("Leaving");
            return;
        }
        for (Map.Entry<String, String> entry : getClaimsPrincipals().entrySet()) {
            String claim = entry.getKey().toString();
            if (claim == null || claim.isEmpty()) {
                first = false;
                continue;
            }
            String value = potClaims.get(claim) != null ? potClaims.get(claim).toString() : null;
            if (value == null || value.isEmpty()) {
                first = false;
                continue;
            }
            String[] values = null;
            if (customClaimsTypes == null || !customClaimsTypes.containsKey(claim)) {
                /* There is no type definition */
                values = new String[1];
                values[0] = value;
            } else {
                switch (customClaimsTypes.get(claim)) {
                    case customClaimTypeJsonArray:
                        try {
                            JSONArray array = JSONArrayUtils.parse(value);
                            values = new String[array.size()];
                            for (int i = 0; i < array.size(); i++) {
                                values[i] = array.get(i).toString();
                            }
                        } catch (ParseException e) {
                            /* json parsing failed, we revert to string type */
                            log.warn("claim type set as jsonarray but parsing failed. claim: {}", value);
                            values = new String[1];
                            values[0] = value;
                        }
                        break;
                    default:
                        /* type definition is unkown to us, we revert to string type */
                        log.warn("unknown type definition for claim, type is {}", value);
                        values = new String[1];
                        values[0] = value;
                }
            }
            for (String newValue : values) {
                log.debug("Adding socialuserprincipal {} of type {}", newValue, entry.getValue());
                subject.getPrincipals().add(new SocialUserPrincipal(entry.getValue(), newValue));
                // First value is treated as usernameprincipal
                if (first) {
                    log.debug("Setting userprincipal to {}", newValue);
                    subject.getPrincipals().add(new UsernamePrincipal(newValue));
                    first = false;
                }

            }
        }
        log.trace("Leaving");
    }

    // Checkstyle: CyclomaticComplexity ON

    /**
     * Obtains access token, calls user info endpoint and finally populates the principals from the claims provided by
     * the user info endpoint.
     * 
     * @param httpRequest the request formed by the oauth2 server
     * @return principals in subject
     * @throws SocialUserAuthenticationException if something unexpected occurs.
     */
    public abstract Subject getSubject(HttpServletRequest httpRequest) throws SocialUserAuthenticationException;
}
