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
import java.io.InputStream;
import java.io.StringWriter;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import javax.annotation.Nonnull;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;

import org.apache.commons.io.IOUtils;
import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;

/**
 * An action that verifies Signature of ID Token.
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
 * 
 *      AND
 * 
 *      <pre>
 *      SocialUserOpenIdConnectContext.getoIDCProviderMetadata() != null
 *      </pre>
 */
@SuppressWarnings("rawtypes")
public class ValidateOIDCIDTokenSignature extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(ValidateOIDCIDTokenSignature.class);

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
        SignedJWT signedJWT = null;
        try {
            signedJWT = SignedJWT.parse(suCtx.getIDToken().serialize());
        } catch (ParseException e) {
            log.error("{} Error when forming signed JWT", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        RSAPublicKey providerKey = null;
        try {
            JSONObject key = getProviderRSAJWK(suCtx.getoIDCProviderMetadata().getJWKSetURI().toURL().openStream(),
                    signedJWT.getHeader().getKeyID());
            if (key == null) {
                log.error("{} Not able to find key to verify signature", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
            providerKey = RSAKey.parse(key).toRSAPublicKey();
        } catch (IOException | java.text.ParseException | JOSEException e) {
            log.error("{} Error when parsing key to verify signature", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        RSASSAVerifier verifier = new RSASSAVerifier(providerKey);
        try {
            if (!signedJWT.verify(verifier)) {
                log.error("{} JWT signature verification failed", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                log.trace("Leaving");
                return;
            }
        } catch (JOSEException e) {
            log.error("{} JWT signature verification not performed", getLogPrefix(), e);
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            log.trace("Leaving");
            return;
        }
        log.debug("ID Token signature verified");
        log.trace("Leaving");
        return;
    }

    /**
     * Parse JWK, RSA public key for signature verification, from stream.
     * 
     * @param is inputstream containing the key
     * @param kid The key ID to be looked after
     * @return RSA public key as JSON Object. Null if there is no key
     * @throws ParseException if parsing fails.
     * @throws IOException if something unexpected happens.
     */
    private JSONObject getProviderRSAJWK(InputStream is, String kid) throws ParseException, IOException {
        log.trace("Entering");
        if (kid == null) {
            log.warn("No kid defined in the JWT, no kid check can be performed!");
        }
        StringWriter writer = new StringWriter();
        IOUtils.copy(is, writer, "UTF-8");
        JSONObject json = JSONObjectUtils.parse(writer.toString());
        JSONArray keyList = (JSONArray) json.get("keys");
        if (keyList == null) {
            log.trace("Leaving");
            return null;
        }
        for (Object key : keyList) {
            JSONObject k = (JSONObject) key;
            if ("sig".equals(k.get("use")) && "RSA".equals(k.get("kty"))) {
                if (kid == null || kid.equals(k.get("kid"))) {
                    log.debug("verification key " + k.toString());
                    log.trace("Leaving");
                    return k;
                }
            }
        }
        log.trace("Leaving");
        return null;
    }

}
