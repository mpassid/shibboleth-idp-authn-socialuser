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

import org.joda.time.DateTime;
import org.mockito.Mockito;
import org.opensaml.profile.action.EventIds;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import fi.mpass.shibboleth.authn.impl.ValidateOIDCAuthentication;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCAuthentication}.
 */
public class ValidateOIDCAuthenticationTest extends AbstractOIDCIDTokenTest {

    /** Action to be tested. */
    private ValidateOIDCAuthentication action;

    /** {@inheritDoc} */
    @Override
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCAuthentication();
    }

    /**
     * Runs action without attempted flow.
     */
    @Test
    public void testMissingFlow() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, EventIds.INVALID_PROFILE_CTX);
    }

    /** {@inheritDoc} */
    @Test
    public void testNoContext() throws Exception {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        super.testNoContext();
    }

    /** {@inheritDoc} */
    @Test
    public void testUnparseable() throws Exception {
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        super.testUnparseable();
    }

    /**
     * Runs action without {@link OIDCTokenResponse}.
     */
    @Test
    public void testNoOidcResponse() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without {@link OIDCTokens} in {@link OIDCTokenResponse}.
     */
    @Test
    public void testNoOidcTokens() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final OIDCTokenResponse oidcTokenResponse = Mockito.mock(OIDCTokenResponse.class);
        Mockito.when(oidcTokenResponse.getOIDCTokens()).thenReturn(null);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without subject in the ID token.
     */
    @Test
    public void testNoSubject() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final OIDCTokenResponse oidcTokenResponse = Mockito.mock(OIDCTokenResponse.class);
        final JWT idToken = Mockito.mock(JWT.class);
        final JWTClaimsSet claimSet = JWTClaimsSet.parse("{ \"mock\" : \"mock\" }");
        Mockito.when(idToken.getJWTClaimsSet()).thenReturn(claimSet);
        final OIDCTokens oidcTokens = new OIDCTokens(idToken, new BearerAccessToken(), new RefreshToken());
        Mockito.when(oidcTokenResponse.getOIDCTokens()).thenReturn(oidcTokens);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action fulfilled requirements.
     */
    @Test
    public void testValid() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().minusSeconds(1).toDate());
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
