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
import java.util.ArrayList;
import java.util.List;

import org.mockito.Mockito;
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import fi.mpass.shibboleth.authn.impl.ValidateOIDCIDTokenACR;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenACR}.
 */
public class ValidateOIDCIDTokenACRTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenACR action;

    /** The ACR value. */
    private String acr;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenACR();
        acr = "mockAcr";
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action without requested acr.
     */
    @Test
    public void testNoAcr() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        authCtx.addSubcontext(new SocialUserOpenIdConnectContext());
        Assert.assertNull(action.execute(src));
    }

    /**
     * Runs action with unparseable response.
     */
    @Test
    public void testUnparseable() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final SocialUserOpenIdConnectContext suCtx = buildContextWithACR(acrs, null);
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without acrs in {@link OIDCTokenResponse} even though they're requested.
     */
    @Test
    public void testNoResponseAcr() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final SocialUserOpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"mock\" : \"mock\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without acrs in {@link OIDCTokenResponse} even though they're requested.
     */
    @Test
    public void testNoMatchingAcr() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final SocialUserOpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"acr\" : \"invalid\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with acr in {@link OIDCTokenResponse} as single requested.
     */
    @Test
    public void testSuccessSingle() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        final SocialUserOpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"acr\" : \"" + acr + "\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        Assert.assertNull(action.execute(src));
    }

    /**
     * Runs action with acr in {@link OIDCTokenResponse} as one of three requested.
     */
    @Test
    public void testSuccessTriple() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final List<ACR> acrs = new ArrayList<>();
        acrs.add(new ACR(acr));
        acrs.add(new ACR("second"));
        acrs.add(new ACR("third"));
        final SocialUserOpenIdConnectContext suCtx = buildContextWithACR(acrs, "{ \"acr\" : \"" + acr + "\" }");
        prc.getSubcontext(AuthenticationContext.class, false).setAttemptedFlow(authenticationFlows.get(0));
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        Assert.assertNull(action.execute(src));
    }

    /**
     * Helper for building {@link SocialUserOpenIdConnectContext}.
     * 
     * @param acrs
     * @param jwt
     * @return
     * @throws Exception
     */
    protected SocialUserOpenIdConnectContext buildContextWithACR(final List<ACR> acrs, final String jwt)
            throws Exception {
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        suCtx.setAcrs(acrs);
        final OIDCTokenResponse oidcTokenResponse = Mockito.mock(OIDCTokenResponse.class);
        final JWT idToken = Mockito.mock(JWT.class);
        if (jwt == null) {
            Mockito.when(idToken.getJWTClaimsSet()).thenThrow(new ParseException("mockException", 1));
        } else {
            final JWTClaimsSet claimSet = JWTClaimsSet.parse(jwt);
            Mockito.when(idToken.getJWTClaimsSet()).thenReturn(claimSet);
        }
        final OIDCTokens oidcTokens = new OIDCTokens(idToken, new BearerAccessToken(), new RefreshToken());
        Mockito.when(oidcTokenResponse.getOIDCTokens()).thenReturn(oidcTokens);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        return suCtx;
    }
}
