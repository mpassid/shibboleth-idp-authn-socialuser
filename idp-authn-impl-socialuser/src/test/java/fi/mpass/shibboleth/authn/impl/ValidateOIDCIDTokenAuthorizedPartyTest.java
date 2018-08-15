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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import fi.mpass.shibboleth.authn.impl.ValidateOIDCIDTokenAuthorizedParty;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenAuthorizedParty}.
 */
public class ValidateOIDCIDTokenAuthorizedPartyTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenAuthorizedParty action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenAuthorizedParty();
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action with single audience.
     * 
     * @throws Exception
     */
    @Test
    public void testSingleAudience() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        suCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }

    /**
     * Runs action without clientID as azp.
     * 
     * @throws Exception
     */
    @Test
    public void testNotAuthorized() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        final List<String> audience = new ArrayList<>();
        audience.add(DEFAULT_CLIENT_ID);
        audience.add("anotherOne");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("azp", DEFAULT_CLIENT_ID);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(null, DEFAULT_ISSUER, audience, claims);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        suCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID + "invalid"));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with clientId as azp.
     * 
     * @throws Exception
     */
    @Test
    public void testAuthorized() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        final List<String> audience = new ArrayList<>();
        audience.add(DEFAULT_CLIENT_ID);
        audience.add("anotherOne");
        final Map<String, Object> claims = new HashMap<>();
        claims.put("azp", DEFAULT_CLIENT_ID);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(null, DEFAULT_ISSUER, audience, claims);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        suCtx.setClientID(new ClientID(DEFAULT_CLIENT_ID));
        Assert.assertNull(action.execute(src));
    }
}
