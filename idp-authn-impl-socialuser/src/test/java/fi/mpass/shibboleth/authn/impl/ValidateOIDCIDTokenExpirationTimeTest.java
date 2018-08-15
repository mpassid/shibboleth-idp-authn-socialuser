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
import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import fi.mpass.shibboleth.authn.impl.ValidateOIDCIDTokenExpirationTime;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenExpirationTime}.
 */
public class ValidateOIDCIDTokenExpirationTimeTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenExpirationTime action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenExpirationTime();
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action with expired OIDC token.
     */
    @Test
    public void testExpired() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().minusSeconds(1).toDate());
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with OIDC token expiring in the future.
     */
    @Test
    public void testValid() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(new DateTime().plusMinutes(5).toDate());
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
