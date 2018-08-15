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

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.joda.time.DateTime;
import org.junit.Assert;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;

import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import fi.mpass.shibboleth.authn.impl.ValidateOIDCIDTokenAuthenticationTime;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenAuthenticationTime}.
 */
public class ValidateOIDCIDTokenAuthenticationTimeTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenAuthenticationTime action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenAuthenticationTime();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        // turn force authn on by default, as otherwise action is not run
        authCtx.setForceAuthn(true);
    }

    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action without forced authentication.
     * 
     * @throws Exception
     */
    @Test
    public void testNoForceAuthn() throws Exception {
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        authCtx.setForceAuthn(false);
        action.initialize();
        Assert.assertNull(action.execute(src));
    }

    /**
     * Runs action with null auth_time.
     * 
     * @throws Exception
     */
    @Test
    public void testNullAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(buildOidcTokenResponse(null));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with auth_time in the future.
     * 
     * @throws Exception
     */
    @Test
    public void testFutureAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(buildOidcTokenResponse(
                new DateTime().plusSeconds((int) (action.getAuthnLifetime() + action.getClockSkew() + 1000)).toDate()));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with expired auth_time.
     * 
     * @throws Exception
     */
    @Test
    public void testExpiredAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(
                buildOidcTokenResponse(new DateTime().minusSeconds((int) action.getClockSkew() + 1000).toDate()));
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with valid auth_time.
     * 
     * @throws Exception
     */
    @Test
    public void testValidAuthTime() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, true);
        suCtx.setOidcTokenResponse(buildOidcTokenResponse(new DateTime().toDate()));
        Assert.assertNull(action.execute(src));
    }

    protected OIDCTokenResponse buildOidcTokenResponse(final Date authTime) {
        final Map<String, Object> claims = new HashMap<>();
        claims.put("auth_time", authTime);
        return getOidcTokenResponse(null, DEFAULT_ISSUER, null, claims);
    }

}
