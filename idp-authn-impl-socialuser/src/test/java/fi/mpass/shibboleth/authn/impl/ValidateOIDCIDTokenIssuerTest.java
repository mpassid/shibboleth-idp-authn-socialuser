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

import org.springframework.webflow.execution.Event;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import fi.mpass.shibboleth.authn.impl.ValidateOIDCIDTokenIssuer;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link ValidateOIDCIDTokenIssuer}.
 */
public class ValidateOIDCIDTokenIssuerTest extends AbstractOIDCIDTokenTest {

    /** The action to be tested. */
    private ValidateOIDCIDTokenIssuer action;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ValidateOIDCIDTokenIssuer();
    }

    @Override
    /** {@inheritDoc} */
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /**
     * Runs action with invalid issuer.
     */
    @Test
    public void testInvalid() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final OIDCProviderMetadata oidcMetadata = buildOidcMetadata(DEFAULT_ISSUER + ".invalid");
        suCtx.setoIDCProviderMetadata(oidcMetadata);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action with valid issuer.
     */
    @Test
    public void testValid() throws Exception {
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final OIDCProviderMetadata oidcMetadata = buildOidcMetadata(DEFAULT_ISSUER);
        suCtx.setoIDCProviderMetadata(oidcMetadata);
        final OIDCTokenResponse oidcTokenResponse = getOidcTokenResponse(DEFAULT_ISSUER);
        suCtx.setOidcTokenResponse(oidcTokenResponse);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        Assert.assertNull(event);
    }
}
