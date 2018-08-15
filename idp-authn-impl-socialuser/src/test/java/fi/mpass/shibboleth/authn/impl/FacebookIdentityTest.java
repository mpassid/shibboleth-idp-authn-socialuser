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

import javax.servlet.http.HttpServletRequest;

import org.junit.Assert;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.SocialAuthenticationRequest;
import fi.mpass.shibboleth.authn.impl.FacebookIdentity;

/**
 * Unit tests for {@link FacebookIdentity}.
 */
public class FacebookIdentityTest extends AbstractSpringSocialOAuth2IdentityTest {

    @BeforeMethod
    public void initTests() {
        appId = "mockId";
        appSecret = "mockSecret";
        identity = new FacebookIdentity();
        identity.setAppId(appId);
        identity.setAppSecret(appSecret);
        ((FacebookIdentity) identity).init();
    }

    @Test
    public void testUnforcedAuthRedirect() {
        final String redirectUrl = identity.getRedirectUrl(new MockHttpServletRequest());
        Assert.assertNotNull(redirectUrl);
        Assert.assertFalse(redirectUrl.contains("&auth_type="));
    }

    @Test
    public void testForcedAuthRedirect() {
        SocialAuthenticationRequest authRequest = Mockito.mock(SocialAuthenticationRequest.class);
        Mockito.when(authRequest.isForcedAuth((HttpServletRequest) Mockito.any())).thenReturn(true);
        identity.setAuthenticationRequest(authRequest);
        final String redirectUrl = identity.getRedirectUrl(new MockHttpServletRequest());
        Assert.assertNotNull(redirectUrl);
        Assert.assertTrue(redirectUrl.contains("&auth_type=reauthenticate"));
    }
}
