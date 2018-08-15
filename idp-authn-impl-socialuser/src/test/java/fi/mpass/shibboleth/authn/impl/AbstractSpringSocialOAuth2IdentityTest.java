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

import javax.servlet.http.HttpSession;

import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.social.oauth2.AccessGrant;
import org.springframework.social.oauth2.OAuth2Operations;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.testng.Assert;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.impl.AbstractSpringSocialOAuth2Identity;

/**
 * Unit tests for {@link AbstractSpringSocialOAuth2Identity}.
 */
public class AbstractSpringSocialOAuth2IdentityTest {

    protected AbstractSpringSocialOAuth2Identity identity;

    protected String appId;

    protected String appSecret;

    @Test
    public void testAccessGrantNoCode() throws Exception {
        identity = new AbstractSpringSocialOAuth2Identity() {};
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        Assert.assertNull(identity.getAccessGrant(httpRequest));
    }

    @Test(expectedExceptions = SocialUserAuthenticationException.class)
    public void testAccessGrantNoState() throws Exception {
        identity = new AbstractSpringSocialOAuth2Identity() {};
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.addParameter("code", "mockCode");
        Assert.assertNull(identity.getAccessGrant(httpRequest));
    }

    @Test(expectedExceptions = SocialUserAuthenticationException.class)
    public void testAccessGrantInvalidState() throws Exception {
        identity = new AbstractSpringSocialOAuth2Identity() {};
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.addParameter("code", "mockCode");
        httpRequest.addParameter("state", "mockState");
        Assert.assertNull(identity.getAccessGrant(httpRequest));
    }

    @Test(expectedExceptions = SocialUserAuthenticationException.class)
    public void testAccessGrantThrow() throws Exception {
        identity = new AbstractSpringSocialOAuth2Identity() {};
        OAuth2Operations operations = Mockito.mock(OAuth2Operations.class);
        Mockito.when(operations.exchangeForAccess(Mockito.anyString(), Mockito.anyString(),
                (MultiValueMap<String, String>) Mockito.any())).thenThrow(HttpClientErrorException.class);
        identity.setOauthOperations(operations);
        identity.getAccessGrant(initHttpRequestWithState());
    }

    @Test
    public void testAccessGrantSuccess() throws Exception {
        identity = new AbstractSpringSocialOAuth2Identity() {};
        OAuth2Operations operations = Mockito.mock(OAuth2Operations.class);
        String accessToken = "mockAccessToken";
        AccessGrant accessGrant = new AccessGrant(accessToken);
        Mockito.when(operations.exchangeForAccess(Mockito.anyString(), Mockito.anyString(),
                (MultiValueMap<String, String>) Mockito.any())).thenReturn(accessGrant);
        identity.setOauthOperations(operations);
        AccessGrant resultGrant = identity.getAccessGrant(initHttpRequestWithState());
        Assert.assertNotNull(resultGrant);
        Assert.assertEquals(resultGrant.getAccessToken(), accessToken);
    }

    protected MockHttpServletRequest initHttpRequestWithState() {
        MockHttpServletRequest httpRequest = Mockito.mock(MockHttpServletRequest.class);
        final String sessionId = "mockSessionId";
        HttpSession httpSession = Mockito.mock(HttpSession.class);
        Mockito.when(httpSession.getId()).thenReturn(sessionId);
        Mockito.when(httpRequest.getSession()).thenReturn(httpSession);
        Mockito.when(httpRequest.getParameter("code")).thenReturn("mockCode");
        Mockito.when(httpRequest.getParameter("state"))
                .thenReturn(AbstractSpringSocialOAuth2Identity.calculateHash(sessionId));
        Mockito.when(httpRequest.getRequestURL()).thenReturn(new StringBuffer());
        return httpRequest;
    }
}
