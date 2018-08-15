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

import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.impl.YleIdentity;

/**
 * Unit tests for {@link YleIdentity}.
 */
public class YleIdentityTest extends OAuth2IdentityTest {

    @Nonnull
    private final Logger log = LoggerFactory.getLogger(YleIdentityTest.class);

    /** Yle App Identifier. */
    private String appId;

    /** Yle App Key. */
    private String appKey;

    /**
     * Set up tests.
     */
    @BeforeMethod
    public void setUp() {
        super.setUp();
        appId = "mockAppId";
        appKey = "mockAppKey";
        userClaim = "user_key";
        errorCode = "access_denied";
        errorDescription = "mock description";
    }

    /**
     * Runs getRedirectUrl with null {@link HttpServletRequest}.
     * 
     * @throws Exception
     */
    @Test
    public void testRedirectNullRequest() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        Assert.assertNull(yleId.getRedirectUrl(null));
    }

    /**
     * Runs getRedirectUrl with empty {@link HttpServletRequest}.
     * 
     * @throws Exception
     */
    @Test
    public void testRedirectNoAuthzEndpoint() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setRequestURI("/mock/");
        Assert.assertNull(yleId.getRedirectUrl(httpRequest));
    }

    /**
     * Runs getRedirectUrl with prerequisites fulfilled.
     * 
     * @throws Exception
     */
    @Test
    public void testRedirect() throws Exception {
        final YleIdentity yleId = initYleIdentity();
        final String authzEndpoint = "http://mock.org/authorize";
        yleId.setAuthorizationEndpoint(authzEndpoint);
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setRequestURI("/mock/");
        final String redirectUrl = yleId.getRedirectUrl(httpRequest);
        Assert.assertNotNull(redirectUrl);
        Assert.assertTrue(redirectUrl.startsWith(authzEndpoint));
        Assert.assertTrue(redirectUrl.contains("app_id=" + appId));
        Assert.assertTrue(redirectUrl.contains("app_key=" + appKey));
        Assert.assertTrue(redirectUrl.contains("client_id=" + clientId));
    }

    /** {@inheritDoc} */
    @Test
    public void testSubjectEmptyRequest() throws Exception {
        super.testSubjectEmptyRequest(initYleIdentity());
    }

    /** {@inheritDoc} */
    @Test
    public void testSubjectErrorToken() throws Exception {
        super.testSubjectErrorToken(initYleIdentity());
    }

    /** {@inheritDoc} */
    @Test
    public void testSubjectUnparseableToken() throws Exception {
        super.testSubjectUnparseableToken(initYleIdentity());
    }

    /** {@inheritDoc} */
    @Test
    public void testSubjectUnparseableUserInfo() throws Exception {
        super.testSubjectUnparseableUserInfo(initYleIdentity());
    }

    /**
     * /** {@inheritDoc}
     */
    @Test
    public void testSubjectSuccess() throws Exception {
        super.testSubjectSuccess(initYleIdentity());
    }

    /**
     * Initializes {@link YleIdentity} with default settings.
     * 
     * @return
     */
    protected YleIdentity initYleIdentity() throws Exception {
        final YleIdentity yleId = new YleIdentity();
        yleId.setAppId(appId);
        yleId.setAppKey(appKey);
        yleId.setClientId(clientId);
        yleId.setClientSecret(clientSecret);
        yleId.setTokenEndpoint(tokenEndpoint);
        yleId.setUserinfoEndpoint(userInfoEndpoint);
        final Map<String, String> claims = new HashMap<>();
        claims.put(userClaim, userClaimValue);
        yleId.setClaimsPrincipals(claims);
        yleId.init();
        return yleId;
    }
}
