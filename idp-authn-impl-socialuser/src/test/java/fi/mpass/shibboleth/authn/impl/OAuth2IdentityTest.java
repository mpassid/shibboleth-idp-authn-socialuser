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

import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.http.core.ContainerSocketProcessor;
import org.simpleframework.transport.SocketProcessor;
import org.simpleframework.transport.connect.Connection;
import org.simpleframework.transport.connect.SocketConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.State;

import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.impl.AbstractOAuth2Identity;
import fi.mpass.shibboleth.authn.impl.OAuth2Identity;

/**
 * Unit tests for {@link OAuth2Identity}.
 */
public class OAuth2IdentityTest {

    @Nonnull
    private final Logger log = LoggerFactory.getLogger(OAuth2IdentityTest.class);

    /** Client identifier. */
    protected String clientId;

    /** Client secret. */
    protected String clientSecret;

    /** The token endpoint for local testing. */
    protected String tokenEndpoint;

    /** The user info endpoint for local testing. */
    protected String userInfoEndpoint;

    /** The user claim key. */
    protected String userClaim;

    /** The user claim value. */
    protected String userClaimValue;

    /** The error code. */
    protected String errorCode;

    /** The error description. */
    protected String errorDescription;

    /**
     * Set up tests.
     */
    @BeforeMethod
    public void setUp() {
        clientId = "mockClientId";
        clientSecret = "mockClientSecret";
        final String urlPrefix = "http://localhost:" + SetOIDCInformationTest.CONTAINER_PORT;
        tokenEndpoint = urlPrefix + "/token";
        userInfoEndpoint = urlPrefix + "/userinfo";
        userClaim = "user_key";
        userClaimValue = "mockUserId";
        errorCode = "access_denied";
        errorDescription = "mock description";
    }

    /**
     * Tests generic setters and getters.
     * 
     * @throws Exception
     */
    @Test
    public void testGenericSetters() throws Exception {
        final Map<String, String> customClaims = new HashMap<>();
        customClaims.put("claim1", "value1");
        customClaims.put("claim2", "value2");
        final OAuth2Identity oAuthId = initOAuth2Identity();
        oAuthId.setCustomClaimsTypes(customClaims);
        Assert.assertEquals(oAuthId.getCustomClaimsTypes(), customClaims);
        oAuthId.setScope(new ArrayList<String>());
        Assert.assertEquals(oAuthId.getScope(), new Scope());
        final ArrayList<String> scopes = new ArrayList<>();
        scopes.add("profile");
        oAuthId.setScope(scopes);
        Assert.assertEquals(oAuthId.getScope(), Scope.parse("profile"));
        final URI redirectUri = new URI("http://mock.org/redirect");
        oAuthId.setRedirectURI(redirectUri);
        Assert.assertEquals(oAuthId.getRedirectURI(), redirectUri);
    }

    /**
     * Runs getSubject with empty {@link HttpServletRequest}.
     * 
     * @throws Exception
     */
    @Test
    public void testSubjectEmptyRequest() throws Exception {
        testSubjectEmptyRequest(initOAuth2Identity());
    }

    /**
     * Runs getSubject with error token response.
     * 
     * @throws Exception
     */
    @Test
    public void testSubjectErrorToken() throws Exception {
        testSubjectErrorToken(initOAuth2Identity());
    }

    /**
     * Runs getSubject with unparseable token response.
     * 
     * @throws Exception
     */
    @Test
    public void testSubjectUnparseableToken() throws Exception {
        testSubjectUnparseableToken(initOAuth2Identity());
    }

    /**
     * Runs getSubject with unparseable user info response.
     * 
     * @throws Exception
     */
    @Test
    public void testSubjectUnparseableUserInfo() throws Exception {
        testSubjectUnparseableUserInfo(initOAuth2Identity());
    }

    /**
     * Runs getSubject with prerequisites fulfilled.
     * 
     * @throws Exception
     */
    @Test
    public void testSubjectSuccess() throws Exception {
        testSubjectSuccess(initOAuth2Identity());
    }

    /**
     * Runs getSubject with empty {@link HttpServletRequest}.
     * 
     * @throws Exception
     */
    protected void testSubjectEmptyRequest(final AbstractOAuth2Identity oAuthId) throws Exception {
        Assert.assertNull(oAuthId.getSubject(new MockHttpServletRequest()));
    }

    /**
     * Runs getSubject with error token response.
     * 
     * @throws Exception
     */
    protected void testSubjectErrorToken(final AbstractOAuth2Identity oAuthId) throws Exception {
        final String urlPrefix = "http://localhost:" + SetOIDCInformationTest.CONTAINER_PORT;
        final String tokenEndpoint = urlPrefix + "/errorToken";
        oAuthId.setTokenEndpoint(tokenEndpoint);
        oAuthId.setUserinfoEndpoint(userInfoEndpoint);
        final MockHttpServletRequest httpRequest = initHttpServletRequest();
        String exception = null;
        try {
            executeGetSubjectWithServer(oAuthId, httpRequest);
        } catch (SocialUserAuthenticationException e) {
            exception = e.getMessage();
        }
        Assert.assertNotNull(exception);
        Assert.assertTrue(exception.startsWith(errorCode));
        Assert.assertTrue(exception.contains(errorDescription));
    }

    /**
     * Runs getSubject with unparseable token response.
     * 
     * @throws Exception
     */
    protected void testSubjectUnparseableToken(final AbstractOAuth2Identity oAuthId) throws Exception {
        final MockHttpServletRequest httpRequest = initHttpServletRequest();
        String exception = null;
        try {
            executeGetSubjectWithServer(oAuthId, httpRequest, true, false);
        } catch (SocialUserAuthenticationException e) {
            exception = e.getMessage();
        }
        Assert.assertNotNull(exception);
    }

    /**
     * Runs getSubject with unparseable user info response.
     * 
     * @throws Exception
     */
    protected void testSubjectUnparseableUserInfo(final AbstractOAuth2Identity oAuthId) throws Exception {
        final MockHttpServletRequest httpRequest = initHttpServletRequest();
        String exception = null;
        try {
            executeGetSubjectWithServer(oAuthId, httpRequest, false, true);
        } catch (SocialUserAuthenticationException e) {
            exception = e.getMessage();
        }
        Assert.assertNotNull(exception);
    }

    /**
     * Runs getSubject with prerequisites fulfilled.
     * 
     * @throws Exception
     */
    protected void testSubjectSuccess(final AbstractOAuth2Identity oAuthId) throws Exception {
        final MockHttpServletRequest httpRequest = initHttpServletRequest();
        final Subject subject = executeGetSubjectWithServer(oAuthId, httpRequest);
        Assert.assertNotNull(subject);
        Assert.assertEquals(subject.getPrincipals().iterator().next().getName(), "mockUser");
    }

    /**
     * Initializes a servlet request.
     * 
     * @return
     */
    protected MockHttpServletRequest initHttpServletRequest() {
        final MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        httpRequest.setQueryString("code=mockCode&state=mockState");
        httpRequest.getSession(true).setAttribute(AbstractOAuth2Identity.SESSION_ATTR_STATE, new State("mockState"));
        return httpRequest;
    }

    /**
     * Initializes {@link OAuth2Identity} with default settings.
     * 
     * @return
     */
    protected OAuth2Identity initOAuth2Identity() throws Exception {
        final OAuth2Identity oAuthId = new OAuth2Identity();
        oAuthId.setClientId(clientId);
        oAuthId.setClientSecret(clientSecret);
        oAuthId.setTokenEndpoint(tokenEndpoint);
        oAuthId.setUserinfoEndpoint(userInfoEndpoint);
        final Map<String, String> claims = new HashMap<>();
        claims.put(userClaim, userClaimValue);
        oAuthId.setClaimsPrincipals(claims);
        oAuthId.init();
        return oAuthId;
    }

    /**
     * Executes the getSubject method with simple container running.
     * 
     * @param oAuthId
     * @param httpRequest
     * @return
     * @throws Exception
     */
    protected Subject executeGetSubjectWithServer(final AbstractOAuth2Identity oAuthId,
            final HttpServletRequest httpRequest) throws Exception {
        return executeGetSubjectWithServer(oAuthId, httpRequest, false, false);
    }

    /**
     * Executes the getSubject method with simple container running.
     * 
     * @param oAuthId
     * @param httpRequest
     * @param unparseableToken
     * @param unparseableUserInfo
     * @return
     * @throws Exception
     */
    protected synchronized Subject executeGetSubjectWithServer(final AbstractOAuth2Identity oAuthId,
            final HttpServletRequest httpRequest, final boolean unparseableToken, final boolean unparseableUserInfo)
            throws Exception {
        final Container container = new SimpleContainer(unparseableToken, unparseableUserInfo);
        final SocketProcessor server = new ContainerSocketProcessor(container);
        final Connection connection = new SocketConnection(server);
        final SocketAddress address = new InetSocketAddress(SetOIDCInformationTest.CONTAINER_PORT);
        connection.connect(address);
        try {
            return oAuthId.getSubject(httpRequest);
        } catch (Exception e) {
            throw e;
        } finally {
            connection.close();
        }
    }

    /**
     * Simple container implementation.
     */
    protected class SimpleContainer implements Container {

        final boolean unparseableToken;

        final boolean unparseableUserInfo;

        /**
         * Constructor.
         */
        public SimpleContainer(final boolean throwToken, final boolean throwUserInfo) {
            unparseableToken = throwToken;
            unparseableUserInfo = throwUserInfo;
        }

        @Override
        /** {@inheritDoc} */
        public void handle(Request request, Response response) {
            log.trace("Server got request for {}", request.getTarget());
            try {
                response.setContentType("application/json");
                String output = "";
                if (request.getTarget().contains("/token")) {
                    if (unparseableToken) {
                        output = "{ unparseable }";
                    } else {
                        output = "{ \"access_token\":\"2YotnFZFEjr1zCsicMWpAA\", \"token_type\":\"Bearer\", "
                                + "\"expires_in\":3600 }";
                    }
                } else if (request.getTarget().contains("/userinfo")) {
                    if (unparseableUserInfo) {
                        output = "{ unparseable }";
                    } else {
                        output = "{ \"" + userClaim + "\":\"mockUser\" }";
                    }
                } else if (request.getTarget().contains("/errorToken")) {
                    output = "{ \"error\":\"" + errorCode + "\", \"error_description\":\"" + errorDescription + "\" }";
                    response.setCode(500);
                }
                IOUtils.copy(new StringReader(output), response.getOutputStream());
                response.getOutputStream().close();
            } catch (Exception e) {
                log.error("Container-side exception ", e);
            }
        }
    }
}
