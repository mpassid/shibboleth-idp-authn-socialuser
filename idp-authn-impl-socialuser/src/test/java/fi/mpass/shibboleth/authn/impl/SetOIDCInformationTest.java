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

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nonnull;

import org.apache.commons.io.IOUtils;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.http.core.ContainerSocketProcessor;
import org.simpleframework.transport.connect.Connection;
import org.simpleframework.transport.connect.SocketConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.simpleframework.transport.SocketProcessor;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.Display;
import com.nimbusds.openid.connect.sdk.Prompt;

import fi.mpass.shibboleth.authn.impl.SetOIDCInformation;
import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;

/**
 * Unit tests for {@link SetOIDCInformation}.
 */
public class SetOIDCInformationTest extends PopulateAuthenticationContextTest {

    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SetOIDCInformationTest.class);

    public static int CONTAINER_PORT = 8997;

    /** Action to be tested. */
    private SetOIDCInformation action;

    private String clientId;

    private String clientSecret;

    private Prompt.Type prompt;

    private URI redirectUri;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        clientId = "mockClientId";
        clientSecret = "mockClientSecret";
        prompt = Prompt.Type.LOGIN;
        redirectUri = new URI("http://mock.example.org/redirect_uri");
        action = new SetOIDCInformation();
        loadMetadata(action, true);
        action.setClientId(clientId);
        action.setClientSecret(clientSecret);
        action.setRedirectURI(redirectUri);
    }

    /**
     * Tests with unavailable server metadata.
     * 
     * @throws Exception
     */
    @Test(expectedExceptions = {IOException.class, ParseException.class, URISyntaxException.class})
    public void testNoMetadata() throws Exception {
        action = new SetOIDCInformation();
        loadMetadata(action, false);
    }

    /**
     * Tests with minimum configuration.
     * 
     * @throws Exception
     */
    @Test
    public void testDefault() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, false);
        Assert.assertNotNull(suCtx);
        Assert.assertNotNull(suCtx.getAuthenticationRequestURI());
        final URI authRequestUri = suCtx.getAuthenticationRequestURI();
        Assert.assertTrue(authRequestUri.toString().contains("scope=openid"));
    }

    /**
     * Tests prompt=login configuration.
     * 
     * @throws Exception
     */
    @Test
    public void testPrompt() throws Exception {
        action.setPrompt(String.valueOf(prompt));
        action.initialize();
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, false);
        Assert.assertNotNull(suCtx);
        Assert.assertNotNull(suCtx.getAuthenticationRequestURI());
        final URI authRequestUri = suCtx.getAuthenticationRequestURI();
        Assert.assertTrue(authRequestUri.toString().contains("scope=openid"));
        Assert.assertTrue(authRequestUri.toString().contains("prompt=login"));
    }

    /**
     * Tests display configuration.
     * 
     * @throws Exception
     */
    @Test
    public void testDisplay() throws Exception {
        action.setDisplay(Display.TOUCH.toString());
        action.initialize();
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, false);
        Assert.assertNotNull(suCtx);
        Assert.assertNotNull(suCtx.getAuthenticationRequestURI());
        final URI authRequestUri = suCtx.getAuthenticationRequestURI();
        Assert.assertTrue(authRequestUri.toString().contains("scope=openid"));
        Assert.assertTrue(authRequestUri.toString().contains("display=touch"));
    }

    /**
     * Tests supported scopes, one by one.
     * 
     * @throws Exception
     */
    @Test
    public void testScopes() throws Exception {
        testScope("ADDRESS", "openid+address");
        testScope("EMAIL", "openid+email");
        testScope("OFFLINE_ACCESS", "openid+offline");
        testScope("PHONE", "openid+phone");
        testScope("PROFILE", "openid+profile");
    }

    /**
     * Tests scope.
     * 
     * @param scope
     * @param scopeParam
     * @throws Exception
     */
    public void testScope(final String scope, final String scopeParam) throws Exception {
        action = new SetOIDCInformation();
        loadMetadata(action, true);
        action.setClientId(clientId);
        action.setClientSecret(clientSecret);
        action.setRedirectURI(redirectUri);
        List<String> oidcScopes = new ArrayList<>();
        oidcScopes.add(scope);
        action.setScope(oidcScopes);
        action.initialize();
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, false);
        Assert.assertNotNull(suCtx);
        Assert.assertNotNull(suCtx.getAuthenticationRequestURI());
        final URI authRequestUri = suCtx.getAuthenticationRequestURI();
        Assert.assertTrue(authRequestUri.toString().contains("scope=" + scopeParam));
    }

    /**
     * Test forced auth {@link AuthenticationContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testForced() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        authCtx.setForceAuthn(true);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, false);
        Assert.assertNotNull(suCtx);
        Assert.assertNotNull(suCtx.getAuthenticationRequestURI());
        final URI authRequestUri = suCtx.getAuthenticationRequestURI();
        log.trace("Auth Request URI: {}", authRequestUri.toString());
        Assert.assertTrue(authRequestUri.toString().contains("scope=openid"));
        Assert.assertTrue(authRequestUri.toString().contains("max_age=1"));
    }

    /**
     * Test passive {@link AuthenticationContext}.
     * 
     * @throws Exception
     */
    @Test
    public void testPassive() throws Exception {
        action.initialize();
        final AuthenticationContext authCtx = prc.getSubcontext(AuthenticationContext.class, false);
        authCtx.setIsPassive(true);
        final Event event = action.execute(src);
        Assert.assertNull(event);
        final SocialUserOpenIdConnectContext suCtx = authCtx.getSubcontext(SocialUserOpenIdConnectContext.class, false);
        Assert.assertNotNull(suCtx);
        Assert.assertNotNull(suCtx.getAuthenticationRequestURI());
        final URI authRequestUri = suCtx.getAuthenticationRequestURI();
        log.trace("Auth Request URI: {}", authRequestUri.toString());
        Assert.assertTrue(authRequestUri.toString().contains("scope=openid"));
        Assert.assertTrue(authRequestUri.toString().contains("prompt=none"));
    }

    /**
     * Loads OIDC configuration metadata.
     * 
     * @param action
     * @param publish
     * @throws Exception
     */
    protected synchronized void loadMetadata(final SetOIDCInformation action, boolean publish)
            throws IOException, ParseException, URISyntaxException {
        final Container container = new SimpleContainer(publish);
        final SocketProcessor server = new ContainerSocketProcessor(container);
        final Connection connection = new SocketConnection(server);
        final SocketAddress address = new InetSocketAddress(CONTAINER_PORT);
        connection.connect(address);
        try {
            action.setProviderMetadataLocation("http://localhost:" + CONTAINER_PORT + "/");
        } catch (IOException | ParseException | URISyntaxException e) {
            throw e;
        } finally {
            connection.close();
        }
    }

    /**
     * Simple container implementation.
     */
    class SimpleContainer implements Container {

        /** Switch to publish openid configuration. */
        private boolean publish;

        /**
         * Constructor.
         * 
         * @param doPublish Switch to publish openid configuration.
         */
        public SimpleContainer(boolean doPublish) {
            publish = doPublish;
        }

        @Override
        /** {@inheritDoc} */
        public void handle(Request request, Response response) {
            log.trace("Server got request for {}", request.getTarget());
            try {
                if (publish) {
                    IOUtils.copy(new FileInputStream("src/test/resources/openid-configuration"),
                            response.getOutputStream());
                }
                response.getOutputStream().close();
            } catch (Exception e) {
                log.error("Container-side exception ", e);
            }
        }

    }
}
