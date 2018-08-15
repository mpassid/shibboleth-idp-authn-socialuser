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

import javax.annotation.Nonnull;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.simpleframework.http.Request;
import org.simpleframework.http.Response;
import org.simpleframework.http.core.Container;
import org.simpleframework.http.core.ContainerSocketProcessor;
import org.simpleframework.transport.SocketProcessor;
import org.simpleframework.transport.connect.Connection;
import org.simpleframework.transport.connect.SocketConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ResponseMode;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

import fi.mpass.shibboleth.authn.impl.GetOIDCTokenResponse;
import fi.mpass.shibboleth.authn.impl.SocialUserOpenIdConnectContext;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.idp.profile.ActionTestingSupport;

/**
 * Unit tests for {@link GetOIDCTokenResponse}.
 */
public class GetOIDCTokenResponseTest extends AbstractOIDCIDTokenTest {

    @Nonnull
    private final Logger log = LoggerFactory.getLogger(GetOIDCTokenResponseTest.class);

    /** Action to be tested. */
    private GetOIDCTokenResponse action;

    /** The token endpoint. */
    private URI tokenUri;

    /** The JWT returned by the token endpoint. */
    private String jwt;

    /** {@inheritDoc} */
    @Override
    protected AbstractProfileAction<?, ?> getAction() {
        return action;
    }

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        nullifyIdToken = true;
        action = new GetOIDCTokenResponse();
        tokenUri = new URI("http://localhost:" + SetOIDCInformationTest.CONTAINER_PORT + "/");
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gR"
                + "G9lIiwiYWRtaW4iOnRydWUsImlkX3Rva2VuIjoibW9jayJ9.WYdJu_tkc4OGfqouYYqFGG5qC6_P8adFaYeiu07W3AY";
    }

    /**
     * Runs action without {@link AuthenticationSuccessResponse} in the context.
     * 
     * @throws Exception
     */
    @Test
    public void tesNoSuccessResponse() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    /**
     * Runs action without access_token coming back from the token endpoint.
     * 
     * @throws Exception
     */
    @Test
    public void testNoAccessToken() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final AuthenticationSuccessResponse response =
                new AuthenticationSuccessResponse(tokenUri, new AuthorizationCode(), null, new BearerAccessToken(),
                        State.parse("mock"), State.parse("mock2"), ResponseMode.FORM_POST);
        suCtx.setAuthenticationSuccessResponse(response);
        suCtx.setClientID(new ClientID("mockClientId"));
        suCtx.setClientSecret(new Secret("mockClientSecret"));
        final OIDCProviderMetadata metadata = buildOidcMetadata(DEFAULT_ISSUER);
        metadata.setTokenEndpointURI(tokenUri);
        suCtx.setoIDCProviderMetadata(metadata);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = executeWithServer(action, null);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.INVALID_CREDENTIALS);
    }

    /**
     * Runs the action with prerequisites fulfilled.
     * 
     * @throws Exception
     */
    @Test
    public void testSuccess() throws Exception {
        final AbstractProfileAction<?, ?> action = getAction();
        action.initialize();
        final SocialUserOpenIdConnectContext suCtx = new SocialUserOpenIdConnectContext();
        final AccessToken accessToken = new BearerAccessToken();
        final AuthenticationSuccessResponse response =
                new AuthenticationSuccessResponse(tokenUri, new AuthorizationCode(), null, accessToken,
                        State.parse("mock"), State.parse("mock2"), ResponseMode.FORM_POST);
        suCtx.setAuthenticationSuccessResponse(response);
        suCtx.setClientID(new ClientID("mockClientId"));
        suCtx.setClientSecret(new Secret("mockClientSecret"));
        final OIDCProviderMetadata metadata = buildOidcMetadata(DEFAULT_ISSUER);
        metadata.setTokenEndpointURI(tokenUri);
        suCtx.setoIDCProviderMetadata(metadata);
        prc.getSubcontext(AuthenticationContext.class, false).addSubcontext(suCtx);
        final Event event = executeWithServer(action, accessToken.toString());
        Assert.assertNull(event);
        Assert.assertNotNull(suCtx.getOidcTokenResponse());
        Assert.assertEquals(jwt, suCtx.getOidcTokenResponse().getOIDCTokens().getIDTokenString());
        Assert.assertEquals(accessToken.toString(),
                suCtx.getOidcTokenResponse().getOIDCTokens().getAccessToken().toString());
    }

    /**
     * Executes the action with server turned on.
     * 
     * @param action
     * @param accessToken
     * @return
     * @throws Exception
     */
    protected Event executeWithServer(final AbstractProfileAction<?, ?> action, final String accessToken)
            throws Exception {
        final Container container = new SimpleContainer(accessToken);
        final SocketProcessor server = new ContainerSocketProcessor(container);
        final Connection connection = new SocketConnection(server);
        final SocketAddress address = new InetSocketAddress(SetOIDCInformationTest.CONTAINER_PORT);
        connection.connect(address);
        try {
            return action.execute(src);
        } catch (Exception e) {
            throw e;
        } finally {
            connection.close();
        }
    }

    /**
     * Simple container implementation.
     */
    class SimpleContainer implements Container {

        final String accessToken;

        /**
         * Constructor.
         */
        public SimpleContainer(final String accToken) {
            accessToken = accToken;
        }

        @Override
        /** {@inheritDoc} */
        public void handle(Request request, Response response) {
            log.trace("Server got request for {}", request.getTarget());
            try {
                response.setContentType("application/json");
                if (accessToken == null) {
                    IOUtils.copy(
                            new StringReader("{ \"id_token\":\"" + jwt + "\"" + ", \"token_type\":\"Bearer\"" + "} "),
                            response.getOutputStream());
                } else {
                    IOUtils.copy(new StringReader("{ \"id_token\":\"" + jwt + "\"" + ", \"token_type\":\"Bearer\""
                            + ", \"access_token\":\"" + accessToken + "\"} "), response.getOutputStream());
                }
                response.getOutputStream().close();
            } catch (Exception e) {
                log.error("Container-side exception ", e);
            }
        }
    }
}
