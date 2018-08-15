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

import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import org.mockito.Mockito;
import org.opensaml.profile.context.ProfileRequestContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.SocialRedirectAuthenticator;
import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;
import fi.mpass.shibboleth.authn.SocialUserErrorIds;
import fi.mpass.shibboleth.authn.impl.SocialIdentityFactory;
import fi.mpass.shibboleth.authn.impl.SocialUserAuthServlet;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;
import net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

/**
 * Unit tests for {@link SocialUserAuthServlet}.
 */
public class SocialUserAuthServletTest {

    SocialUserAuthServlet servlet;

    String nullAuthenticator;

    String throwingAuthenticator;

    String subjectAuthenticator;

    String throwingEvent;

    String username;

    String authnRedirectUrl;

    @BeforeMethod
    public void initTests() throws Exception {
        nullAuthenticator = "/method1";
        throwingAuthenticator = "/method2";
        subjectAuthenticator = "/method3";
        throwingEvent = "throwingEvent";
        username = "mockUser";
        authnRedirectUrl = "http://localhost/redirect";
        servlet = new SocialUserAuthServlet();
        SocialIdentityFactory factory = new SocialIdentityFactory();
        Map<String, Object> authenticators = new HashMap<String, Object>();
        authenticators.put(nullAuthenticator, initNullAuthenticator());
        authenticators.put(throwingAuthenticator, initThrowingAuthenticator());
        authenticators.put(subjectAuthenticator, initSubjectAuthenticator());
        factory.setSocialImplBeans(authenticators);
        MockServletContext servletContext = new MockServletContext();
        servletContext.setAttribute("socialUserImplementationFactoryBeanInServletContext", factory);
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servlet.init(servletConfig);
    }

    @Test
    public void testUnmapped() throws Exception {
        MockHttpServletRequest httpRequest = initHttpRequest();
        httpRequest.setRequestURI("/notMapped");
        servlet.service(httpRequest, new MockHttpServletResponse());
        Assert.assertEquals(httpRequest.getAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY),
                SocialUserErrorIds.EXCEPTION);
    }

    @Test
    public void testAuthnStart() throws Exception {
        MockHttpServletRequest httpRequest = initHttpRequest();
        MockHttpServletResponse httpResponse = new MockHttpServletResponse();
        httpRequest.setRequestURI(nullAuthenticator);
        servlet.service(httpRequest, httpResponse);
        Assert.assertNull(httpRequest.getAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY));
        Assert.assertEquals(httpResponse.getRedirectedUrl(), authnRedirectUrl);
    }

    @Test
    public void testAuthnThrows() throws Exception {
        MockHttpServletRequest httpRequest = initHttpRequest();
        MockHttpServletResponse httpResponse = new MockHttpServletResponse();
        httpRequest.setRequestURI(throwingAuthenticator);
        servlet.service(httpRequest, httpResponse);
        Assert.assertEquals(httpRequest.getAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY), throwingEvent);
    }

    @Test
    public void testAuthnSuccess() throws Exception {
        MockHttpServletRequest httpRequest = initHttpRequest();
        MockHttpServletResponse httpResponse = new MockHttpServletResponse();
        httpRequest.setRequestURI(subjectAuthenticator);
        servlet.service(httpRequest, httpResponse);
        Assert.assertNull(httpRequest.getAttribute(ExternalAuthentication.AUTHENTICATION_ERROR_KEY));
        Subject subject = (Subject) httpRequest.getAttribute(ExternalAuthentication.SUBJECT_KEY);
        Assert.assertEquals(subject.getPrincipals().iterator().next().getName(), username);
    }

    protected MockHttpServletRequest initHttpRequest() {
        String conversationKey = "mockKey";
        String startKey = "mockStartKey";
        MockHttpServletRequest httpRequest = new MockHttpServletRequest();
        MockHttpSession httpSession = new MockHttpSession();
        httpSession.setAttribute("ext_auth_start_key", startKey);
        ProfileRequestContext<?, ?> profileContext = new ProfileRequestContext<Object, Object>();
        final AuthenticationContext authnContext = profileContext.getSubcontext(AuthenticationContext.class, true);
        authnContext.setAttemptedFlow(new AuthenticationFlowDescriptor());
        final ExternalAuthenticationContext extAuthnContext =
                authnContext.getSubcontext(ExternalAuthenticationContext.class, true);
        extAuthnContext.setFlowExecutionUrl("http://localhost.example.org/mock");
        httpSession.setAttribute(ExternalAuthentication.CONVERSATION_KEY + startKey,
                new ExternalAuthenticationImpl(profileContext));
        httpSession.setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey,
                new ExternalAuthenticationImpl(profileContext));
        httpRequest.setSession(httpSession);
        httpRequest.addParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        return httpRequest;
    }

    protected SocialRedirectAuthenticator initNullAuthenticator() {
        SocialRedirectAuthenticator authenticator = Mockito.mock(SocialRedirectAuthenticator.class);
        Mockito.when(authenticator.getRedirectUrl((HttpServletRequest) Mockito.any())).thenReturn(authnRedirectUrl);
        return authenticator;
    }

    protected SocialRedirectAuthenticator initThrowingAuthenticator() throws Exception {
        SocialRedirectAuthenticator authenticator = Mockito.mock(SocialRedirectAuthenticator.class);
        SocialUserAuthenticationException exception = new SocialUserAuthenticationException("mock", throwingEvent);
        Mockito.when(authenticator.getSubject((HttpServletRequest) Mockito.any())).thenThrow(exception);
        return authenticator;
    }

    protected SocialRedirectAuthenticator initSubjectAuthenticator() throws Exception {
        SocialRedirectAuthenticator authenticator = Mockito.mock(SocialRedirectAuthenticator.class);
        Subject subject = new Subject();
        subject.getPrincipals().add(new UsernamePrincipal(username));
        Mockito.when(authenticator.getSubject((HttpServletRequest) Mockito.any())).thenReturn(subject);
        return authenticator;
    }
}
