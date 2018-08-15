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

import org.testng.Assert;

import net.shibboleth.idp.authn.AuthnEventIds;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;
import net.shibboleth.idp.authn.impl.PopulateAuthenticationContextTest;

import javax.security.auth.Subject;

import org.springframework.webflow.execution.Event;

import net.shibboleth.idp.profile.ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.springframework.mock.web.MockHttpServletRequest;

import fi.mpass.shibboleth.authn.impl.ExtractSocialPrincipalsFromSubject;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal.Types;
import fi.mpass.shibboleth.context.SocialUserContext;

/** {@link ExtractSocialPrincipalsFromSubject} unit test. */
public class ExtractSocialPrincipalsFromSubjectTest extends PopulateAuthenticationContextTest {

    private ExtractSocialPrincipalsFromSubject action;

    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        action = new ExtractSocialPrincipalsFromSubject();

    }

    @Test
    public void testNoServlet() throws Exception {
        action.initialize();
        final Event event = action.execute(src);
        ActionTestingSupport.assertEvent(event, AuthnEventIds.NO_CREDENTIALS);
    }

    @Test
    public void testIdentity() throws Exception {
        Subject subject = new Subject();

        SocialUserPrincipal socialUserPrincipalProviderId = new SocialUserPrincipal(Types.providerId, "providerId");
        subject.getPrincipals().add(socialUserPrincipalProviderId);
        SocialUserPrincipal socialUserPrincipalDisplayName = new SocialUserPrincipal(Types.displayName, "displayName");
        subject.getPrincipals().add(socialUserPrincipalDisplayName);
        SocialUserPrincipal socialUserPrincipalEmail = new SocialUserPrincipal(Types.email, "email");
        subject.getPrincipals().add(socialUserPrincipalEmail);
        SocialUserPrincipal socialUserPrincipalFirstName = new SocialUserPrincipal(Types.firstName, "firstName");
        subject.getPrincipals().add(socialUserPrincipalFirstName);
        SocialUserPrincipal socialUserPrincipalLastName = new SocialUserPrincipal(Types.lastName, "lastName");
        subject.getPrincipals().add(socialUserPrincipalLastName);
        SocialUserPrincipal socialUserPrincipalUserId = new SocialUserPrincipal(Types.userId, "userId");
        subject.getPrincipals().add(socialUserPrincipalUserId);
        SocialUserPrincipal socialUserPrincipalUS = new SocialUserPrincipal("unsupported", "unsupported");
        subject.getPrincipals().add(socialUserPrincipalUS);

        SocialUserContext suCtx = initContexts(subject);

        Assert.assertNotNull(suCtx);
        Assert.assertEquals(suCtx.getProviderId(), "providerId");
        Assert.assertEquals(suCtx.getDisplayName(), "displayName");
        Assert.assertEquals(suCtx.getEmail(), "email");
        Assert.assertEquals(suCtx.getFirstName(), "firstName");
        Assert.assertEquals(suCtx.getLastName(), "lastName");
        Assert.assertEquals(suCtx.getUserId(), "userId");
    }

    private SocialUserContext initContexts(Subject subject) throws ComponentInitializationException {
        MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
        action.setHttpServletRequest(mockHttpServletRequest);
        action.initialize();
        final AuthenticationContext ac = prc.getSubcontext(AuthenticationContext.class, false);
        ExternalAuthenticationContext externalAuthenticationContext = new ExternalAuthenticationContext();
        externalAuthenticationContext.setSubject(subject);
        ac.addSubcontext(externalAuthenticationContext);
        final Event event = action.execute(src);
        ActionTestingSupport.assertProceedEvent(event);
        return (SocialUserContext) ac.getSubcontext(SocialUserContext.class, false);
    }

}
