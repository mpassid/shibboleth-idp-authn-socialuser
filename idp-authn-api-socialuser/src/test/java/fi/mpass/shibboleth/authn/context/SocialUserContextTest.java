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

package fi.mpass.shibboleth.authn.context;

import org.testng.Assert;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.context.SocialUserContext;

/**
 * Unit tests for {@link SocialUserContext}.
 */
public class SocialUserContextTest {

    /** Tests mutating the DisplayName. */
    @Test
    public void testDisplayName() {
        SocialUserContext ctx = new SocialUserContext();
        Assert.assertNull(ctx.getDisplayName());
        ctx.setDisplayName("DisplayName");
        Assert.assertEquals(ctx.getDisplayName(), "DisplayName");
        ctx.setDisplayName("DisplayName2");
        Assert.assertEquals(ctx.getDisplayName(), "DisplayName2");
        ctx.setDisplayName("");
        Assert.assertEquals(ctx.getDisplayName(), "");
        ctx.setDisplayName(null);
        Assert.assertNull(ctx.getDisplayName());
    }

    /** Tests mutating the Email. */
    @Test
    public void testEmail() {
        SocialUserContext ctx = new SocialUserContext();
        Assert.assertNull(ctx.getEmail());
        ctx.setEmail("Email");
        Assert.assertEquals(ctx.getEmail(), "Email");
        ctx.setEmail("Email2");
        Assert.assertEquals(ctx.getEmail(), "Email2");
        ctx.setEmail("");
        Assert.assertEquals(ctx.getEmail(), "");
        ctx.setEmail(null);
        Assert.assertNull(ctx.getEmail());
    }

    /** Tests mutating the FirstName. */
    @Test
    public void testFirstName() {
        SocialUserContext ctx = new SocialUserContext();
        Assert.assertNull(ctx.getFirstName());
        ctx.setFirstName("FirstName");
        Assert.assertEquals(ctx.getFirstName(), "FirstName");
        ctx.setFirstName("FirstName2");
        Assert.assertEquals(ctx.getFirstName(), "FirstName2");
        ctx.setFirstName("");
        Assert.assertEquals(ctx.getFirstName(), "");
        ctx.setFirstName(null);
        Assert.assertNull(ctx.getFirstName());
    }

    /** Tests mutating the LastName. */
    @Test
    public void testLastName() {
        SocialUserContext ctx = new SocialUserContext();
        Assert.assertNull(ctx.getLastName());
        ctx.setLastName("LastName");
        Assert.assertEquals(ctx.getLastName(), "LastName");
        ctx.setLastName("LastName2");
        Assert.assertEquals(ctx.getLastName(), "LastName2");
        ctx.setLastName("");
        Assert.assertEquals(ctx.getLastName(), "");
        ctx.setLastName(null);
        Assert.assertNull(ctx.getLastName());
    }

    /** Tests mutating the ProviderId. */
    @Test
    public void testProviderId() {
        SocialUserContext ctx = new SocialUserContext();
        Assert.assertNull(ctx.getProviderId());
        ctx.setProviderId("ProviderId");
        Assert.assertEquals(ctx.getProviderId(), "ProviderId");
        ctx.setProviderId("ProviderId2");
        Assert.assertEquals(ctx.getProviderId(), "ProviderId2");
        ctx.setProviderId("");
        Assert.assertEquals(ctx.getProviderId(), "");
        ctx.setProviderId(null);
        Assert.assertNull(ctx.getProviderId());
    }

    /** Tests mutating the UserId. */
    @Test
    public void testUserId() {
        SocialUserContext ctx = new SocialUserContext();
        Assert.assertNull(ctx.getUserId());
        ctx.setUserId("UserId");
        Assert.assertEquals(ctx.getUserId(), "UserId");
        ctx.setUserId("UserId2");
        Assert.assertEquals(ctx.getUserId(), "UserId2");
        ctx.setUserId("");
        Assert.assertEquals(ctx.getUserId(), "");
        ctx.setUserId(null);
        Assert.assertNull(ctx.getUserId());
    }

}
