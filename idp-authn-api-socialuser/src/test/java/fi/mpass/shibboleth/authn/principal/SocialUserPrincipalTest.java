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

package fi.mpass.shibboleth.authn.principal;

import org.testng.Assert;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal.Types;

/**
 * Unit tests for {@link SocialUserPrincipal}.
 */
public class SocialUserPrincipalTest {

    /**
     * Test creating a null principal.
     */
    @Test
    public void createNullPrincipal() {
        SocialUserPrincipal sup = new SocialUserPrincipal((String) null, null);
        Assert.assertNull(sup.getName());
        Assert.assertNull(sup.getValue());
        Assert.assertNull(sup.getType());
        Assert.assertNull(sup.getTypesType());

    }

    /**
     * Test creating a unmapped principal of unknown type.
     */
    @Test
    public void createUnmappedPrincipal() {
        SocialUserPrincipal sup = new SocialUserPrincipal("principal_type_unknown", "value");
        Assert.assertEquals(sup.getName(), "value");
        Assert.assertEquals(sup.getValue(), "value");
        Assert.assertEquals(sup.getType(), "principal_type_unknown");
        Assert.assertNull(sup.getTypesType());
    }

    /**
     * Test creating a unmapped principal with empty strings.
     */
    @Test
    public void createUnmappedPrincipalEmptyStrings() {
        SocialUserPrincipal sup = new SocialUserPrincipal("", "");
        Assert.assertEquals(sup.getName(), "");
        Assert.assertEquals(sup.getValue(), "");
        Assert.assertEquals(sup.getType(), "");
        Assert.assertNull(sup.getTypesType());
    }

    /**
     * Test creating a mapped principal using string constructor.
     */
    @Test
    public void createPrincipalbyString() {
        SocialUserPrincipal sup = new SocialUserPrincipal(Types.displayName.toString(), "value");
        Assert.assertEquals(sup.getName(), "value");
        Assert.assertEquals(sup.getValue(), "value");
        Assert.assertEquals(sup.getType(), Types.displayName.toString());
        Assert.assertEquals(sup.getTypesType(), Types.displayName);
    }

    /**
     * Test creating a mapped principal.
     */
    @Test
    public void createPrincipalby() {
        SocialUserPrincipal sup = new SocialUserPrincipal(Types.displayName, "value");
        Assert.assertEquals(sup.getName(), "value");
        Assert.assertEquals(sup.getValue(), "value");
        Assert.assertEquals(sup.getType(), Types.displayName.toString());
        Assert.assertEquals(sup.getTypesType(), Types.displayName);
    }
}
