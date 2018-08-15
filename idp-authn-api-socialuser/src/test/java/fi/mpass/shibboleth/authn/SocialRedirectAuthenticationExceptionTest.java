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

package fi.mpass.shibboleth.authn;

import org.testng.Assert;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.SocialUserAuthenticationException;

/**
 * Unit tests for {@link SocialUserAuthenticationException}.
 */
public class SocialRedirectAuthenticationExceptionTest {

    /**
     * Tests exception parameters
     */
    @Test
    public void testExceptionParameters() {
        try {
            throw new SocialUserAuthenticationException(null, null);
        } catch (SocialUserAuthenticationException e) {
            Assert.assertNull(e.getMessage());
            Assert.assertNull(e.getAuthEventId());
        }
        try {
            throw new SocialUserAuthenticationException("", "");
        } catch (SocialUserAuthenticationException e) {
            Assert.assertEquals(e.getMessage(), "");
            Assert.assertEquals(e.getAuthEventId(), "");
        }
        try {
            throw new SocialUserAuthenticationException("description", "event");
        } catch (SocialUserAuthenticationException e) {
            Assert.assertEquals(e.getMessage(), "description");
            Assert.assertEquals(e.getAuthEventId(), "event");
        }
    }

}
