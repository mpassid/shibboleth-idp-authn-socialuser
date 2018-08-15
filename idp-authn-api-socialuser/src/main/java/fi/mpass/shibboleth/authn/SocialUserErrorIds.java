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

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

/**
 * Constants to use for error results related to social user authentication.
 */
public final class SocialUserErrorIds {

    /**
     * Generic ID for exception thrown.
     */
    @Nonnull
    @NotEmpty
    public static final String EXCEPTION = "SocialUserException";

    /**
     * ID for user canceling the authentication.
     */
    @Nonnull
    @NotEmpty
    public static final String USER_CANCELED = "SocialUserCanceled";

    /** private constructor to prohibit use of it. */
    private SocialUserErrorIds() {

    };

}
