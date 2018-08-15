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

package fi.mpass.shibboleth.context;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.BaseContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class is used to pass user information produced in authentication for webflow to process later.
 */
public class SocialUserContext extends BaseContext {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(SocialUserContext.class);

    /** The email. */
    @Nullable
    private String email;

    /** The first name. */
    @Nullable
    private String firstName;

    /** The last name. */
    @Nullable
    private String lastName;

    /** The userid. */
    @Nullable
    private String userId;

    /** The display name. */
    @Nullable
    private String displayName;

    /** The provider id. */
    @Nullable
    private String providerId;

    /** Map of principals. */
    private Map<String, List<String>> principalMap;

    /**
     * Gets the principal map.
     * 
     * @return principal map
     */
    @Nullable
    public Map<String, List<String>> getPrincipalMap() {
        log.trace("Entering & Leaving");
        return principalMap;
    }

    /**
     * Adds a principal to principal map.
     * 
     * @param key to principal
     * @param value of principal
     */
    public void addPrincipal(String key, String value) {
        log.trace("Entering");
        if (principalMap == null) {
            principalMap = new HashMap<String, List<String>>();
        }
        if (!principalMap.containsKey(key)) {
            principalMap.put(key, new ArrayList<String>());
        }
        principalMap.get(key).add(value);
    }

    /**
     * Gets the email.
     * 
     * @return the email
     */
    @Nullable
    public String getEmail() {
        log.trace("Entering & Leaving");
        return email;
    }

    /**
     * Sets the email.
     * 
     * @param scEmail the email
     * 
     * @return this context
     */
    public SocialUserContext setEmail(@Nullable final String scEmail) {
        log.trace("Entering");
        email = scEmail;
        log.trace("Leaving");
        return this;
    }

    /**
     * Gets the first name.
     * 
     * @return the first name
     */
    @Nullable
    public String getFirstName() {
        log.trace("Entering & Leaving");
        return firstName;
    }

    /**
     * Sets the first name.
     * 
     * @param scFirstName the first name
     * 
     * @return this context
     */
    public SocialUserContext setFirstName(@Nullable final String scFirstName) {
        log.trace("Entering");
        firstName = scFirstName;
        log.trace("Leaving");
        return this;
    }

    /**
     * Gets the last Name.
     * 
     * @return the last Name
     */
    @Nullable
    public String getLastName() {
        log.trace("Entering & Leaving");
        return lastName;
    }

    /**
     * Sets the last Name.
     * 
     * @param scLastName the last Name
     * 
     * @return this context
     */
    public SocialUserContext setLastName(@Nullable final String scLastName) {
        log.trace("Entering");
        lastName = scLastName;
        log.trace("Leaving");
        return this;
    }

    /**
     * Gets the userid.
     * 
     * @return the userid
     */
    @Nullable
    public String getUserId() {
        log.trace("Entering & Leaving");
        return userId;
    }

    /**
     * Sets the userid.
     * 
     * @param scUserId the userid
     * 
     * @return this context
     */
    public SocialUserContext setUserId(@Nullable final String scUserId) {
        log.trace("Entering");
        userId = scUserId;
        log.trace("Leaving");
        return this;
    }

    /**
     * Gets the display Name.
     * 
     * @return the display Name
     */
    @Nullable
    public String getDisplayName() {
        log.trace("Entering & Leaving");
        return displayName;
    }

    /**
     * Sets the display Name.
     * 
     * @param scDisplayName the display Name
     * 
     * @return this context
     */
    public SocialUserContext setDisplayName(@Nullable final String scDisplayName) {
        log.trace("Entering");
        displayName = scDisplayName;
        log.trace("Leaving");
        return this;
    }

    /**
     * Gets the providerid.
     * 
     * @return the providerid
     */
    @Nullable
    public String getProviderId() {
        log.trace("Entering & Leaving");
        return providerId;
    }

    /**
     * Sets the providerid.
     * 
     * @param scProviderId the providerid
     * 
     * @return this context
     */
    public SocialUserContext setProviderId(@Nullable final String scProviderId) {
        log.trace("Entering");
        providerId = scProviderId;
        log.trace("Leaving");
        return this;
    }

}
