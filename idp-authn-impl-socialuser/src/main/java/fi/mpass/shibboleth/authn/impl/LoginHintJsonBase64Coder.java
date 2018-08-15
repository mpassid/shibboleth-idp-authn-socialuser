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

import java.util.Map;

import javax.annotation.Nonnull;

import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.SocialLoginHintCoder;

import org.apache.commons.codec.binary.Base64;

/** Class for encoding (and decoding) string maps to base64 encoded jsons. */
public class LoginHintJsonBase64Coder implements SocialLoginHintCoder {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(LoginHintJsonBase64Coder.class);

    /** Parameter name for login hint. */
    @NotEmpty
    private Map<String, String> loginHintRenameMapping;

    /**
     * Set the login hint coded field names.
     * 
     * @param loginHintRename the new login hint field names
     */
    public void setLoginHintRenameMapping(@NotEmpty final Map<String, String> loginHintRename) {
        log.trace("Entering");
        loginHintRenameMapping = loginHintRename;
        log.trace("Leaving");
    }

    @Override
    public String encode(Map<String, String> loginHints) {
        log.trace("Entering");
        if (loginHints == null) {
            log.trace("Entering");
            return null;
        }
        // Rename fields if ncessary
        if (loginHintRenameMapping != null) {
            for (Map.Entry<String, String> entry : loginHintRenameMapping.entrySet()) {
                if (loginHints.containsKey(entry.getKey())) {
                    loginHints.put(entry.getValue(), loginHints.get(entry.getKey()));
                    loginHints.remove(entry.getKey());
                }
            }
        }
        String ret = new String(Base64.encodeBase64(new JSONObject(loginHints).toJSONString().getBytes()));
        log.debug("encoded hints" + ret);
        log.trace("Leaving");
        return ret;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Map<String, String> decode(String loginHints) {
        log.trace("Entering");
        Map<String, String> ret = null;
        try {
            ret = (Map<String, String>) JSONValue.parse(Base64.decodeBase64(loginHints));
        } catch (Exception e) {
            log.trace("Leaving");
            return null;
        }
        log.trace("Leaving");
        return ret;
    }
}
