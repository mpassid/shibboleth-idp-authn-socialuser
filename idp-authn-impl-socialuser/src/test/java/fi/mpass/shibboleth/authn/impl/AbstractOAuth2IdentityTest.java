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
import java.util.Set;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.impl.AbstractOAuth2Identity;
import fi.mpass.shibboleth.authn.impl.OAuth2Identity;
import fi.mpass.shibboleth.authn.principal.SocialUserPrincipal;

public class AbstractOAuth2IdentityTest {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(AbstractOAuth2IdentityTest.class);

    private AbstractOAuth2Identity abstractOAuth2Identity;

    private boolean prin1Match;

    private boolean prin2Match;

    private boolean prin3Match;

    @BeforeMethod
    public void setUp() throws Exception {
        abstractOAuth2Identity = new OAuth2Identity();
        Map<String, String> oauth2PrincipalsDefaults = new HashMap<String, String>();
        oauth2PrincipalsDefaults.put("principal1", "value1");
        oauth2PrincipalsDefaults.put("principal2", "value2");
        oauth2PrincipalsDefaults.put("principal3", "value3");
        abstractOAuth2Identity.setPrincipalsDefaults(oauth2PrincipalsDefaults);

    }

    private void performMatch(Subject subject) {
        prin1Match = false;
        prin2Match = false;
        prin3Match = false;
        final Set<SocialUserPrincipal> principals = subject.getPrincipals(SocialUserPrincipal.class);
        for (SocialUserPrincipal sprin : principals) {
            if ("principal1".equals(sprin.getType()) && "value1".equals(sprin.getValue())) {
                prin1Match = true;
            }
            if ("principal2".equals(sprin.getType()) && "value2".equals(sprin.getValue())) {
                prin2Match = true;
            }
            if ("principal3".equals(sprin.getType()) && "value3".equals(sprin.getValue())) {
                prin3Match = true;
            }
        }
    }

    @Test
    public void testDefaultsEmptySubject() throws Exception {
        Subject subject = new Subject();
        abstractOAuth2Identity.addDefaultPrincipals(subject);
        performMatch(subject);
        Assert.assertEquals(subject.getPrincipals().size(), 3);
        Assert.assertEquals(prin1Match, true);
        Assert.assertEquals(prin2Match, true);
        Assert.assertEquals(prin3Match, true);
    }

    @Test
    public void testDefaultsNonEmptySubject() throws Exception {
        Subject subject = new Subject();
        SocialUserPrincipal suPrincipal1 = new SocialUserPrincipal("principalNoMatch", "valueNoMatch");
        SocialUserPrincipal suPrincipal2 = new SocialUserPrincipal("principal1", "value1");
        SocialUserPrincipal suPrincipal3 = new SocialUserPrincipal("principal2", "value2NoMatch");
        subject.getPrincipals().add(suPrincipal1);
        subject.getPrincipals().add(suPrincipal2);
        subject.getPrincipals().add(suPrincipal3);
        abstractOAuth2Identity.addDefaultPrincipals(subject);
        performMatch(subject);
        Assert.assertEquals(subject.getPrincipals().size(), 4);
        Assert.assertEquals(prin1Match, true);
        Assert.assertEquals(prin2Match, false);
        Assert.assertEquals(prin3Match, true);
    }

    @Test
    public void testParsingPrincipalsFromSubject() throws Exception {

        Map<String, String> oauth2ClaimsPrincipals = new HashMap<String, String>();
        oauth2ClaimsPrincipals.put("sub", "userId");
        oauth2ClaimsPrincipals.put("urn:oid:1.2.246.22", "special");
        oauth2ClaimsPrincipals.put("urn:oid:1.2.246.XX", "special2");
        abstractOAuth2Identity.setClaimsPrincipals(oauth2ClaimsPrincipals);

        Map<String, String> oauth2CustomClaimTypes = new HashMap<String, String>();
        oauth2CustomClaimTypes.put("sub", "notsupportedtype");
        oauth2CustomClaimTypes.put("urn:oid:1.2.246.22", "jsonarray");
        oauth2CustomClaimTypes.put("urn:oid:1.2.246.XX", "jsonarray");
        abstractOAuth2Identity.setCustomClaimsTypes(oauth2CustomClaimTypes);

        JSONObject json = new JSONObject();
        JSONArray jsonArray = new JSONArray();
        jsonArray.add("010191-123A");
        JSONArray jsonArray2 = new JSONArray();
        jsonArray2.add("Tammi Tauno Matias");
        jsonArray2.add("Matiasson");

        json.put("sub", "CN=test,OU=Luottamusverkosto,CN=Ubilogin,DC=oidc,DC=ubidemo,DC=com");
        json.put("aud", "zjaj93fcf5os1zbjt2pe5jrubb4xkeqw3lgm");
        json.put("urn:oid:1.2.246.22", jsonArray);
        json.put("urn:oid:1.2.246.XX", jsonArray2);
        json.put("iat", 354739);

        Subject subject = new Subject();
        abstractOAuth2Identity.parsePrincipalsFromClaims(subject, json);
        // 5 claims, 3 mapped and one of the 3 is set as userprincipal
        // Assert.assertEquals(4,subject.getPrincipals().size());

        boolean bFind1 = false;
        boolean bFind2 = false;
        boolean bFind3 = false;
        boolean bFind4 = false;
        final Set<SocialUserPrincipal> principals = subject.getPrincipals(SocialUserPrincipal.class);
        for (SocialUserPrincipal sprin : principals) {
            if ("userId".equals(sprin.getType())
                    && "CN=test,OU=Luottamusverkosto,CN=Ubilogin,DC=oidc,DC=ubidemo,DC=com".equals(sprin.getValue())) {
                bFind1 = true;
            }
            if ("special".equals(sprin.getType()) && "010191-123A".equals(sprin.getValue())) {
                bFind2 = true;
            }
            if ("special2".equals(sprin.getType()) && "Tammi Tauno Matias".equals(sprin.getValue())) {
                bFind3 = true;
            }
            if ("special2".equals(sprin.getType()) && "Matiasson".equals(sprin.getValue())) {
                bFind4 = true;
            }
        }
        Assert.assertTrue(bFind1);
        Assert.assertTrue(bFind2);
        Assert.assertTrue(bFind3);
        Assert.assertTrue(bFind4);

    }

}
