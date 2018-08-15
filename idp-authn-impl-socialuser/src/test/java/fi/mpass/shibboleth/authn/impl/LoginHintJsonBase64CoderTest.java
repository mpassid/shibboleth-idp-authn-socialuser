
package fi.mpass.shibboleth.authn.impl;

import java.util.HashMap;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.impl.LoginHintJsonBase64Coder;

public class LoginHintJsonBase64CoderTest {

    private LoginHintJsonBase64Coder loginHintJsonBase64Coder;

    Map<String, String> loginHintMap;

    @BeforeMethod
    public void setUp() throws Exception {
        loginHintJsonBase64Coder = new LoginHintJsonBase64Coder();
        loginHintMap = new HashMap<String, String>();
        loginHintMap.put("key1", "value1");
        loginHintMap.put("key2", "value2");
        loginHintMap.put("key3", "value3");

    }

    @Test
    public void failNullMapEncode() throws Exception {
        loginHintMap = null;
        Assert.assertNull(loginHintJsonBase64Coder.encode(loginHintMap));
    }

    @Test
    public void emptyMapEncode() throws Exception {
        loginHintMap.clear();
        Assert.assertEquals(loginHintJsonBase64Coder.encode(loginHintMap), "e30=");
    }

    @Test
    public void failNullStringDecode() throws Exception {
        Assert.assertNull(loginHintJsonBase64Coder.decode(null));
    }

    @Test
    public void failNonJsonStringDecode() throws Exception {
        Assert.assertNull(loginHintJsonBase64Coder.decode("non_json"));
    }

    @Test
    public void successEncode() throws Exception {
        String encoded = loginHintJsonBase64Coder.encode(loginHintMap);
        Map<String, String> decoded = loginHintJsonBase64Coder.decode(encoded);
        Assert.assertTrue(decoded.equals(loginHintMap));
    }

}
