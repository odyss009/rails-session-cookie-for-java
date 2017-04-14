package crypto;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.SecretKey;

import static org.junit.Assert.*;

/**
 * Created by odyss009 on 4/13/17.
 */
public class KeyGeneratorTest {

    private String secret = "db1c366b854c235f98fc3dd356ad6be8dd388f82ad1ddf14dcad9397ddfdb759b4a9fb33385f695f2cc335041eed0fae74eb669c9fb0c40cafdb118d881215a9";

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void testGenerateKeyWithEncryptedCookieSalt() throws Exception {
        KeyGenerator keyGenerator = new KeyGenerator(secret, 1000);
        String encryptedCookieSalt = "encrypted cookie";
        SecretKey secretKey = keyGenerator.generateKey(encryptedCookieSalt, 256);
        assertNotNull(secretKey);
    }

    @Test
    public void testGenerateKeyWithEncryptedSignedCookieSalt() throws Exception {
        KeyGenerator keyGenerator = new KeyGenerator(secret, 1000);
        String encryptedSignedCookieSalt = "signed encrypted cookie";
        SecretKey secretKey = keyGenerator.generateKey(encryptedSignedCookieSalt, 256);
        assertNotNull(secretKey);
    }
}