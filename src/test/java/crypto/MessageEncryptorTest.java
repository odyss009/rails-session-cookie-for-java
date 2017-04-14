package crypto;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

/**
 * Created by odyss009 on 4/13/17.
 */
public class MessageEncryptorTest {

    private String secretKeyBase = "8adb50b57844591f898eebf4bb2b069d6614245fbef4c54f8d11c071b4fd5bda2d49280c6d8e797a1dab2cdd48690f6fef7547b55e0d117d9d5ad865fe585f1b";
    private String encryptedCookieSalt = "abcdefg hijklmno";
    private String encryptedSignedCookieSalt = "signed abcdefg hijklmno";

    private MessageEncryptor getMessageEncryptor() throws InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException {
        KeyGenerator keyGenerator = new KeyGenerator(secretKeyBase, 1000);
        SecretKey secretKey = keyGenerator.generateKey(encryptedCookieSalt, 256);
        SecretKey signSecretKey = keyGenerator.generateKey(encryptedSignedCookieSalt, 512);
        return new MessageEncryptor(secretKey, signSecretKey);
    }

    @Test
    public void testEncryptAndSign() throws Exception {
        MessageEncryptor messageEncryptor = getMessageEncryptor();
        String value = "{\"session_id\":\"6022d05887d2ab9c1bad8a87cf8fb949\",\"_csrf_token\":\"OPv/LxbiA5dUjVsbG4EllSS9cca630WOHQcMtPxSQUE=\"}";
        String result = messageEncryptor.encryptAndSign(value);
        assertNotNull(result);
    }

    @Test
    public void testDecryptAndVerify() throws Exception {
        MessageEncryptor messageEncryptor = getMessageEncryptor();
        String value = "OFdndzlEaTFCbjhRWk10dDZtZENyRkE3bU1uZFNuNUY5S2phdmZ1Q1gvNkFkb0g1SmpKaUtocDVEam5QajN0SDNCNGdxOVJOWU1ic3RuS1JSbTBjc3Z3NWZOWDJXQ2tPMUpKNC9QYk95Vnc4M3dUK0d6eGllZHFGWldZR1RTTllHVjBmQy9sU3BuaExWMjE2dkk3cURRPT0tLWxoOUJlSTlOSHhmWkRWVnVUTTFQeGc9PQ==--cdfd8d1c4c1e15ca10d2c7faddc0b0eeb4b18f32";
        String decryptedMessage = messageEncryptor.decryptAndVerify(value);
        assertEquals("{\"session_id\":\"6022d05887d2ab9c1bad8a87cf8fb949\",\"_csrf_token\":\"OPv/LxbiA5dUjVsbG4EllSS9cca630WOHQcMtPxSQUE=\"}", decryptedMessage);
    }

    @Test
    public void testEncryptAndDecrypt() throws Exception {
        MessageEncryptor messageEncryptor = getMessageEncryptor();
        String value = "{\"session_id\":\"6022d05887d2ab9c1bad8a87cf8fb949\",\"_csrf_token\":\"OPv/LxbiA5dUjVsbG4EllSS9cca630WOHQcMtPxSQUE=\"}";
        String encryptedMessage = messageEncryptor.encryptAndSign(value);
        String decryptedMessage = messageEncryptor.decryptAndVerify(encryptedMessage);
        assertEquals("{\"session_id\":\"6022d05887d2ab9c1bad8a87cf8fb949\",\"_csrf_token\":\"OPv/LxbiA5dUjVsbG4EllSS9cca630WOHQcMtPxSQUE=\"}", decryptedMessage);
    }
}