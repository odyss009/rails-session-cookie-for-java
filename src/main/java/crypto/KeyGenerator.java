package crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

/**
 * Created by odyss009 on 4/13/17.
 */
public class KeyGenerator {
    private String secret = null;
    private int iterationCount = 2 << 15;
    private Logger logger = LoggerFactory.getLogger(KeyGenerator.class);

    public KeyGenerator(String secret, int iterationCount) {
        this.secret = secret;
        this.iterationCount = iterationCount;
    }

    public SecretKey generateKey(String salt, int keySize) throws InvalidKeySpecException, NoSuchAlgorithmException,
            UnsupportedEncodingException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec =  new PBEKeySpec(secret.toCharArray(), salt.getBytes("UTF-8"), iterationCount , keySize );
        SecretKey tmp = factory.generateSecret(spec);

//        logger.info("key length is {}", tmp.getEncoded().length);

        SecretKey secret = new SecretKeySpec(tmp.getEncoded(),"AES");
        return secret;
    }
}
