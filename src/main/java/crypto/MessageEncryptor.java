package crypto;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;

/**
 * Created by odyss009 on 4/13/17.
 */
public class MessageEncryptor {
    private SecretKey secretKey;
    private SecretKey signSecretKey;
    private MessageVerifier verifier;
    private Logger logger = LoggerFactory.getLogger(MessageEncryptor.class);

    public MessageEncryptor(SecretKey secretKey, SecretKey signSecretKey) {
        this.secretKey = secretKey;
        this.signSecretKey = signSecretKey;
        this.verifier = new MessageVerifier(signSecretKey);
    }

    public String encryptAndSign(String value) throws NoSuchPaddingException, BadPaddingException,
            NoSuchAlgorithmException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidKeyException,
            InvalidParameterSpecException {
        return this.verifier.generate(encrypt(value));
    }

    public String decryptAndVerify(String value) throws UnsupportedEncodingException, InvalidMessageException,
            NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException,
            BadPaddingException, InvalidAlgorithmParameterException {
        return decrypt(this.verifier.verify(value));
    }

    private String encrypt(String value) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidParameterSpecException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        SecretKey secret = new SecretKeySpec(this.secretKey.getEncoded(), "AES");
        /* Encrypt the message. */
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] cipherText = cipher.doFinal(value.getBytes("UTF-8"));

        Base64 base64 = new Base64 ();
        return base64.encodeToString(cipherText) + "--" + base64.encodeToString(iv);
    }

    private String decrypt(String encryptedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        String[] arr = encryptedMessage.split("--");
        Base64 base64 =  new Base64 ();
        byte[] encryptedData = base64.decode(arr[0]);
        byte[] iv = base64.decode(arr[1]);

        SecretKey secret = new SecretKeySpec(this.secretKey.getEncoded(), "AES");

        /* Decrypt the message, given derived key and initialization vector. */
        Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
        String plaintext = new String(decipher.doFinal(encryptedData));
        return plaintext;
    }
}
