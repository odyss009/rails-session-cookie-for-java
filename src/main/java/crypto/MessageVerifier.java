package crypto;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by odyss009 on 4/13/17.
 */
public class MessageVerifier {

    private SecretKey secret;
    private String digest;
    private Logger logger = LoggerFactory.getLogger(MessageVerifier.class);

    public MessageVerifier(SecretKey secret) {
        this.secret = secret;
        this.digest = "HmacSHA1";
    }

    public boolean validMessage(String signedMessage) {
        if(signedMessage == null || signedMessage.equals("")) {
            return false;
        }

        String[] splitedMessages = signedMessage.split("--");
        String data = splitedMessages[0];
        String extractedDigest = splitedMessages[1];

        try {
            if(data != null && extractedDigest != null) {
                MessageDigest.isEqual(data.getBytes("UTF-8"), generateDigest(data).getBytes("UTF-8"));
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public String verify(String signedMessage) throws InvalidMessageException, UnsupportedEncodingException {
        if(validMessage(signedMessage)) {
            String[] splitedMessages = signedMessage.split("--");
            String data = splitedMessages[0];
            if(data != null) {
                Base64 base64 = new Base64 ();
                return new String(base64.decode(data), "UTF-8");
            } else {
                throw new InvalidMessageException();
            }
        } else {
            throw new InvalidMessageException();
        }
    }

    public String generate(String value) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException {
        Base64 base64 = new Base64 ();
        String data = base64.encodeToString(value.getBytes("UTF-8"));
        return data + "--" + generateDigest(data);
    }

    private String generateDigest(String value) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        SecretKeySpec signingKey = new SecretKeySpec(this.secret.getEncoded(), this.digest);

        Mac mac = Mac.getInstance(this.digest);
        mac.init(signingKey);
        byte[] result = mac.doFinal(value.getBytes("UTF-8"));

        return Hex.encodeHexString(result);
    }
}
