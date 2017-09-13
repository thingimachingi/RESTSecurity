package security;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;

public final class HMACUtil {
	
	   public static final String calculateHMAC(String secret, String data) {
	        try {
	            SecretKeySpec signingKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
	            Mac mac = Mac.getInstance("HmacSHA256");
	            mac.init(signingKey);
	            byte[] rawHmac = mac.doFinal(data.getBytes());
	            String result = new String(Base64.encodeBase64(rawHmac));
	            return result;
	        } catch (GeneralSecurityException e) {
	            throw new IllegalArgumentException();
	        }
	    }	


}
