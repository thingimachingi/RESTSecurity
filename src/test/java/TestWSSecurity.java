import static org.junit.Assert.*;

import java.security.GeneralSecurityException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Locale;
import java.util.TimeZone;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import io.restassured.RestAssured;
import io.restassured.RestAssured.*;
import io.restassured.http.Header;
import io.restassured.matcher.RestAssuredMatchers.*;
import io.restassured.response.Response;

import org.hamcrest.Matchers.*;
public class TestWSSecurity {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		
		SimpleDateFormat dateFormat;
        dateFormat = new SimpleDateFormat(
                "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

	    String contentType = "application/json";
	    
	    String date = dateFormat.format(Calendar.getInstance().getTime());
	    System.out.println("date="+date);
	    // create signature: method + content md5 + content-type + date + uri
	    StringBuilder signature = new StringBuilder();
	    String method = "GET";
		signature.append(method ).append("\n")
				.append("").append("\n")
		        .append("").append("\n")
	          .append(date).append("\n")
	          .append("/greeting");
		
		
		String auth   		= "apiKey2" + ":" + calculateHMAC("secretsecret2", signature.toString());
		Header header 		= new Header("Authorization", auth);
		Response response 	= RestAssured.given().header(header).header("Date", date).get("http://localhost:8080/greeting?name=Mohan");
		
		assertNotNull (response);
		
		System.out.println(response.getStatusCode());
		assertTrue (response.getStatusCode()==200);
		System.out.println(response.getStatusLine());
		System.out.println(response.asString());
		
	}
	
	   private String calculateHMAC(String secret, String data) {
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
