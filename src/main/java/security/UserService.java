package security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

@Service
public class UserService {
	
	Map<String,String> apiKeyToSecret = new ConcurrentHashMap<>();
	
	public UserService() {
		apiKeyToSecret.put("apiKey","secretsecret");
		apiKeyToSecret.put("apiKey2","secretsecret2");
	}
	
	public String loadSecretByUsername(String apiKey) {
		return apiKeyToSecret.get(apiKey);
	}

}
