package security;

public final class RestCredentials {
	
	private String requestData;
	public String getRequestData() {
		return requestData;
	}
	private String signature;
	public RestCredentials(String requestDatal, String signature) {
		super();
		this.requestData = requestDatal;
		this.signature = signature;
	}
	public String getSignature() {
		return signature;
	}
	
	
	

}
