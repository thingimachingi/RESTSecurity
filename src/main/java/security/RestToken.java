package security;

import java.util.Collection;
import java.util.Date;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class RestToken extends UsernamePasswordAuthenticationToken {

	private Date timestamp;

	public RestToken(Object principal, Object credentials) {
		super(principal, credentials);
		// TODO Auto-generated constructor stub
	}
	public RestToken(Object principal, Object credentials, Date timestamp) {
		super(principal, credentials);
		this.timestamp = timestamp;
		// TODO Auto-generated constructor stub
	}


	public RestToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
		// TODO Auto-generated constructor stub
	}
	
	public RestToken (Object principal, Object credentials, Date timestamp,Collection<? extends GrantedAuthority> authorities) {
		super(principal, credentials, authorities);
		this.timestamp = timestamp;
	}
	@Override
	public Object getCredentials() {
		// TODO Auto-generated method stub
		return super.getCredentials();
	}
	@Override
	public Object getPrincipal() {
		// TODO Auto-generated method stub
		return super.getPrincipal();
	}
	public Date getTimestamp() {
		return timestamp;
	}
	
	

}
