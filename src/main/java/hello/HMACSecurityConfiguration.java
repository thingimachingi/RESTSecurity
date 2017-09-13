package hello;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import security.RestAuthenticationEntryPoint;
import security.RestAuthenticationProvider;
import security.RestSecurityFilter;
import security.SecurityContants;


@Configuration
@Order(SecurityProperties.BASIC_AUTH_ORDER-10)
@EnableWebSecurity
public class HMACSecurityConfiguration extends WebSecurityConfigurerAdapter {

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.csrf().disable().addFilterAt(getRestSecurityFilter(), UsernamePasswordAuthenticationFilter.class).authorizeRequests().anyRequest().authenticated().
		and().authenticationProvider(getAuthenticationProvider())
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		.and().httpBasic().realmName(SecurityContants.SECURE_REALM)
		.and().antMatcher("/greeting/**").authorizeRequests();
	}
	
	
	@Bean
	public RestSecurityFilter getRestSecurityFilter() throws Exception {
		
		RestSecurityFilter restSecurityFilter = new RestSecurityFilter(super.authenticationManager(), getAuthenticationEntryPoint());
		return restSecurityFilter;
		
	}
	
	@Bean
	public AuthenticationEntryPoint getAuthenticationEntryPoint() {
		BasicAuthenticationEntryPoint authenticationEntryPoint = new RestAuthenticationEntryPoint();
		authenticationEntryPoint.setRealmName(SecurityContants.SECURE_REALM);
		return authenticationEntryPoint;
		
	}
	
	
	@Bean
	public AuthenticationProvider getAuthenticationProvider() {
		return new RestAuthenticationProvider();
	}

	/*
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(getAuthenticationProvider());
		
	}
	*/


	
	
}
