package com.mab.jwt.service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.mab.jwt.exception.JwtCustomException;
import com.mab.jwt.mapper.JwtMapper;
import com.mab.jwt.vo.JwtErrorCodes;
import com.mab.jwt.vo.JwtUser;

@Service
public class JwtUserDetailService implements UserDetailsService {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	
	@Autowired
	JwtProvider jwtProvider;
	
	@Autowired
	JwtMapper jwtMapper;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	/**
     * <B>History</B>
     * <ul>
     * <li>Date : 2019. 2. 15.
     * <li>Developer : devmrko
     * <li>get user information from database, and create user object. this time input password is going to be encrypted(BCryptPasswordEncoder).
     * </ul>
     *  
     * @param username
     * @return
     */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		logger.debug("### ### ### loadUserByUsername");
		JwtUser jwtUser = jwtMapper.selectUser(username);
		User user = new User(jwtUser.getUsername(), jwtUser.getPassword(), getAuthority(jwtUser.getUsername()));
		return user;
	}
	

	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>get user roles from database, and convert to SimpleGrantedAuthority set
	     * </ul>
	     *  
	     * @param username
	     * @return
	     */
	private Set<SimpleGrantedAuthority> getAuthority(String username) {
		Set<SimpleGrantedAuthority> authorities = new HashSet<>();
		String jwtRoles = jwtMapper.selectRoles(username);
		String[] jwtRoleArray = jwtRoles.split(",");
		for(int i = 0; jwtRoleArray.length > i; i++) {
			authorities.add(new SimpleGrantedAuthority(jwtRoleArray[i]));
		}
		return authorities;
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create UsernamePasswordAuthenticationToken by JwtUser
	     * </ul>
	     *  
	     * @param jwtUser
	     * @return
	     */
	public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(JwtUser jwtUser) {
//		return new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), jwtUser.getPassword(), 
//				getAuthority(jwtUser.getUsername()));
		Authentication request = null;
		try {
			request = new UsernamePasswordAuthenticationToken(jwtUser.getUsername(), jwtUser.getPassword());
	        Authentication result = authenticationManager.authenticate(request);
	        SecurityContextHolder.getContext().setAuthentication(result);

	    } catch(AuthenticationException ex) {
	    	logger.error("### ### ### validateJwtToken - SignatureException: {}", ex.getMessage());
			throw new JwtCustomException(JwtErrorCodes.CSC_BAD_CREDENTIALS, "CSC_BAD_CREDENTIALS");
	    }
		return (UsernamePasswordAuthenticationToken) request;
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : Joungmin
	     * <li>create UsernamePasswordAuthenticationToken
	     * </ul>
	     *  
	     * @param user
	     * @param credential
	     * @param authorities
	     * @return
	     */
	public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(User user, String credential, Collection<? extends GrantedAuthority> authorities) {
		return new UsernamePasswordAuthenticationToken(user, credential, authorities);
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>create UsernamePasswordAuthenticationToken without password when create JWT access token by refresh token 
	     * </ul>
	     *  
	     * @param username
	     * @return
	     */
	public UsernamePasswordAuthenticationToken getUsernamePasswordAuthenticationToken(String username) {
		return new UsernamePasswordAuthenticationToken(username, "", getAuthority(username));
	}
	
	/**
	     * <B>History</B>
	     * <ul>
	     * <li>Date : 2019. 2. 15.
	     * <li>Developer : devmrko
	     * <li>get authentication from JwtUser
	     * </ul>
	     *  
	     * @param jwtUser
	     * @return
	     */
	public Authentication getAuthentication(JwtUser jwtUser) {
		return authenticationManager.authenticate(getUsernamePasswordAuthenticationToken(jwtUser));
	}
	
}
