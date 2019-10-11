package com.mab.jwt.vo;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenDetail {
    
	private JwtUser jwtUser;
    
	private String accessToken;
    
	private String refreshToken;
	
}
