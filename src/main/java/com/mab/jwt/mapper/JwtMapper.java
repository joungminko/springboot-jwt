package com.mab.jwt.mapper;

import java.util.List;
import java.util.Map;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;

import com.mab.jwt.vo.JwtUser;

@Mapper
public interface JwtMapper {
	
	public List<JwtUser> selectUsers();
	
	public JwtUser selectUser(@Param("username") String username);
	
	public String selectRoles(@Param("username") String username);
	
	public int selectIsUrlEnabled(@Param("request_url") String requestUrl, @Param("request_method") String requestMethod, @Param("rolename") String rolename);
	
	public void insertRefreshToken(@Param("token") String token, @Param("username") String username);
	
	public int updateRefreshTokenAsUsed(@Param("token") String token, @Param("username") String username);
	
	public List<Map<String, String>> selectMenu();
	
}