package com.mab.jwt.mock;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Component
public class JwtRefreshKeys {
	
	private final Logger logger = LoggerFactory.getLogger(getClass());

	List<JwtRefreshKey> jwtRefreshKeys = new ArrayList<JwtRefreshKey>();
	
	public boolean isJwtRefreshKeyAvailable(String refreshKey, String username) {
		JwtRefreshKey curJwtRefreshKey = null;
		boolean keyAvailBool = false;
		
		for(int i = 0; jwtRefreshKeys.size() > i; i++) {
			curJwtRefreshKey = jwtRefreshKeys.get(i);
			
			// compare JWT refresh token issue date to current date
			if(addedHourToDatetime(curJwtRefreshKey.getCreateDate(), 1).compareTo(new Date()) > 0) {
				// in one hour
				logger.debug("### ### ### JwtRefreshKeys - isJwtRefreshKeyUsed: {} - {} - {}", curJwtRefreshKey.getJwtRefreshKey(), curJwtRefreshKey.getUsername(), curJwtRefreshKey.getUseYn());
				if(refreshKey.equals(curJwtRefreshKey.getJwtRefreshKey()) && "N".equals(curJwtRefreshKey.getUseYn()) && username.equals(curJwtRefreshKey.getUsername())) {
					curJwtRefreshKey.setUseYn("Y");
					return true;
				}
				
			} else {
				// one hour out
				logger.debug("### ### ### JwtRefreshKeys - isJwtRefreshKeyAvailable: refresh time is passed");
			}
			
		}
		return keyAvailBool;
	}
	
	public Date addedHourToDatetime(Date inputDate, int hours) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(inputDate);
		cal.add(Calendar.HOUR, hours);
		return cal.getTime();
	}
	
	public void addJwtRefreshKey(String refreshKey, String username) {
		JwtRefreshKey jwtRefreshKey = new JwtRefreshKey();
		jwtRefreshKey.setJwtRefreshKey(refreshKey);
		jwtRefreshKey.setUseYn("N");
		jwtRefreshKey.setUsername(username);
		jwtRefreshKey.setCreateDate(new Date());
		jwtRefreshKeys.add(jwtRefreshKey);
	}

	public void setJwtRefreshKeyAsUsed(String refreshKey, String username) {
		JwtRefreshKey curJwtRefreshKey = null;
		for(int i = 0; jwtRefreshKeys.size() > 0; i++) {
			curJwtRefreshKey = jwtRefreshKeys.get(i);
			if(refreshKey.equals(curJwtRefreshKey.getJwtRefreshKey()) && "N".equals(curJwtRefreshKey.getUseYn()) && username.equals(curJwtRefreshKey.getUsername())) {
				curJwtRefreshKey.setUseYn("Y");
			}
		}
	}

	@Getter
	@Setter
	public static class JwtRefreshKey {
		private String jwtRefreshKey;
		private String username;
		private String useYn;
		private Date createDate;
	}

}
