package com.mab.jwt.service;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {
	
	private final Logger logger = LoggerFactory.getLogger(getClass());

	public String getDatetime(long miliSeconds) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		Date resultdate = new Date(miliSeconds);
		return sdf.format(resultdate);
	}
	
	public long getIat() {
		long iat = System.currentTimeMillis();
		logger.debug("### ### ### JwtUtil - getIat: {}", this.getDatetime(iat));
		return iat;
	}

}
