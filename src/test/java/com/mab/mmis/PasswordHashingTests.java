package com.mab.mmis;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class PasswordHashingTests {
	
	protected final Logger logger = LoggerFactory.getLogger(getClass());
	
	@Autowired
	BCryptPasswordEncoder encoder;
	
	@Test
	public void matchTest() {
		String plainPassword = "oracle";
		String hashedPassword = encoder.encode(plainPassword);
		logger.info("# plain password: {}, hashed password: {}", plainPassword, hashedPassword);
		assertEquals(true, encoder.matches(plainPassword, hashedPassword));
	}

}
