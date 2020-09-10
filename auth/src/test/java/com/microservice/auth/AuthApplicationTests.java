package com.microservice.auth;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class AuthApplicationTests {

	@Test
	void contextLoads() {
	}

	@Test
	public void passwordEncrypted(){
		System.out.println(new BCryptPasswordEncoder().encode("pass"));
	}
}
