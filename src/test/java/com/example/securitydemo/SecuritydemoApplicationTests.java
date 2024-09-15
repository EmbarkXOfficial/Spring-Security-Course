package com.example.securitydemo;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SecuritydemoApplicationTests {

	@Test
	void contextLoads() {
	}

	@BeforeEach
	public void beforeEach() {
		System.out.println("Sample Case");
	}

}
