package com.example.rsa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

// Exclude default security to implement manual token handling resembling the Python code
@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
public class RsaEncryptionServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(RsaEncryptionServiceApplication.class, args);
    }

}
