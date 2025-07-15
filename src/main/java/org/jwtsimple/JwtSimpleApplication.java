package org.jwtsimple;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@EnableJpaAuditing
@SpringBootApplication
public class JwtSimpleApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtSimpleApplication.class, args);
    }

}
