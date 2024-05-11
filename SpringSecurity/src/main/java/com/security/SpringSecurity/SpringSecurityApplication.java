package com.security.SpringSecurity;

import com.security.SpringSecurity.auth.AuthService;
import com.security.SpringSecurity.auth.RegisterRequest;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import static com.security.SpringSecurity.user.Role.ADMIN;
import static com.security.SpringSecurity.user.Role.MANAGER;


@SpringBootApplication
public class SpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(AuthService service){
		return args -> {
			var admin=RegisterRequest.builder()
					.firstname("adminJoe")
					.lastname("adminlastname")
					.email("admin@gmail.com")
					.password("admin123")
					.role(ADMIN)
					.build();
			System.out.println("Admin token: "+service.register(admin).getAccessToken());

			var manager=RegisterRequest.builder()
					.firstname("managerJoe")
					.lastname("managerlastname")
					.email("manager@gmail.com")
					.password("manager123")
					.role(MANAGER)
					.build();
			System.out.println("manager token: "+service.register(manager).getAccessToken());
		};
	}

}
