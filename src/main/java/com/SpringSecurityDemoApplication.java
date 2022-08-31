package com;

import com.models.AppUser;
import com.models.Role;
import com.service.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityDemoApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// runs after app launch to add to database
	@Bean
	CommandLineRunner run(AppUserService userService){
		return args -> {
			userService.saveRole(new Role(null,"USER"));
			userService.saveRole(new Role(null,"MANAGER"));
			userService.saveRole(new Role(null,"ADMIN"));
			userService.saveRole(new Role(null,"SUPERADMIN"));

			userService.saveUser(new AppUser(null, "John Cena", "jcena12", "12345",new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Keanu Reaves", "keeanuki", "12345",new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Guy Fieri", "SupaHotFiya666", "12345",new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Zack Rawr", "Asmongold", "12345",new ArrayList<>()));

			userService.addRoleToUser("jcena12","USER");
			userService.addRoleToUser("keeanuki", "SUPERADMIN");
			userService.addRoleToUser("keeanuki", "ADMIN");
			userService.addRoleToUser("SupaHotFiya666", "ADMIN");
			userService.addRoleToUser("Asmongold", "MANAGER");
		};
	}
}
