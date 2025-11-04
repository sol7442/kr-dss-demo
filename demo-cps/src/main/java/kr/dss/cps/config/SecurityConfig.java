package kr.dss.cps.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(auth -> 
		auth
        .requestMatchers("/tsa/**", "/ocsp/**", "/crl/**").permitAll()
		.anyRequest().authenticated())
		.httpBasic(httpBasic -> httpBasic.disable())
		.formLogin(form -> form.disable())
		.csrf(csrf -> csrf.disable());
		
		return http.build();
	}

}
