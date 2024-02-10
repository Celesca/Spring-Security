package com.example.securitycourse.securityconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import static org.springframework.security.config.Customizer.withDefaults;

//        http.formLogin(withDefaults());
@Component
@EnableWebSecurity // Handle Security Config
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests((requests) -> requests
                        .requestMatchers("/public/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/member/**").hasAuthority("MEMBER_READ")
                        .requestMatchers(HttpMethod.PUT, "/member/**").hasAuthority("MEMBER_UPDATE")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(new ApiKeyAuthFilter(), BasicAuthenticationFilter.class)
                .httpBasic(withDefaults())
                .build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        UserDetails user = User.withUsername("member")
                .password(encoder.encode("password"))
                .authorities("MEMBER_READ", "MEMBER_UPDATE")
                .build();

        return new InMemoryUserDetailsManager(user);
    }

}
