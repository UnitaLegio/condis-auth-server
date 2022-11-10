package com.unitalegio.sso.web.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // Form login handles the redirect to the login page from the
        // authorization server filter chain
        httpSecurity.authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());

        return httpSecurity.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        // TODO: Implement real userDetailService #1
        // TODO: Create bean of passwordEncoder #2
        UserDetails tempUser = User.withDefaultPasswordEncoder()
                .username("tempUser")
                .password("password")
                .roles("tempRole")
                .build();
        return new InMemoryUserDetailsManager(tempUser);
    }
}
