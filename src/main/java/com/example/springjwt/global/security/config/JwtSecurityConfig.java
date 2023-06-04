package com.example.springjwt.global.security.config;

import com.example.springjwt.global.security.jwt.authencitation.JwtAuthenticationFilter;
import com.example.springjwt.global.security.jwt.handler.AbstractJwtLoginSuccessHandler;
import com.example.springjwt.global.security.jwt.handler.AbstractJwtLogoutSuccessHandler;
import com.example.springjwt.global.security.jwt.refresh.JwtRefreshFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.CorsConfiguration;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Component
@RequiredArgsConstructor
public class JwtSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtRefreshFilter jwtRefreshFilter;
    private final AbstractJwtLoginSuccessHandler jwtLoginSuccessHandler;
    private final AbstractJwtLogoutSuccessHandler jwtLogoutSuccessHandler;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .addFilterAfter(jwtRefreshFilter, LogoutFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, LogoutFilter.class)
                .formLogin(fromLogin -> fromLogin
                        .successHandler(jwtLoginSuccessHandler)
                )
                .logout(logout -> logout
                        .addLogoutHandler((LogoutHandler) jwtLogoutSuccessHandler)
                );
    }
}