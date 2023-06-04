package com.example.springjwt.global.security.config;

import com.example.springjwt.global.security.jwt.authencitation.JwtAuthenticationFilter;
import com.example.springjwt.global.security.jwt.handler.AbstractJwtLoginSuccessHandler;
import com.example.springjwt.global.security.jwt.handler.AbstractJwtLogoutSuccessHandler;
import com.example.springjwt.global.security.jwt.refresh.JwtRefreshFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.web.cors.CorsConfiguration;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
//    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtRefreshFilter jwtRefreshFilter;
    private final AbstractJwtLoginSuccessHandler jwtLoginSuccessHandler;
    private final AbstractJwtLogoutSuccessHandler jwtLogoutSuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues()))
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(formLogin -> formLogin.loginPage("api/auth/login"))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(header -> header.frameOptions(frameOptions -> frameOptions.sameOrigin())
                )
                .authorizeHttpRequests(httpRequests -> httpRequests
                        .requestMatchers(toH2Console()).permitAll()
                        .requestMatchers("api/auth/**").permitAll()
                        .requestMatchers("api/public/**").permitAll()
                        .requestMatchers("api/authenticated/**").authenticated()
                        .anyRequest().authenticated()
                )
                .addFilterAfter(jwtRefreshFilter, LogoutFilter.class)
                .addFilterAfter(jwtAuthenticationFilter, LogoutFilter.class)
                .formLogin(fromLogin -> fromLogin
                        .successHandler(jwtLoginSuccessHandler)
                )
                .logout(logout -> logout
                        .addLogoutHandler((LogoutHandler) jwtLogoutSuccessHandler)
                );
                //.apply(jwtSecurityConfig());
        return http.build();
    }

//    public JwtSecurityConfig jwtSecurityConfig() {
//        return new JwtSecurityConfig(jwtAuthenticationFilter, jwtRefreshFilter, jwtLoginSuccessHandler, jwtLogoutSuccessHandler);
//    }
}