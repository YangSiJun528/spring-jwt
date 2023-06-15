package com.example.springjwt.global.security.config;

import com.example.springjwt.global.security.jwt.authencitation.JwtAuthenticationFilter;
import com.example.springjwt.global.security.jwt.handler.AbstractJwtLoginSuccessHandler;
import com.example.springjwt.global.security.jwt.handler.AbstractJwtLogoutSuccessHandler;
import com.example.springjwt.global.security.jwt.refresh.JwtRefreshFilter;
import com.example.springjwt.global.security.jwt.repository.MapRefreshTokenRepository;
import com.example.springjwt.global.security.jwt.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
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
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtRefreshFilter jwtRefreshFilter;
    private final AbstractJwtLoginSuccessHandler jwtLoginSuccessHandler;
    private final AbstractJwtLogoutSuccessHandler jwtLogoutSuccessHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(cors -> cors.configurationSource(request -> new CorsConfiguration().applyPermitDefaultValues()))
                .httpBasic(httpBasic -> httpBasic.disable())
                .formLogin(withDefaults())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .headers(header -> header.frameOptions(frameOptions -> frameOptions.sameOrigin())
                )
                .authorizeHttpRequests(httpRequests -> httpRequests
                        .requestMatchers(toH2Console()).permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/public/**").permitAll()
                        .requestMatchers("/api/authenticated/**").authenticated()
                        .anyRequest().permitAll()
                )
                .addFilterAfter(jwtRefreshFilter, LogoutFilter.class)
                .addFilterAfter(jwtAuthenticationFilter(), LogoutFilter.class)
                .formLogin(fromLogin -> fromLogin
                        .successHandler(jwtLoginSuccessHandler)
                )
                .logout(logout -> logout
                        .logoutSuccessHandler(jwtLogoutSuccessHandler)
                );
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception{
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration));
        return filter;
    }

    @Bean
    public RefreshTokenRepository repository() { // TODO 이런식으로 다형성 주입 필요함 / 근데 이러면 의존성 loop 생길거 같은데, 이런거 설정해주는 config 파일을 따로 만들어야 할듯 - jwtconfig 같은 걸로
        return new MapRefreshTokenRepository();
    }
}