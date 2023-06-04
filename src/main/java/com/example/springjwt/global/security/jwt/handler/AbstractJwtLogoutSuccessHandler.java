package com.example.springjwt.global.security.jwt.handler;

import com.example.springjwt.global.security.jwt.JwtData;
import com.example.springjwt.global.security.jwt.JwtManager;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@RequiredArgsConstructor
public abstract class AbstractJwtLogoutSuccessHandler implements LogoutSuccessHandler {
    private final JwtManager jwtManager;
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        JwtData jwtData = getJwtData(authentication);
        jwtManager.removeRefreshToken(jwtData);
    }

    abstract JwtData getJwtData(Authentication authentication);
}
