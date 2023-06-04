package com.example.springjwt.global.security.jwt.handler;

import com.example.springjwt.global.security.jwt.JwtData;
import com.example.springjwt.global.security.jwt.JwtManager;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@RequiredArgsConstructor
public abstract class AbstractJwtLoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtManager jwtManager;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        JwtData jwtData = getJwtData(authentication);
        String newAccessToken = jwtManager.generateAccessToken(jwtData);
        String newRefreshToken = jwtManager.generateRefreshToken(jwtData);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"accessToken\": \"" + newAccessToken + "\", " +
                        "\"refreshToken\": \"" + newRefreshToken + "\"}"
        );
        response.getWriter().flush();
    }

    abstract JwtData getJwtData(Authentication authentication);
}
