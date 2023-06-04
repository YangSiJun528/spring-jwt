package com.example.springjwt.global.security.jwt.handler;

import com.example.springjwt.domain.user.entity.User;
import com.example.springjwt.domain.user.service.UserService;
import com.example.springjwt.global.security.jwt.JwtData;
import com.example.springjwt.global.security.jwt.JwtDataImpl;
import com.example.springjwt.global.security.jwt.JwtManager;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class ImplJwtLogoutSuccessHandler extends AbstractJwtLogoutSuccessHandler {
    private final UserService userService;

    public ImplJwtLogoutSuccessHandler(JwtManager jwtManager, UserService userService) {
        super(jwtManager);
        this.userService = userService;
    }

    @Override
    JwtData getJwtData(Authentication authentication) {
        User user = userService.getUser(Long.valueOf(authentication.getPrincipal().toString()));
        return new JwtDataImpl(user);
    }
}
