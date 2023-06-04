package com.example.springjwt.global.security.jwt.handler;

import com.example.springjwt.domain.user.entity.User;
import com.example.springjwt.domain.user.service.UserService;
import com.example.springjwt.global.security.jwt.JwtData;
import com.example.springjwt.global.security.jwt.JwtDataImpl;
import com.example.springjwt.global.security.jwt.JwtManager;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class ImplJwtLoginSuccessHandler extends AbstractJwtLoginSuccessHandler {

    private final UserService userService;

    public ImplJwtLoginSuccessHandler(JwtManager jwtManager, UserService userService) {
        super(jwtManager);
        this.userService = userService;
    }

    @Override
    JwtData getJwtData(Authentication authentication) {
        User user = userService.getUser(Long.valueOf(authentication.getPrincipal().toString()));
        return new JwtDataImpl(user);
    }
}
