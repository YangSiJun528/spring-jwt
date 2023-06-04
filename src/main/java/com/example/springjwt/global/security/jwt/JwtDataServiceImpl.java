package com.example.springjwt.global.security.jwt;

import com.example.springjwt.domain.user.entity.User;
import com.example.springjwt.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtDataServiceImpl implements JwtDataService {

    private final UserService userService;

    @Override
    public JwtData loadBySubject(String subject) {
        User user = userService.getUser(Long.valueOf(subject));
        return new JwtDataImpl(user);
    }
}
