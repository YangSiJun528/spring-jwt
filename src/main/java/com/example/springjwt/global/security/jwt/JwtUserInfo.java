package com.example.springjwt.global.security.jwt;

import com.example.springjwt.domain.user.entity.User;

import java.util.Set;

public class JwtUserInfo implements JwtData {

    User user;

    @Override
    public String getSubject() {
        return String.valueOf(user.getId());
    }

    @Override
    public Set<String> getRoles() {
        return Set.of(String.valueOf(user.getRole()));
    }
}