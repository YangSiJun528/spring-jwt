package com.example.springjwt.global.security.jwt;

import java.util.Set;

public interface JwtData {
    String getSubject();
    Set<String> getRoles();
}
