package com.example.springjwt.global.security.jwt;

import java.util.Set;

public interface JwtUserDetails {
    String getSubject();
    Set<String> getRoles();
}
