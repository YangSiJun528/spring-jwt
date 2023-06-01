package com.example.springjwt.global.security.jwt;

public interface JwtDataService {
    JwtData loadBySubject(String subject);
}
