package com.example.springjwt.global.security.jwt.data;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "jwt")
public record JwtEnvironment(
        String secretKey,
        Long accessExpiration,
        Long refreshExpiration,
        String issuer
) {
}

