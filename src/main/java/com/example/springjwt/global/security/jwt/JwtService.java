package com.example.springjwt.global.security.jwt;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Component
@RequiredArgsConstructor
public class JwtService {
    private final JwtData jwtData;
    private final JwtManager jwtManager;
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenVO generate(String id) {
        String accessToken = jwtManager.generateAccessToken(new HashMap<>(), jwtData);
        String refreshToken = jwtManager.generateRefreshToken(jwtData);
        refreshTokenRepository.save(id, refreshToken);
        return new TokenVO(accessToken, refreshToken);
    }

    public JwtData loadUserInfoById(String id) {
        String accessToken = jwtManager.generateAccessToken(new HashMap<>(), jwtData);
        String refreshToken = jwtManager.generateRefreshToken(jwtData);
        refreshTokenRepository.save(id, refreshToken);
        return JwtData;
    }

    public void delete(String id) {
        refreshTokenRepository.deleteById(id);
    }

    public boolean validation(String accessToken) throws JwtException {
        return jwtManager.validate(accessToken);
    }
}
