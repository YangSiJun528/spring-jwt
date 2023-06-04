package com.example.springjwt.global.security.jwt.repository;

import java.util.Map;
import java.util.Optional;

public interface RefreshTokenRepository<K, V> {
    void save(K subject, V refreshToken);

    void delete(K subject, V refreshToken);

    void deleteBySubject(K subject);

    void deleteByRefreshToken(V refreshToken);

    Optional<String> findBySubject(K subject);

    Optional<Map<String, String>> findByRefreshToken(V refreshToken);
}