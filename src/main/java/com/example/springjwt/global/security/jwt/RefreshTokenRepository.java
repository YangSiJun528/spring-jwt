package com.example.springjwt.global.security.jwt;

import java.util.Map;
import java.util.Optional;

public interface RefreshTokenRepository<K, V> {
    void save(K id, V refreshToken);

    void delete(K id, V refreshToken);

    void deleteById(K id);

    void deleteByRefreshToken(V refreshToken);

    Optional<String> findById(K id);

    Optional<Map<String, String>> findByRefreshToken(V refreshToken);
}