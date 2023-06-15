package com.example.springjwt.global.security.jwt.repository;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class MapRefreshTokenRepository implements RefreshTokenRepository<String, String> {
    Map<String, String> db = new HashMap<>(Collections.emptyMap());

    @Override
    public void save(String subject, String refreshToken) {
        db.put(subject, refreshToken);
    }

    @Override
    public void delete(String subject, String refreshToken) {
        db.remove(subject, refreshToken);
    }

    @Override
    public void deleteBySubject(String subject) {
        db.remove(subject);
    }

    @Override
    public void deleteByRefreshToken(String refreshToken) {
        db.values().remove(refreshToken);
    }

    @Override
    public Optional<String> findBySubject(String subject) {
        return Optional.ofNullable(db.get(subject));
    }

    @Override
    public Optional<Map<String, String>> findByRefreshToken(String refreshToken) {
        Map<String, String> rs = db.entrySet().stream()
                .filter(v -> v.equals(refreshToken))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        return Optional.ofNullable(rs);
    }

}