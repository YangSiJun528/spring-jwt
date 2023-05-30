package com.example.springjwt.global.security.jwt;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

//TODO @ConditionalOnMissingBean << 여기 있는게 아니라 그 설정 클래스를 하나 만들어야 함
public class DefaultRefreshTokenRepository implements RefreshTokenRepository<String,String> {

    Map<String,String> db = new HashMap<>(Collections.emptyMap());

    @Override
    public void save(String id, String refreshToken) {
        db.put(id, refreshToken);
    }

    @Override
    public void delete(String id, String refreshToken) {
        db.remove(id, refreshToken);
    }

    @Override
    public void deleteById(String id) {
        db.remove(id);
    }

    @Override
    public void deleteByRefreshToken(String refreshToken) {
        db.values().remove(refreshToken);
    }

    @Override
    public Optional<String> findById(String id) {
        return Optional.ofNullable(db.get(id));
    }

    @Override
    public Optional<Map<String, String>> findByRefreshToken(String refreshToken) {
        Map<String,String> rs = db.entrySet().stream()
                .filter(v -> v.equals(refreshToken))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
        return Optional.ofNullable(rs);
    }
}
