package com.example.springjwt.global.security.jwt;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

public interface JwtData {
    String getSubject();
    Set<String> getRoles();
    Map<String, Object> getAdditional();
}
