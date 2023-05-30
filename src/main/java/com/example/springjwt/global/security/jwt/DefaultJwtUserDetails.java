package com.example.springjwt.global.security.jwt;

import java.util.Set;

public class DefaultJwtUserDetails
        implements JwtUserDetails {
    @Override
    public String getUserId() {
        return null;
    }

    @Override
    public Set<String> getRoles() {
        return null;
    }
}
