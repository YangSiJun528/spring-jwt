package com.example.springjwt.global.security.jwt.authencitation;

import com.example.springjwt.global.security.jwt.data.JwtInvalidException;
import com.example.springjwt.global.security.jwt.JwtManager;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {
    private final JwtManager jwtManager;

    private Collection<? extends GrantedAuthority> createGrantedAuthorities(Set<String> roles) {
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        for (String role : roles) {
            grantedAuthorities.add(() -> role);
        }
        return grantedAuthorities;
    }

    /**
     * MalformedJwtException – 지정된 JWT가 잘못 구성되어 (따라서 유효하지 않은) 경우.
     * SignatureException – JWS 서명이 발견되었지만 검증할 수 없는 경우.
     * ExpiredJwtException – 만료 시간을 넘긴 JWT인 경우.
     * IllegalArgumentException – 지정된 문자열이 null 또는 비어 있거나 공백만 있는 경우.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String subject;
        Set<String> roles;
        Claims allClaims;
        try {
            String accessToken = ((JwtAuthenticationToken) authentication).getAccessToken();
            subject = jwtManager.extractSubject(accessToken);
            allClaims = jwtManager.extractAllClaims(accessToken);
            roles = jwtManager.extractRoles(accessToken);
        } catch (SignatureException signatureException) {
            throw new JwtInvalidException("서명 키가 다릅니다", signatureException);
        } catch (ExpiredJwtException expiredJwtException) {
            throw new JwtInvalidException("만료된 토큰입니다", expiredJwtException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new JwtInvalidException("잘못된 형식의 토큰입니다", malformedJwtException);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new JwtInvalidException("null과 같은 잘못된 인수를 사용했습니다", illegalArgumentException);
        }
        return new JwtAuthenticationToken(subject, allClaims, createGrantedAuthorities(roles));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
