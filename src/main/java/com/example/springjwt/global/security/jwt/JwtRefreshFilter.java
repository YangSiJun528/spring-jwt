package com.example.springjwt.global.security.jwt;

import com.example.springjwt.global.security.domain.user.entity.User;
import com.example.springjwt.global.security.domain.user.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.util.StreamUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtRefreshFilter extends OncePerRequestFilter {
    private final String ENDPOINT = "/api/auth/v1";

    private final String TOKEN_VALUE = "refreshToken";

    private final ObjectMapper objectMapper = new ObjectMapper();

    private final JwtManager jwtManager;
    private final RefreshTokenRepository tokenRepository;
    private final JwtDataService jwtDataService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getServletPath().contains(ENDPOINT) && !request.getMethod().equals("POST")) {
            filterChain.doFilter(request, response);
            return;
        }
        ServletInputStream inputStream = request.getInputStream();
        String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
        System.out.println("messageBody = " + messageBody);

        Map<String, Object> jsonBody = objectMapper.readValue(messageBody, Map.class);
        String refreshToken = (String) jsonBody.get(TOKEN_VALUE); // TODO 이 부분 String 아닌 경우 예외처리
        if (refreshToken == null) {
            filterChain.doFilter(request, response);
            return;
        }
        JwtData jwtData = null;
        try {
            String subject = jwtManager.extractSubject(refreshToken);
            jwtData = jwtDataService.loadBySubject(subject); // 굳이 User 도메인 객체일 필요는 없고, JWT에 들어가야 할 사용자 정보만 포함하고 있으면 됨
        } catch (SignatureException signatureException) {
            throw new JwtInvalidException("서명 키가 다릅니다", signatureException);
        } catch (ExpiredJwtException expiredJwtException) {
            throw new JwtInvalidException("만료된 토큰입니다", expiredJwtException);
        } catch (MalformedJwtException malformedJwtException) {
            throw new JwtInvalidException("잘못된 형식의 토큰입니다", malformedJwtException);
        } catch (IllegalArgumentException illegalArgumentException) {
            throw new JwtInvalidException("null과 같은 잘못된 인수를 사용했습니다", illegalArgumentException);
        }
        String newAccessToken = jwtManager.generateAccessToken(Collections.emptyMap(), jwtData);
        String newRefreshToken = jwtManager.generateRefreshToken(jwtData);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(
                "{\"accessToken\": \"" + newAccessToken + "\", " +
                "\"refreshToken\": \"" + newRefreshToken + "\"}"
        );
        response.getWriter().flush();
    }
}
